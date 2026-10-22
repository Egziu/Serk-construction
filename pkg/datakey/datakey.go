// Package datakey encrypts sensitive columns in the application so the
// database, its exports and its backups hold ciphertext only
// (R-BANK-AT-REST). AES-256-GCM under a per-tenant subkey derived with HKDF
// from a master data key; the ciphertext is bound to its row by additional
// authenticated data, so a value copied to another row or tenant does not
// decrypt. The master belongs in a vault or KMS; here it comes from
// SERK_BANK_DATA_KEY (file or secret store) and never reaches PostgreSQL.
//
// Format: 0x01 | key id (1 byte length + bytes) | 12-byte nonce | ciphertext.
package datakey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrKey is returned for an unusable key or a ciphertext this key cannot open.
var ErrKey = errors.New("datakey: cannot decrypt")

// Key is a master data key with an identifier for rotation.
type Key struct {
	ID     string
	Master []byte
}

// Ring holds the current key and any previous keys still needed to read old
// ciphertext. Encryption always uses Current.
type Ring struct {
	Current  Key
	Previous []Key
	// DigestKey keys Digest (never rotated in place).
	DigestKey []byte
}

func (k Key) sub(tenant string) ([]byte, error) {
	if len(k.Master) < 32 {
		return nil, fmt.Errorf("%w: master key must be at least 32 bytes", ErrKey)
	}
	if k.ID == "" || len(k.ID) > 255 {
		return nil, fmt.Errorf("%w: key id", ErrKey)
	}
	return hkdf.Key(sha256.New, k.Master, []byte("serk-datakey:"+tenant), "bank-account", 32)
}

// Encrypt seals plaintext for the tenant, bound to aad (table and row).
func (r Ring) Encrypt(tenant string, aad, plaintext []byte) ([]byte, error) {
	sub, err := r.Current.sub(tenant)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := []byte{1, byte(len(r.Current.ID))}
	out = append(out, r.Current.ID...)
	out = append(out, nonce...)
	return g.Seal(out, nonce, plaintext, aad), nil
}

// Decrypt opens ciphertext produced by Encrypt with the key it names.
func (r Ring) Decrypt(tenant string, aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2 || ciphertext[0] != 1 {
		return nil, fmt.Errorf("%w: format", ErrKey)
	}
	n := int(ciphertext[1])
	if len(ciphertext) < 2+n+12+16 {
		return nil, fmt.Errorf("%w: format", ErrKey)
	}
	kid := string(ciphertext[2 : 2+n])
	var key *Key
	if r.Current.ID == kid {
		key = &r.Current
	} else {
		for i := range r.Previous {
			if r.Previous[i].ID == kid {
				key = &r.Previous[i]
				break
			}
		}
	}
	if key == nil {
		return nil, fmt.Errorf("%w: unknown key id %q", ErrKey, kid)
	}
	sub, err := key.sub(tenant)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[2+n : 2+n+12]
	pt, err := g.Open(nil, nonce, ciphertext[2+n+12:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrKey)
	}
	return pt, nil
}

// AAD builds the row binding: table, row id and tenant.
func AAD(table, id, tenant string) []byte {
	return []byte(table + "\x1f" + id + "\x1f" + tenant)
}

// Digest is a deterministic keyed digest of a value for one tenant, used for
// uniqueness and for approval binding of bank account numbers (R10-F4). It
// is computed in the API with a key the database never holds, so a tenant
// database credential cannot test guesses against stored digests. The key
// must never be rotated without re-digesting every stored value (it is
// separate from the encryption keys for that reason).
func Digest(key []byte, tenant, value string) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("%w: digest key must be at least 32 bytes", ErrKey)
	}
	sub, err := hkdf.Key(sha256.New, key, []byte("serk-digest:"+tenant), "bank-account-digest", 32)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, sub)
	m.Write([]byte(value))
	return "hkey:" + hex.EncodeToString(m.Sum(nil)), nil
}
