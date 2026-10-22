package config

import "testing"

// R11 probe: SERK_BANK_DIGEST_KEY is compared with the data key, tenant DB
// secret and abuse key, but not with SERK_BANK_DATA_KEY_PREVIOUS.
func TestR11_DigestKeyEqualsPreviousDataKey(t *testing.T) {
	env := prodEnv()
	env["SERK_BANK_DATA_KEY_PREVIOUS"] = goodSecret3
	env["SERK_BANK_DIGEST_KEY"] = goodSecret3
	if _, err := Load(src(env, nil)); err == nil {
		t.Errorf("OPEN: production accepted SERK_BANK_DIGEST_KEY equal to SERK_BANK_DATA_KEY_PREVIOUS")
	} else {
		t.Logf("held: %v", err)
	}
}
