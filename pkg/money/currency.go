// Package money implements exact-decimal monetary values for the SERK
// Construction financial kernel.
//
// LAW 06: never use floating point for authoritative monetary calculations.
// Every amount carries its currency and is quantised to that currency's
// ISO 4217 minor units under an explicit, versioned rounding policy.
package money

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Currency is an ISO 4217 alphabetic code (e.g. "ETB").
type Currency string

// CurrencyInfo describes the authoritative precision of a currency.
type CurrencyInfo struct {
	Code       Currency
	Numeric    int    // ISO 4217 numeric code
	MinorUnits int32  // decimal digits in the minor unit (exponent)
	Name       string // English name
}

var (
	// ErrUnknownCurrency is returned for codes not present in the registry.
	ErrUnknownCurrency = errors.New("money: unknown currency")
	// ErrCurrencyMismatch is returned when operating on two different currencies.
	ErrCurrencyMismatch = errors.New("money: currency mismatch")
)

// registry holds all currencies known to the kernel. Seeded with the full
// African set required by the specification plus the major hard currencies.
// Additional ISO 4217 currencies may be registered at start-up by
// configuration (Register) — never by hardcoding in business modules.
var registry = struct {
	sync.RWMutex
	m map[Currency]CurrencyInfo
}{m: map[Currency]CurrencyInfo{}}

func init() {
	seed := []CurrencyInfo{
		{"ETB", 230, 2, "Ethiopian Birr"},
		{"KES", 404, 2, "Kenyan Shilling"},
		{"UGX", 800, 0, "Ugandan Shilling"},
		{"TZS", 834, 2, "Tanzanian Shilling"},
		{"RWF", 646, 0, "Rwandan Franc"},
		{"NGN", 566, 2, "Nigerian Naira"},
		{"GHS", 936, 2, "Ghanaian Cedi"},
		{"ZAR", 710, 2, "South African Rand"},
		{"EGP", 818, 2, "Egyptian Pound"},
		{"MAD", 504, 2, "Moroccan Dirham"},
		{"XOF", 952, 0, "CFA Franc BCEAO"},
		{"XAF", 950, 0, "CFA Franc BEAC"},
		{"DJF", 262, 0, "Djiboutian Franc"},
		{"SDG", 938, 2, "Sudanese Pound"},
		{"SSP", 728, 2, "South Sudanese Pound"},
		{"SOS", 706, 2, "Somali Shilling"},
		{"ERN", 232, 2, "Eritrean Nakfa"},
		{"MZN", 943, 2, "Mozambican Metical"},
		{"ZMW", 967, 2, "Zambian Kwacha"},
		{"BWP", 72, 2, "Pula"},
		{"NAD", 516, 2, "Namibia Dollar"},
		{"AOA", 973, 2, "Kwanza"},
		{"CDF", 976, 2, "Congolese Franc"},
		{"BIF", 108, 0, "Burundi Franc"},
		{"MWK", 454, 2, "Malawi Kwacha"},
		{"MUR", 480, 2, "Mauritius Rupee"},
		{"TND", 788, 3, "Tunisian Dinar"},
		{"DZD", 12, 2, "Algerian Dinar"},
		{"LYD", 434, 3, "Libyan Dinar"},
		{"USD", 840, 2, "US Dollar"},
		{"EUR", 978, 2, "Euro"},
		{"GBP", 826, 2, "Pound Sterling"},
		{"CNY", 156, 2, "Yuan Renminbi"},
		{"AED", 784, 2, "UAE Dirham"},
		{"SAR", 682, 2, "Saudi Riyal"},
		{"INR", 356, 2, "Indian Rupee"},
		{"JPY", 392, 0, "Yen"},
		{"TRY", 949, 2, "Turkish Lira"},
		{"KWD", 414, 3, "Kuwaiti Dinar"},
		{"BHD", 48, 3, "Bahraini Dinar"},
		{"CHF", 756, 2, "Swiss Franc"},
	}
	for _, c := range seed {
		registry.m[c.Code] = c
	}
}

// Register adds or replaces a currency definition. Intended for start-up
// configuration from an administratively approved ISO 4217 table.
func Register(info CurrencyInfo) error {
	code := Currency(strings.ToUpper(strings.TrimSpace(string(info.Code))))
	if len(code) != 3 {
		return fmt.Errorf("%w: %q is not a 3-letter code", ErrUnknownCurrency, info.Code)
	}
	if info.MinorUnits < 0 || info.MinorUnits > 6 {
		return fmt.Errorf("money: minor units %d out of range for %s", info.MinorUnits, code)
	}
	info.Code = code
	registry.Lock()
	defer registry.Unlock()
	registry.m[code] = info
	return nil
}

// Lookup returns the registry entry for a currency code.
func Lookup(code Currency) (CurrencyInfo, error) {
	registry.RLock()
	defer registry.RUnlock()
	info, ok := registry.m[Currency(strings.ToUpper(string(code)))]
	if !ok {
		return CurrencyInfo{}, fmt.Errorf("%w: %q", ErrUnknownCurrency, code)
	}
	return info, nil
}

// MinorUnits returns the number of decimal places for the currency.
func MinorUnits(code Currency) (int32, error) {
	info, err := Lookup(code)
	if err != nil {
		return 0, err
	}
	return info.MinorUnits, nil
}

// IsKnown reports whether the currency is registered.
func IsKnown(code Currency) bool {
	_, err := Lookup(code)
	return err == nil
}
