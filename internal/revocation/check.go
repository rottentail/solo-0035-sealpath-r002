package revocation

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"time"
)

// Result describes the CRL evidence selected for one certificate. It carries
// the signed fields needed to combine CRL and OCSP evidence without relying on
// the unsigned index stored alongside the DER.
type Result struct {
	Check      model.Check
	ID         string
	Revoked    bool
	Reason     int
	RevokedAt  time.Time
	ThisUpdate time.Time
	NextUpdate time.Time
}

// Inspect selects the highest-numbered issuer list that had taken effect at
// the requested time and evaluates the certificate against it.
func Inspect(cert, issuer *x509.Certificate, lists map[string]model.RevocationList, at time.Time) Result {
	issuerID := codec.Digest(issuer.Raw)
	var chosen *model.RevocationList
	for _, item := range lists {
		if item.IssuerID != issuerID || item.ThisUpdate.After(at) {
			continue
		}
		number, ok := new(big.Int).SetString(item.Number, 10)
		if !ok {
			continue
		}
		if chosen == nil {
			copy := item
			chosen = &copy
			continue
		}
		old, _ := new(big.Int).SetString(chosen.Number, 10)
		if number.Cmp(old) > 0 {
			copy := item
			chosen = &copy
		}
	}
	if chosen == nil {
		return Result{Check: model.Check{Code: "revocation", Status: "unknown", Detail: "no issuer CRL exists at the requested time", Source: "crl"}}
	}
	out := Result{ID: chosen.ID, ThisUpdate: chosen.ThisUpdate, NextUpdate: chosen.NextUpdate}
	list, err := codec.ParseCRL(chosen.DER)
	if err != nil || codec.Digest(chosen.DER) != chosen.ID || list.CheckSignatureFrom(issuer) != nil {
		out.Check = model.Check{Code: "revocation", Status: "fail", Detail: "CRL material signature or identity is invalid", Source: "crl", Evidence: chosen.ID}
		return out
	}
	if !at.Before(list.NextUpdate) {
		out.Check = model.Check{Code: "revocation", Status: "unknown", Detail: "issuer CRL has expired", Source: "crl", Evidence: chosen.ID}
		return out
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 && !entry.RevocationTime.After(at) {
			out.Revoked = true
			out.Reason = entry.ReasonCode
			out.RevokedAt = entry.RevocationTime.UTC()
			out.Check = model.Check{Code: "revocation", Status: "fail", Detail: fmt.Sprintf("certificate %s was revoked at %s", cert.SerialNumber, entry.RevocationTime.UTC().Format(time.RFC3339)), Source: "crl", Evidence: chosen.ID}
			return out
		}
	}
	out.Check = model.Check{Code: "revocation", Status: "pass", Detail: "serial is absent from the valid issuer CRL", Source: "crl", Evidence: chosen.ID}
	return out
}

// Check preserves the original single-source helper.
func Check(cert, issuer *x509.Certificate, lists map[string]model.RevocationList, at time.Time) (model.Check, string) {
	result := Inspect(cert, issuer, lists, at)
	return result.Check, result.ID
}
