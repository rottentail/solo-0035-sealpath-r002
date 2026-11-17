package ocsp

import (
	"crypto/x509"
	"fmt"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/revocation"
	"time"
)

// Result is the OCSP evidence selected for one certificate at the decision
// time, together with the approval revision it was resolved under.
type Result struct {
	Check      model.Check
	ResponseID string
	Responder  string
	Revision   int
	Revoked    bool
	ThisUpdate time.Time
	NextUpdate time.Time
	Fresh      bool
	Valid      bool
}

// Inspect chooses the freshest usable response approved for the certificate.
// A response is usable when its this_update has taken effect by at, its
// next_update has not passed, and the responder that signed it is currently
// approved and not retired. Retired responders contribute nothing to new
// decisions, even while an old response is nominally unexpired.
func Inspect(certID string, certificates map[string]model.Certificate, responders map[string]model.OCSPResponder, responses map[string]model.OCSPResponse, at time.Time) Result {
	certValue, certOK := certificates[certID]
	var cert *x509.Certificate
	if certOK {
		cert, _ = codec.ParseCertificate(certValue.DER)
	}
	var chosen *model.OCSPResponse
	var chosenResponder model.OCSPResponder
	for _, response := range responses {
		responder, ok := responders[response.ResponderID]
		if !ok || responder.Status != "active" || response.ThisUpdate.After(at) {
			continue
		}
		// Authorization is checked against the certificate being examined,
		// so a response approved for another certificate cannot leak in.
		if !authorizes(responder, certID) {
			continue
		}
		// A response is only current if it was signed by the certificate
		// the responder approves today; rotating the signing certificate
		// retires older material from new decisions without deleting it.
		if response.CertificateID != responder.CertificateID {
			continue
		}
		if cert != nil {
			// The response must actually answer for this certificate; a
			// fresher answer for a different serial is not evidence here.
			issuerValue, ok := certificates[response.IssuerID]
			if !ok {
				continue
			}
			issuer, err := codec.ParseCertificate(issuerValue.DER)
			if err != nil {
				continue
			}
			status, err := codec.ParseOCSP(response.DER)
			if err != nil || codec.Digest(response.DER) != response.ID || status.MatchesCertID(issuer, cert) != nil {
				continue
			}
		}
		if chosen == nil || response.ThisUpdate.After(chosen.ThisUpdate) || (response.ThisUpdate.Equal(chosen.ThisUpdate) && response.ID < chosen.ID) {
			copy := response
			chosen = &copy
			chosenResponder = responder
		}
	}
	if chosen == nil {
		return Result{Check: model.Check{Code: "revocation", Status: "unknown", Detail: "no approved responder has answered for this certificate", Source: "ocsp"}}
	}
	out := Result{ResponseID: chosen.ID, Responder: chosenResponder.ID, Revision: chosenResponder.Revision, ThisUpdate: chosen.ThisUpdate, NextUpdate: chosen.NextUpdate, Valid: true}
	issuerValue, ok := certificates[chosen.IssuerID]
	if !ok {
		out.Check = model.Check{Code: "revocation", Status: "fail", Detail: "OCSP issuer certificate is absent", Source: "ocsp", Evidence: chosen.ID}
		return out
	}
	issuer, err := codec.ParseCertificate(issuerValue.DER)
	if err != nil {
		out.Check = model.Check{Code: "revocation", Status: "fail", Detail: "OCSP issuer certificate is invalid", Source: "ocsp", Evidence: chosen.ID}
		return out
	}
	status, err := codec.ParseOCSP(chosen.DER)
	if err != nil || codec.Digest(chosen.DER) != chosen.ID {
		out.Check = model.Check{Code: "revocation", Status: "fail", Detail: "OCSP material signature or identity is invalid", Source: "ocsp", Evidence: chosen.ID}
		return out
	}
	if at.Before(status.ThisUpdate) || !at.Before(status.NextUpdate) {
		out.Valid = false
		out.Check = model.Check{Code: "revocation", Status: "unknown", Detail: "OCSP response is not valid at the requested time", Source: "ocsp", Evidence: chosen.ID}
		return out
	}
	if cert == nil {
		out.Valid = false
		out.Check = model.Check{Code: "revocation", Status: "unknown", Detail: "certificate is unavailable for OCSP comparison", Source: "ocsp", Evidence: chosen.ID}
		return out
	}
	if status.MatchesCertID(issuer, cert) != nil {
		out.Check = model.Check{Code: "revocation", Status: "fail", Detail: "OCSP response does not answer for this certificate", Source: "ocsp", Evidence: chosen.ID}
		return out
	}
	out.Fresh = true
	if status.Revoked {
		out.Revoked = true
		out.Check = model.Check{Code: "revocation", Status: "fail", Detail: fmt.Sprintf("certificate %s was revoked at %s", cert.SerialNumber, status.RevocationTime.Format(time.RFC3339)), Source: "ocsp", Evidence: chosen.ID}
		return out
	}
	if !status.Good {
		out.Valid = false
		out.Check = model.Check{Code: "revocation", Status: "unknown", Detail: "OCSP responder could not state a status", Source: "ocsp", Evidence: chosen.ID}
		return out
	}
	out.Check = model.Check{Code: "revocation", Status: "pass", Detail: "OCSP responder reports the certificate as good", Source: "ocsp", Evidence: chosen.ID}
	return out
}

// Combine merges CRL and OCSP evidence. A fresh, affirmative OCSP response
// takes precedence for availability, but it cannot erase a revocation that
// was already confirmed: a CRL revocation effective at or before the
// response's this_update still rejects. An OCSP revocation likewise stands
// unless a CRL issued at or after the response omitted the serial.
func Combine(crl revocation.Result, status Result) (model.Check, string) {
	crlCheck, ocspCheck := crl.Check, status.Check
	if !status.Fresh || !status.Valid {
		// No usable OCSP evidence: fall back to the CRL result unchanged.
		return crlCheck, crl.ID
	}
	switch {
	case status.Revoked:
		return ocspCheck, status.ResponseID
	case crl.Revoked:
		// A confirmed revocation effective before the response must survive
		// a fresher "good" reply.
		detail := crlCheck.Detail
		if status.ResponseID != "" {
			detail = fmt.Sprintf("%s; fresh OCSP status does not override a confirmed revocation", detail)
		}
		return model.Check{Code: "revocation", Status: "fail", Detail: detail, Source: "crl", Evidence: crl.ID}, crl.ID
	}
	if crlCheck.Status == "pass" {
		return ocspCheck, status.ResponseID
	}
	// CRL is missing, expired or unknown: the fresh OCSP pass is the best
	// available affirmative evidence and satisfies a required policy.
	return ocspCheck, status.ResponseID
}

func authorizes(responder model.OCSPResponder, certID string) bool {
	for _, id := range responder.Certificates {
		if id == certID {
			return true
		}
	}
	return false
}
