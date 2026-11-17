package codec

import (
	"crypto/x509"
	"sealpath/internal/model"
)

// ValidateOCSPResponder re-checks a captured or persisted responder record
// against the certificates it references. Derived fields are never trusted
// across an evidence boundary.
func ValidateOCSPResponder(value model.OCSPResponder, certificates map[string]model.Certificate) error {
	if value.Status != "active" && value.Status != "retired" {
		return model.Invalid("responder %s has an unknown status", value.ID)
	}
	if value.Revision < 1 {
		return model.Invalid("responder %s has no revision", value.ID)
	}
	if len(value.Certificates) == 0 {
		return model.Invalid("responder %s authorizes no certificates", value.ID)
	}
	issuerValue, ok := certificates[value.IssuerID]
	if !ok {
		return model.Invalid("responder %s names an absent issuer", value.ID)
	}
	issuer, err := ParseCertificate(issuerValue.DER)
	if err != nil || !issuer.IsCA {
		return model.Invalid("responder %s issuer is not a CA", value.ID)
	}
	signerValue, ok := certificates[value.CertificateID]
	if !ok {
		return model.Invalid("responder %s names an absent signing certificate", value.ID)
	}
	signer, err := ParseCertificate(signerValue.DER)
	if err != nil {
		return model.Invalid("responder %s signing certificate is invalid", value.ID)
	}
	if value.CertificateID != value.IssuerID {
		if signer.CheckSignatureFrom(issuer) != nil || signer.IsCA || !hasOCSPSigning(signer) {
			return model.Invalid("responder %s delegation is invalid", value.ID)
		}
	}
	for _, id := range value.Certificates {
		certValue, ok := certificates[id]
		if !ok {
			return model.Invalid("responder %s names an absent authorized certificate", value.ID)
		}
		cert, err := ParseCertificate(certValue.DER)
		if err != nil || cert.CheckSignatureFrom(issuer) != nil {
			return model.Invalid("responder %s authorization does not match the named CA", value.ID)
		}
	}
	return nil
}

// ValidateOCSPResponse establishes that a stored response is signed by the
// certificate recorded with it, names that certificate as responder, matches
// its index fields with the signed content, and echoes the issuer recorded
// with it. Whether the responder is still approved, still signs with that
// certificate, or is still authorized for a particular certificate is decided
// at selection time, not at rest, so later rotation, narrowing or retirement
// never invalidates already-received material or historical decisions.
func ValidateOCSPResponse(value model.OCSPResponse, responders map[string]model.OCSPResponder, certificates map[string]model.Certificate) error {
	if value.ID == "" || Digest(value.DER) != value.ID {
		return model.Invalid("OCSP response identity is inconsistent: %s", value.ID)
	}
	if _, ok := responders[value.ResponderID]; !ok {
		return model.Invalid("OCSP responder is absent: %s", value.ID)
	}
	signerValue, ok := certificates[value.CertificateID]
	if !ok {
		return model.Invalid("OCSP response signing certificate is absent: %s", value.ID)
	}
	signer, err := ParseCertificate(signerValue.DER)
	if err != nil {
		return model.Invalid("OCSP response signing certificate is invalid: %s", value.ID)
	}
	status, err := ParseOCSP(value.DER)
	if err != nil {
		return model.Invalid("OCSP response cannot be parsed: %s", value.ID)
	}
	if !status.Present || status.ResponseStatus != 0 {
		return model.Invalid("OCSP response carries no status: %s", value.ID)
	}
	if !value.ProducedAt.Equal(status.ProducedAt) || !value.ThisUpdate.Equal(status.ThisUpdate) || !value.NextUpdate.Equal(status.NextUpdate) {
		return model.Invalid("OCSP index does not match signed content: %s", value.ID)
	}
	verified, err := status.CheckOCSPSignature(signer)
	if err != nil {
		return err
	}
	matched := false
	for _, cert := range verified {
		if Digest(cert.Raw) == value.CertificateID {
			matched = true
		}
	}
	if !matched {
		return model.Invalid("OCSP response was not signed by the recorded signing certificate: %s", value.ID)
	}
	if !status.MatchesResponder(signer) {
		return model.Invalid("OCSP responder identifier does not name the recorded certificate: %s", value.ID)
	}
	issuerValue, ok := certificates[value.IssuerID]
	if !ok {
		return model.Invalid("OCSP response names an absent issuer: %s", value.ID)
	}
	issuer, err := ParseCertificate(issuerValue.DER)
	if err != nil || !issuer.IsCA {
		return model.Invalid("OCSP response issuer is not a CA: %s", value.ID)
	}
	if _, err := status.CertIDIssuer(issuer); err != nil {
		return model.Invalid("OCSP response CertID does not match its issuer: %s", value.ID)
	}
	return nil
}

// AnsweredCertificate returns the authorized certificate the response names.
func AnsweredCertificate(status *OCSPStatus, responder model.OCSPResponder, certificates map[string]model.Certificate) (string, error) {
	issuerValue, ok := certificates[responder.IssuerID]
	if !ok {
		return "", model.Invalid("responder issuer is absent")
	}
	issuer, err := ParseCertificate(issuerValue.DER)
	if err != nil {
		return "", err
	}
	for _, id := range responder.Certificates {
		certValue, ok := certificates[id]
		if !ok {
			continue
		}
		cert, err := ParseCertificate(certValue.DER)
		if err != nil {
			continue
		}
		if status.MatchesCertID(issuer, cert) == nil {
			return id, nil
		}
	}
	return "", model.Invalid("OCSP response answers a certificate outside the responder's authorization")
}

func hasOCSPSigning(cert *x509.Certificate) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	return false
}
