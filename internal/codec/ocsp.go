package codec

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"sealpath/internal/model"
	"time"
)

// OCSP support is deliberately narrow: one embedded single response per
// artifact, explicit signature verification, and no implicit signer trust.
// Go's standard library parses X.509 CRLs but not OCSP, so the RFC 6960
// structures are decoded here with encoding/asn1.

var (
	OIDOCSPBasic       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	OIDSHA1            = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	OIDSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

// Certificate status values of a SingleResponse (RFC 6960).
const (
	OCSPGood    = 0
	OCSPRevoked = 1
	OCSPUnknown = 2
)

type ocspCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type ocspRevokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type ocspSingleResponse struct {
	CertID           ocspCertID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          ocspRevokedInfo  `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type ocspResponseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []ocspSingleResponse
}

type ocspBasicResponse struct {
	TBSResponseData    ocspResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspOuterResponse struct {
	Status   asn1.Enumerated
	Response ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

// OCSPStatus is the parsed revocation status of one certificate.
type OCSPStatus struct {
	Present            bool
	ResponseStatus     int
	CertID             []byte
	SerialNumber       *big.Int
	Good               bool
	Revoked            bool
	RevocationTime     time.Time
	RevocationReason   int
	ProducedAt         time.Time
	ThisUpdate         time.Time
	NextUpdate         time.Time
	ResponderName      []byte
	ResponderKeyHash   []byte
	TBS                []byte
	Signature          []byte
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Certificates       []*x509.Certificate
}

// ParseOCSP parses one DER- or PEM-encoded OCSP response. It does not decide
// trust: the signature must still be checked against an approved responder.
func ParseOCSP(data []byte) (*OCSPStatus, error) {
	if len(data) == 0 || len(data) > 65536 {
		return nil, model.Invalid("OCSP response must contain 1-65536 bytes")
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "OCSP RESPONSE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, model.Invalid("expected exactly one OCSP RESPONSE PEM block")
		}
		data = block.Bytes
	}
	var outer ocspOuterResponse
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) != 0 {
		return nil, model.Invalid("invalid OCSP response: %v", err)
	}
	out := &OCSPStatus{ResponseStatus: int(outer.Status)}
	if outer.Status != 0 {
		return out, nil
	}
	if len(outer.Response.ResponseType) == 0 || !outer.Response.ResponseType.Equal(OIDOCSPBasic) {
		return nil, model.Invalid("unsupported OCSP response type")
	}
	var basic ocspBasicResponse
	rest, err = asn1.Unmarshal(outer.Response.Response, &basic)
	if err != nil || len(rest) != 0 {
		return nil, model.Invalid("invalid OCSP basic response: %v", err)
	}
	if len(basic.TBSResponseData.Responses) != 1 {
		return nil, model.Invalid("OCSP response must contain exactly one single response")
	}
	single := basic.TBSResponseData.Responses[0]
	out.ProducedAt = basic.TBSResponseData.ProducedAt.UTC()
	out.ThisUpdate = single.ThisUpdate.UTC()
	out.NextUpdate = single.NextUpdate.UTC()
	out.TBS = append([]byte(nil), basic.TBSResponseData.Raw...)
	out.Signature = basic.Signature.RightAlign()
	out.SignatureAlgorithm = basic.SignatureAlgorithm
	out.SerialNumber = single.CertID.SerialNumber
	if rawCertID, cidErr := asn1.Marshal(single.CertID); cidErr == nil {
		out.CertID = rawCertID
	}
	switch basic.TBSResponseData.RawResponderID.Tag {
	case 1:
		out.ResponderName = append([]byte(nil), basic.TBSResponseData.RawResponderID.Bytes...)
	case 2:
		if rest, err := asn1.Unmarshal(basic.TBSResponseData.RawResponderID.Bytes, &out.ResponderKeyHash); err != nil || len(rest) != 0 {
			return nil, model.Invalid("invalid OCSP responder key hash")
		}
	default:
		return nil, model.Invalid("unrecognized OCSP responder identifier")
	}
	statusSet := 0
	if single.Good {
		out.Good = true
		statusSet++
	}
	if !single.Revoked.RevocationTime.IsZero() {
		out.Revoked = true
		out.RevocationTime = single.Revoked.RevocationTime.UTC()
		out.RevocationReason = int(single.Revoked.Reason)
		statusSet++
	}
	if single.Unknown {
		statusSet++
	}
	if statusSet != 1 {
		return nil, model.Invalid("OCSP single response must declare exactly one certificate status")
	}
	for _, ext := range single.SingleExtensions {
		if ext.Critical {
			return nil, model.Invalid("unsupported critical OCSP single extension")
		}
	}
	for _, raw := range basic.Certificates {
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, model.Invalid("invalid certificate embedded in OCSP response: %v", err)
		}
		out.Certificates = append(out.Certificates, cert)
	}
	out.Present = true
	return out, nil
}

func ocspHash(algorithm pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	switch {
	case algorithm.Algorithm.Equal(OIDSHA1):
		return crypto.SHA1, nil
	case algorithm.Algorithm.Equal(OIDSHA256):
		return crypto.SHA256, nil
	case algorithm.Algorithm.Equal(OIDSHA384):
		return crypto.SHA384, nil
	case algorithm.Algorithm.Equal(OIDSHA512):
		return crypto.SHA512, nil
	default:
		return 0, model.Invalid("unsupported OCSP CertID hash algorithm")
	}
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New()
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	}
	return nil
}

// CertificateIDDigest computes the issuer name and key hashes a responder
// must echo to answer for a certificate issued by issuer.
func CertificateIDDigest(issuer *x509.Certificate, algorithm pkix.AlgorithmIdentifier) (nameHash, keyHash []byte, err error) {
	h, err := ocspHash(algorithm)
	if err != nil {
		return nil, nil, err
	}
	digest := newHash(h)
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, model.Invalid("issuer public key cannot be decoded")
	}
	digest.Write(spki.PublicKey.RightAlign())
	keyHash = digest.Sum(nil)
	digest.Reset()
	digest.Write(issuer.RawSubject)
	nameHash = digest.Sum(nil)
	return nameHash, keyHash, nil
}

// CertIDIssuer checks only that the response's CertID names issuer, without
// tying it to a particular certificate. It lets stored responses prove which
// CA they speak for even after a responder's authorization is narrowed.
func (status *OCSPStatus) CertIDIssuer(issuer *x509.Certificate) (*big.Int, error) {
	if len(status.CertID) == 0 {
		return nil, model.Invalid("OCSP response has no CertID")
	}
	var id ocspCertID
	rest, err := asn1.Unmarshal(status.CertID, &id)
	if err != nil || len(rest) != 0 {
		return nil, model.Invalid("invalid OCSP CertID")
	}
	nameHash, keyHash, err := CertificateIDDigest(issuer, id.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(nameHash, id.NameHash) || !bytes.Equal(keyHash, id.IssuerKeyHash) {
		return nil, model.Invalid("OCSP response names a different issuer")
	}
	return id.SerialNumber, nil
}

// MatchesCertID checks that the CertID in the parsed response names cert as
// issued by issuer. A response that echoes a different issuer or key cannot
// stand in as evidence for this certificate.
func (status *OCSPStatus) MatchesCertID(issuer, cert *x509.Certificate) error {
	if len(status.CertID) == 0 {
		return model.Invalid("OCSP response has no CertID")
	}
	var id ocspCertID
	rest, err := asn1.Unmarshal(status.CertID, &id)
	if err != nil || len(rest) != 0 {
		return model.Invalid("invalid OCSP CertID")
	}
	if id.SerialNumber == nil || id.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return model.Invalid("OCSP response answers a different certificate serial")
	}
	nameHash, keyHash, err := CertificateIDDigest(issuer, id.HashAlgorithm)
	if err != nil {
		return err
	}
	if !bytes.Equal(nameHash, id.NameHash) || !bytes.Equal(keyHash, id.IssuerKeyHash) {
		return model.Invalid("OCSP response names a different issuer")
	}
	return nil
}

// CheckOCSPSignature verifies the response signature. If the responder
// embedded a certificate, that certificate's key must verify the signature;
// otherwise signer is used. The caller remains responsible for approving
// the signing identity.
func (status *OCSPStatus) CheckOCSPSignature(signer *x509.Certificate) ([]*x509.Certificate, error) {
	if len(status.TBS) == 0 || len(status.Signature) == 0 {
		return nil, model.Invalid("OCSP response has no signature")
	}
	algorithm, err := ocspSignatureAlgorithm(status.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	candidates := status.Certificates
	if len(candidates) == 0 {
		candidates = []*x509.Certificate{signer}
	}
	verified := []*x509.Certificate{}
	for _, cert := range candidates {
		if cert.CheckSignature(algorithm, status.TBS, status.Signature) == nil {
			verified = append(verified, cert)
		}
	}
	if len(verified) == 0 {
		return nil, model.Invalid("OCSP response signature is invalid")
	}
	return verified, nil
}

// MatchesResponder reports whether cert is the identity named by the
// response's ResponderID (subject name or SHA-1 of the public key).
func (status *OCSPStatus) MatchesResponder(cert *x509.Certificate) bool {
	if len(status.ResponderName) > 0 {
		return bytes.Equal(status.ResponderName, cert.RawSubject)
	}
	if len(status.ResponderKeyHash) > 0 {
		var spki struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
			return false
		}
		sum := sha1.Sum(spki.PublicKey.RightAlign())
		return bytes.Equal(status.ResponderKeyHash, sum[:])
	}
	return false
}

func ocspSignatureAlgorithm(id pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case id.Algorithm.Equal(OIDEd25519):
		return x509.PureEd25519, nil
	case id.Algorithm.Equal(OIDECDSAWithSHA256):
		return x509.ECDSAWithSHA256, nil
	case id.Algorithm.Equal(OIDECDSAWithSHA384):
		return x509.ECDSAWithSHA384, nil
	case id.Algorithm.Equal(OIDECDSAWithSHA512):
		return x509.ECDSAWithSHA512, nil
	case id.Algorithm.Equal(OIDSHA256WithRSA):
		return x509.SHA256WithRSA, nil
	case id.Algorithm.Equal(OIDSHA384WithRSA):
		return x509.SHA384WithRSA, nil
	case id.Algorithm.Equal(OIDSHA512WithRSA):
		return x509.SHA512WithRSA, nil
	case id.Algorithm.Equal(OIDRSAPSS):
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("RSA-PSS OCSP signatures are not supported")
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported OCSP signature algorithm %v", id.Algorithm)
	}
}
