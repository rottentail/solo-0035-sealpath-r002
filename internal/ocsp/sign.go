package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"sealpath/internal/codec"
	"time"
)

// CreateResponse builds a signed RFC 6960 basic response for one certificate.
// It exists so the sample workflows and tests can produce real responder
// output; the service itself never signs responses.
type ResponseTemplate struct {
	Status         int
	RevokedAt      time.Time
	Reason         int
	ThisUpdate     time.Time
	NextUpdate     time.Time
	ProducedAt     time.Time
	IssuerHash     crypto.Hash
	EmbedResponder bool
	ResponderKeyID bool
}

type buildCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type buildRevoked struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type buildSingle struct {
	CertID     buildCertID
	Good       asn1.Flag    `asn1:"tag:0,optional"`
	Revoked    buildRevoked `asn1:"tag:1,optional"`
	Unknown    asn1.Flag    `asn1:"tag:2,optional"`
	ThisUpdate time.Time    `asn1:"generalized"`
	NextUpdate time.Time    `asn1:"generalized,explicit,tag:0,optional"`
}

type buildResponseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []buildSingle
}

type buildBasic struct {
	TBSResponseData    buildResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type buildResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type buildOuter struct {
	Status   asn1.Enumerated
	Response buildResponseBytes `asn1:"explicit,tag:0,optional"`
}

// CreateResponse signs one status response. The responder certificate is the
// identity the response names; key signs the response data.
func CreateResponse(issuer, cert, responder *x509.Certificate, key crypto.Signer, template ResponseTemplate) ([]byte, error) {
	if issuer == nil || cert == nil || responder == nil || key == nil {
		return nil, fmt.Errorf("issuer, certificate, responder and key are required")
	}
	if template.IssuerHash == 0 {
		template.IssuerHash = crypto.SHA1
	}
	algorithm, digest := buildHash(template.IssuerHash)
	if digest == nil {
		return nil, fmt.Errorf("unsupported issuer hash")
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, err
	}
	digest.Write(spki.PublicKey.RightAlign())
	keyHash := digest.Sum(nil)
	digest.Reset()
	digest.Write(issuer.RawSubject)
	nameHash := digest.Sum(nil)
	single := buildSingle{
		CertID:     buildCertID{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algorithm, Parameters: asn1.RawValue{Tag: 5}}, NameHash: nameHash, IssuerKeyHash: keyHash, SerialNumber: cert.SerialNumber},
		ThisUpdate: template.ThisUpdate.UTC(),
		NextUpdate: template.NextUpdate.UTC(),
	}
	switch template.Status {
	case codec.OCSPGood:
		single.Good = true
	case codec.OCSPRevoked:
		single.Revoked = buildRevoked{RevocationTime: template.RevokedAt.UTC(), Reason: asn1.Enumerated(template.Reason)}
	default:
		single.Unknown = true
	}
	var responderID asn1.RawValue
	if template.ResponderKeyID {
		var signerSPKI struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(responder.RawSubjectPublicKeyInfo, &signerSPKI); err != nil {
			return nil, err
		}
		sum := sha1.Sum(signerSPKI.PublicKey.RightAlign())
		encoded, err := asn1.Marshal(sum[:])
		if err != nil {
			return nil, err
		}
		responderID = asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: encoded}
	} else {
		responderID = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: responder.RawSubject}
	}
	produced := template.ProducedAt
	if produced.IsZero() {
		produced = template.ThisUpdate
	}
	tbs, err := asn1.Marshal(buildResponseData{RawResponderID: responderID, ProducedAt: produced.UTC(), Responses: []buildSingle{single}})
	if err != nil {
		return nil, err
	}
	signatureAlgorithm, signature, err := signResponse(key, tbs)
	if err != nil {
		return nil, err
	}
	basic := buildBasic{TBSResponseData: buildResponseData{Raw: tbs}, SignatureAlgorithm: signatureAlgorithm, Signature: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}}
	if template.EmbedResponder {
		basic.Certificates = []asn1.RawValue{{FullBytes: responder.Raw}}
	}
	// Re-marshal with Raw set: encoding/asn1 uses RawContent verbatim.
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(buildOuter{Status: 0, Response: buildResponseBytes{ResponseType: codec.OIDOCSPBasic, Response: basicDER}})
}

func buildHash(value crypto.Hash) (asn1.ObjectIdentifier, hash.Hash) {
	switch value {
	case crypto.SHA1:
		return codec.OIDSHA1, sha1.New()
	case crypto.SHA256:
		return codec.OIDSHA256, sha256.New()
	}
	return nil, nil
}

func signResponse(key crypto.Signer, tbs []byte) (pkix.AlgorithmIdentifier, []byte, error) {
	switch key.Public().(type) {
	case ed25519.PublicKey:
		signature, err := key.Sign(rand.Reader, tbs, crypto.Hash(0))
		if err != nil {
			return pkix.AlgorithmIdentifier{}, nil, err
		}
		return pkix.AlgorithmIdentifier{Algorithm: codec.OIDEd25519}, signature, nil
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(tbs)
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return pkix.AlgorithmIdentifier{}, nil, err
		}
		return pkix.AlgorithmIdentifier{Algorithm: codec.OIDECDSAWithSHA256}, signature, nil
	case *rsa.PublicKey:
		digest := sha256.Sum256(tbs)
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return pkix.AlgorithmIdentifier{}, nil, err
		}
		return pkix.AlgorithmIdentifier{Algorithm: codec.OIDSHA256WithRSA}, signature, nil
	default:
		return pkix.AlgorithmIdentifier{}, nil, fmt.Errorf("unsupported responder key type")
	}
}
