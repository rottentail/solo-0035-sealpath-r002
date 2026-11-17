package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sealpath/internal/codec"
	"sealpath/internal/ocsp"
	"time"
)

type Samples struct {
	Root           string    `json:"root"`
	Intermediate   string    `json:"intermediate"`
	Signer         string    `json:"signer"`
	Responder      string    `json:"responder"`
	RootCRL        string    `json:"root_crl"`
	CleanCRL       string    `json:"clean_crl"`
	RevokedCRL     string    `json:"revoked_crl"`
	GoodOCSP       string    `json:"good_ocsp"`
	RevokedOCSP    string    `json:"revoked_ocsp"`
	Content        []byte    `json:"content"`
	Signature      []byte    `json:"signature"`
	Algorithm      string    `json:"algorithm"`
	At             time.Time `json:"at"`
	RootID         string    `json:"root_id"`
	IntermediateID string    `json:"intermediate_id"`
	SignerID       string    `json:"signer_id"`
	ResponderID    string    `json:"responder_id"`
}

func generate(algorithm string) (Samples, error) {
	var out Samples
	out.Algorithm = algorithm
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	out.At = at
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return out, err
	}
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return out, err
	}
	signerKey, err := sampleSigner(algorithm)
	if err != nil {
		return out, err
	}
	signerPub := signerKey.Public()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "Sealpath Example Root"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2, SubjectKeyId: []byte("sealpath-root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootKey)
	if err != nil {
		return out, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return out, err
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(200), Subject: pkix.Name{CommonName: "Sealpath Example Issuer"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(3, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true, SubjectKeyId: []byte("sealpath-issuer")}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, root, caPub, rootKey)
	if err != nil {
		return out, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return out, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(301), Subject: pkix.Name{CommonName: "Sealpath Release Signer"}, NotBefore: at.AddDate(0, -1, 0), NotAfter: at.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true}
	signerDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, signerPub, caKey)
	if err != nil {
		return out, err
	}
	responderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return out, err
	}
	responderTemplate := &x509.Certificate{SerialNumber: big.NewInt(302), Subject: pkix.Name{CommonName: "Sealpath Status Responder"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(3, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, BasicConstraintsValid: true}
	responderDER, err := x509.CreateCertificate(rand.Reader, responderTemplate, ca, responderKey.Public(), caKey)
	if err != nil {
		return out, err
	}
	encode := func(kind string, data []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}))
	}
	out.Root = encode("CERTIFICATE", rootDER)
	out.Intermediate = encode("CERTIFICATE", caDER)
	out.Signer = encode("CERTIFICATE", signerDER)
	out.Responder = encode("CERTIFICATE", responderDER)
	out.RootID = codec.Digest(rootDER)
	out.IntermediateID = codec.Digest(caDER)
	out.SignerID = codec.Digest(signerDER)
	out.ResponderID = codec.Digest(responderDER)
	parsedResponder, err := x509.ParseCertificate(responderDER)
	if err != nil {
		return out, err
	}
	goodOCSP, err := ocsp.CreateResponse(ca, &x509.Certificate{SerialNumber: leaf.SerialNumber}, parsedResponder, responderKey, ocsp.ResponseTemplate{Status: codec.OCSPGood, ThisUpdate: at.Add(-2 * time.Hour), NextUpdate: at.Add(2 * time.Hour), ProducedAt: at.Add(-2 * time.Hour)})
	if err != nil {
		return out, err
	}
	out.GoodOCSP = encode("OCSP RESPONSE", goodOCSP)
	revokedOCSP, err := ocsp.CreateResponse(ca, &x509.Certificate{SerialNumber: leaf.SerialNumber}, parsedResponder, responderKey, ocsp.ResponseTemplate{Status: codec.OCSPRevoked, RevokedAt: at.Add(-90 * time.Minute), Reason: 1, ThisUpdate: at.Add(-time.Hour), NextUpdate: at.Add(2 * time.Hour), ProducedAt: at.Add(-time.Hour)})
	if err != nil {
		return out, err
	}
	out.RevokedOCSP = encode("OCSP RESPONSE", revokedOCSP)
	crlTemplate := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-24 * time.Hour), NextUpdate: at.Add(24 * time.Hour)}
	rootCRL, err := x509.CreateRevocationList(rand.Reader, crlTemplate, root, rootKey)
	if err != nil {
		return out, err
	}
	out.RootCRL = encode("X509 CRL", rootCRL)
	cleanCRL, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		return out, err
	}
	out.CleanCRL = encode("X509 CRL", cleanCRL)
	revokedTemplate := &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: at.Add(-time.Hour), NextUpdate: at.Add(24 * time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: at.Add(-2 * time.Hour), ReasonCode: 1}}}
	revokedCRL, err := x509.CreateRevocationList(rand.Reader, revokedTemplate, ca, caKey)
	if err != nil {
		return out, err
	}
	out.RevokedCRL = encode("X509 CRL", revokedCRL)
	out.Content = []byte("sealpath-example-release\ncomponent=verifier\nrevision=1\n")
	if algorithm == "ed25519" {
		out.Signature, err = signerKey.Sign(rand.Reader, out.Content, crypto.Hash(0))
	} else {
		hash := sha256.Sum256(out.Content)
		var options crypto.SignerOpts = crypto.SHA256
		if algorithm == "rsa_pss_sha256" {
			options = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		}
		out.Signature, err = signerKey.Sign(rand.Reader, hash[:], options)
	}
	if err != nil {
		return out, err
	}
	return out, nil
}

func sampleSigner(algorithm string) (crypto.Signer, error) {
	switch algorithm {
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	case "rsa_pss_sha256":
		return rsa.GenerateKey(rand.Reader, 1<<11)
	case "ecdsa_sha256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported sample algorithm %q", algorithm)
	}
}
