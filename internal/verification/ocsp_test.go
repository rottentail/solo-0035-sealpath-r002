package verification

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"sealpath/internal/artifact"
	"sealpath/internal/authority"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/ocsp"
	"sealpath/internal/policy"
	"sealpath/internal/repository"
	"sealpath/internal/revocation"
	"sealpath/internal/signature"
)

type fixture struct {
	store   *repository.Store
	svc     Service
	pki     testPKI
	at      time.Time
	request model.VerifyRequest
}

type testPKI struct {
	root, issuer, leaf, responder *x509.Certificate
	rootKey, issuerKey            crypto.Signer
	leafKey, responderKey         crypto.Signer
	rootDER, issuerDER            []byte
	leafDER, responderDER         []byte
	content, signature            []byte
}

func buildFixture(t *testing.T, withCRLs bool) *fixture {
	t.Helper()
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	_, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2, SubjectKeyId: []byte("root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Issuer"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(3, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(issuerDER)
	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Release Signer"}, NotBefore: at.AddDate(0, -1, 0), NotAfter: at.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	responderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	responderTemplate := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Responder"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(3, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
	responderDER, err := x509.CreateCertificate(rand.Reader, responderTemplate, issuer, responderKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	responder, _ := x509.ParseCertificate(responderDER)
	content := []byte("release-bytes")
	digest := sha256.Sum256(content)
	sig, err := leafKey.Sign(rand.Reader, content, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	_ = digest
	p := testPKI{root: root, issuer: issuer, leaf: leaf, responder: responder, rootKey: rootKey, issuerKey: issuerKey, leafKey: leafKey, responderKey: responderKey, rootDER: rootDER, issuerDER: issuerDER, leafDER: leafDER, responderDER: responderDER, content: content, signature: sig}

	store, err := repository.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: store, svc: Service{Store: store}, pki: p, at: at}
	f.importPKI(t)
	sigValue, err := (&signature.Service{Store: store}).Import(signature.Request{ArtifactID: f.artifactID(t), CertificateID: codec.Digest(leafDER), Algorithm: "ed25519", Value: sig})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&authority.Service{Store: store}).PutTrust(authority.TrustRequest{ID: "trust", Name: "t", Roots: []string{codec.Digest(rootDER)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&policy.Service{Store: store}).Create(policy.Request{ID: "policy", Algorithms: []string{"ed25519"}, Revocation: "required", MaxArtifactBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if withCRLs {
		f.importCRL(t, codec.Digest(rootDER), root, rootKey, 1, at.Add(-time.Hour))
		f.importCRL(t, codec.Digest(issuerDER), issuer, issuerKey, 1, at.Add(-time.Hour))
	}
	f.request = model.VerifyRequest{SignatureID: sigValue.ID, TrustSetID: "trust", PolicyID: "policy", At: at}
	return f
}

func (f *fixture) importCertificate(der []byte) (model.Certificate, error) {
	return (&authority.Service{Store: f.store}).ImportCertificate(der)
}

func (f *fixture) importPKI(t *testing.T) {
	for _, der := range [][]byte{f.pki.rootDER, f.pki.issuerDER, f.pki.leafDER, f.pki.responderDER} {
		if _, err := (&authority.Service{Store: f.store}).ImportCertificate(der); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) artifactID(t *testing.T) string {
	t.Helper()
	out, err := (&artifact.Service{Store: f.store}).Import(artifact.Request{Name: "release", Content: f.pki.content})
	if err != nil {
		t.Fatal(err)
	}
	return out.ID
}

func (f *fixture) importCRL(t *testing.T, issuerID string, issuer *x509.Certificate, key crypto.Signer, number int64, thisUpdate time.Time) {
	t.Helper()
	template := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: thisUpdate, NextUpdate: thisUpdate.Add(24 * time.Hour)}
	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&revocation.Service{Store: f.store}).Import(issuerID, der); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) registerResponder(t *testing.T, revision int, scope []string) model.OCSPResponder {
	t.Helper()
	out, err := (&ocsp.Service{Store: f.store}).Register(ocsp.RegisterRequest{ID: "responder", IssuerID: codec.Digest(f.pki.issuerDER), CertificateID: codec.Digest(f.pki.responderDER), Certificates: scope, ExpectedRevision: revision})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *fixture) importOCSP(t *testing.T, template ocsp.ResponseTemplate) model.OCSPResponse {
	t.Helper()
	der, err := ocsp.CreateResponse(f.pki.issuer, f.pki.leaf, f.pki.responder, f.pki.responderKey, template)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&ocsp.Service{Store: f.store}).Import("responder", der)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOCSPAloneSatisfiesRequiredPolicy(t *testing.T) {
	f := buildFixture(t, false)
	f.registerResponder(t, 0, []string{codec.Digest(f.pki.leafDER)})
	f.importOCSP(t, ocsp.ResponseTemplate{Status: codec.OCSPGood, ThisUpdate: f.at.Add(-time.Hour), NextUpdate: f.at.Add(time.Hour)})
	f.importCRL(t, codec.Digest(f.pki.rootDER), f.pki.root, f.pki.rootKey, 1, f.at.Add(-time.Hour))
	decision, err := f.svc.Verify(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != "trusted" {
		t.Fatalf("expected trusted via OCSP, got %s: %+v", decision.Verdict, decision.Checks)
	}
	if len(decision.OCSPResponses) != 1 || decision.ResponderRevision["responder"] != 1 {
		t.Fatalf("decision did not pin OCSP evidence: %+v", decision)
	}
}

func TestDecisionReplaysAfterAuthorizationNarrowed(t *testing.T) {
	f := buildFixture(t, false)
	second := f.pki.otherLeaf(t)
	if _, err := f.importCertificate(second.Raw); err != nil {
		t.Fatal(err)
	}
	f.registerResponder(t, 0, []string{codec.Digest(f.pki.leafDER)})
	f.importOCSP(t, ocsp.ResponseTemplate{Status: codec.OCSPGood, ThisUpdate: f.at.Add(-time.Hour), NextUpdate: f.at.Add(time.Hour)})
	f.importCRL(t, codec.Digest(f.pki.rootDER), f.pki.root, f.pki.rootKey, 1, f.at.Add(-time.Hour))
	original, err := f.svc.Verify(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if original.Verdict != "trusted" {
		t.Fatalf("baseline was not trusted: %+v", original.Checks)
	}
	// Narrow the responder to a different certificate. The stored response
	// keeps its captured authorization, so replay still reproduces exactly.
	f.registerResponder(t, 1, []string{codec.Digest(second.Raw)})
	state, err := f.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	material := state.Materials[original.ID]
	replayed, err := Evaluate(material, original.Request)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Verdict != original.Verdict || replayed.ID != original.ID || replayed.ResponderRevision["responder"] != 1 {
		t.Fatalf("historical decision changed after authorization edit: %s -> %s (%+v)", original.Verdict, replayed.Verdict, replayed.ResponderRevision)
	}
	// A new decision must not reuse the now out-of-scope response.
	fresh, err := f.svc.Verify(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ID == original.ID {
		t.Fatal("new decision captured the old authorization revision")
	}
	if fresh.Verdict != "indeterminate" {
		t.Fatalf("narrowed authorization still satisfied a required policy: %s", fresh.Verdict)
	}
}

func (p testPKI) otherLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "Other Signer"}, NotBefore: p.issuer.NotBefore, NotAfter: p.issuer.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, template, p.issuer, key.Public(), p.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
