package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"sealpath/internal/revocation"
)

type pki struct {
	root, issuer, leaf, leaf2, responder  *x509.Certificate
	rootKey, issuerKey, leafKey           crypto.Signer
	responderKey                          crypto.Signer
	leafDER, leaf2DER, issuerDER, rootDER []byte
	responderDER                          []byte
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	_, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2, SubjectKeyId: []byte("root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Issuer"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(3, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true, SubjectKeyId: []byte("issuer")}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(issuerDER)

	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(301), Subject: pkix.Name{CommonName: "Test Signer"}, NotBefore: at.AddDate(0, -1, 0), NotAfter: at.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	leaf2Template := &x509.Certificate{SerialNumber: big.NewInt(302), Subject: pkix.Name{CommonName: "Second Signer"}, NotBefore: at.AddDate(0, -1, 0), NotAfter: at.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true}
	_, leaf2Key, _ := ed25519.GenerateKey(rand.Reader)
	leaf2DER, err := x509.CreateCertificate(rand.Reader, leaf2Template, issuer, leaf2Key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf2, _ := x509.ParseCertificate(leaf2DER)

	responderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	responderTemplate := &x509.Certificate{SerialNumber: big.NewInt(900), Subject: pkix.Name{CommonName: "Test Responder"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(3, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, BasicConstraintsValid: true}
	responderDER, err := x509.CreateCertificate(rand.Reader, responderTemplate, issuer, responderKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	responder, _ := x509.ParseCertificate(responderDER)
	return &pki{root: root, issuer: issuer, leaf: leaf, leaf2: leaf2, responder: responder, rootKey: rootKey, issuerKey: issuerKey, leafKey: leafKey, responderKey: responderKey, leafDER: leafDER, leaf2DER: leaf2DER, issuerDER: issuerDER, rootDER: rootDER, responderDER: responderDER}
}

func newService(t *testing.T) (*Service, *pki) {
	t.Helper()
	p := newPKI(t)
	path := t.TempDir() + "/state.json"
	store, err := repository.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{Store: store}, p
}

func (s *Service) addCert(t *testing.T, der []byte) string {
	t.Helper()
	id := codec.Digest(der)
	err := s.Store.Update("certificate.accepted", id, func(st *model.State) error {
		cert, _ := codec.ParseCertificate(der)
		st.Certificates[id] = model.Certificate{ID: id, DER: cert.Raw, Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), Serial: cert.SerialNumber.String(), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, IsCA: cert.IsCA, ReceivedAt: time.Now().UTC()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func goodTemplate(at time.Time) ResponseTemplate {
	return ResponseTemplate{Status: codec.OCSPGood, ThisUpdate: at.Add(-time.Hour), NextUpdate: at.Add(time.Hour), ProducedAt: at.Add(-time.Hour)}
}

func mustResponse(t *testing.T, p *pki, template ResponseTemplate) []byte {
	t.Helper()
	der, err := CreateResponse(p.issuer, p.leaf, p.responder, p.responderKey, template)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// ocspResponseFor signs an answer for one specific certificate.
func ocspResponseFor(t *testing.T, p *pki, cert *x509.Certificate, template ResponseTemplate) ([]byte, error) {
	t.Helper()
	return CreateResponse(p.issuer, cert, p.responder, p.responderKey, template)
}

func TestRegisterValidatesIssuerBinding(t *testing.T) {
	svc, p := newService(t)
	leafID := svc.addCert(t, p.leafDER)
	issuerID := svc.addCert(t, p.issuerDER)
	responderID := svc.addCert(t, p.responderDER)

	// A leaf certificate cannot act as an issuer.
	_, err := svc.Register(RegisterRequest{ID: "bad", IssuerID: leafID, CertificateID: leafID, Certificates: []string{leafID}})
	if err == nil {
		t.Fatal("expected non-CA issuer to be rejected")
	}
	// Delegated responder without the OCSP signing usage is rejected.
	_, err = svc.Register(RegisterRequest{ID: "bad2", IssuerID: issuerID, CertificateID: issuerID, Certificates: []string{issuerID}})
	if err == nil {
		t.Fatal("expected CA-scoped responder over a CA certificate to be rejected")
	}
	// Authorized scope must belong to the named CA.
	other := newPKI(t)
	otherLeafID := svc.addCert(t, other.leafDER)
	_, err = svc.Register(RegisterRequest{ID: "bad3", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{otherLeafID}})
	if err == nil {
		t.Fatal("expected cross-CA scope to be rejected")
	}
	out, err := svc.Register(RegisterRequest{ID: "good", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{leafID}})
	if err != nil {
		t.Fatalf("valid registration failed: %v", err)
	}
	if out.Revision != 1 || out.Status != "active" {
		t.Fatalf("unexpected responder: %+v", out)
	}
}

func TestImportRejectsForeignSignerAndScope(t *testing.T) {
	svc, p := newService(t)
	leafID := svc.addCert(t, p.leafDER)
	issuerID := svc.addCert(t, p.issuerDER)
	responderID := svc.addCert(t, p.responderDER)
	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{leafID}}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)

	// Signed by the CA rather than the approved responder.
	wrongSigner, err := CreateResponse(p.issuer, p.leaf, p.responder, p.issuerKey, goodTemplate(at))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Import("r", wrongSigner); err == nil {
		t.Fatal("expected response signed by a different key to be rejected")
	}

	// Responder answers for a certificate outside its authorization.
	other := newPKI(t)
	svc.addCert(t, other.issuerDER)
	foreign, err := CreateResponse(other.issuer, other.leaf, other.responder, p.responderKey, goodTemplate(at))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Import("r", foreign); err == nil {
		t.Fatal("expected out-of-scope response to be rejected")
	}

	// Valid response is accepted.
	good := mustResponse(t, p, goodTemplate(at))
	out, err := svc.Import("r", good)
	if err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	if out.IssuerID != issuerID || out.CertificateID != responderID {
		t.Fatalf("unexpected binding: %+v", out)
	}
}

func TestRetiredResponderDoesNotBackNewDecisions(t *testing.T) {
	svc, p := newService(t)
	leafID := svc.addCert(t, p.leafDER)
	issuerID := svc.addCert(t, p.issuerDER)
	responderID := svc.addCert(t, p.responderDER)
	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{leafID}}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	good := mustResponse(t, p, goodTemplate(at))
	if _, err := svc.Import("r", good); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Retire("r", 1); err != nil {
		t.Fatal(err)
	}
	// A retired responder cannot accept new responses.
	fresh := mustResponse(t, p, ResponseTemplate{Status: codec.OCSPGood, ThisUpdate: at, NextUpdate: at.Add(2 * time.Hour), ProducedAt: at})
	if _, err := svc.Import("r", fresh); err == nil {
		t.Fatal("retired responder accepted a new response")
	}
	state, err := svc.Store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	result := Inspect(leafID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at)
	if result.Fresh || result.Valid {
		t.Fatalf("retired responder still contributed evidence: %+v", result)
	}
	if result.Check.Status != "unknown" {
		t.Fatalf("expected unknown status, got %+v", result.Check)
	}
}

func TestAuthorizationScopeChangeAppliesToNewDecisionsOnly(t *testing.T) {
	svc, p := newService(t)
	leafID := svc.addCert(t, p.leafDER)
	otherLeafID := svc.addCert(t, p.leaf2DER)
	issuerID := svc.addCert(t, p.issuerDER)
	responderID := svc.addCert(t, p.responderDER)
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)

	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{leafID}}); err != nil {
		t.Fatal(err)
	}
	good := mustResponse(t, p, goodTemplate(at))
	if _, err := svc.Import("r", good); err != nil {
		t.Fatal(err)
	}
	// Narrow the scope to a different (unrelated) certificate. The stored
	// response is still valid material, but no longer answers for leafID.
	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{otherLeafID}, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	state, _ := svc.Store.Snapshot()
	result := Inspect(leafID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at)
	if result.Fresh {
		t.Fatalf("narrowed authorization still used for leaf: %+v", result)
	}
	// Reloading the whole state must still accept the historical response.
	if err := repository.ValidateState(state); err != nil {
		t.Fatalf("state with a no-longer-authorized response failed integrity: %v", err)
	}
}

func TestSigningCertificateRotationExcludesOldResponses(t *testing.T) {
	svc, p := newService(t)
	leafID := svc.addCert(t, p.leafDER)
	issuerID := svc.addCert(t, p.issuerDER)
	responderID := svc.addCert(t, p.responderDER)
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{leafID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Import("r", mustResponse(t, p, goodTemplate(at))); err != nil {
		t.Fatal(err)
	}
	// Rotate the signing identity to a fresh delegated responder.
	rotated := p.newResponder(t)
	rotatedID := svc.addCert(t, rotated.der)
	state, _ := svc.Store.Snapshot()
	if result := Inspect(leafID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at); !result.Fresh {
		t.Fatalf("baseline response was not used: %+v", result)
	}
	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: rotatedID, Certificates: []string{leafID}, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	state, _ = svc.Store.Snapshot()
	// The old material is still intact and passes integrity, but no longer
	// counts as current evidence.
	if err := repository.ValidateState(state); err != nil {
		t.Fatalf("rotation invalidated stored material: %v", err)
	}
	if result := Inspect(leafID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at); result.Fresh {
		t.Fatalf("response from the previous signing certificate was still used: %+v", result)
	}
}

func TestResponseForDifferentSerialIsNotUsed(t *testing.T) {
	svc, p := newService(t)
	leafID := svc.addCert(t, p.leafDER)
	leaf2ID := svc.addCert(t, p.leaf2DER)
	issuerID := svc.addCert(t, p.issuerDER)
	responderID := svc.addCert(t, p.responderDER)
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	// The responder is approved for both certificates.
	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{leafID, leaf2ID}}); err != nil {
		t.Fatal(err)
	}
	// Accept an answer for leaf2 only.
	leaf2DER, err := ocspResponseFor(t, p, p.leaf2, goodTemplate(at))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Import("r", leaf2DER); err != nil {
		t.Fatal(err)
	}
	state, _ := svc.Store.Snapshot()
	if result := Inspect(leafID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at); result.Fresh {
		t.Fatalf("response for another serial was used for the leaf: %+v", result)
	}
	if result := Inspect(leaf2ID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at); !result.Fresh || result.Check.Status != "pass" {
		t.Fatalf("response for the authorized serial was not used: %+v", result)
	}
}

func TestExpiredResponseFallsBackToUnknown(t *testing.T) {
	svc, p := newService(t)
	leafID := svc.addCert(t, p.leafDER)
	issuerID := svc.addCert(t, p.issuerDER)
	responderID := svc.addCert(t, p.responderDER)
	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{leafID}}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	stale := mustResponse(t, p, ResponseTemplate{Status: codec.OCSPGood, ThisUpdate: at.Add(-4 * time.Hour), NextUpdate: at.Add(-3 * time.Hour)})
	if _, err := svc.Import("r", stale); err != nil {
		t.Fatal(err)
	}
	state, _ := svc.Store.Snapshot()
	result := Inspect(leafID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at)
	if result.Fresh {
		t.Fatalf("expired response was treated as fresh: %+v", result)
	}
	if result.Check.Status != "unknown" {
		t.Fatalf("expired response did not fall back to unknown: %+v", result.Check)
	}
}

func TestFreshOCSPDoesNotEraseConfirmedRevocation(t *testing.T) {
	svc, p := newService(t)
	leafID := svc.addCert(t, p.leafDER)
	issuerID := svc.addCert(t, p.issuerDER)
	responderID := svc.addCert(t, p.responderDER)
	if _, err := svc.Register(RegisterRequest{ID: "r", IssuerID: issuerID, CertificateID: responderID, Certificates: []string{leafID}}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	good := mustResponse(t, p, goodTemplate(at))
	if _, err := svc.Import("r", good); err != nil {
		t.Fatal(err)
	}
	state, _ := svc.Store.Snapshot()
	status := Inspect(leafID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at)
	if !status.Fresh || status.Check.Status != "pass" {
		t.Fatalf("expected fresh pass, got %+v", status)
	}
	// Simulate a CRL revocation effective before the response.
	crl := crlResult("crl-1", at.Add(-2*time.Hour), true)
	check, evidence := Combine(crl, status)
	if check.Status != "fail" || evidence != "crl-1" {
		t.Fatalf("fresh OCSP erased a confirmed revocation: %+v evidence=%s", check, evidence)
	}
	if missing := crlResult("", at, false); func() bool { c, _ := Combine(missing, status); return c.Status == "pass" }() == false {
		t.Fatal("fresh OCSP did not supply availability when the CRL was absent")
	}
	// An OCSP revocation is itself not overridden by a CRL pass.
	revoked := mustResponse(t, p, ResponseTemplate{Status: codec.OCSPRevoked, RevokedAt: at.Add(-2 * time.Hour), ThisUpdate: at.Add(-30 * time.Minute), NextUpdate: at.Add(time.Hour)})
	if _, err := svc.Import("r", revoked); err != nil {
		t.Fatal(err)
	}
	state, _ = svc.Store.Snapshot()
	status = Inspect(leafID, state.Certificates, state.OCSPResponders, state.OCSPResponses, at)
	if !status.Revoked {
		t.Fatalf("expected freshest OCSP to report revocation: %+v", status)
	}
	missing := crlResult("", at, false)
	if check, _ := Combine(missing, status); check.Status != "fail" {
		t.Fatalf("OCSP revocation was lost: %+v", check)
	}
}

// crlResult builds a minimal CRL result for combination tests.
func crlResult(id string, revokedAt time.Time, revoked bool) revocation.Result {
	if !revoked {
		return revocation.Result{ID: "", Check: model.Check{Code: "revocation", Status: "unknown", Source: "crl"}}
	}
	return revocation.Result{ID: id, Revoked: true, RevokedAt: revokedAt, Check: model.Check{Code: "revocation", Status: "fail", Detail: "certificate was revoked", Source: "crl", Evidence: id}}
}

// newResponder creates a second delegated responder certificate under the
// fixture's CA.
func (p *pki) newResponder(t *testing.T) struct {
	cert *x509.Certificate
	key  crypto.Signer
	der  []byte
} {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(901), Subject: pkix.Name{CommonName: "Rotated Responder"}, NotBefore: p.issuer.NotBefore, NotAfter: p.issuer.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
	der, err := x509.CreateCertificate(rand.Reader, template, p.issuer, key.Public(), p.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return struct {
		cert *x509.Certificate
		key  crypto.Signer
		der  []byte
	}{cert, key, der}
}
