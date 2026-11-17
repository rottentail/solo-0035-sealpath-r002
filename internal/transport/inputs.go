package transport

import (
	"net/http"
	"sealpath/internal/artifact"
	"sealpath/internal/authority"
	"sealpath/internal/ocsp"
	"sealpath/internal/policy"
	"sealpath/internal/signature"
)

func (s *Server) importCertificate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PEM string `json:"pem"`
	}
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Authority.ImportCertificate([]byte(input.PEM))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) putTrust(w http.ResponseWriter, r *http.Request) {
	var input authority.TrustRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Authority.PutTrust(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) retireTrust(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExpectedRevision int `json:"expected_revision"`
	}
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Authority.Retire(r.PathValue("id"), input.ExpectedRevision)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) importArtifact(w http.ResponseWriter, r *http.Request) {
	var input artifact.Request
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Artifacts.Import(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) importSignature(w http.ResponseWriter, r *http.Request) {
	var input signature.Request
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Signatures.Import(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) importCRL(w http.ResponseWriter, r *http.Request) {
	var input struct {
		IssuerID string `json:"issuer_id"`
		PEM      string `json:"pem"`
	}
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Revocations.Import(input.IssuerID, []byte(input.PEM))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) registerResponder(w http.ResponseWriter, r *http.Request) {
	var input ocsp.RegisterRequest
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Statuses.Register(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) retireResponder(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExpectedRevision int `json:"expected_revision"`
	}
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Statuses.Retire(r.PathValue("id"), input.ExpectedRevision)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) importOCSP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ResponderID string `json:"responder_id"`
		PEM         string `json:"pem"`
	}
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Statuses.Import(input.ResponderID, []byte(input.PEM))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var input policy.Request
	if err := readJSON(r, &input); err != nil {
		s.fail(w, err)
		return
	}
	out, err := s.Policies.Create(input)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, out)
}
