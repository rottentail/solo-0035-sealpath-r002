package transport

import (
	"net/http"
	"sealpath/internal/model"
	"sort"
)

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"service": "sealpath", "status": "ready", "state_version": state.Version, "sequence": state.Sequence})
}
func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.Certificate{}
	for _, v := range state.Certificates {
		values = append(values, v)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	writeJSON(w, 200, values)
}
func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	value, ok := state.Certificates[r.PathValue("id")]
	if !ok {
		s.fail(w, model.Missing("certificate", r.PathValue("id")))
		return
	}
	writeJSON(w, 200, value)
}
func (s *Server) listTrust(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.TrustSet{}
	for _, v := range state.TrustSets {
		values = append(values, v)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	writeJSON(w, 200, values)
}
func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	value, ok := state.Artifacts[r.PathValue("id")]
	if !ok {
		s.fail(w, model.Missing("artifact", r.PathValue("id")))
		return
	}
	writeJSON(w, 200, value)
}
func (s *Server) getSignature(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	value, ok := state.Signatures[r.PathValue("id")]
	if !ok {
		s.fail(w, model.Missing("signature", r.PathValue("id")))
		return
	}
	writeJSON(w, 200, value)
}
func (s *Server) listCRLs(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.RevocationList{}
	for _, v := range state.Revocations {
		values = append(values, v)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	writeJSON(w, 200, values)
}
func (s *Server) listResponders(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.OCSPResponder{}
	for _, v := range state.OCSPResponders {
		values = append(values, v)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	writeJSON(w, 200, values)
}
func (s *Server) listOCSP(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.OCSPResponse{}
	for _, v := range state.OCSPResponses {
		values = append(values, v)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	writeJSON(w, 200, values)
}
func (s *Server) getPolicies(w http.ResponseWriter, r *http.Request) {
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values, ok := state.Policies[r.PathValue("id")]
	if !ok {
		s.fail(w, model.Missing("policy", r.PathValue("id")))
		return
	}
	writeJSON(w, 200, values)
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	limit, after, err := page(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	state, err := s.Store.Snapshot()
	if err != nil {
		s.fail(w, err)
		return
	}
	values := []model.Event{}
	for _, event := range state.Events {
		if event.Sequence > uint64(after) {
			values = append(values, event)
			if len(values) == limit {
				break
			}
		}
	}
	writeJSON(w, 200, values)
}
