package ocsp

import (
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"sort"
	"time"
)

type Service struct{ Store *repository.Store }

// RegisterRequest declares one receiver-approved status responder. IssuerID is
// the CA the responder speaks for; CertificateID is the key that signs its
// responses (the CA itself or a delegated responder certificate); Certificates
// restricts which of that CA's certificates it may answer for.
type RegisterRequest struct {
	ID               string   `json:"id"`
	IssuerID         string   `json:"issuer_id"`
	CertificateID    string   `json:"certificate_id"`
	Certificates     []string `json:"certificates"`
	ExpectedRevision int      `json:"expected_revision"`
}

func (s Service) Register(input RegisterRequest) (model.OCSPResponder, error) {
	var out model.OCSPResponder
	if err := model.ValidateID(input.ID); err != nil {
		return out, err
	}
	if len(input.Certificates) == 0 || len(input.Certificates) > 256 {
		return out, model.Invalid("one to 256 authorized certificates are required")
	}
	scope := append([]string(nil), input.Certificates...)
	sort.Strings(scope)
	for i := 1; i < len(scope); i++ {
		if scope[i] == scope[i-1] {
			return out, model.Invalid("duplicate authorized certificate")
		}
	}
	err := s.Store.Update("ocsp.responder_revised", input.ID, func(st *model.State) error {
		current, exists := st.OCSPResponders[input.ID]
		if current.Revision != input.ExpectedRevision {
			return model.Conflict("responder revision changed")
		}
		if exists && current.Status == "retired" {
			return model.Conflict("retired responder cannot be edited")
		}
		for _, id := range append([]string{input.IssuerID, input.CertificateID}, scope...) {
			if _, ok := st.Certificates[id]; !ok {
				return model.Missing("certificate", id)
			}
		}
		created := current.CreatedAt
		if !exists {
			created = time.Now().UTC()
		}
		out = model.OCSPResponder{ID: input.ID, IssuerID: input.IssuerID, CertificateID: input.CertificateID, Certificates: scope, Status: "active", Revision: current.Revision + 1, CreatedAt: created}
		if err := codec.ValidateOCSPResponder(out, st.Certificates); err != nil {
			return err
		}
		st.OCSPResponders[out.ID] = out
		return nil
	})
	return out, err
}

func (s Service) Retire(id string, revision int) (model.OCSPResponder, error) {
	var out model.OCSPResponder
	err := s.Store.Update("ocsp.responder_retired", id, func(st *model.State) error {
		current, ok := st.OCSPResponders[id]
		if !ok {
			return model.Missing("OCSP responder", id)
		}
		if current.Revision != revision {
			return model.Conflict("responder revision changed")
		}
		if current.Status == "retired" {
			return model.Conflict("responder is already retired")
		}
		current.Status = "retired"
		current.Revision++
		out = current
		st.OCSPResponders[id] = current
		return nil
	})
	return out, err
}
