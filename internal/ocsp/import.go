package ocsp

import (
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"time"
)

// Import accepts one responder-signed status response for a registered,
// currently approved responder. Acceptance is not itself a revocation
// decision; it only fixes which signed material later verification may use.
func (s Service) Import(responderID string, data []byte) (model.OCSPResponse, error) {
	var out model.OCSPResponse
	status, err := codec.ParseOCSP(data)
	if err != nil {
		return out, err
	}
	if status.ResponseStatus != 0 {
		return out, model.Invalid("OCSP responder returned error status %d", status.ResponseStatus)
	}
	if !status.Present {
		return out, model.Invalid("OCSP response carries no certificate status")
	}
	if status.NextUpdate.IsZero() || !status.NextUpdate.After(status.ThisUpdate) {
		return out, model.Invalid("OCSP response requires next_update after this_update")
	}
	out = model.OCSPResponse{ID: codec.Digest(data), ResponderID: responderID, DER: data, ProducedAt: status.ProducedAt, ThisUpdate: status.ThisUpdate, NextUpdate: status.NextUpdate, ReceivedAt: time.Now().UTC()}
	err = s.Store.Update("ocsp.response_accepted", out.ID, func(st *model.State) error {
		if existing, ok := st.OCSPResponses[out.ID]; ok {
			if existing.ResponderID != responderID {
				return model.Conflict("identical OCSP response was accepted under a different responder")
			}
			out = existing
			return nil
		}
		responder, ok := st.OCSPResponders[responderID]
		if !ok {
			return model.Missing("OCSP responder", responderID)
		}
		if responder.Status != "active" {
			return model.Conflict("retired responder cannot accept new responses")
		}
		out.IssuerID = responder.IssuerID
		out.CertificateID = responder.CertificateID
		if _, err := codec.AnsweredCertificate(status, responder, st.Certificates); err != nil {
			return err
		}
		for _, existing := range st.OCSPResponses {
			if existing.ResponderID != responderID {
				continue
			}
			if existing.ProducedAt.After(out.ProducedAt) {
				return model.Conflict("new OCSP response cannot move produced_at backwards")
			}
		}
		if err := codec.ValidateOCSPResponse(out, st.OCSPResponders, st.Certificates); err != nil {
			return err
		}
		st.OCSPResponses[out.ID] = out
		return nil
	})
	return out, err
}
