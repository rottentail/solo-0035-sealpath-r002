package repository

import (
	"fmt"
	"sealpath/internal/codec"
	"sealpath/internal/model"
)

func ValidateState(s model.State) error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	if s.Certificates == nil || s.TrustSets == nil || s.Artifacts == nil || s.Signatures == nil || s.Revocations == nil || s.OCSPResponders == nil || s.OCSPResponses == nil || s.Policies == nil || s.Decisions == nil || s.Materials == nil {
		return fmt.Errorf("state collections must not be null")
	}
	for id, c := range s.Certificates {
		if c.ID != id || codec.Digest(c.DER) != id {
			return fmt.Errorf("certificate identity mismatch %s", id)
		}
	}
	for id, a := range s.Artifacts {
		if a.ID != id || codec.Digest(a.Content) != id || a.Size != len(a.Content) {
			return fmt.Errorf("artifact identity mismatch %s", id)
		}
	}
	for id, t := range s.TrustSets {
		if t.ID != id || t.Revision < 1 || (t.Status != "active" && t.Status != "retired") {
			return fmt.Errorf("invalid trust set %s", id)
		}
		for _, root := range t.Roots {
			if _, ok := s.Certificates[root]; !ok {
				return fmt.Errorf("trust root is missing")
			}
		}
	}
	for id, v := range s.Signatures {
		_, a := s.Artifacts[v.ArtifactID]
		_, c := s.Certificates[v.CertificateID]
		if v.ID != id || !a || !c {
			return fmt.Errorf("dangling signature %s", id)
		}
	}
	for id, r := range s.Revocations {
		if r.ID != id || codec.Digest(r.DER) != id {
			return fmt.Errorf("revocation identity mismatch")
		}
		if _, ok := s.Certificates[r.IssuerID]; !ok {
			return fmt.Errorf("revocation issuer is missing")
		}
	}
	if err := codec.ValidateRevocations(s.Revocations, s.Certificates); err != nil {
		return err
	}
	for id, responder := range s.OCSPResponders {
		if responder.ID != id {
			return fmt.Errorf("OCSP responder identity mismatch")
		}
		if err := codec.ValidateOCSPResponder(responder, s.Certificates); err != nil {
			return err
		}
	}
	for id, response := range s.OCSPResponses {
		if response.ID != id {
			return fmt.Errorf("OCSP response identity mismatch")
		}
		if err := codec.ValidateOCSPResponse(response, s.OCSPResponders, s.Certificates); err != nil {
			return err
		}
	}
	for id, versions := range s.Policies {
		for i, p := range versions {
			if p.ID != id || p.Version != i+1 {
				return fmt.Errorf("policy version gap")
			}
		}
	}
	for id, d := range s.Decisions {
		material, ok := s.Materials[id]
		hash, err := codec.JSONDigest(material)
		if !ok || err != nil || d.ID != id || d.MaterialHash != hash {
			return fmt.Errorf("decision evidence mismatch %s", id)
		}
	}
	var sequence uint64
	for _, event := range s.Events {
		if event.Sequence != sequence+1 {
			return fmt.Errorf("event sequence gap")
		}
		sequence = event.Sequence
	}
	if sequence != s.Sequence {
		return fmt.Errorf("event head mismatch")
	}
	return nil
}
