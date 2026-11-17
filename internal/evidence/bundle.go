package evidence

import (
	"reflect"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/repository"
	"sealpath/internal/verification"
)

type Service struct{ Store *repository.Store }

func digest(bundle model.Bundle) (string, error) { bundle.Digest = ""; return codec.JSONDigest(bundle) }
func (s Service) Export(id string) (model.Bundle, error) {
	st, err := s.Store.Snapshot()
	if err != nil {
		return model.Bundle{}, err
	}
	decision, ok := st.Decisions[id]
	if !ok {
		return model.Bundle{}, model.Missing("decision", id)
	}
	bundle := model.Bundle{Format: "sealpath-evidence-v1", Decision: decision, Material: st.Materials[id]}
	bundle.Digest, err = digest(bundle)
	return bundle, err
}

type ReplayResult struct {
	Matches      bool   `json:"matches"`
	Verdict      string `json:"verdict"`
	DecisionID   string `json:"decision_id"`
	Authenticity string `json:"authenticity"`
}

func Replay(bundle model.Bundle) (ReplayResult, error) {
	var out ReplayResult
	if bundle.Format != "sealpath-evidence-v1" {
		return out, model.Invalid("unsupported evidence format")
	}
	hash, err := digest(bundle)
	if err != nil {
		return out, err
	}
	if hash != bundle.Digest {
		return out, model.Invalid("bundle digest mismatch")
	}
	result, err := verification.Evaluate(bundle.Material, bundle.Decision.Request)
	if err != nil {
		return out, err
	}
	original := bundle.Decision
	if result.ID != original.ID || result.MaterialHash != original.MaterialHash || result.Verdict != original.Verdict || result.TrustRevision != original.TrustRevision || !reflect.DeepEqual(result.Chain, original.Chain) || !equalStrings(result.Revocations, original.Revocations) || !equalStrings(result.OCSPResponses, original.OCSPResponses) || !equalRevisions(result.ResponderRevision, original.ResponderRevision) || !reflect.DeepEqual(result.Checks, original.Checks) {
		return out, model.Invalid("decision cannot be reproduced from captured evidence")
	}
	out = ReplayResult{Matches: true, Verdict: result.Verdict, DecisionID: result.ID, Authenticity: "self-contained consistency; trust origin must be established separately"}
	return out, nil
}

// equalStrings treats an absent slice and an empty slice as identical, so a
// decision recorded before a field existed still replays against a bundle
// that omits it during JSON round-trips.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalRevisions(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
