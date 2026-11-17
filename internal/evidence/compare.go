package evidence

import (
	"reflect"
	"sealpath/internal/model"
	"sort"
)

type Difference struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}
type Comparison struct {
	Left         string       `json:"left"`
	Right        string       `json:"right"`
	SameArtifact bool         `json:"same_artifact"`
	Differences  []Difference `json:"differences"`
}

func (s Service) Compare(left, right string) (Comparison, error) {
	st, err := s.Store.Snapshot()
	if err != nil {
		return Comparison{}, err
	}
	a, ok := st.Decisions[left]
	if !ok {
		return Comparison{}, model.Missing("decision", left)
	}
	b, ok := st.Decisions[right]
	if !ok {
		return Comparison{}, model.Missing("decision", right)
	}
	ma, mb := st.Materials[left], st.Materials[right]
	out := Comparison{Left: left, Right: right, SameArtifact: ma.Artifact.ID == mb.Artifact.ID, Differences: []Difference{}}
	add := func(field string, x, y any) {
		if !reflect.DeepEqual(x, y) {
			out.Differences = append(out.Differences, Difference{field, x, y})
		}
	}
	add("artifact", ma.Artifact.ID, mb.Artifact.ID)
	add("verdict", a.Verdict, b.Verdict)
	add("time", a.Request.At, b.Request.At)
	add("policy", ma.Policy, mb.Policy)
	add("trust_roots", ma.TrustSet.Roots, mb.TrustSet.Roots)
	add("chain", a.Chain, b.Chain)
	add("crls", a.Revocations, b.Revocations)
	add("ocsp_responses", a.OCSPResponses, b.OCSPResponses)
	add("responder_revision", a.ResponderRevision, b.ResponderRevision)
	checksA, checksB := map[string]model.Check{}, map[string]model.Check{}
	for _, c := range a.Checks {
		checksA[c.Code] = c
	}
	for _, c := range b.Checks {
		checksB[c.Code] = c
	}
	codes := map[string]bool{}
	for code := range checksA {
		codes[code] = true
	}
	for code := range checksB {
		codes[code] = true
	}
	sorted := []string{}
	for code := range codes {
		sorted = append(sorted, code)
	}
	sort.Strings(sorted)
	for _, code := range sorted {
		add("check:"+code, checksA[code], checksB[code])
	}
	return out, nil
}
