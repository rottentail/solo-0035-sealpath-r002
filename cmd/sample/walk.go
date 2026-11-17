package main

import (
	"fmt"
	"sealpath/internal/artifact"
	"sealpath/internal/authority"
	"sealpath/internal/evidence"
	"sealpath/internal/model"
	"sealpath/internal/policy"
	"sealpath/internal/repository"
	"sealpath/internal/signature"
	"strings"
)

func walk(c *client, s Samples, workflow, statePath string) (map[string]any, error) {
	result := map[string]any{"workflow": workflow}
	for _, value := range []string{s.Root, s.Intermediate, s.Signer, s.Responder} {
		var cert model.Certificate
		if err := c.call("POST", "/v1/certificates", map[string]string{"pem": value}, &cert); err != nil {
			return nil, err
		}
	}
	result["signer"] = s.SignerID
	if workflow == "certificates" {
		return result, nil
	}
	var trust model.TrustSet
	if err := c.call("POST", "/v1/trust-sets", authority.TrustRequest{ID: "release-roots", Name: "示例发行信任集合", Roots: []string{s.RootID}}, &trust); err != nil {
		return nil, err
	}
	result["trust_revision"] = trust.Revision
	if workflow == "trust" {
		return result, nil
	}
	var a model.Artifact
	if err := c.call("POST", "/v1/artifacts", artifact.Request{Name: "example-release.txt", Content: s.Content}, &a); err != nil {
		return nil, err
	}
	result["artifact"] = a.ID
	if workflow == "artifact" {
		return result, nil
	}
	var sig model.Signature
	if err := c.call("POST", "/v1/signatures", signature.Request{ArtifactID: a.ID, CertificateID: s.SignerID, Algorithm: s.Algorithm, Value: s.Signature}, &sig); err != nil {
		return nil, err
	}
	result["signature"] = sig.ID
	if workflow == "signature" {
		return result, nil
	}
	var p model.Policy
	policyInput := policy.Request{ID: "release", Algorithms: []string{s.Algorithm}, Revocation: "required", MaxArtifactBytes: 1048576}
	if err := c.call("POST", "/v1/policies", policyInput, &p); err != nil {
		return nil, err
	}
	result["policy_version"] = p.Version
	if workflow == "policy" {
		return result, nil
	}
	request := model.VerifyRequest{SignatureID: sig.ID, TrustSetID: trust.ID, PolicyID: p.ID, At: s.At}
	if workflow == "unknown" {
		var d model.Decision
		if err := c.call("POST", "/v1/decisions", request, &d); err != nil {
			return nil, err
		}
		result["verdict"] = d.Verdict
		if d.Verdict != "indeterminate" {
			return nil, fmt.Errorf("missing revocation evidence must remain indeterminate")
		}
		return result, nil
	}
	for _, pair := range [][2]string{{s.RootID, s.RootCRL}, {s.IntermediateID, s.CleanCRL}} {
		if err := c.call("POST", "/v1/revocations", map[string]string{"issuer_id": pair[0], "pem": pair[1]}, nil); err != nil {
			return nil, err
		}
	}
	if workflow == "revocation" {
		result["accepted_crls"] = 2
		return result, nil
	}
	if strings.HasPrefix(workflow, "ocsp") {
		return walkOCSP(c, s, workflow, request, result)
	}
	var d model.Decision
	if err := c.call("POST", "/v1/decisions", request, &d); err != nil {
		return nil, err
	}
	result["verdict"] = d.Verdict
	result["decision"] = d.ID
	if d.Verdict != "trusted" {
		return nil, fmt.Errorf("valid material did not produce a trusted decision: %v", d.Checks)
	}
	switch workflow {
	case "verify":
		return result, nil
	case "history":
		policyInput.ExpectedVersion = 1
		policyInput.SubjectContains = "Different Signer"
		if err := c.call("POST", "/v1/policies", policyInput, nil); err != nil {
			return nil, err
		}
		var old model.Decision
		if err := c.call("GET", "/v1/decisions/"+d.ID, nil, &old); err != nil {
			return nil, err
		}
		if old.Request.PolicyVersion != 1 || old.Verdict != "trusted" {
			return nil, fmt.Errorf("historical decision changed after policy update")
		}
		result["old_policy_version"] = old.Request.PolicyVersion
		return result, nil
	case "bundle":
		var bundle model.Bundle
		if err := c.call("GET", "/v1/decisions/"+d.ID+"/bundle", nil, &bundle); err != nil {
			return nil, err
		}
		var replay evidence.ReplayResult
		if err := c.call("POST", "/v1/evidence/replay", bundle, &replay); err != nil {
			return nil, err
		}
		result["replay"] = replay
		return result, nil
	case "compare":
		if err := c.call("POST", "/v1/revocations", map[string]string{"issuer_id": s.IntermediateID, "pem": s.RevokedCRL}, nil); err != nil {
			return nil, err
		}
		var changed model.Decision
		if err := c.call("POST", "/v1/decisions", request, &changed); err != nil {
			return nil, err
		}
		if changed.Verdict != "rejected" {
			return nil, fmt.Errorf("revoked signer was not rejected")
		}
		var comparison evidence.Comparison
		if err := c.call("GET", "/v1/evidence/compare?left="+d.ID+"&right="+changed.ID, nil, &comparison); err != nil {
			return nil, err
		}
		result["comparison"] = comparison
		return result, nil
	case "restart":
		reopened, err := repository.Open(statePath)
		if err != nil {
			return nil, err
		}
		state, err := reopened.Snapshot()
		if err != nil {
			return nil, err
		}
		if state.Decisions[d.ID].Verdict != "trusted" {
			return nil, fmt.Errorf("persisted decision is missing")
		}
		result["restored_decisions"] = len(state.Decisions)
		return result, nil
	case "retire":
		if err := c.call("POST", "/v1/trust-sets/"+trust.ID+"/retire", map[string]int{"expected_revision": 1}, nil); err != nil {
			return nil, err
		}
		if err := c.call("POST", "/v1/decisions", request, nil); err == nil {
			return nil, fmt.Errorf("retired trust set must not issue new decisions")
		}
		var old model.Decision
		if err := c.call("GET", "/v1/decisions/"+d.ID, nil, &old); err != nil {
			return nil, err
		}
		result["historical_verdict"] = old.Verdict
		return result, nil
	default:
		return nil, fmt.Errorf("unknown workflow %s", workflow)
	}
}
