package main

import (
	"fmt"
	"sealpath/internal/evidence"
	"sealpath/internal/model"
	"sealpath/internal/ocsp"
)

// walkOCSP exercises responder registration, response acceptance, freshness
// precedence, revocation stickiness and retirement through the real HTTP API.
func walkOCSP(c *client, s Samples, workflow string, request model.VerifyRequest, result map[string]any) (map[string]any, error) {
	var responder model.OCSPResponder
	if err := c.call("POST", "/v1/ocsp-responders", ocsp.RegisterRequest{ID: "issuer-status", IssuerID: s.IntermediateID, CertificateID: s.ResponderID, Certificates: []string{s.SignerID}}, &responder); err != nil {
		return nil, err
	}
	result["responder"] = responder
	if workflow == "ocsp-responder" {
		return result, nil
	}

	// A response signed by a key the responder did not register is refused.
	var ignored model.OCSPResponse
	if err := c.call("POST", "/v1/ocsp-responses", map[string]string{"responder_id": "issuer-status", "pem": s.Responder}, &ignored); err == nil {
		return nil, fmt.Errorf("certificate material must not be accepted as an OCSP response")
	}

	var accepted model.OCSPResponse
	if err := c.call("POST", "/v1/ocsp-responses", map[string]string{"responder_id": "issuer-status", "pem": s.GoodOCSP}, &accepted); err != nil {
		return nil, err
	}
	result["ocsp_response"] = accepted.ID
	if workflow == "ocsp-accept" {
		return result, nil
	}

	// CRLs are still present; the fresh OCSP pass supplies availability and
	// the CRL remains the historical revocation record.
	var d model.Decision
	if err := c.call("POST", "/v1/decisions", request, &d); err != nil {
		return nil, err
	}
	result["verdict"] = d.Verdict
	result["decision"] = d.ID
	if d.Verdict != "trusted" {
		return nil, fmt.Errorf("OCSP-backed verification was not trusted: %v", d.Checks)
	}
	if len(d.OCSPResponses) == 0 || d.ResponderRevision["issuer-status"] != 1 {
		return nil, fmt.Errorf("decision did not pin the responder revision it used")
	}
	if workflow == "ocsp-verify" {
		var bundle model.Bundle
		if err := c.call("GET", "/v1/decisions/"+d.ID+"/bundle", nil, &bundle); err != nil {
			return nil, err
		}
		var replay evidence.ReplayResult
		if err := c.call("POST", "/v1/evidence/replay", bundle, &replay); err != nil {
			return nil, err
		}
		if !replay.Matches {
			return nil, fmt.Errorf("OCSP evidence bundle did not replay")
		}
		result["replay"] = replay
		return result, nil
	}

	// A confirmed CRL revocation must survive a fresher "good" response.
	if err := c.call("POST", "/v1/revocations", map[string]string{"issuer_id": s.IntermediateID, "pem": s.RevokedCRL}, nil); err != nil {
		return nil, err
	}
	var conflicted model.Decision
	if err := c.call("POST", "/v1/decisions", request, &conflicted); err != nil {
		return nil, err
	}
	if conflicted.Verdict != "rejected" {
		return nil, fmt.Errorf("fresh OCSP erased a confirmed CRL revocation: %v", conflicted.Checks)
	}
	result["conflict_verdict"] = conflicted.Verdict
	if workflow == "ocsp-conflict" {
		return result, nil
	}

	// Retiring the responder removes it from new decisions while leaving the
	// already-issued decision and its captured authorization untouched.
	if err := c.call("POST", "/v1/ocsp-responders/issuer-status/retire", map[string]int{"expected_revision": 1}, nil); err != nil {
		return nil, err
	}
	var old model.Decision
	if err := c.call("GET", "/v1/decisions/"+d.ID, nil, &old); err != nil {
		return nil, err
	}
	if old.ResponderRevision["issuer-status"] != 1 {
		return nil, fmt.Errorf("historical decision lost the authorization it rested on")
	}
	if err := c.call("POST", "/v1/ocsp-responses", map[string]string{"responder_id": "issuer-status", "pem": s.RevokedOCSP}, nil); err == nil {
		return nil, fmt.Errorf("retired responder accepted a new response")
	}
	result["historical_verdict"] = old.Verdict
	result["historical_responder_revision"] = old.ResponderRevision["issuer-status"]
	return result, nil
}
