package verification

import (
	"fmt"
	"sealpath/internal/chain"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sealpath/internal/ocsp"
	"sealpath/internal/policy"
	"sealpath/internal/revocation"
	"sealpath/internal/signature"
	"time"
)

func Evaluate(material model.Material, request model.VerifyRequest) (model.Decision, error) {
	out := model.Decision{Request: request, TrustRevision: material.TrustSet.Revision, Chain: []string{}, Revocations: []string{}, OCSPResponses: []string{}, Checks: []model.Check{}, CreatedAt: time.Now().UTC()}
	if request.At.IsZero() || request.SignatureID != material.Signature.ID || request.TrustSetID != material.TrustSet.ID || request.PolicyID != material.Policy.ID || request.PolicyVersion != material.Policy.Version {
		return out, model.Invalid("request does not match captured evidence")
	}
	if material.TrustSet.Status != "active" {
		return out, model.Invalid("captured trust set is not active")
	}
	if _, err := codec.DecodeCertificates(material.Certificates); err != nil {
		return out, model.Invalid("%v", err)
	}
	if err := codec.ValidateRevocations(material.Revocations, material.Certificates); err != nil {
		return out, model.Invalid("%v", err)
	}
	for _, response := range material.OCSPResponses {
		if err := codec.ValidateOCSPResponse(response, material.OCSPResponders, material.Certificates); err != nil {
			return out, model.Invalid("%v", err)
		}
	}
	if codec.Digest(material.Artifact.Content) != material.Artifact.ID || material.Artifact.Size != len(material.Artifact.Content) || material.Signature.ArtifactID != material.Artifact.ID {
		return out, model.Invalid("artifact identity does not match captured content")
	}
	certificate, ok := material.Certificates[material.Signature.CertificateID]
	if !ok {
		return out, model.Invalid("signer certificate is absent")
	}
	parsed, err := codec.ParseCertificate(certificate.DER)
	if err != nil {
		return out, err
	}
	// Derived certificate attributes are never trusted across an evidence boundary.
	certificate.Subject = parsed.Subject.String()
	out.Checks = append(out.Checks, policy.Assess(material.Policy, material.Artifact, material.Signature, certificate)...)
	check := model.Check{Code: "signature", Status: "pass", Detail: "detached signature matches the artifact bytes"}
	if err = signature.Verify(parsed, material.Signature.Algorithm, material.Artifact.Content, material.Signature.Value); err != nil {
		check.Status = "fail"
		check.Detail = err.Error()
	}
	out.Checks = append(out.Checks, check)
	path, err := chain.Build(material.Signature.CertificateID, material.Certificates, material.TrustSet, request.At)
	if err != nil {
		out.Checks = append(out.Checks, model.Check{Code: "certificate_path", Status: "fail", Detail: err.Error()})
	} else {
		out.Chain = path.IDs
		out.Checks = append(out.Checks, model.Check{Code: "certificate_path", Status: "pass", Detail: fmt.Sprintf("valid code-signing chain with %d certificates", len(path.IDs))})
		for i := 0; i+1 < len(path.Certificates); i++ {
			cert, issuer := path.Certificates[i], path.Certificates[i+1]
			crlResult := revocation.Inspect(cert, issuer, material.Revocations, request.At)
			statusResult := ocsp.Inspect(path.IDs[i], material.Certificates, material.OCSPResponders, material.OCSPResponses, request.At)
			status, _ := ocsp.Combine(crlResult, statusResult)
			status.Code = fmt.Sprintf("revocation:%s", path.IDs[i])
			out.Checks = append(out.Checks, status)
			if crlResult.ID != "" {
				out.Revocations = append(out.Revocations, crlResult.ID)
			}
			if statusResult.Fresh && statusResult.ResponseID != "" {
				out.OCSPResponses = append(out.OCSPResponses, statusResult.ResponseID)
				if out.ResponderRevision == nil {
					out.ResponderRevision = map[string]int{}
				}
				out.ResponderRevision[statusResult.Responder] = statusResult.Revision
			}
		}
	}
	out.Verdict = "trusted"
	for _, c := range out.Checks {
		if c.Status == "unknown" {
			out.Verdict = "indeterminate"
		}
	}
	for _, c := range out.Checks {
		if c.Status == "fail" {
			out.Verdict = "rejected"
		}
	}
	// Best-effort reports uncertainty explicitly; it never labels an unknown signer trusted.
	if material.Policy.Revocation == "best_effort" && out.Verdict == "indeterminate" {
		out.Verdict = "trusted_with_warning"
	}
	out.MaterialHash, err = codec.JSONDigest(material)
	if err != nil {
		return out, err
	}
	out.ID, err = codec.JSONDigest(struct {
		Request      model.VerifyRequest
		MaterialHash string
	}{request, out.MaterialHash})
	return out, err
}
