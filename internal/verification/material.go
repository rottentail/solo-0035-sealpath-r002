package verification

import (
	"sealpath/internal/model"
	"sealpath/internal/policy"
)

func Capture(st model.State, request model.VerifyRequest) (model.Material, model.VerifyRequest, error) {
	var out model.Material
	s, ok := st.Signatures[request.SignatureID]
	if !ok {
		return out, request, model.Missing("signature", request.SignatureID)
	}
	trust, ok := st.TrustSets[request.TrustSetID]
	if !ok {
		return out, request, model.Missing("trust set", request.TrustSetID)
	}
	if trust.Status != "active" {
		return out, request, model.Conflict("trust set is retired")
	}
	p, err := policy.Select(st, request.PolicyID, request.PolicyVersion)
	if err != nil {
		return out, request, err
	}
	request.PolicyVersion = p.Version
	if request.At.IsZero() {
		return out, request, model.Invalid("explicit verification time is required")
	}
	request.At = request.At.UTC()
	out = model.Material{Certificates: st.Certificates, TrustSet: trust, Artifact: st.Artifacts[s.ArtifactID], Signature: s, Policy: p, Revocations: st.Revocations, OCSPResponders: st.OCSPResponders, OCSPResponses: st.OCSPResponses}
	return out, request, nil
}
