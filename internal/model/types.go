package model

import "time"

type Certificate struct {
	ID         string    `json:"id"`
	DER        []byte    `json:"der"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	IsCA       bool      `json:"is_ca"`
	ReceivedAt time.Time `json:"received_at"`
}

type TrustSet struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Roots     []string  `json:"roots"`
	Status    string    `json:"status"`
	Revision  int       `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
}

type Artifact struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	MediaType  string    `json:"media_type"`
	Content    []byte    `json:"content"`
	Size       int       `json:"size"`
	ReceivedAt time.Time `json:"received_at"`
}

type Signature struct {
	ID            string    `json:"id"`
	ArtifactID    string    `json:"artifact_id"`
	CertificateID string    `json:"certificate_id"`
	Algorithm     string    `json:"algorithm"`
	Value         []byte    `json:"value"`
	ReceivedAt    time.Time `json:"received_at"`
}

type RevocationList struct {
	ID         string    `json:"id"`
	IssuerID   string    `json:"issuer_id"`
	DER        []byte    `json:"der"`
	Number     string    `json:"number"`
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
	ReceivedAt time.Time `json:"received_at"`
}

// OCSPResponder is a receiver-approved status responder. CertificateID names
// the certificate whose key signs responses (the issuer itself or a delegated
// responder); Certificates bounds the certificates it may answer for.
type OCSPResponder struct {
	ID            string    `json:"id"`
	IssuerID      string    `json:"issuer_id"`
	CertificateID string    `json:"certificate_id"`
	Certificates  []string  `json:"certificates"`
	Status        string    `json:"status"`
	Revision      int       `json:"revision"`
	CreatedAt     time.Time `json:"created_at"`
}

type OCSPResponse struct {
	ID            string    `json:"id"`
	ResponderID   string    `json:"responder_id"`
	IssuerID      string    `json:"issuer_id"`
	CertificateID string    `json:"certificate_id"`
	DER           []byte    `json:"der"`
	ProducedAt    time.Time `json:"produced_at"`
	ThisUpdate    time.Time `json:"this_update"`
	NextUpdate    time.Time `json:"next_update"`
	ReceivedAt    time.Time `json:"received_at"`
}

type Policy struct {
	ID               string    `json:"id"`
	Version          int       `json:"version"`
	Status           string    `json:"status"`
	Algorithms       []string  `json:"algorithms"`
	Revocation       string    `json:"revocation"`
	MaxArtifactBytes int       `json:"max_artifact_bytes"`
	SubjectContains  string    `json:"subject_contains"`
	CreatedAt        time.Time `json:"created_at"`
}

type Check struct {
	Code     string `json:"code"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	Source   string `json:"source,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type VerifyRequest struct {
	SignatureID   string    `json:"signature_id"`
	TrustSetID    string    `json:"trust_set_id"`
	PolicyID      string    `json:"policy_id"`
	PolicyVersion int       `json:"policy_version"`
	At            time.Time `json:"at"`
}

// Decision carries the acceptance decisions that were in force when its
// evidence was captured, so a later revocation or retirement cannot rewrite
// which authorization a historical verdict rested on.
type Decision struct {
	ID                string         `json:"id"`
	Verdict           string         `json:"verdict"`
	Request           VerifyRequest  `json:"request"`
	TrustRevision     int            `json:"trust_revision"`
	Chain             []string       `json:"chain"`
	Revocations       []string       `json:"revocations"`
	OCSPResponses     []string       `json:"ocsp_responses"`
	ResponderRevision map[string]int `json:"responder_revision,omitempty"`
	Checks            []Check        `json:"checks"`
	CreatedAt         time.Time      `json:"created_at"`
	MaterialHash      string         `json:"material_hash"`
}

type Material struct {
	Certificates   map[string]Certificate    `json:"certificates"`
	TrustSet       TrustSet                  `json:"trust_set"`
	Artifact       Artifact                  `json:"artifact"`
	Signature      Signature                 `json:"signature"`
	Policy         Policy                    `json:"policy"`
	Revocations    map[string]RevocationList `json:"revocations"`
	OCSPResponders map[string]OCSPResponder  `json:"ocsp_responders,omitempty"`
	OCSPResponses  map[string]OCSPResponse   `json:"ocsp_responses,omitempty"`
}

type Bundle struct {
	Format   string   `json:"format"`
	Decision Decision `json:"decision"`
	Material Material `json:"material"`
	Digest   string   `json:"digest"`
}

type Event struct {
	Sequence uint64    `json:"sequence"`
	Kind     string    `json:"kind"`
	ObjectID string    `json:"object_id"`
	At       time.Time `json:"at"`
}

type State struct {
	Version        int                       `json:"version"`
	Sequence       uint64                    `json:"sequence"`
	Certificates   map[string]Certificate    `json:"certificates"`
	TrustSets      map[string]TrustSet       `json:"trust_sets"`
	Artifacts      map[string]Artifact       `json:"artifacts"`
	Signatures     map[string]Signature      `json:"signatures"`
	Revocations    map[string]RevocationList `json:"revocations"`
	OCSPResponders map[string]OCSPResponder  `json:"ocsp_responders"`
	OCSPResponses  map[string]OCSPResponse   `json:"ocsp_responses"`
	Policies       map[string][]Policy       `json:"policies"`
	Decisions      map[string]Decision       `json:"decisions"`
	Materials      map[string]Material       `json:"materials"`
	Events         []Event                   `json:"events"`
}
