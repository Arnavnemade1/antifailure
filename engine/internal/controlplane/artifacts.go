package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Uploading a run's recordings.
//
// The control plane refuses an upload for most of the reasons it could fail,
// and every refusal carries a code, so the caller can tell the ones worth
// waiting for from the ones that will never succeed. A run whose events have
// not arrived yet is told to wait; an organization that has not turned storage
// on is told so once, and nothing more is sent.

// UploadTimeout bounds one upload, from the first byte sent to the answer.
// Sixty four megabytes at a sustained megabit a second is under nine minutes.
const UploadTimeout = 10 * time.Minute

// ArtifactUpload names one file and what it is.
type ArtifactUpload struct {
	// EnvID and RunID are the environment and the run as the engine reported
	// them, which is how the control plane finds the run's row.
	EnvID string
	RunID string
	// Kind is video, trace or screenshot.
	Kind string
	// Workflow is the workflow the file is evidence for.
	Workflow string
	// ContentType is what the file is, which the control plane checks
	// against the file's own first bytes.
	ContentType string
	// Size and SHA256 are the file's, computed before it is sent. The control
	// plane refuses a body that does not match either.
	Size   int64
	SHA256 string
}

// StoredArtifact is what the control plane recorded.
type StoredArtifact struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Workflow    string    `json:"workflow"`
	ContentType string    `json:"content_type"`
	SizeBytes   int64     `json:"size_bytes"`
	SHA256      string    `json:"sha256"`
	ExpiresAt   time.Time `json:"expires_at"`
	// Created is false for a file the control plane already held, which is
	// what a retry of an upload that landed the first time is answered with.
	Created bool `json:"created"`
}

// Codes the control plane refuses an upload with, the ones the caller acts on.
const (
	ArtifactUploadsDisabled = "uploads_disabled"
	ArtifactRunNotRecorded  = "run_not_recorded"
	ArtifactQuota           = "quota"
	ArtifactBusy            = "busy"
	ArtifactSuspended       = "suspended"
	ArtifactExists          = "artifact_exists"
)

// ArtifactRefused is an upload the control plane answered and did not store.
type ArtifactRefused struct {
	Status int
	// Code is the control plane's reason, or a description of the status
	// when it gave none.
	Code string
	// Message is the control plane's sentence, redacted.
	Message string
	// RetryAfter is how long the control plane asked the caller to wait, and
	// zero when it did not ask.
	RetryAfter time.Duration
}

func (e *ArtifactRefused) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("controlplane: the upload was refused with %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("controlplane: %s", e.Message)
}

// Retryable reports whether the same upload can succeed later without anything
// changing on this side.
func (e *ArtifactRefused) Retryable() bool {
	switch e.Code {
	case ArtifactRunNotRecorded, ArtifactBusy:
		return true
	}
	return e.Status == http.StatusServiceUnavailable || e.Status == http.StatusTooManyRequests
}

// Final reports whether no further upload in this run can succeed either,
// because the refusal is about the organization rather than the file.
func (e *ArtifactRefused) Final() bool {
	switch e.Code {
	case ArtifactUploadsDisabled, ArtifactQuota, ArtifactSuspended:
		return true
	}
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusPaymentRequired
}

// UploadArtifact sends one file.
//
// body must yield exactly up.Size bytes. It is read once, so a caller retrying
// opens the file again.
func (c *Client) UploadArtifact(ctx context.Context, up ArtifactUpload, body io.Reader) (StoredArtifact, error) {
	var zero StoredArtifact
	if strings.TrimSpace(up.EnvID) == "" || strings.TrimSpace(up.RunID) == "" {
		return zero, errors.New("controlplane: an upload needs an environment and a run")
	}
	if up.Size <= 0 {
		return zero, errors.New("controlplane: an upload needs a size, and an empty file is not one")
	}
	if err := c.ensureCredential(ctx); err != nil {
		return zero, err
	}

	target := *c.baseURL
	target.Path = strings.TrimRight(target.Path, "/") + "/v1/environments/" + url.PathEscape(up.EnvID) +
		"/runs/" + url.PathEscape(up.RunID) + "/artifacts"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), body)
	if err != nil {
		return zero, fmt.Errorf("controlplane: %w", err)
	}
	// Set rather than left to the transport, because the control plane
	// reserves memory for the body from this number before it reads a byte,
	// and refuses a request that does not declare one.
	req.ContentLength = up.Size
	req.Header.Set("authorization", "Bearer "+c.bearer())
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", up.ContentType)
	req.Header.Set("x-artifact-kind", up.Kind)
	// Percent encoded, because a header is Latin-1 and a workflow is named in
	// whatever language its author wrote.
	req.Header.Set("x-artifact-workflow", url.PathEscape(up.Workflow))
	req.Header.Set("x-artifact-sha256", up.SHA256)

	client := c.upload
	if client == nil {
		client = c.http
	}
	res, err := client.Do(req)
	if err != nil {
		return zero, fmt.Errorf("controlplane: could not reach %s: %w", c.baseURL.Host, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		var stored StoredArtifact
		if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&stored); err != nil {
			return zero, fmt.Errorf("controlplane: the response was not the expected shape: %w", err)
		}
		if stored.ID == "" {
			return zero, errors.New("controlplane: the control plane answered without an artifact")
		}
		return stored, nil
	}

	var refusal struct {
		Error             string `json:"error"`
		Code              string `json:"code"`
		RetryAfterSeconds int    `json:"retryAfterSeconds"`
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	_ = json.Unmarshal(raw, &refusal)
	refused := &ArtifactRefused{
		Status:  res.StatusCode,
		Code:    refusal.Code,
		Message: c.scrub(strings.TrimSpace(refusal.Error)),
	}
	if refused.Code == "" {
		refused.Code = strings.ToLower(strings.ReplaceAll(http.StatusText(res.StatusCode), " ", "_"))
	}
	if res.StatusCode == http.StatusUnauthorized {
		refused.Message = "the token was refused. Run 'af token create ci' and set AF_CONTROL_PLANE_TOKEN " +
			"to what it prints, or run 'af login' again"
	}
	if seconds := refusal.RetryAfterSeconds; seconds > 0 {
		refused.RetryAfter = time.Duration(seconds) * time.Second
	} else if h := res.Header.Get("retry-after"); h != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n > 0 {
			refused.RetryAfter = time.Duration(n) * time.Second
		}
	}
	return zero, refused
}
