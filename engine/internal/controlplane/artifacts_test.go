package controlplane_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/antifailure/antifailure/engine/internal/controlplane"
	"github.com/antifailure/antifailure/engine/internal/redact"
)

func uploadClient(t *testing.T, handler http.HandlerFunc) *controlplane.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := controlplane.New(controlplane.Options{
		BaseURL: srv.URL, Token: "aft_upload_test", Redactor: redact.New(),
	})
	require.NoError(t, err)
	return c
}

func sample() (controlplane.ArtifactUpload, []byte) {
	body := []byte("\x1a\x45\xdf\xa3 a webm, near enough")
	return controlplane.ArtifactUpload{
		EnvID: "env-feature-x", RunID: "run_20261024_abcd", Kind: "video",
		Workflow: "Sign in / out, as 管理者", ContentType: "video/webm",
		Size: int64(len(body)), SHA256: "ab" + string(bytes.Repeat([]byte("0"), 62)),
	}, body
}

// What the control plane needs to refuse without reading the body is all in
// the request line and the headers, and the body is exactly the declared
// length.
func TestUploadArtifact_SendsWhatTheControlPlaneChecksBeforeTheBody(t *testing.T) {
	up, body := sample()
	var seen *http.Request
	var got []byte
	c := uploadClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"8b2e3c9a-1f2d-4c5e-9a7b-0c1d2e3f4a5b","kind":"video","workflow":"Sign in / out, as 管理者",` +
			`"content_type":"video/webm","size_bytes":28,"sha256":"x","expires_at":"2026-11-23T00:00:00Z","created":true}`))
	})
	stored, err := c.UploadArtifact(context.Background(), up, bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, "8b2e3c9a-1f2d-4c5e-9a7b-0c1d2e3f4a5b", stored.ID)
	require.True(t, stored.Created)

	require.Equal(t, http.MethodPost, seen.Method)
	require.Equal(t, "/v1/environments/env-feature-x/runs/run_20261024_abcd/artifacts", seen.URL.Path)
	require.Equal(t, int64(len(body)), seen.ContentLength)
	require.Equal(t, "Bearer aft_upload_test", seen.Header.Get("authorization"))
	require.Equal(t, "video", seen.Header.Get("x-artifact-kind"))
	require.Equal(t, "video/webm", seen.Header.Get("content-type"))
	require.Equal(t, up.SHA256, seen.Header.Get("x-artifact-sha256"))
	// Percent encoded, so a workflow named in any script and holding a slash
	// survives a header that is Latin-1 on the wire.
	require.Equal(t, "Sign%20in%20%2F%20out%2C%20as%20%E7%AE%A1%E7%90%86%E8%80%85",
		seen.Header.Get("x-artifact-workflow"))
	require.Equal(t, body, got)
}

func TestUploadArtifact_ReadsARefusalIntoACodeAndAWait(t *testing.T) {
	up, body := sample()
	cases := []struct {
		name      string
		status    int
		header    string
		response  string
		code      string
		wait      time.Duration
		retryable bool
		final     bool
	}{
		{"storage is off", 403, "", `{"error":"not turned on","code":"uploads_disabled"}`,
			controlplane.ArtifactUploadsDisabled, 0, false, true},
		{"the run has not arrived", 409, "5", `{"error":"no record","code":"run_not_recorded","retryAfterSeconds":5}`,
			controlplane.ArtifactRunNotRecorded, 5 * time.Second, true, false},
		{"the server is full", 429, "10", `{"error":"busy","code":"busy"}`,
			controlplane.ArtifactBusy, 10 * time.Second, true, false},
		{"the quota is spent", 507, "", `{"error":"over","code":"quota"}`,
			controlplane.ArtifactQuota, 0, false, true},
		{"the bytes were not the file", 422, "", `{"error":"mismatch","code":"digest_mismatch"}`,
			"digest_mismatch", 0, false, false},
		{"the token is gone", 401, "", `{"error":"This token is not valid."}`,
			"unauthorized", 0, false, true},
		{"a proxy answered with no body", 503, "", ``,
			"service_unavailable", 0, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := uploadClient(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if tc.header != "" {
					w.Header().Set("retry-after", tc.header)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.response))
			})
			_, err := c.UploadArtifact(context.Background(), up, bytes.NewReader(body))
			var refused *controlplane.ArtifactRefused
			require.True(t, errors.As(err, &refused), "%v", err)
			require.Equal(t, tc.status, refused.Status)
			require.Equal(t, tc.code, refused.Code)
			require.Equal(t, tc.wait, refused.RetryAfter)
			require.Equal(t, tc.retryable, refused.Retryable())
			require.Equal(t, tc.final, refused.Final())
		})
	}
}

func TestUploadArtifact_RefusesToSendWhatCannotBeChecked(t *testing.T) {
	up, body := sample()
	c := uploadClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("a request was sent")
	})
	empty := up
	empty.Size = 0
	_, err := c.UploadArtifact(context.Background(), empty, bytes.NewReader(nil))
	require.ErrorContains(t, err, "empty file")

	noRun := up
	noRun.RunID = ""
	_, err = c.UploadArtifact(context.Background(), noRun, bytes.NewReader(body))
	require.ErrorContains(t, err, "a run")
}

// The control plane's sentence is shown to a person, and everything the
// client shows passes the redactor first.
func TestUploadArtifact_RedactsTheRefusalItRepeats(t *testing.T) {
	up, body := sample()
	r := redact.New()
	r.Register("hunter2-secret-value")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"refused for hunter2-secret-value","code":"length"}`))
	}))
	t.Cleanup(srv.Close)
	c, err := controlplane.New(controlplane.Options{BaseURL: srv.URL, Token: "aft_t", Redactor: r})
	require.NoError(t, err)
	_, err = c.UploadArtifact(context.Background(), up, bytes.NewReader(body))
	require.Error(t, err)
	require.NotContains(t, err.Error(), "hunter2-secret-value")
}
