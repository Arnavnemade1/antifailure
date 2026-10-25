package env

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/antifailure/antifailure/engine/internal/clock"
	"github.com/antifailure/antifailure/engine/internal/events"
	"github.com/antifailure/antifailure/engine/internal/redact"
	"github.com/antifailure/antifailure/engine/internal/telemetry"
)

// writeEvidence writes a file that begins the way its type does.
func writeEvidence(t *testing.T, dir, name string, size int) string {
	t.Helper()
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i * 13)
	}
	switch filepath.Ext(name) {
	case ".webm":
		copy(body, []byte{0x1a, 0x45, 0xdf, 0xa3})
	case ".zip":
		copy(body, []byte{0x50, 0x4b, 0x03, 0x04})
	case ".png":
		copy(body, []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})
	}
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, body, 0o644))
	return path
}

func evidenceResult(workflow, video, trace, screenshot string) WorkflowResult {
	var r WorkflowResult
	r.Workflow = workflow
	r.Evidence.Video = video
	r.Evidence.Trace = trace
	r.Evidence.Screenshot = screenshot
	return r
}

// ---------------------------------------------------------------------------
// What may leave the machine
// ---------------------------------------------------------------------------

func TestCollectEvidence_SendsOnlyRegularFilesInsideTheArtifactsDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	video := writeEvidence(t, dir, "checkout.webm", 4096)
	trace := writeEvidence(t, dir, "checkout.trace.zip", 2048)
	writeEvidence(t, dir, "checkout.png", 1024)
	secret := writeEvidence(t, outside, "id_ed25519.png", 256)
	escape := filepath.Join(dir, "escape.png")
	require.NoError(t, os.Symlink(secret, escape))
	writeEvidence(t, dir, "notes.txt", 64)
	empty := filepath.Join(dir, "empty.png")
	require.NoError(t, os.WriteFile(empty, nil, 0o644))
	huge := filepath.Join(dir, "huge.png")
	f, err := os.Create(huge)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(9<<20))
	require.NoError(t, f.Close())

	files, notes := collectEvidence(dir, []WorkflowResult{
		// A relative screenshot path is read relative to the directory.
		evidenceResult("Checkout", video, trace, "checkout.png"),
		evidenceResult("Exfiltrate", "", "", secret),
		evidenceResult("Through a link", "", "", escape),
		evidenceResult("Up and out", "", "", filepath.Join(dir, "..", filepath.Base(outside), "id_ed25519.png")),
		evidenceResult("Wrong type", filepath.Join(dir, "notes.txt"), "", ""),
		evidenceResult("Empty", "", "", empty),
		evidenceResult("Huge", "", "", huge),
		evidenceResult("Gone", filepath.Join(dir, "never-written.webm"), "", ""),
		// A workflow the runner retried reports a second set of paths for the
		// same slots, and the control plane keeps one per slot.
		evidenceResult("Checkout", video, "", ""),
	})

	var sent []string
	for _, f := range files {
		sent = append(sent, f.workflow+" "+f.kind+" "+f.contentType)
	}
	require.Equal(t, []string{
		"Checkout video video/webm",
		"Checkout trace application/zip",
		"Checkout screenshot image/png",
	}, sent)

	joined := strings.Join(notes, "\n")
	for _, want := range []string{
		"the screenshot for Exfiltrate was not uploaded: it is outside this environment's artifacts directory",
		"the screenshot for Through a link was not uploaded: it is outside",
		"the screenshot for Up and out was not uploaded: it is outside",
		"the video for Wrong type was not uploaded: a video cannot be a .txt file",
		"the screenshot for Empty was not uploaded: it is empty",
		"the screenshot for Huge was not uploaded: it is 9.0 MB and a screenshot may be at most 8.0 MB",
		"the video for Gone was not uploaded: the file is not there any more",
	} {
		require.Contains(t, joined, want)
	}
}

// ---------------------------------------------------------------------------
// Against a control plane
// ---------------------------------------------------------------------------

// fakeControlPlane answers what an engine sends after a run: event batches and
// uploads. Each upload is answered by the next scripted reply, and 201 once
// the script runs out.
type fakeControlPlane struct {
	mu      sync.Mutex
	script  []func(w http.ResponseWriter)
	uploads []uploadSeen
	events  []map[string]any
	srv     *httptest.Server
}

type uploadSeen struct {
	path, kind, workflow, digest string
	body                         []byte
}

func newFakeControlPlane(t *testing.T) *fakeControlPlane {
	f := &fakeControlPlane{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/v1/events" {
			var batch struct {
				Events []map[string]any `json:"events"`
			}
			_ = json.NewDecoder(r.Body).Decode(&batch)
			f.events = append(f.events, batch.Events...)
			outcomes := make([]map[string]any, len(batch.Events))
			for i, e := range batch.Events {
				outcomes[i] = map[string]any{"id": e["id"], "status": "accepted"}
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accepted": len(batch.Events), "duplicates": 0, "rejected": 0, "unprojected": 0,
				"outcomes": outcomes,
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/artifacts") {
			body, _ := io.ReadAll(r.Body)
			f.uploads = append(f.uploads, uploadSeen{
				path: r.URL.Path, kind: r.Header.Get("x-artifact-kind"),
				workflow: r.Header.Get("x-artifact-workflow"), digest: r.Header.Get("x-artifact-sha256"),
				body: body,
			})
			if len(f.script) > 0 {
				next := f.script[0]
				f.script = f.script[1:]
				next(w)
				return
			}
			sum := sha256.Sum256(body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "0b8f4a7e-9d2c-4b1a-8e3f-" + hex.EncodeToString(sum[:6]), "kind": r.Header.Get("x-artifact-kind"),
				"size_bytes": len(body), "sha256": hex.EncodeToString(sum[:]),
				"expires_at": "2026-11-23T00:00:00Z", "created": true,
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func refuse(status int, code string, retryAfter int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(status)
		body := map[string]any{"error": "refused: " + code, "code": code}
		if retryAfter > 0 {
			body["retryAfterSeconds"] = retryAfter
		}
		_ = json.NewEncoder(w).Encode(body)
	}
}

// evidenceRun is an orchestrator and a reporting session pointed at a control
// plane, with the run's recordings in a directory of their own.
type evidenceRun struct {
	o      *Orchestrator
	s      *session
	dir    string
	report *TestReport
}

func newEvidenceRun(t *testing.T, controlPlaneURL string, env map[string]string) *evidenceRun {
	t.Helper()
	getenv := func(k string) string { return env[k] }
	red := redact.New()
	c := clock.New()
	bus := events.NewBus(c)
	var tel *telemetry.Telemetry
	if controlPlaneURL != "" {
		var err error
		tel, err = telemetry.Attach(context.Background(), bus, telemetry.Options{
			StateDir: t.TempDir(), EnvID: "env-evidence", Redactor: red, Clock: c, Getenv: getenv,
			ControlPlaneURL: controlPlaneURL, ControlPlaneToken: "aft_evidence_test_token",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = tel.Close(context.Background()) })
	}
	dir := t.TempDir()
	run := &evidenceRun{
		o:   &Orchestrator{opts: Options{Redactor: red, Clock: c, Getenv: getenv}, envID: "env-evidence", progress: func(string) {}},
		s:   &session{bus: bus, tel: tel},
		dir: dir,
	}
	video := writeEvidence(t, dir, "sign-in.webm", 3000)
	trace := writeEvidence(t, dir, "sign-in.trace.zip", 1500)
	shot := writeEvidence(t, dir, "sign-in.png", 700)
	run.report = &TestReport{Results: []WorkflowResult{evidenceResult("Sign in", video, trace, shot)}}
	return run
}

func (r *evidenceRun) upload(t *testing.T) []string {
	t.Helper()
	return r.o.uploadEvidence(context.Background(), r.s, "run_evidence_1", r.dir, r.report)
}

func noWaiting(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	previous := evidenceSleep
	evidenceSleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	t.Cleanup(func() { evidenceSleep = previous })
	return &waits
}

func TestUploadEvidence_SendsEveryRecordingAndReportsEachOne(t *testing.T) {
	noWaiting(t)
	cp := newFakeControlPlane(t)
	run := newEvidenceRun(t, cp.srv.URL, nil)

	notes := run.upload(t)
	require.Len(t, notes, 1, "%v", notes)
	require.Contains(t, notes[0], "uploaded 3 recording(s) for 1 workflow(s)")

	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Len(t, cp.uploads, 3)
	for _, u := range cp.uploads {
		require.Equal(t, "/v1/environments/env-evidence/runs/run_evidence_1/artifacts", u.path)
		require.Equal(t, "Sign%20in", u.workflow)
		sum := sha256.Sum256(u.body)
		require.Equal(t, hex.EncodeToString(sum[:]), u.digest, "the digest sent is not of the body sent")
	}
	// One artifact.stored per upload, delivered, naming what it reports.
	var stored []map[string]any
	for _, e := range cp.events {
		if e["type"] == "artifact.stored" {
			stored = append(stored, e)
		}
	}
	require.Len(t, stored, 3)
	payload, _ := stored[0]["payload"].(map[string]any)
	require.NotEmpty(t, payload["artifact_id"])
	require.Equal(t, "run_evidence_1", payload["run_id"])
}

func TestUploadEvidence_StopsAtTheFirstRefusalAboutTheOrganization(t *testing.T) {
	noWaiting(t)
	cp := newFakeControlPlane(t)
	cp.script = []func(http.ResponseWriter){refuse(http.StatusForbidden, "uploads_disabled", 0)}
	run := newEvidenceRun(t, cp.srv.URL, nil)

	notes := run.upload(t)
	require.Equal(t, []string{
		"the run's recordings stayed on this machine: this organization has not turned on artifact " +
			"storage. An administrator can turn it on in the console under Settings, Artifacts",
	}, notes)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Len(t, cp.uploads, 1, "a refusal about the organization was asked again for every file")
}

func TestUploadEvidence_WaitsForTheRunsOwnEventsAndThenSends(t *testing.T) {
	waits := noWaiting(t)
	cp := newFakeControlPlane(t)
	cp.script = []func(http.ResponseWriter){refuse(http.StatusConflict, "run_not_recorded", 5)}
	run := newEvidenceRun(t, cp.srv.URL, nil)

	notes := run.upload(t)
	require.Contains(t, notes[0], "uploaded 3 recording(s)")
	require.Equal(t, []time.Duration{5 * time.Second}, *waits)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Len(t, cp.uploads, 4, "the refused file was not sent again")
}

func TestUploadEvidence_KeepsGoingPastARefusalAboutOneFile(t *testing.T) {
	noWaiting(t)
	cp := newFakeControlPlane(t)
	cp.script = []func(http.ResponseWriter){refuse(http.StatusUnprocessableEntity, "digest_mismatch", 0)}
	run := newEvidenceRun(t, cp.srv.URL, nil)

	notes := run.upload(t)
	require.Contains(t, notes[0], "uploaded 2 recording(s)")
	require.Contains(t, strings.Join(notes, "\n"), "the video for Sign in was not uploaded: refused: digest_mismatch")
}

func TestUploadEvidence_SendsNothingWhenThisMachineSaysLocal(t *testing.T) {
	cp := newFakeControlPlane(t)
	run := newEvidenceRun(t, cp.srv.URL, map[string]string{ArtifactsEnv: "local"})

	notes := run.upload(t)
	require.Equal(t, []string{"the run's recordings stayed on this machine because AF_ARTIFACTS=local"}, notes)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	require.Empty(t, cp.uploads)
}

func TestUploadEvidence_SaysNothingWithNoControlPlane(t *testing.T) {
	run := newEvidenceRun(t, "", nil)
	require.Nil(t, run.upload(t))
}

func TestUploadEvidence_GivesUpOnAControlPlaneThatCannotBeReached(t *testing.T) {
	noWaiting(t)
	cp := newFakeControlPlane(t)
	url := cp.srv.URL
	run := newEvidenceRun(t, url, nil)
	cp.srv.Close()

	notes := run.upload(t)
	joined := strings.Join(notes, "\n")
	require.Contains(t, joined, "could not be reached twice in a row")
	require.Equal(t, 3, len(notes), "%v", notes)
}
