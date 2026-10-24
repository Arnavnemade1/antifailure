package env

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/antifailure/antifailure/engine/internal/controlplane"
	"github.com/antifailure/antifailure/engine/internal/events"
)

// A run's recordings, sent to the control plane once the run is over.
//
// The runner records a video, a Playwright trace and a screenshot for every
// workflow it drives, into the environment's artifacts directory, and until
// this file they never left it. On a developer's machine that is fine, the
// files are there to open. On a CI runner it is not: the runner is discarded
// with everything on it, and the person sent a link to a failed run had a
// verdict and no way to see why.
//
// So when this run reports to a control plane, each workflow's evidence is
// uploaded after the run, and the run's page in the console shows it. Whether
// that happens is the ORGANIZATION's decision, made in the console and refused
// by the control plane until it is made, because these are recordings of an
// application and the data boundary has always said they stay where the run
// happened. This side adds one more refusal of its own: AF_ARTIFACTS=local
// keeps them here whatever the organization decided, for a machine that must
// never send one.

// ArtifactsEnv is the variable that keeps a run's recordings on this machine.
const ArtifactsEnv = "AF_ARTIFACTS"

// The most bytes each kind may be, matching what the control plane accepts, so
// a file it would refuse is never read and sent to be refused.
var evidenceLimits = map[string]int64{
	"video":      64 << 20,
	"trace":      64 << 20,
	"screenshot": 8 << 20,
}

// evidenceTypes are the content types each kind may be, by file extension.
var evidenceTypes = map[string]map[string]string{
	"video":      {".webm": "video/webm", ".mp4": "video/mp4"},
	"trace":      {".zip": "application/zip"},
	"screenshot": {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"},
}

// evidenceFile is one file a workflow recorded, checked and ready to send.
type evidenceFile struct {
	workflow    string
	kind        string
	path        string
	contentType string
	size        int64
}

// evidenceSleep waits between attempts. A variable so a test does not wait in
// real time for a control plane that asked it to.
var evidenceSleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// getenv reads this command's environment, through the orchestrator's own
// reader when it was given one.
func (o *Orchestrator) getenv(name string) string {
	if o.opts.Getenv != nil {
		return o.opts.Getenv(name)
	}
	return os.Getenv(name)
}

// uploadEvidence sends the run's recordings and returns what to tell the
// person about them, or nothing when there is nothing to say: a run that
// reports to no control plane has no recordings to send anywhere, and that is
// the ordinary state of a developer's machine rather than news.
func (o *Orchestrator) uploadEvidence(
	ctx context.Context, s *session, runID, artifactsDir string, report *TestReport,
) []string {
	if s == nil || s.tel == nil || report == nil {
		return nil
	}
	client := s.tel.ControlPlane()
	if client == nil {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(o.getenv(ArtifactsEnv)), "local") {
		return []string{fmt.Sprintf(
			"the run's recordings stayed on this machine because %s=local", ArtifactsEnv)}
	}

	files, skipped := collectEvidence(artifactsDir, report.Results)
	if len(files) == 0 {
		return skipped
	}

	// The run's own events first. The control plane files a recording under
	// the run those events created, and refuses one for a run it has not heard
	// of; a flush now is the difference between one round of uploads and one
	// round of being told to wait.
	flushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	_ = s.tel.FlushControlPlane(flushCtx)
	cancel()

	var (
		sent, sentBytes int64
		workflows       = map[string]bool{}
		notes           = skipped
		networkFailures int
	)
	for _, f := range files {
		stored, err := o.sendEvidence(ctx, s, client, runID, f)
		if err == nil {
			networkFailures = 0
			sent++
			sentBytes += stored.SizeBytes
			workflows[f.workflow] = true
			o.event(s, events.ArtifactStored,
				fmt.Sprintf("the %s for %s was uploaded", f.kind, f.workflow),
				append(o.runFields(runID, "workflows"),
					events.F("artifact_id", stored.ID),
					events.F("workflow", f.workflow),
					events.F("artifact_kind", f.kind),
					events.F("size_bytes", stored.SizeBytes),
					events.F("sha256", stored.SHA256),
				)...)
			continue
		}
		var refused *controlplane.ArtifactRefused
		if errors.As(err, &refused) {
			networkFailures = 0
			if refused.Final() {
				// About the organization, not the file, so every file after
				// this one would be refused the same way. Said once.
				notes = append(notes, finalRefusal(refused))
				break
			}
			notes = append(notes, fmt.Sprintf("the %s for %s was not uploaded: %s",
				f.kind, f.workflow, o.opts.Redactor.String(refused.Message)))
			continue
		}
		networkFailures++
		notes = append(notes, fmt.Sprintf("the %s for %s was not uploaded: %s",
			f.kind, f.workflow, o.opts.Redactor.String(err.Error())))
		if networkFailures >= 2 {
			// Two in a row is a control plane that cannot be reached, and
			// another thirty files would be thirty more of the same line.
			notes = append(notes, "the remaining recordings were not sent, because the control "+
				"plane could not be reached twice in a row; they are still on this machine")
			break
		}
	}

	if sent > 0 {
		// The artifact.stored events are the timeline's record of the uploads,
		// and they are only worth emitting if they arrive.
		flushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_ = s.tel.FlushControlPlane(flushCtx)
		cancel()
		notes = append([]string{fmt.Sprintf(
			"uploaded %d recording(s) for %d workflow(s), %s, to the control plane; the run's page "+
				"in the console shows them", sent, len(workflows), humanBytes(sentBytes))}, notes...)
	}
	return notes
}

// sendEvidence uploads one file, waiting out the refusals that say to wait.
func (o *Orchestrator) sendEvidence(
	ctx context.Context, s *session, client *controlplane.Client, runID string, f evidenceFile,
) (controlplane.StoredArtifact, error) {
	digest, err := fileDigest(f.path, f.size)
	if err != nil {
		return controlplane.StoredArtifact{}, err
	}
	const attempts = 4
	for attempt := 1; ; attempt++ {
		file, err := os.Open(f.path)
		if err != nil {
			return controlplane.StoredArtifact{}, err
		}
		stored, err := client.UploadArtifact(ctx, controlplane.ArtifactUpload{
			EnvID: o.envID, RunID: runID, Kind: f.kind, Workflow: f.workflow,
			ContentType: f.contentType, Size: f.size, SHA256: digest,
		}, io.LimitReader(file, f.size))
		_ = file.Close()
		var refused *controlplane.ArtifactRefused
		if err == nil || !errors.As(err, &refused) || !refused.Retryable() || attempt >= attempts {
			return stored, err
		}
		if refused.Code == controlplane.ArtifactRunNotRecorded {
			// The run's events may still be in the sink. Sending them is what
			// the control plane is waiting for.
			flushCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			_ = s.tel.FlushControlPlane(flushCtx)
			cancel()
		}
		wait := refused.RetryAfter
		if wait <= 0 || wait > 30*time.Second {
			wait = time.Duration(attempt) * 2 * time.Second
		}
		if err := evidenceSleep(ctx, wait); err != nil {
			return controlplane.StoredArtifact{}, err
		}
	}
}

// finalRefusal is the sentence for a refusal that ends the uploads.
func finalRefusal(r *controlplane.ArtifactRefused) string {
	switch r.Code {
	case controlplane.ArtifactUploadsDisabled:
		return "the run's recordings stayed on this machine: this organization has not turned on " +
			"artifact storage. An administrator can turn it on in the console under Settings, Artifacts"
	case controlplane.ArtifactQuota:
		return "the remaining recordings were not uploaded: " + r.Message
	default:
		return "the run's recordings were not uploaded: " + r.Message
	}
}

// collectEvidence lists the files the run's results name that may be sent,
// and says why each of the others may not.
//
// A path is sent only if it resolves, symlinks and all, to a regular file
// inside this environment's artifacts directory. The paths come out of the
// runner's own report, and a report is a file on disk: a path in it that
// named ~/.ssh/id_ed25519 must not become an upload because it was written
// where a screenshot's name belongs.
func collectEvidence(artifactsDir string, results []WorkflowResult) ([]evidenceFile, []string) {
	root, err := filepath.EvalSymlinks(artifactsDir)
	if err != nil {
		return nil, []string{"the run's recordings were not uploaded: its artifacts directory " +
			"could not be read"}
	}
	var (
		out   []evidenceFile
		notes []string
		seen  = map[string]bool{}
	)
	for _, r := range results {
		for _, item := range []struct{ kind, path string }{
			{"video", r.Evidence.Video},
			{"trace", r.Evidence.Trace},
			{"screenshot", r.Evidence.Screenshot},
		} {
			if strings.TrimSpace(item.path) == "" {
				continue
			}
			f, why := checkEvidence(root, r.Workflow, item.kind, item.path)
			if why != "" {
				notes = append(notes, fmt.Sprintf("the %s for %s was not uploaded: %s", item.kind, r.Workflow, why))
				continue
			}
			// A workflow retried within one run reports its last attempt's
			// files; one slot per workflow and kind is what the control plane
			// keeps, so a second path for the same slot is not sent.
			key := r.Workflow + "\x00" + item.kind
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	return out, notes
}

func checkEvidence(root, workflow, kind, path string) (evidenceFile, string) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return evidenceFile{}, "the file is not there any more"
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return evidenceFile{}, "it is outside this environment's artifacts directory, so it is not sent"
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return evidenceFile{}, "it is not a regular file"
	}
	if info.Size() == 0 {
		return evidenceFile{}, "it is empty"
	}
	if limit := evidenceLimits[kind]; info.Size() > limit {
		return evidenceFile{}, fmt.Sprintf("it is %s and a %s may be at most %s",
			humanBytes(info.Size()), kind, humanBytes(limit))
	}
	contentType, ok := evidenceTypes[kind][strings.ToLower(filepath.Ext(resolved))]
	if !ok {
		return evidenceFile{}, fmt.Sprintf("a %s cannot be a %s file", kind, filepath.Ext(resolved))
	}
	return evidenceFile{
		workflow: workflow, kind: kind, path: resolved, contentType: contentType, size: info.Size(),
	}, ""
}

// fileDigest is the SHA-256 of a file, read once, and refused if the file is
// no longer the size it was when it was checked.
func fileDigest(path string, size int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", err
	}
	if n != size {
		return "", fmt.Errorf("%s changed size while it was being read", filepath.Base(path))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// humanBytes renders a size the way a person reads one.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
