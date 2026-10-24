//go:build unix

package installsh

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Ctrl-C used to be a pause rather than a stop.
//
// install.sh set one trap for EXIT, INT and TERM that removed its temporary
// directory and did not exit, and a trap that does not exit is a handler the
// shell RETURNS from: sh, bash, dash and zsh all carried on with the next
// command. Pressed during the download, it killed curl, the script asked
// github.com again why the download had failed, and it told the person who had
// just cancelled it that github.com had not delivered the build, exiting 1. A
// script running the installer could not tell that it had been cancelled.
//
// These deliver the interrupt the way a terminal does, to the installer's whole
// process group, so curl and the shell receive it together. The script is run
// directly rather than through `cat | sh`: the defect is in what the script does
// with the signal, and an outer shell in the same group would die of it first
// and say nothing about the script.

// interrupted runs the installer, waits for ready, then interrupts it, and
// returns what it printed and how it ended.
func (s *session) interrupted(ready <-chan string) (string, syscall.WaitStatus) {
	s.t.Helper()
	var out bytes.Buffer
	cmd := exec.Command("/bin/sh", filepath.Join(s.root, "install.sh"))
	cmd.Env = s.environ()
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	group := -cmd.Process.Pid
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		_ = syscall.Kill(group, syscall.SIGKILL)
		_ = cmd.Wait()
		s.t.Fatalf("the installer never reached the point this test interrupts:\n%s", out.String())
	}
	if err := syscall.Kill(group, syscall.SIGINT); err != nil {
		s.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = syscall.Kill(group, syscall.SIGKILL)
		<-done
		s.t.Fatalf("the installer was still running 30 seconds after an interrupt:\n%s", out.String())
	}
	assertNoRawToolErrorReachedTheReader(s.t, out.String())
	return out.String(), cmd.ProcessState.Sys().(syscall.WaitStatus)
}

func TestAnInterruptedDownloadStopsAndBlamesNobody(t *testing.T) {
	s := newSession(t)
	scratch := t.TempDir()
	s.env["TMPDIR"] = scratch
	held := make(chan string, 1)
	archive := name() + ".tar.gz"
	s.github.set(func(g *githubStandIn) { g.holdSuffix, g.held = archive, held })

	out, status := s.interrupted(held)

	if !status.Signaled() || status.Signal() != syscall.SIGINT {
		t.Errorf("an interrupted installer should die of the interrupt so whatever ran it stops too; it ended with %v:\n%s", status, out)
	}
	// The sentences the script used to say about a download it had cancelled.
	absent(t, out, "answered")
	absent(t, out, "did not arrive")
	absent(t, out, "Installed")
	asked := s.github.paths()
	if last := asked[len(asked)-1]; !strings.HasSuffix(last, "/"+archive) {
		t.Errorf("the installer kept asking github.com after it was interrupted, last for %s; everything it asked: %v", last, asked)
	}
	if _, err := os.Stat(filepath.Join(s.binDir(), "af")); err == nil {
		t.Errorf("af was installed by a run that was interrupted before its checksum was read")
	}
	left, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range left {
		t.Errorf("an interrupted install left %s in the temporary directory", e.Name())
	}
}

// Stopping at the signal means stopping wherever the signal lands, and one
// place it can land is an upgrade with the new runner in place and af not yet
// written. The script used to fall into its failure path from there, because
// the copy it was in had been killed, and that path puts the old runner back.
// Stopping straight away must not skip that.
func TestAnInterruptedUpgradeLeavesTheOldInstall(t *testing.T) {
	s := newSession(t)
	s.install()

	share := filepath.Join(s.home, ".antifailure", "share", "antifailure")
	marker := filepath.Join(share, "runner", "OLD")
	if err := os.WriteFile(marker, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	af := filepath.Join(s.binDir(), "af")
	if err := os.WriteFile(af, []byte("#!/bin/sh\necho old\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A cp that stops when it is asked to write af, which is the last step
	// before the upgrade is complete, and says that it has got there.
	reached := filepath.Join(t.TempDir(), "reached")
	wrapper := "#!/bin/sh\n" +
		"for a in \"$@\"; do\n" +
		"  case \"$a\" in */.af.new.*) : > '" + reached + "'; exec sleep 30 ;; esac\n" +
		"done\n" +
		"exec " + realTool(t, "cp") + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(s.stubs, "cp"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			if _, err := os.Stat(reached); err == nil {
				ready <- reached
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()

	out, status := s.interrupted(ready)

	if !status.Signaled() || status.Signal() != syscall.SIGINT {
		t.Errorf("an interrupted upgrade should die of the interrupt; it ended with %v:\n%s", status, out)
	}
	absent(t, out, "Installed")
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the old runner is gone after an interrupted upgrade: %v", err)
	}
	if body, _ := os.ReadFile(af); string(body) != "#!/bin/sh\necho old\n" {
		t.Errorf("af was replaced by an upgrade that was then interrupted")
	}
	entries, err := os.ReadDir(share)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "runner" {
			t.Errorf("an interrupted upgrade left %s behind in %s", e.Name(), share)
		}
	}
	bins, err := os.ReadDir(s.binDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range bins {
		if e.Name() != "af" {
			t.Errorf("an interrupted upgrade left %s behind in %s", e.Name(), s.binDir())
		}
	}
}
