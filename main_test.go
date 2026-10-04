package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMainChild is main itself, run by mainCmd in a process of its own, since a bad option exits it.
func TestMainChild(t *testing.T) {
	spec := os.Getenv("SIXUP_MAIN_ARGS")
	if spec == "" {
		t.Skip("run by mainCmd")
	}
	var args []string
	if err := json.Unmarshal([]byte(spec), &args); err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"sixup"}, args...)
	main()
	os.Exit(0) // keep the test runner's PASS out of the output
}

// mainCmd prepares a child that runs main with args. Under -cover it writes its counters into the
// parent's directory, which go test merges.
func mainCmd(t *testing.T, args ...string) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	spec, _ := json.Marshal(args)
	targs := []string{"-test.run=^TestMainChild$"}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		targs = append(targs, "-test.gocoverdir="+f.Value.String())
	}
	cmd := exec.Command(os.Args[0], targs...)
	cmd.Env = append(os.Environ(), "SIXUP_MAIN_ARGS="+string(spec), "NO_COLOR=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	return cmd, &stdout, &stderr
}

// runMain runs main with args and returns what it printed and its exit code.
func runMain(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd, out, errOut := mainCmd(t, args...)
	err := cmd.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return out.String(), errOut.String(), ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errOut.String(), 0
}

func TestMainHelp(t *testing.T) {
	_, stderr, code := runMain(t, "-h")
	if code != 0 {
		t.Fatalf("-h exited %d", code)
	}
	for _, want := range []string{"usage: sixup -wan <interface>", "\nInterfaces and prefixes\n  -wan\n", "\nRuntime\n", "(default 56)", "\nOther\n  -test."} {
		if !strings.Contains(stderr, want) {
			t.Errorf("-h output lacks %q:\n%s", want, stderr)
		}
	}
	// A false or empty default is not worth printing.
	if strings.Contains(stderr, "(default false)") || strings.Contains(stderr, "(default )") {
		t.Errorf("-h prints an empty default:\n%s", stderr)
	}
	// Every grouped name must be a real flag, or -h silently drops it.
	for _, g := range usageGroups {
		for _, n := range g.names {
			if flag.Lookup(n) == nil {
				t.Errorf("group %q lists unknown flag -%s", g.title, n)
			}
		}
	}
}

func TestMainVersionAndLicense(t *testing.T) {
	if out, _, code := runMain(t, "-version"); code != 0 || out != "sixup dev\n" {
		t.Errorf("-version: %q, exit %d", out, code)
	}
	out, _, code := runMain(t, "-license")
	if code != 0 || !strings.HasPrefix(out, "sixup dev\n\n") || !strings.Contains(out, licenseText) || !strings.HasSuffix(out, noticeText) {
		t.Errorf("-license: exit %d, output:\n%.300s", code, out)
	}
}

func TestMainRejectsBadOptions(t *testing.T) {
	daemon := "at least one -lan is required"
	if runtime.GOOS != "linux" {
		daemon = "only -dry-run is supported"
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "-wan is required"},
		{[]string{"-wan", "x"}, daemon},
		{[]string{"-wan", "x", "-log-level", "loud"}, "-log-level must be"},
		{[]string{"-dry-run", "-wan", "x", "-wan-prefix", "fd00::/48"}, "-wan-prefix:"},
		{[]string{"-dry-run", "-wan", "x", "-lan", "a", "-lan", "b", "-wan-prefer", "ra"}, "multiple LAN interfaces"},
		{[]string{"-dry-run", "-wan", "x", "-dhcp6s-mode", "on"}, "-dhcp6s-mode must be"},
		{[]string{"-dry-run", "-wan", "x", "-tunnel-nat", "on"}, "-tunnel-nat must be"},
		{[]string{"-dry-run", "-wan", "x", "-nat64", "tayga"}, "-nat64 must be"},
		{[]string{"-dry-run", "-wan", "x", "-jool-ipv4", "192.168.0.0/30"}, "-jool-ipv4 must be"},
		{[]string{"-dry-run", "-wan", "x", "-nat64-prefix", "x"}, "-nat64-prefix:"},
		{[]string{"-dry-run", "-wan", "x", "-ra-pref64", "x"}, "-ra-pref64:"},
		{[]string{"-dry-run", "-wan", "x", "-nat64", "jool", "-ra-pref64", "2001:db8:64::/96"}, "would announce a prefix nothing here translates"},
		{[]string{"-dry-run", "-wan", "x", "-unsolicited", "some"}, "-unsolicited must be"},
		{[]string{"-dry-run", "-wan", "x", "-wan-shared64", "both"}, "-wan-shared64 must be"},
		{[]string{"-dry-run", "-wan", "x", "-ndproxy-mode", "on"}, "-ndproxy-mode must be"},
		{[]string{"-dry-run", "-wan", "x", "-dhcp6s-pd-len", "65"}, "-dhcp6s-pd-len must be"},
		{[]string{"-dry-run", "-wan", "x", "-ra-min", "1s"}, "-ra-min must be"},
		{[]string{"-dry-run", "-wan", "x", "-dhcp6c-mode", "off", "-wan-ra=false"}, "at least one of the DHCPv6 client"},
		{[]string{"-dry-run", "-wan", "x", "-wan-iid", "::1:2:3:4:5"}, "-wan-iid:"},
		{[]string{"-dry-run", "-wan", "x", "-lan-iid", "::1:2:3:4:5"}, "-lan-iid:"},
		{[]string{"-dry-run", "-wan", "x", "-ula", "2001:db8::/48"}, "-ula:"},
		{[]string{"-dry-run", "-wan", "x", "-lan", "eth1:x"}, `-lan "eth1:x" has an invalid subnet id`},
	} {
		_, stderr, code := runMain(t, c.args...)
		if code != 1 || !strings.Contains(stderr, c.want) {
			t.Errorf("%q: exit %d, want 1 with %q:\n%s", c.args, code, c.want, stderr)
		}
	}
}

// A dry run with a static prefix needs no upstream: it reports the prefix and, at the deadline, the counters.
func TestMainDryRunDeadline(t *testing.T) {
	stdout, stderr, code := runMain(t, "-dry-run", "-wan", "sixup-none0", "-dry-run-timeout", "500ms", "-settle", "10ms", "-state-dir", t.TempDir(),
		"-dhcp6c-mode", "off", "-wan-ra=false", "-wan-prefix", "2001:db8:1::/48", "-ula", "auto", "-nat64", "jool", "-ra-slaac=false")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	for _, want := range []string{"-ra-slaac off without -dhcp6s-mode stateful", "parameters changed (initial parameters)", "deadline reached", "packet counters:", "hint: "} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if !strings.Contains(stdout, `"prefix": "2001:db8:1::/48"`) || !strings.Contains(stdout, `"lan": [`) {
		t.Errorf("report lacks the static prefix or its LAN split:\n%s", stdout)
	}
}

// An interrupted dry run prints the final report too, after the DHCPv6 client has let go.
func TestMainDryRunInterrupt(t *testing.T) {
	cmd, stdout, _ := mainCmd(t, "-dry-run", "-wan", "sixup-none0", "-state-dir", t.TempDir(), "-log-level", "info",
		"-wan-ra=false", "-wan-prefix", "2001:db8:2::/64")
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	kill := time.AfterFunc(10*time.Second, func() { cmd.Process.Kill() })
	defer kill.Stop()
	var stderr strings.Builder
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		stderr.WriteString(sc.Text() + "\n")
		if strings.Contains(sc.Text(), "initial parameters") {
			cmd.Process.Signal(syscall.SIGINT)
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%v:\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "interrupted, printing the final parameters") || strings.Contains(stderr.String(), " DEBUG ") {
		t.Errorf("stderr:\n%s", stderr.String())
	}
	if strings.Count(stdout.String(), `"prefix": "2001:db8:2::/64"`) != 2 {
		t.Errorf("want the prefix in the initial and the final report:\n%s", stdout)
	}
}
