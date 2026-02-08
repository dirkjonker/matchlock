//go:build acceptance

package acceptance

import (
	"strings"
	"testing"
	"time"
)

func TestCLIRunHelpShowsDNSServersFlag(t *testing.T) {
	stdout, _, exitCode := runCLI(t, "run", "--help")
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout, "--dns-servers") {
		t.Errorf("run --help should mention --dns-servers flag, got: %s", stdout)
	}
}

func TestCLIDNSServersResolvConf(t *testing.T) {
	stdout, _, exitCode := runCLIWithTimeout(t, 2*time.Minute,
		"run", "--image", "alpine:latest",
		"--dns-servers", "1.1.1.1,1.0.0.1",
		"cat", "/etc/resolv.conf",
	)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout, "1.1.1.1") {
		t.Errorf("resolv.conf should contain 1.1.1.1, got: %s", stdout)
	}
	if !strings.Contains(stdout, "1.0.0.1") {
		t.Errorf("resolv.conf should contain 1.0.0.1, got: %s", stdout)
	}
}

func TestCLIDNSServersDefaultResolvConf(t *testing.T) {
	stdout, _, exitCode := runCLIWithTimeout(t, 2*time.Minute,
		"run", "--image", "alpine:latest",
		"cat", "/etc/resolv.conf",
	)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout, "8.8.8.8") {
		t.Errorf("default resolv.conf should contain 8.8.8.8, got: %s", stdout)
	}
	if !strings.Contains(stdout, "8.8.4.4") {
		t.Errorf("default resolv.conf should contain 8.8.4.4, got: %s", stdout)
	}
}

func TestCLIAllowedHostHTTP(t *testing.T) {
	stdout, _, exitCode := runCLIWithTimeout(t, 2*time.Minute,
		"run", "--image", "alpine:latest",
		"--allow-host", "example.com",
		"--", "sh", "-c", "wget -q -O - http://example.com/ 2>&1",
	)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Errorf("expected 'Example Domain' in response, got: %s", stdout)
	}
}

func TestCLIBlockedHostHTTP(t *testing.T) {
	stdout, stderr, _ := runCLIWithTimeout(t, 2*time.Minute,
		"run", "--image", "alpine:latest",
		"--allow-host", "httpbin.org",
		"--", "sh", "-c", "wget -q -T 5 -O - http://example.com/ 2>&1 || echo BLOCKED",
	)
	combined := stdout + stderr
	if strings.Contains(combined, "Example Domain") {
		t.Errorf("expected request to example.com to be blocked, got: %s", combined)
	}
}

func TestCLIPassthroughAllowed(t *testing.T) {
	stdout, _, exitCode := runCLIWithTimeout(t, 2*time.Minute,
		"run", "--image", "alpine:latest",
		"--allow-host", "httpbin.org",
		"--", "sh", "-c", "wget -q -O - https://httpbin.org/get 2>&1",
	)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, `"url"`) {
		t.Errorf("expected request to succeed, got: %s", stdout)
	}
}

func TestCLIPassthroughBlocked(t *testing.T) {
	stdout, stderr, _ := runCLIWithTimeout(t, 2*time.Minute,
		"run", "--image", "alpine:latest",
		"--allow-host", "example.com",
		"--", "sh", "-c", "wget -q -T 5 -O - https://httpbin.org/get 2>&1 || echo BLOCKED",
	)
	combined := stdout + stderr
	if strings.Contains(combined, `"url"`) {
		t.Errorf("expected request to httpbin.org to be blocked, got: %s", combined)
	}
}
