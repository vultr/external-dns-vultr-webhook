package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Run the real entrypoint in a subprocess so listener startup, environment
// parsing, route wiring, and signal handling are exercised together.
func TestWebhookProcess(t *testing.T) {
	if os.Getenv("WEBHOOK_TEST_PROCESS") == "1" {
		main()
		return
	}
	freePort := func() string {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, err := net.SplitHostPort(l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		return port
	}
	webhookPort, healthPort := freePort(), freePort()
	for healthPort == webhookPort {
		healthPort = freePort()
	}
	for name, value := range map[string]string{
		"WEBHOOK_TEST_PROCESS": "1", "VULTR_API_KEY": "test-only-no-network",
		"WEBHOOK_HOST": "127.0.0.1", "WEBHOOK_PORT": webhookPort,
		"HEALTH_HOST": "127.0.0.1", "HEALTH_PORT": healthPort,
		"DOMAIN_FILTER": "example.com", "EXCLUDE_DOMAIN_FILTER": "",
		"REGEXP_DOMAIN_FILTER": "", "REGEXP_DOMAIN_FILTER_EXCLUSION": "", "DRY_RUN": "false",
		"READ_TIMEOUT": "1000", "WRITE_TIMEOUT": "1000", "READ_HEADER_TIMEOUT": "1000", "IDLE_TIMEOUT": "1000", "MAX_BODY_SIZE": "128",
	} {
		t.Setenv(name, value)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestWebhookProcess$")
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		// Wait before accessing the buffer written by the subprocess copier.
		<-done
		if t.Failed() {
			t.Log(output.String())
		}
	})
	client := &http.Client{Timeout: time.Second}
	ready := "http://127.0.0.1:" + healthPort + "/ready"
	for {
		response, err := client.Get(ready)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		if ctx.Err() != nil {
			t.Fatal("server never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, tt := range []struct {
		port, method, path, body string
		status                   int
	}{
		{healthPort, "GET", "/health", "", 200},
		{healthPort, "GET", "/ready", "", 200},
		{healthPort, "GET", "/", "", 200},
		{webhookPort, "GET", "/", "", 200},
		{webhookPort, "POST", "/records", "{}", 204},
		{webhookPort, "POST", "/records", "{", 400},
		{webhookPort, "POST", "/records", `{"create":[{"dnsName":"` + strings.Repeat("a", 200) + `"}]}`, 413},
		{webhookPort, "POST", "/adjustendpoints", `[{"dnsName":"APP.Example.COM.","recordType":"cname","targets":["Target.Example.NET."]}]`, 200},
	} {
		req, err := http.NewRequestWithContext(ctx, tt.method, "http://127.0.0.1:"+tt.port+tt.path, strings.NewReader(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != tt.status {
			t.Fatalf("%s %s: status=%d body=%s err=%v", tt.method, tt.path, response.StatusCode, body, err)
		}
		if tt.path == "/adjustendpoints" && (!bytes.Contains(body, []byte("app.example.com")) || !bytes.Contains(body, []byte("target.example.net"))) {
			t.Fatalf("incorrect adjustment response: %s", body)
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		done <- err // Leave the result available for cleanup.
		if err != nil {
			t.Fatalf("shutdown failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("process did not exit after SIGTERM")
	}
}
