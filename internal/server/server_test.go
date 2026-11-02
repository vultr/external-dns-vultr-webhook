package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/codingconcepts/env"
)

func TestServerEnvironment(t *testing.T) {
	for _, name := range []string{"WEBHOOK_HOST", "WEBHOOK_PORT", "HEALTH_HOST", "HEALTH_PORT", "READ_TIMEOUT", "WRITE_TIMEOUT", "READ_HEADER_TIMEOUT", "IDLE_TIMEOUT", "MAX_BODY_SIZE"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	var options ServerOptions
	if err := env.Set(&options); err != nil {
		t.Fatal(err)
	}
	if options.GetWebhookAddress() != "localhost:8888" || options.GetHealthAddress() != "0.0.0.0:8080" || options.GetReadTimeout() != time.Minute || options.GetWriteTimeout() != time.Minute || options.GetReadHeaderTimeout() != 5*time.Second || options.GetIdleTimeout() != time.Minute || options.MaxBodySize != 1048576 {
		t.Fatalf("incorrect defaults: %+v", options)
	}
	t.Setenv("WEBHOOK_HOST", "::1")
	t.Setenv("HEALTH_HOST", "::")
	t.Setenv("WEBHOOK_PORT", "1234")
	t.Setenv("HEALTH_PORT", "1235")
	t.Setenv("READ_TIMEOUT", "125")
	t.Setenv("WRITE_TIMEOUT", "250")
	t.Setenv("READ_HEADER_TIMEOUT", "50")
	t.Setenv("IDLE_TIMEOUT", "500")
	t.Setenv("MAX_BODY_SIZE", "4096")
	if err := env.Set(&options); err != nil {
		t.Fatal(err)
	}
	if options.GetWebhookAddress() != "[::1]:1234" || options.GetHealthAddress() != "[::]:1235" || options.GetReadTimeout() != 125*time.Millisecond || options.GetWriteTimeout() != 250*time.Millisecond || options.GetReadHeaderTimeout() != 50*time.Millisecond || options.GetIdleTimeout() != 500*time.Millisecond || options.MaxBodySize != 4096 {
		t.Fatalf("incorrect overrides: %+v", options)
	}
	t.Setenv("WEBHOOK_PORT", "65536")
	if err := env.Set(&options); err != nil {
		t.Fatal(err)
	}
	if err := options.Validate(); err == nil {
		t.Fatal("accepted invalid port")
	}
	options.WebhookPort = 8888
	if err := options.Validate(); err != nil {
		t.Fatal(err)
	}
	options.ReadTimeout = -1
	if err := options.Validate(); err == nil {
		t.Fatal("accepted negative timeout")
	}
}

func TestHealthHandlers(t *testing.T) {
	status := &HealthStatus{}
	s := HealthServer{status: status}
	for _, healthy := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			status.SetHealth(healthy)
			status.SetReady(ready)
			for _, tt := range []struct {
				handler http.HandlerFunc
				ok      bool
			}{{s.livenessHandler, healthy}, {s.readinessHandler, ready}} {
				w := httptest.NewRecorder()
				tt.handler(w, httptest.NewRequest(http.MethodGet, "/", nil))
				want := http.StatusServiceUnavailable
				if tt.ok {
					want = http.StatusOK
				}
				if w.Code != want || w.Body.String() != http.StatusText(want) {
					t.Fatalf("probe returned %d %q, want %d", w.Code, w.Body, want)
				}
			}
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				status.SetHealth(j%2 == 0)
				status.SetReady(j%2 != 0)
				status.IsHealthy()
				status.IsReady()
			}
		})
	}
	wg.Wait()
}
