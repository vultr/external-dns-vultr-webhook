package vultr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	govultr "github.com/vultr/govultr/v3"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider/webhook/api"
)

func providerWithHTTPAPI(t *testing.T, handler http.HandlerFunc) *VultrProvider {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	client := govultr.NewClient(s.Client())
	if err := client.SetBaseURL(s.URL); err != nil {
		t.Fatal(err)
	}
	return &VultrProvider{domains: client.Domain, records: client.DomainRecord, domainFilter: endpoint.NewDomainFilter([]string{"example.com"})}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}

// Exercise both protocol boundaries: ExternalDNS JSON -> webhook -> govultr HTTP,
// and Vultr JSON -> govultr -> webhook JSON. Fixtures deliberately contain API
// sentinels and noncanonical values rather than only the values we would write.
func TestWebhookRecordLifecycle(t *testing.T) {
	fixtures := []struct {
		name, record, target, replacement string
	}{
		{"A", `{"id":"old","type":"A","name":"app","data":"192.0.2.1","priority":-1,"ttl":300}`, "192.0.2.1", "192.0.2.2"},
		{"AAAA", `{"id":"old","type":"AAAA","name":"app","data":"2001:0DB8:0000:0000:0000:0000:0000:0001","priority":-1,"ttl":300}`, "2001:db8::1", "2001:db8::2"},
		{"CNAME", `{"id":"old","type":"CNAME","name":"app","data":"Old.Example.NET.","priority":-1,"ttl":300}`, "old.example.net", "new.example.net"},
		{"TXT", `{"id":"old","type":"TXT","name":"app","data":"\"heritage=external-dns,external-dns/owner=test\"","priority":-1,"ttl":300}`, `"heritage=external-dns,external-dns/owner=test"`, "preserve  spaces and CASE"},
		{"NS", `{"id":"old","type":"NS","name":"app","data":"NS1.Example.NET.","priority":-1,"ttl":300}`, "ns1.example.net", "ns2.example.net"},
		{"MX", `{"id":"old","type":"MX","name":"app","data":"Mail.Example.NET.","priority":10,"ttl":300}`, "10 mail.example.net", "20 mail.example.net"},
		{"SRV", `{"id":"old","type":"SRV","name":"app","data":"20 443 Service.Example.NET.","priority":10,"ttl":300}`, "10 20 443 service.example.net.", "20 20 443 service.example.net."},
		{"apex", `{"id":"old","type":"A","name":"example.com","data":"192.0.2.1","priority":-1,"ttl":300}`, "192.0.2.1", "192.0.2.2"},
		{"absolute-name", `{"id":"old","type":"A","name":"App.Example.COM.","data":"192.0.2.1","priority":-1,"ttl":300}`, "192.0.2.1", "192.0.2.2"},
		{"null-MX", `{"id":"old","type":"MX","name":"app","data":".","priority":0,"ttl":300}`, "0 .", "10 mail.example.net"},
		{"unavailable-SRV", `{"id":"old","type":"SRV","name":"app","data":"0 0 .","priority":0,"ttl":300}`, "0 0 0 .", "10 20 443 service.example.net."},
	}
	for _, tt := range fixtures {
		t.Run(tt.name, func(t *testing.T) {
			var initial govultr.DomainRecord
			if err := json.Unmarshal([]byte(tt.record), &initial); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			records := []govultr.DomainRecord{initial}
			nextID := 0
			p := providerWithHTTPAPI(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case r.URL.Path == "/v2/domains" && r.Method == http.MethodGet:
					writeJSON(t, w, map[string]any{"domains": []map[string]string{{"domain": "example.com"}}})
				case r.URL.Path == "/v2/domains/example.com/records" && r.Method == http.MethodGet:
					writeJSON(t, w, map[string]any{"records": records})
				case r.URL.Path == "/v2/domains/example.com/records" && r.Method == http.MethodPost:
					var req govultr.DomainRecordCreateReq
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					priority := -1
					if req.Priority != nil {
						priority = *req.Priority
					}
					if (req.Type == "MX" || req.Type == "SRV") != (req.Priority != nil) {
						t.Errorf("unexpected priority in request: %+v", req)
					}
					nextID++
					data := req.Data
					// The live API adds quotes to unquoted TXT submissions. Model
					// that response independently of provider normalization.
					if req.Type == "TXT" && !strings.HasPrefix(data, `"`) {
						data = `"` + data + `"`
					}
					record := govultr.DomainRecord{ID: fmt.Sprint(nextID), Name: req.Name, Type: req.Type, Data: data, Priority: priority, TTL: req.TTL}
					records = append(records, record)
					writeJSON(t, w, map[string]any{"record": record})
				case strings.HasPrefix(r.URL.Path, "/v2/domains/example.com/records/") && r.Method == http.MethodDelete:
					id := strings.TrimPrefix(r.URL.Path, "/v2/domains/example.com/records/")
					for i, record := range records {
						if record.ID == id {
							records = append(records[:i], records[i+1:]...)
							w.WriteHeader(http.StatusNoContent)
							return
						}
					}
					http.Error(w, "unknown record", http.StatusNotFound)
				default:
					t.Errorf("unexpected API request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			webhook := &api.WebhookServer{Provider: p, MaxBodySize: 1048576}
			call := func(handler http.HandlerFunc, method string, body any, status int) *httptest.ResponseRecorder {
				t.Helper()
				data, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest(method, "/", bytes.NewReader(data)))
				if w.Code != status {
					t.Fatalf("webhook status=%d, want %d: %s", w.Code, status, w.Body)
				}
				return w
			}
			list := func() []*endpoint.Endpoint {
				t.Helper()
				w := call(webhook.RecordsHandler, http.MethodGet, nil, http.StatusOK)
				if w.Header().Get("Content-Type") != api.MediaTypeFormatAndVersion {
					t.Fatal("missing webhook media type")
				}
				var eps []*endpoint.Endpoint
				if err := json.Unmarshal(w.Body.Bytes(), &eps); err != nil {
					t.Fatal(err)
				}
				return eps
			}
			old := list()
			if len(old) != 1 || !reflect.DeepEqual(old[0].Targets, endpoint.Targets{tt.target}) {
				t.Fatalf("unexpected initial endpoints: %+v", old)
			}
			name := "app.example.com"
			if tt.name == "apex" {
				name = "example.com"
			}
			if old[0].DNSName != name || old[0].RecordTTL != 300 {
				t.Fatalf("unexpected initial endpoint: %+v", old[0])
			}
			want := []*endpoint.Endpoint{endpoint.NewEndpointWithTTL(name, initial.Type, 600, tt.replacement)}
			adjusted := call(webhook.AdjustEndpointsHandler, http.MethodPost, want, http.StatusOK)
			want = nil
			if err := json.Unmarshal(adjusted.Body.Bytes(), &want); err != nil {
				t.Fatal(err)
			}
			call(webhook.RecordsHandler, http.MethodPost, &plan.Changes{UpdateOld: old, UpdateNew: want}, http.StatusNoContent)
			if got := list(); !reflect.DeepEqual(got, want) {
				t.Fatalf("update did not converge: got %+v, want %+v", got, want)
			}
			call(webhook.RecordsHandler, http.MethodPost, &plan.Changes{Delete: want}, http.StatusNoContent)
			if got := list(); len(got) != 0 {
				t.Fatalf("delete left records: %+v", got)
			}
			call(webhook.RecordsHandler, http.MethodPost, &plan.Changes{Create: want}, http.StatusNoContent)
			if got := list(); !reflect.DeepEqual(got, want) {
				t.Fatalf("create did not converge: got %+v, want %+v", got, want)
			}
		})
	}
}

func TestAPIPagination(t *testing.T) {
	for _, repeated := range []bool{false, true} {
		t.Run(fmt.Sprintf("repeated=%t", repeated), func(t *testing.T) {
			p := providerWithHTTPAPI(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("per_page") != "500" {
					t.Error("missing page size")
				}
				next := ""
				if r.URL.Query().Get("cursor") == "" || repeated {
					next = "second-page"
				}
				meta := map[string]any{"links": map[string]string{"next": next}}
				if r.URL.Path == "/v2/domains" {
					zone := "example.com"
					if r.URL.Query().Get("cursor") == "" {
						zone = "excluded.net"
					}
					writeJSON(t, w, map[string]any{"domains": []map[string]string{{"domain": zone}}, "meta": meta})
				} else {
					data := "192.0.2.1"
					if r.URL.Query().Get("cursor") != "" {
						data = "192.0.2.2"
					}
					writeJSON(t, w, map[string]any{"records": []govultr.DomainRecord{{Type: "A", Name: "app", Data: data, TTL: 300, Priority: -1}}, "meta": meta})
				}
			})
			eps, err := p.Records(context.Background())
			if repeated {
				if err == nil || !strings.Contains(err.Error(), "repeated cursor") {
					t.Fatalf("expected pagination error, got %v", err)
				}
				// Also exercise record pagination independently of zone pagination.
				if _, err := p.fetchRecords(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "repeated cursor") {
					t.Fatalf("expected record pagination error, got %v", err)
				}
				return
			}
			if err != nil || len(eps) != 1 || !reflect.DeepEqual(eps[0].Targets, endpoint.Targets{"192.0.2.1", "192.0.2.2"}) {
				t.Fatalf("pagination/aggregation failed: endpoints=%+v, err=%v", eps, err)
			}
		})
	}
}

func TestAPIErrorsAndCancellation(t *testing.T) {
	for _, operation := range []string{"zones", "records", "create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			p := providerWithHTTPAPI(t, func(w http.ResponseWriter, r *http.Request) {
				fail := operation == "zones" && r.URL.Path == "/v2/domains" ||
					operation == "records" && strings.HasSuffix(r.URL.Path, "/records") && r.Method == http.MethodGet ||
					operation == "create" && r.Method == http.MethodPost ||
					operation == "delete" && r.Method == http.MethodDelete
				if fail {
					w.WriteHeader(http.StatusForbidden)
					writeJSON(t, w, map[string]any{"error": "permission denied", "status": 403})
					return
				}
				if r.URL.Path == "/v2/domains" {
					writeJSON(t, w, map[string]any{"domains": []map[string]string{{"domain": "example.com"}}})
				} else if r.Method == http.MethodGet {
					writeJSON(t, w, map[string]any{"records": []govultr.DomainRecord{{ID: "old", Type: "A", Name: "app", Data: "192.0.2.1", Priority: -1, TTL: 300}}})
				} else {
					t.Errorf("unexpected write after failed operation: %s", r.Method)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			var err error
			if operation == "zones" || operation == "records" {
				_, err = p.Records(context.Background())
			} else {
				ep := endpoint.NewEndpoint("app.example.com", "A", "192.0.2.1")
				changes := &plan.Changes{Create: []*endpoint.Endpoint{ep}}
				if operation == "delete" {
					changes = &plan.Changes{UpdateOld: []*endpoint.Endpoint{ep}, UpdateNew: []*endpoint.Endpoint{endpoint.NewEndpoint("app.example.com", "A", "192.0.2.2")}}
				}
				err = p.ApplyChanges(context.Background(), changes)
			}
			if err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("lost API failure: %v", err)
			}
			if operation != "zones" && !strings.Contains(err.Error(), "example.com") {
				t.Fatalf("error lacks zone context: %v", err)
			}
			webhook := api.WebhookServer{Provider: p}
			if operation == "zones" || operation == "records" {
				w := httptest.NewRecorder()
				webhook.RecordsHandler(w, httptest.NewRequest(http.MethodGet, "/records", nil))
				if w.Code != http.StatusInternalServerError {
					t.Fatalf("API failure reported as status %d", w.Code)
				}
			}
		})
	}
	p := providerWithHTTPAPI(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("canceled operation reached API")
		w.WriteHeader(http.StatusBadRequest)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Records(ctx); err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
	if err := p.ApplyChanges(ctx, &plan.Changes{Create: []*endpoint.Endpoint{endpoint.NewEndpoint("app.example.com", "A", "192.0.2.1")}}); err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("write cancellation not propagated: %v", err)
	}
}
