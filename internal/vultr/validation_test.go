package vultr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/codingconcepts/env"
	govultr "github.com/vultr/govultr/v3"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider/webhook/api"
)

func TestTargetNormalization(t *testing.T) {
	for _, tt := range []struct{ recordType, input, want string }{
		{"AAAA", "2001:0DB8:0:0:0:0:0:1", "2001:db8::1"},
		{"MX", "0010 MAIL.Example.NET.", "10 mail.example.net"},
		{"MX", "0 .", "0 ."},
		{"SRV", "0010 0020 00443 Service.Example.NET", "10 20 443 service.example.net."},
		{"SRV", "0 0 0 .", "0 0 0 ."},
		{"SSHFP", "01 01 ABCDEF", "1 1 abcdef"},
		{"CAA", `00 IODEF "mailto:test@example.net?subject=two  words"`, `0 iodef "mailto:test@example.net?subject=two  words"`},
		{"TXT", `"keep CASE,  spaces, and dots.."`, `"keep CASE,  spaces, and dots.."`},
		{"TXT", "unquoted  text", `"unquoted  text"`},
		{"TXT", "", `""`},
		{"TXT", `text with "quotes"`, `"text with \034quotes\034"`},
		{"TXT", `"text with \"quotes\""`, `"text with \034quotes\034"`},
		{"TXT", "line\nwith\ttabs", `"line\010with\009tabs"`},
		{"TXT", `path\to\value`, `"path\\to\\value"`},
		{"TXT", `"ends with a slash\\"`, `"ends with a slash\\"`},
	} {
		t.Run(tt.recordType+"/"+tt.input, func(t *testing.T) {
			got, err := canonicalTarget(tt.recordType, tt.input)
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
			p := testProvider(&fakeRecords{})
			ep := &endpoint.Endpoint{DNSName: "APP.Example.COM.", RecordType: strings.ToLower(tt.recordType), Targets: endpoint.Targets{tt.input}}
			adjusted, err := p.AdjustEndpoints([]*endpoint.Endpoint{ep})
			if err != nil || adjusted[0].DNSName != "app.example.com" || adjusted[0].RecordType != tt.recordType || adjusted[0].Targets[0] != tt.want {
				t.Fatalf("adjustment failed: %+v, %v", adjusted, err)
			}
		})
	}
	for _, tt := range []struct{ recordType, target string }{
		{"AAAA", "fe80::1%eth0"}, {"A", "2001:db8::1"}, {"AAAA", "192.0.2.1"},
		{"MX", "65536 mail.example.net"}, {"MX", "-1 mail.example.net"},
		{"SRV", "0 -1 443 service.example.net"}, {"SRV", "0 1 65536 service.example.net"},
		{"CAA", `0 invalid-tag "value"`}, {"SSHFP", "0 1 abcdef"},
	} {
		if _, err := canonicalTarget(tt.recordType, tt.target); err == nil {
			t.Errorf("accepted invalid %s target %q", tt.recordType, tt.target)
		}
	}
}

func TestConfigurationAndFilters(t *testing.T) {
	for _, name := range []string{"VULTR_API_KEY", "DRY_RUN", "DOMAIN_FILTER", "EXCLUDE_DOMAIN_FILTER", "REGEXP_DOMAIN_FILTER", "REGEXP_DOMAIN_FILTER_EXCLUSION"} {
		t.Setenv(name, "")
	}
	var config Configuration
	if err := env.Set(&config); err == nil {
		t.Fatal("missing API key accepted")
	}
	t.Setenv("VULTR_API_KEY", "test-only")
	t.Setenv("DRY_RUN", "true")
	t.Setenv("DOMAIN_FILTER", "example.com,example.net")
	t.Setenv("EXCLUDE_DOMAIN_FILTER", "private.example.com")
	if err := env.Set(&config); err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(&config)
	if err != nil || !p.DryRun {
		t.Fatalf("provider configuration failed: %v", err)
	}
	for _, tt := range []struct {
		config Configuration
		name   string
		match  bool
	}{
		{config, "example.com", true}, {config, "app.example.net", true},
		{config, "private.example.com", false}, {config, "other.net", false},
		{Configuration{}, "any.example.org", true},
		{Configuration{RegexDomainFilter: `\.example\.com$`, RegexDomainExclusion: `^private\.`}, "app.example.com", true},
		{Configuration{RegexDomainFilter: `\.example\.com$`, RegexDomainExclusion: `^private\.`}, "private.example.com", false},
	} {
		filter, err := GetDomainFilter(tt.config)
		if err != nil || filter.Match(tt.name) != tt.match {
			t.Errorf("filter %q: err=%v, want match=%t", tt.name, err, tt.match)
		}
		webhook := api.WebhookServer{Provider: &VultrProvider{domainFilter: filter}}
		w := httptest.NewRecorder()
		webhook.NegotiateHandler(w, httptest.NewRequest(http.MethodGet, "/", nil))
		var advertised endpoint.DomainFilter
		if err := json.Unmarshal(w.Body.Bytes(), &advertised); err != nil || advertised.Match(tt.name) != tt.match {
			t.Errorf("negotiated filter %q changed behavior: %s, %v", tt.name, w.Body, err)
		}
	}
	if _, err := GetDomainFilter(Configuration{RegexDomainFilter: ".*", RegexDomainExclusion: "["}); err == nil {
		t.Fatal("invalid exclusion regex accepted")
	}
}

func TestPlansValidateBeforeWritesAcrossZones(t *testing.T) {
	records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{"example.com": {}, "sub.example.com": {}}}
	p := testProvider(records)
	p.domains = &fakeDomains{zones: []govultr.Domain{{Domain: "example.com"}, {Domain: "sub.example.com"}}}
	err := p.ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{endpoint.NewEndpoint("app.example.com", "A", "192.0.2.1")},
		Delete: []*endpoint.Endpoint{endpoint.NewEndpoint("app.sub.example.com", "A", "192.0.2.2")},
	})
	if err == nil || !strings.Contains(err.Error(), `zone "sub.example.com"`) || len(records.created) != 0 || len(records.deleted) != 0 {
		t.Fatalf("cross-zone preflight failed: %v, %+v", err, records)
	}
	for _, changes := range []*plan.Changes{
		nil,
		{Create: []*endpoint.Endpoint{nil}},
		{Create: []*endpoint.Endpoint{{DNSName: "app.example.com", RecordType: "A"}}},
	} {
		if err := p.ApplyChanges(context.Background(), changes); err == nil {
			t.Errorf("accepted invalid plan: %+v", changes)
		}
	}
	if err := p.ApplyChanges(context.Background(), &plan.Changes{}); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateRecordsAndDryRunUpdate(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{"example.com": {
			{ID: "one", Name: "app", Type: "A", Data: "192.0.2.1", Priority: -1},
			{ID: "two", Name: "app", Type: "A", Data: "192.0.2.1", Priority: -1},
		}}}
		p := testProvider(records)
		p.DryRun = dryRun
		err := p.ApplyChanges(context.Background(), &plan.Changes{
			UpdateOld: []*endpoint.Endpoint{endpoint.NewEndpoint("app.example.com", "A", "192.0.2.1", "192.0.2.1")},
			UpdateNew: []*endpoint.Endpoint{endpoint.NewEndpoint("app.example.com", "A", "192.0.2.2", "192.0.2.3")},
		})
		if err != nil {
			t.Fatal(err)
		}
		if dryRun {
			if len(records.created) != 0 || len(records.deleted) != 0 || records.lists != 1 {
				t.Fatalf("dry run failed: %+v", records)
			}
		} else if !reflect.DeepEqual(records.deleted, []string{"one", "two"}) || len(records.created) != 2 || records.created[0].TTL != vultrTTL {
			t.Fatalf("duplicate record update failed: %+v", records)
		}
	}
}

func TestWebhookRejectsBadRequests(t *testing.T) {
	records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{}}
	webhook := &api.WebhookServer{Provider: testProvider(records), MaxBodySize: 32}
	for _, handler := range []http.HandlerFunc{webhook.RecordsHandler, webhook.AdjustEndpointsHandler} {
		for _, tt := range []struct {
			method, body string
			status       int
		}{
			{http.MethodPost, "{", http.StatusBadRequest},
			{http.MethodPost, `{"create":[{"dnsName":"` + strings.Repeat("a", 100) + `"}]}`, http.StatusRequestEntityTooLarge},
			{http.MethodDelete, "", http.StatusBadRequest},
		} {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest(tt.method, "/", strings.NewReader(tt.body)))
			if w.Code != tt.status {
				t.Errorf("status=%d, want %d", w.Code, tt.status)
			}
		}
	}
	w := httptest.NewRecorder()
	webhook.NegotiateHandler(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != api.MediaTypeFormatAndVersion || !strings.Contains(w.Body.String(), "example.com") {
		t.Fatalf("negotiation failed: %d %s", w.Code, w.Body)
	}
	if len(records.created) != 0 || len(records.deleted) != 0 {
		t.Fatal("invalid webhook request mutated records")
	}
}

func TestZoneRoutingAndRecordReadErrors(t *testing.T) {
	store := &storedRecords{fakeRecords: fakeRecords{byZone: map[string][]govultr.DomainRecord{}}}
	p := testProvider(&store.fakeRecords)
	p.records = store
	p.domains = &fakeDomains{zones: []govultr.Domain{{Domain: "example.com"}, {Domain: "sub.example.com"}}}
	if err := p.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint("example.com", "A", "192.0.2.1"),
		endpoint.NewEndpoint("app.sub.example.com", "A", "192.0.2.2"),
		endpoint.NewEndpoint("*.sub.example.com", "A", "192.0.2.3"),
	}}); err != nil {
		t.Fatal(err)
	}
	parent, child := store.byZone["example.com"], store.byZone["sub.example.com"]
	if len(parent) != 1 || parent[0].Name != "" || len(child) != 2 || child[0].Name != "app" || child[1].Name != "*" {
		t.Fatalf("incorrect zone routing: parent=%+v child=%+v", parent, child)
	}
	for _, tt := range []struct {
		name    string
		records []govultr.DomainRecord
		want    string
	}{
		{"inconsistent TTL", []govultr.DomainRecord{{Name: "app", Type: "A", Data: "192.0.2.1", TTL: 300}, {Name: "app", Type: "A", Data: "192.0.2.2", TTL: 600}}, "inconsistent TTLs"},
		{"invalid data", []govultr.DomainRecord{{Name: "app", Type: "AAAA", Data: "not-an-address"}}, "decode AAAA"},
		{"invalid name", []govultr.DomainRecord{{Name: strings.Repeat("a", 64), Type: "A", Data: "192.0.2.1"}}, "invalid A record name"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := testProvider(&fakeRecords{byZone: map[string][]govultr.DomainRecord{"example.com": tt.records}})
			if _, err := p.Records(context.Background()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("unexpected read result: %v", err)
			}
		})
	}
	for _, ep := range []*endpoint.Endpoint{nil, endpoint.NewEndpoint("app.example.com", "DNAME", "example.net"), endpoint.NewEndpoint("app.example.com", "A", "bad-ip")} {
		if _, err := p.AdjustEndpoints([]*endpoint.Endpoint{ep}); err == nil {
			t.Errorf("adjust accepted invalid endpoint: %+v", ep)
		}
	}
}
