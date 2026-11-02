package vultr

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	govultr "github.com/vultr/govultr/v3"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

type fakeDomains struct {
	zones []govultr.Domain
}

func (f *fakeDomains) List(context.Context, *govultr.ListOptions) ([]govultr.Domain, *govultr.Meta, *http.Response, error) {
	return f.zones, nil, nil, nil
}

type fakeRecords struct {
	byZone  map[string][]govultr.DomainRecord
	created []*govultr.DomainRecordCreateReq
	deleted []string
	lists   int
}

func (f *fakeRecords) Create(_ context.Context, _ string, record *govultr.DomainRecordCreateReq) (*govultr.DomainRecord, *http.Response, error) {
	copy := *record
	f.created = append(f.created, &copy)
	return &govultr.DomainRecord{}, nil, nil
}

func (f *fakeRecords) Delete(_ context.Context, _ string, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeRecords) List(_ context.Context, zone string, _ *govultr.ListOptions) ([]govultr.DomainRecord, *govultr.Meta, *http.Response, error) {
	f.lists++
	return f.byZone[zone], nil, nil, nil
}

func testProvider(records *fakeRecords) *VultrProvider {
	filter := endpoint.NewDomainFilter([]string{"example.com"})
	return &VultrProvider{
		domains:      &fakeDomains{zones: []govultr.Domain{{Domain: "example.com"}}},
		records:      records,
		domainFilter: filter,
	}
}

func TestRecordsSupportsVultrRecordTypes(t *testing.T) {
	records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{"example.com": {
		{ID: "1", Type: "A", Name: "www", Data: "192.0.2.1", TTL: 300},
		{ID: "2", Type: "A", Name: "www", Data: "192.0.2.2", TTL: 300},
		{ID: "3", Type: "AAAA", Name: "example.com", Data: "2001:db8::1", TTL: 300},
		{ID: "4", Type: "CNAME", Name: "app", Data: "Target.Example.COM.", TTL: 600},
		{ID: "5", Type: "MX", Name: "", Data: "Mail.Example.COM.", Priority: 10, TTL: 600},
		{ID: "6", Type: "SRV", Name: "_https._tcp", Data: "20 443 Service.Example.COM.", Priority: 5, TTL: 600},
		{ID: "7", Type: "CAA", Name: "", Data: `0 issue "letsencrypt.org"`, TTL: 600},
		{ID: "8", Type: "SSHFP", Name: "host", Data: "1 1 abcdef", TTL: 600},
		{ID: "9", Type: "TXT", Name: "txt", Data: "value with spaces", TTL: 600},
		{ID: "10", Type: "NS", Name: "delegated", Data: "NS1.Example.NET.", TTL: 600},
		{ID: "11", Type: "DNAME", Name: "ignored", Data: "example.net", TTL: 600},
	}}}

	got, err := testProvider(records).Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("_https._tcp.example.com", "SRV", 600, "5 20 443 service.example.com."),
		endpoint.NewEndpointWithTTL("app.example.com", "CNAME", 600, "target.example.com"),
		endpoint.NewEndpointWithTTL("delegated.example.com", "NS", 600, "ns1.example.net"),
		endpoint.NewEndpointWithTTL("example.com", "AAAA", 300, "2001:db8::1"),
		endpoint.NewEndpointWithTTL("example.com", "MX", 600, "10 mail.example.com"),
		endpoint.NewEndpointWithTTL("txt.example.com", "TXT", 600, `"value with spaces"`),
		endpoint.NewEndpointWithTTL("www.example.com", "A", 300, "192.0.2.1", "192.0.2.2"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Records() mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestApplyChangesUsesRelativeNamesAndPriority(t *testing.T) {
	records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{}}
	p := testProvider(records)
	changes := &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("app.example.com.", "CNAME", 120, "Target.Example.NET."),
		endpoint.NewEndpointWithTTL("example.com", "MX", 300, "10 Mail.Example.COM."),
		endpoint.NewEndpointWithTTL("_https._tcp.example.com", "SRV", 300, "5 20 443 Service.Example.COM."),
	}}

	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatal(err)
	}
	if len(records.created) != 3 {
		t.Fatalf("created %d records, want 3", len(records.created))
	}
	want := []govultr.DomainRecordCreateReq{
		{Name: "app", Type: "CNAME", Data: "target.example.net", TTL: 120},
		{Name: "", Type: "MX", Data: "mail.example.com", TTL: 300, Priority: intPtr(10)},
		{Name: "_https._tcp", Type: "SRV", Data: "20 443 service.example.com", TTL: 300, Priority: intPtr(5)},
	}
	for i := range want {
		if !reflect.DeepEqual(*records.created[i], want[i]) {
			t.Errorf("created[%d] = %#v, want %#v", i, *records.created[i], want[i])
		}
	}
}

func TestApplyChangesDryRunValidatesWithoutMutating(t *testing.T) {
	records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{"example.com": {
		{ID: "record-id", Type: "CNAME", Name: "app", Data: "target.example.net", TTL: 300},
	}}}
	p := testProvider(records)
	p.DryRun = true
	changes := &plan.Changes{Delete: []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("app.example.com", "CNAME", 300, "target.example.net"),
	}}

	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatal(err)
	}
	if len(records.created) != 0 || len(records.deleted) != 0 {
		t.Fatalf("dry run mutated records: created=%d deleted=%d", len(records.created), len(records.deleted))
	}
	if records.lists != 1 {
		t.Fatalf("dry run listed records %d times, want 1 validation pass", records.lists)
	}
}

func TestApplyChangesListsZoneOnceForMultipleDeletes(t *testing.T) {
	records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{"example.com": {
		{ID: "one", Type: "A", Name: "www", Data: "192.0.2.1"},
		{ID: "two", Type: "A", Name: "www", Data: "192.0.2.2"},
	}}}
	p := testProvider(records)
	changes := &plan.Changes{Delete: []*endpoint.Endpoint{
		endpoint.NewEndpointWithTTL("www.example.com", "A", 300, "192.0.2.1", "192.0.2.2"),
	}}

	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatal(err)
	}
	if records.lists != 1 {
		t.Fatalf("listed records %d times, want once", records.lists)
	}
	if !reflect.DeepEqual(records.deleted, []string{"one", "two"}) {
		t.Fatalf("deleted IDs = %v", records.deleted)
	}
}

func TestApplyChangesMatchesRecordPriority(t *testing.T) {
	tests := []struct {
		recordType, data, oldTarget, newTarget string
	}{
		{"A", "192.0.2.1", "192.0.2.1", "192.0.2.2"},
		{"AAAA", "2001:db8::1", "2001:db8::1", "2001:db8::2"},
		{"CNAME", "old.example.net", "old.example.net", "new.example.net"},
		{"TXT", "old value", `"old value"`, `"new value"`},
		{"NS", "ns1.example.net", "ns1.example.net", "ns2.example.net"},
		{"MX", "mail.example.net", "10 mail.example.net", "20 mail.example.net"},
		{"SRV", "20 443 service.example.net", "10 20 443 service.example.net.", "20 20 443 service.example.net."},
	}
	for _, tt := range tests {
		priorities := []int{-1, 0}
		usesPriority := tt.recordType == "MX" || tt.recordType == "SRV"
		if usesPriority {
			priorities = []int{10}
		}
		for _, priority := range priorities {
			for _, update := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/priority=%d/update=%t", tt.recordType, priority, update), func(t *testing.T) {
					records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{"example.com": {
						{ID: "old", Type: tt.recordType, Name: "app", Data: tt.data, Priority: priority},
					}}}
					if usesPriority {
						// Same name/type/data, different priority: this record must survive.
						records.byZone["example.com"] = append([]govultr.DomainRecord{
							{ID: "other", Type: tt.recordType, Name: "app", Data: tt.data, Priority: 30},
						}, records.byZone["example.com"]...)
					}
					old := endpoint.NewEndpointWithTTL("app.example.com", tt.recordType, 300, tt.oldTarget)
					changes := &plan.Changes{Delete: []*endpoint.Endpoint{old}}
					if update {
						changes = &plan.Changes{
							UpdateOld: []*endpoint.Endpoint{old},
							UpdateNew: []*endpoint.Endpoint{endpoint.NewEndpointWithTTL("app.example.com", tt.recordType, 300, tt.newTarget)},
						}
					}
					if err := testProvider(records).ApplyChanges(context.Background(), changes); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(records.deleted, []string{"old"}) {
						t.Fatalf("deleted IDs = %v, want [old]", records.deleted)
					}
					if update {
						if len(records.created) != 1 {
							t.Fatalf("created %d records, want 1", len(records.created))
						}
						created := records.created[0]
						p := 0
						if created.Priority != nil {
							p = *created.Priority
						}
						target, err := externalDNSTarget(govultr.DomainRecord{Type: created.Type, Data: created.Data, Priority: p})
						if err != nil || target != tt.newTarget || created.Name != "app" || created.Type != tt.recordType {
							t.Fatalf("unexpected created record: %#v, target=%q, err=%v", created, target, err)
						}
					} else if len(records.created) != 0 {
						t.Fatal("delete created records")
					}
				})
			}
		}
	}
}

func TestApplyChangesRejectsInvalidRecordsBeforeAPIWrites(t *testing.T) {
	tests := []struct {
		name string
		ep   *endpoint.Endpoint
		want string
	}{
		{"unsupported", endpoint.NewEndpoint("bad.example.com", "DNAME", "example.net"), "unsupported DNS record type"},
		{"multiple CNAME targets", endpoint.NewEndpoint("bad.example.com", "CNAME", "one.example.net", "two.example.net"), "exactly one target"},
		{"invalid MX", endpoint.NewEndpoint("bad.example.com", "MX", "mail.example.net"), "expected 'priority hostname'"},
		{"invalid SRV", endpoint.NewEndpoint("bad.example.com", "SRV", "high 10 443 app.example.net"), "priority"},
		{"invalid A", endpoint.NewEndpoint("bad.example.com", "A", "not-an-address"), "IPv4"},
		{"invalid AAAA", endpoint.NewEndpoint("bad.example.com", "AAAA", "192.0.2.1"), "IPv6"},
		{"unsupported CAA", endpoint.NewEndpoint("bad.example.com", "CAA", `0 issue "letsencrypt.org"`), "unsupported DNS record type"},
		{"unsupported SSHFP", endpoint.NewEndpoint("bad.example.com", "SSHFP", "1 1 abcdef"), "unsupported DNS record type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{}}
			err := testProvider(records).ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{tt.ep}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
			if len(records.created) != 0 {
				t.Fatal("invalid change performed an API write")
			}
		})
	}
}

func TestApplyChangesRejectsUnknownZone(t *testing.T) {
	records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{}}
	err := testProvider(records).ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint("www.other.test", "A", "192.0.2.1"),
	}})
	if err == nil || !strings.Contains(err.Error(), "no managed Vultr zone") {
		t.Fatalf("error = %v", err)
	}
}

func TestUnsupportedTypesRejectAllChanges(t *testing.T) {
	for _, recordType := range []string{"CAA", "SSHFP", "caa", "sshfp"} {
		t.Run(recordType, func(t *testing.T) {
			records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{}}
			p := testProvider(records)
			unsupported := []*endpoint.Endpoint{endpoint.NewEndpoint("app.example.com", recordType, "unsupported")}
			if _, err := p.AdjustEndpoints(unsupported); err == nil || !strings.Contains(err.Error(), "unsupported DNS record type") {
				t.Fatalf("AdjustEndpoints accepted unsupported type: %v", err)
			}
			for _, changes := range []*plan.Changes{
				{Create: unsupported}, {Delete: unsupported},
				{UpdateOld: unsupported}, {UpdateNew: unsupported},
			} {
				// Even a valid change in the same batch must not be written.
				changes.Create = append(changes.Create, endpoint.NewEndpoint("valid.example.com", "A", "192.0.2.1"))
				if err := p.ApplyChanges(context.Background(), changes); err == nil || !strings.Contains(err.Error(), "unsupported DNS record type") {
					t.Fatalf("ApplyChanges accepted unsupported type: %v", err)
				}
			}
			if len(records.created) != 0 || len(records.deleted) != 0 || records.lists != 0 {
				t.Fatal("unsupported changes reached the record API")
			}
		})
	}
}

func TestApplyChangesValidatesDeletesBeforeWrites(t *testing.T) {
	records := &fakeRecords{byZone: map[string][]govultr.DomainRecord{"example.com": {}}}
	err := testProvider(records).ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{endpoint.NewEndpoint("new.example.com", "A", "192.0.2.1")},
		Delete: []*endpoint.Endpoint{endpoint.NewEndpoint("missing.example.com", "A", "192.0.2.2")},
	})
	if err == nil || !strings.Contains(err.Error(), "matching record not found") {
		t.Fatalf("error = %v", err)
	}
	if len(records.created) != 0 || len(records.deleted) != 0 {
		t.Fatal("invalid plan performed an API write")
	}
}

func TestGetDomainFilterRejectsInvalidRegex(t *testing.T) {
	_, err := GetDomainFilter(Configuration{RegexDomainFilter: "["})
	if err == nil || !strings.Contains(err.Error(), "REGEXP_DOMAIN_FILTER") {
		t.Fatalf("error = %v", err)
	}
}

func TestCanonicalTargetPreservesRootHostname(t *testing.T) {
	got, err := canonicalTarget("MX", "0 .")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0 ." {
		t.Fatalf("canonicalTarget() = %q", got)
	}
}

func intPtr(value int) *int {
	return &value
}
