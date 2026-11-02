package vultr

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	govultr "github.com/vultr/govultr/v3"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/pkg/apis/externaldns"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/registry/txt"
)

type storedRecords struct {
	fakeRecords
	sequence int
}

func (s *storedRecords) Create(_ context.Context, zone string, req *govultr.DomainRecordCreateReq) (*govultr.DomainRecord, *http.Response, error) {
	for _, old := range s.byZone[zone] {
		if old.Name == req.Name && (old.Type == "CNAME" || req.Type == "CNAME") {
			return nil, nil, fmt.Errorf("CNAME conflicts with existing record")
		}
	}
	priority := -1
	if req.Priority != nil {
		priority = *req.Priority
	}
	s.sequence++
	r := govultr.DomainRecord{ID: fmt.Sprint(s.sequence), Name: req.Name, Type: req.Type, Data: req.Data, Priority: priority, TTL: req.TTL}
	s.byZone[zone] = append(s.byZone[zone], r)
	return &r, nil, nil
}

func (s *storedRecords) Delete(_ context.Context, zone, id string) error {
	for i, r := range s.byZone[zone] {
		if r.ID == id {
			s.byZone[zone] = append(s.byZone[zone][:i], s.byZone[zone][i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("unknown record ID %s", id)
}

// Use the actual ExternalDNS planner and TXT registry, not hand-constructed
// changes, to verify ownership and convergence over successive reconciliations.
func TestExternalDNSReconciliation(t *testing.T) {
	for _, tt := range []struct {
		recordType string
		old, new   []string
	}{
		{"A", []string{"192.0.2.1", "192.0.2.2"}, []string{"192.0.2.2", "192.0.2.3"}},
		{"AAAA", []string{"2001:db8::1"}, []string{"2001:db8::2"}},
		{"CNAME", []string{"old.example.net"}, []string{"new.example.net"}},
		{"MX", []string{"10 mail.example.net"}, []string{"20 mail.example.net"}},
		{"SRV", []string{"10 20 443 service.example.net."}, []string{"20 20 443 service.example.net."}},
		{"NS", []string{"ns1.example.net"}, []string{"ns2.example.net"}},
		{"TXT", []string{"old text"}, []string{"new text"}},
	} {
		t.Run(tt.recordType, func(t *testing.T) {
			store := &storedRecords{fakeRecords: fakeRecords{byZone: map[string][]govultr.DomainRecord{}}}
			p := testProvider(&store.fakeRecords)
			p.records = store
			managed := []string{tt.recordType}
			registry, err := txt.New(&externaldns.Config{TXTPrefix: "reg-", TXTOwnerID: "test-owner", ManagedDNSRecordTypes: managed}, p)
			if err != nil {
				t.Fatal(err)
			}
			calculate := func(desired []*endpoint.Endpoint) *plan.Changes {
				t.Helper()
				current, err := registry.Records(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				desired, err = registry.AdjustEndpoints(desired)
				if err != nil {
					t.Fatal(err)
				}
				return (&plan.Plan{Current: current, Desired: desired, Policies: []plan.Policy{&plan.SyncPolicy{}}, ManagedRecords: managed, OwnerID: registry.OwnerID()}).Calculate().Changes
			}
			old := []*endpoint.Endpoint{endpoint.NewEndpointWithTTL("app.example.com", tt.recordType, 300, tt.old...)}
			updated := []*endpoint.Endpoint{endpoint.NewEndpointWithTTL("app.example.com", tt.recordType, 600, tt.new...)}
			for i, desired := range [][]*endpoint.Endpoint{old, updated, nil} {
				changes := calculate(desired)
				if !changes.HasChanges() {
					t.Fatalf("stage %d unexpectedly has no changes", i)
				}
				if err := registry.ApplyChanges(context.Background(), changes); err != nil {
					t.Fatalf("stage %d: %v", i, err)
				}
				if changes := calculate(desired); changes.HasChanges() {
					t.Fatalf("stage %d never converged: %+v", i, changes)
				}
				if i < 2 {
					ownershipFound := false
					for _, record := range store.byZone["example.com"] {
						if record.Type == "TXT" && record.Name != "app" {
							ownershipFound = true
						}
					}
					if !ownershipFound {
						t.Fatal("missing TXT ownership record")
					}
				}
			}
			if len(store.byZone["example.com"]) != 0 {
				t.Fatal("delete left data or ownership records behind")
			}
		})
	}
}

func TestRecordTypeTransitions(t *testing.T) {
	store := &storedRecords{fakeRecords: fakeRecords{byZone: map[string][]govultr.DomainRecord{}}}
	p := testProvider(&store.fakeRecords)
	p.records = store
	for _, desired := range []*endpoint.Endpoint{
		endpoint.NewEndpoint("app.example.com", "A", "192.0.2.1"),
		endpoint.NewEndpoint("app.example.com", "CNAME", "target.example.net"),
		endpoint.NewEndpoint("app.example.com", "AAAA", "2001:db8::1"),
	} {
		current, err := p.Records(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		changes := (&plan.Plan{Current: current, Desired: []*endpoint.Endpoint{desired}, Policies: []plan.Policy{&plan.SyncPolicy{}}, ManagedRecords: []string{"A", "AAAA", "CNAME"}}).Calculate().Changes
		if err := p.ApplyChanges(context.Background(), changes); err != nil {
			t.Fatalf("transition to %s failed: %v", desired.RecordType, err)
		}
		current, err = p.Records(context.Background())
		if err != nil || len(current) != 1 || current[0].RecordType != desired.RecordType || current[0].Targets[0] != desired.Targets[0] {
			t.Fatalf("transition to %s did not converge: %+v, %v", desired.RecordType, current, err)
		}
	}
}

func TestTXTRegistryPreservesOtherOwners(t *testing.T) {
	store := &storedRecords{fakeRecords: fakeRecords{byZone: map[string][]govultr.DomainRecord{}}}
	p := testProvider(&store.fakeRecords)
	p.records = store
	other, err := txt.New(&externaldns.Config{TXTPrefix: "reg-", TXTOwnerID: "other-owner", ManagedDNSRecordTypes: []string{"A"}}, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Records(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := other.ApplyChanges(context.Background(), &plan.Changes{Create: []*endpoint.Endpoint{endpoint.NewEndpoint("app.example.com", "A", "192.0.2.1")}}); err != nil {
		t.Fatal(err)
	}
	ours, err := txt.New(&externaldns.Config{TXTPrefix: "reg-", TXTOwnerID: "our-owner", ManagedDNSRecordTypes: []string{"A"}}, p)
	if err != nil {
		t.Fatal(err)
	}
	current, err := ours.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changes := (&plan.Plan{Current: current, Policies: []plan.Policy{&plan.SyncPolicy{}}, ManagedRecords: []string{"A"}, OwnerID: ours.OwnerID()}).Calculate().Changes
	if changes.HasChanges() {
		t.Fatalf("planned deletion of another owner's records: %+v", changes)
	}
	if err := ours.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatal(err)
	}
	if len(store.byZone["example.com"]) != 2 {
		t.Fatal("another owner's data or TXT ownership was changed")
	}
}
