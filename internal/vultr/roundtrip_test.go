package vultr

import (
	"testing"

	govultr "github.com/vultr/govultr/v3"
)

func FuzzRecordRoundTrip(f *testing.F) {
	for _, seed := range []struct{ recordType, target string }{
		{"A", "192.0.2.1"}, {"AAAA", "2001:0db8:0:0:0:0:0:1"},
		{"CNAME", "Target.Example.NET."}, {"NS", "NS1.Example.NET."},
		{"MX", "0010 Mail.Example.NET."}, {"MX", "0 ."},
		{"SRV", "0010 0020 00443 Service.Example.NET."}, {"SRV", "0 0 0 ."},
		{"TXT", `"preserve  spaces and dots.."`},
		{"TXT", `text with "quotes" and \slashes`},
		{"TXT", "line\nwith\ttabs"},
		{"TXT", `"ends with slash\\"`},
		{"CAA", `0 IODEF "mailto:test@example.net?subject=two  words"`},
		{"SSHFP", "01 01 ABCDEF"},
	} {
		f.Add(seed.recordType, seed.target)
	}
	f.Fuzz(func(t *testing.T, recordType, target string) {
		if !supportedRecordType(recordType) {
			return
		}
		req, err := vultrRecord(recordType, target, 300)
		if err != nil {
			return // Invalid targets are rejected before any write.
		}
		canonical, err := canonicalTarget(req.Type, target)
		if err != nil {
			t.Fatal(err)
		}
		priority := -1
		if req.Priority != nil {
			priority = *req.Priority
		}
		record := govultr.DomainRecord{ID: "id", Name: "", Type: req.Type, Data: req.Data, Priority: priority, TTL: 300}
		decoded, err := externalDNSTarget(record)
		if err != nil || decoded != canonical {
			t.Fatalf("round trip changed %s target: %q -> %q (err=%v)", req.Type, canonical, decoded, err)
		}
		ids := indexRecords([]govultr.DomainRecord{record}, "example.com")[keyForRequest(req)]
		if len(ids) != 1 || ids[0] != "id" {
			t.Fatal("created record cannot be matched for deletion")
		}
	})
}
