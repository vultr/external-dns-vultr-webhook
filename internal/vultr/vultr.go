package vultr

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	govultr "github.com/vultr/govultr/v3"
	"golang.org/x/oauth2"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

const (
	vultrCreate = "CREATE"
	vultrDelete = "DELETE"
	vultrTTL    = 3600
	pageSize    = 500
)

var supportedRecordTypes = map[string]struct{}{
	"A": {}, "AAAA": {}, "CAA": {}, "CNAME": {}, "MX": {},
	"NS": {}, "SRV": {}, "SSHFP": {}, "TXT": {},
}

type domainService interface {
	List(context.Context, *govultr.ListOptions) ([]govultr.Domain, *govultr.Meta, *http.Response, error)
}

type domainRecordService interface {
	Create(context.Context, string, *govultr.DomainRecordCreateReq) (*govultr.DomainRecord, *http.Response, error)
	Delete(context.Context, string, string) error
	List(context.Context, string, *govultr.ListOptions) ([]govultr.DomainRecord, *govultr.Meta, *http.Response, error)
}

type VultrProvider struct {
	provider.BaseProvider
	domains      domainService
	records      domainRecordService
	domainFilter endpoint.DomainFilterInterface
	DryRun       bool
}

// VultrChange is one Vultr DNS API operation.
type VultrChange struct {
	Action  string
	DNSName string
	Record  *govultr.DomainRecordCreateReq
}

// Configuration contains the Vultr provider's configuration.
type Configuration struct {
	APIKey               string   `env:"VULTR_API_KEY" required:"true"`
	DryRun               bool     `env:"DRY_RUN" default:"false"`
	DomainFilter         []string `env:"DOMAIN_FILTER" default:""`
	ExcludeDomains       []string `env:"EXCLUDE_DOMAIN_FILTER" default:""`
	RegexDomainFilter    string   `env:"REGEXP_DOMAIN_FILTER" default:""`
	RegexDomainExclusion string   `env:"REGEXP_DOMAIN_FILTER_EXCLUSION" default:""`
}

func NewProvider(providerConfig *Configuration) (*VultrProvider, error) {
	domainFilter, err := GetDomainFilter(*providerConfig)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: providerConfig.APIKey})
	httpClient := oauth2.NewClient(ctx, ts)
	httpClient.Timeout = 30 * time.Second
	client := govultr.NewClient(httpClient)

	return &VultrProvider{
		domains:      client.Domain,
		records:      client.DomainRecord,
		DryRun:       providerConfig.DryRun,
		domainFilter: domainFilter,
	}, nil
}

// GetDomainFilter returns the filter advertised during webhook negotiation.
func (p *VultrProvider) GetDomainFilter() endpoint.DomainFilterInterface {
	return p.domainFilter
}

// Zones returns the filtered hosted zones.
func (p *VultrProvider) Zones(ctx context.Context) ([]govultr.Domain, error) {
	return p.fetchZones(ctx)
}

// Records returns all supported Vultr records as ExternalDNS endpoints.
func (p *VultrProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	zones, err := p.Zones(ctx)
	if err != nil {
		return nil, err
	}

	type endpointKey struct {
		name       string
		recordType string
	}
	endpointMap := make(map[endpointKey]*endpoint.Endpoint)

	for _, zone := range zones {
		records, err := p.fetchRecords(ctx, zone.Domain)
		if err != nil {
			return nil, err
		}

		for _, record := range records {
			if !supportedRecordType(record.Type) {
				continue
			}
			name := absoluteRecordName(record.Name, zone.Domain)
			target, err := externalDNSTarget(record)
			if err != nil {
				return nil, fmt.Errorf("decode %s record %q in zone %q: %w", record.Type, record.Name, zone.Domain, err)
			}

			key := endpointKey{name: name, recordType: record.Type}
			if ep, exists := endpointMap[key]; exists {
				if ep.RecordTTL != endpoint.TTL(record.TTL) {
					return nil, fmt.Errorf("records for %s %s have inconsistent TTLs", name, record.Type)
				}
				ep.Targets = append(ep.Targets, target)
				continue
			}

			ep := endpoint.NewEndpointWithTTL(name, record.Type, endpoint.TTL(record.TTL), target)
			if ep == nil {
				return nil, fmt.Errorf("invalid %s record name %q returned by Vultr", record.Type, name)
			}
			endpointMap[key] = ep
		}
	}

	endpoints := make([]*endpoint.Endpoint, 0, len(endpointMap))
	for _, ep := range endpointMap {
		sort.Strings(ep.Targets)
		endpoints = append(endpoints, ep)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].DNSName == endpoints[j].DNSName {
			return endpoints[i].RecordType < endpoints[j].RecordType
		}
		return endpoints[i].DNSName < endpoints[j].DNSName
	})
	return endpoints, nil
}

func (p *VultrProvider) fetchRecords(ctx context.Context, domain string) ([]govultr.DomainRecord, error) {
	var allRecords []govultr.DomainRecord
	listOptions := &govultr.ListOptions{PerPage: pageSize}
	seenCursors := make(map[string]struct{})

	for {
		records, meta, _, err := p.records.List(ctx, domain, listOptions)
		if err != nil {
			return nil, fmt.Errorf("list records in zone %q: %w", domain, err)
		}
		allRecords = append(allRecords, records...)

		next, err := nextCursor(meta, seenCursors)
		if err != nil {
			return nil, fmt.Errorf("paginate records in zone %q: %w", domain, err)
		}
		if next == "" {
			return allRecords, nil
		}
		listOptions.Cursor = next
	}
}

func (p *VultrProvider) fetchZones(ctx context.Context) ([]govultr.Domain, error) {
	var zones []govultr.Domain
	listOptions := &govultr.ListOptions{PerPage: pageSize}
	seenCursors := make(map[string]struct{})

	for {
		page, meta, _, err := p.domains.List(ctx, listOptions)
		if err != nil {
			return nil, fmt.Errorf("list Vultr domains: %w", err)
		}
		for _, zone := range page {
			if p.domainFilter.Match(zone.Domain) {
				zones = append(zones, zone)
			}
		}

		next, err := nextCursor(meta, seenCursors)
		if err != nil {
			return nil, fmt.Errorf("paginate Vultr domains: %w", err)
		}
		if next == "" {
			sort.Slice(zones, func(i, j int) bool { return zones[i].Domain < zones[j].Domain })
			return zones, nil
		}
		listOptions.Cursor = next
	}
}

func nextCursor(meta *govultr.Meta, seen map[string]struct{}) (string, error) {
	if meta == nil || meta.Links == nil || meta.Links.Next == "" {
		return "", nil
	}
	if _, exists := seen[meta.Links.Next]; exists {
		return "", fmt.Errorf("API returned repeated cursor %q", meta.Links.Next)
	}
	seen[meta.Links.Next] = struct{}{}
	return meta.Links.Next, nil
}

func (p *VultrProvider) submitChanges(ctx context.Context, changes []*VultrChange) error {
	if len(changes) == 0 {
		log.Info("All records are already up to date")
		return nil
	}

	zones, err := p.Zones(ctx)
	if err != nil {
		return err
	}
	zoneChanges, err := separateChangesByZone(zones, changes)
	if err != nil {
		return err
	}

	zoneNames := make([]string, 0, len(zoneChanges))
	for zoneName := range zoneChanges {
		zoneNames = append(zoneNames, zoneName)
	}
	sort.Strings(zoneNames)

	// Resolve every deletion before making a write, so invalid plans cannot
	// partially mutate an earlier zone.
	deleteIDs := make(map[*VultrChange]string)
	for _, zoneName := range zoneNames {
		plannedChanges := zoneChanges[zoneName]
		if !containsDelete(plannedChanges) {
			continue
		}
		records, err := p.fetchRecords(ctx, zoneName)
		if err != nil {
			return err
		}
		recordIndex := indexRecords(records)
		for _, change := range plannedChanges {
			if change.Action != vultrDelete {
				continue
			}
			record := *change.Record
			record.Name, err = relativeRecordName(change.DNSName, zoneName)
			if err != nil {
				return err
			}
			key := keyForRequest(&record)
			ids := recordIndex[key]
			if len(ids) == 0 {
				return fmt.Errorf("delete %s %s in zone %q: matching record not found", record.Type, change.DNSName, zoneName)
			}
			deleteIDs[change] = ids[0]
			recordIndex[key] = ids[1:]
		}
	}

	for _, zoneName := range zoneNames {
		for _, change := range zoneChanges[zoneName] {
			record := *change.Record
			record.Name, err = relativeRecordName(change.DNSName, zoneName)
			if err != nil {
				return err
			}
			fields := log.Fields{"record": change.DNSName, "type": record.Type, "ttl": record.TTL, "action": change.Action, "zone": zoneName, "dryRun": p.DryRun}
			log.WithFields(fields).Info("Changing record")

			switch change.Action {
			case vultrCreate:
				if p.DryRun {
					continue
				}
				if _, _, err := p.records.Create(ctx, zoneName, &record); err != nil {
					return fmt.Errorf("create %s %s in zone %q: %w", record.Type, change.DNSName, zoneName, err)
				}
			case vultrDelete:
				if p.DryRun {
					continue
				}
				if err := p.records.Delete(ctx, zoneName, deleteIDs[change]); err != nil {
					return fmt.Errorf("delete %s %s in zone %q: %w", record.Type, change.DNSName, zoneName, err)
				}
			default:
				return fmt.Errorf("unsupported change action %q", change.Action)
			}
		}
	}
	return nil
}

// ApplyChanges validates and applies a set of ExternalDNS changes.
func (p *VultrProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if changes == nil {
		return fmt.Errorf("changes must not be nil")
	}
	combined := make([]*VultrChange, 0, len(changes.Create)+len(changes.UpdateOld)+len(changes.UpdateNew)+len(changes.Delete))

	for _, group := range []struct {
		action    string
		endpoints []*endpoint.Endpoint
	}{{vultrCreate, changes.Create}, {vultrDelete, changes.UpdateOld}, {vultrCreate, changes.UpdateNew}, {vultrDelete, changes.Delete}} {
		converted, err := newVultrChanges(group.action, group.endpoints)
		if err != nil {
			return err
		}
		combined = append(combined, converted...)
	}
	return p.submitChanges(ctx, combined)
}

func newVultrChanges(action string, endpoints []*endpoint.Endpoint) ([]*VultrChange, error) {
	changes := make([]*VultrChange, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep == nil {
			return nil, fmt.Errorf("endpoint must not be nil")
		}
		recordType := strings.ToUpper(ep.RecordType)
		if !supportedRecordType(recordType) {
			return nil, fmt.Errorf("unsupported DNS record type %q for %s", ep.RecordType, ep.DNSName)
		}
		if recordType == "CNAME" && len(ep.Targets) != 1 {
			return nil, fmt.Errorf("CNAME %s must have exactly one target", ep.DNSName)
		}

		ttl := vultrTTL
		if ep.RecordTTL.IsConfigured() {
			ttl = int(ep.RecordTTL)
		}
		for _, target := range ep.Targets {
			record, err := vultrRecord(recordType, target, ttl)
			if err != nil {
				return nil, fmt.Errorf("invalid %s target %q for %s: %w", ep.RecordType, target, ep.DNSName, err)
			}
			changes = append(changes, &VultrChange{Action: action, DNSName: canonicalName(ep.DNSName), Record: record})
		}
	}
	return changes, nil
}

func separateChangesByZone(zones []govultr.Domain, changes []*VultrChange) (map[string][]*VultrChange, error) {
	zoneNames := provider.ZoneIDName{}
	for _, zone := range zones {
		zoneNames.Add(zone.Domain, zone.Domain)
	}

	grouped := make(map[string][]*VultrChange)
	for _, change := range changes {
		zone, _ := zoneNames.FindZone(change.DNSName)
		if zone == "" {
			return nil, fmt.Errorf("no managed Vultr zone matches DNS name %q", change.DNSName)
		}
		grouped[zone] = append(grouped[zone], change)
	}
	return grouped, nil
}

// AdjustEndpoints normalizes hostname targets to the representation returned by Records.
func (p *VultrProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	for _, ep := range endpoints {
		if ep == nil {
			return nil, fmt.Errorf("endpoint must not be nil")
		}
		ep.RecordType = strings.ToUpper(ep.RecordType)
		if !supportedRecordType(ep.RecordType) {
			return nil, fmt.Errorf("unsupported DNS record type %q for %s", ep.RecordType, ep.DNSName)
		}
		ep.DNSName = canonicalName(ep.DNSName)
		for i, target := range ep.Targets {
			normalized, err := canonicalTarget(ep.RecordType, target)
			if err != nil {
				return nil, fmt.Errorf("invalid %s target %q for %s: %w", ep.RecordType, target, ep.DNSName, err)
			}
			ep.Targets[i] = normalized
		}
		sort.Strings(ep.Targets)
	}
	return endpoints, nil
}

func GetDomainFilter(config Configuration) (endpoint.DomainFilterInterface, error) {
	if config.RegexDomainFilter != "" {
		include, err := regexp.Compile(config.RegexDomainFilter)
		if err != nil {
			return nil, fmt.Errorf("compile REGEXP_DOMAIN_FILTER: %w", err)
		}
		exclude, err := regexp.Compile(config.RegexDomainExclusion)
		if err != nil {
			return nil, fmt.Errorf("compile REGEXP_DOMAIN_FILTER_EXCLUSION: %w", err)
		}
		log.WithFields(log.Fields{"include": config.RegexDomainFilter, "exclude": config.RegexDomainExclusion}).Info("Creating Vultr provider with regex domain filter")
		return endpoint.NewRegexDomainFilter(include, exclude), nil
	}

	log.WithFields(log.Fields{"include": config.DomainFilter, "exclude": config.ExcludeDomains}).Info("Creating Vultr provider with domain filter")
	return endpoint.NewDomainFilterWithExclusions(config.DomainFilter, config.ExcludeDomains), nil
}

func supportedRecordType(recordType string) bool {
	_, ok := supportedRecordTypes[strings.ToUpper(recordType)]
	return ok
}

func canonicalName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func canonicalHostname(name string) string {
	if strings.TrimSpace(name) == "." {
		return "."
	}
	return canonicalName(name)
}

func absoluteRecordName(name, zone string) string {
	name = canonicalName(name)
	zone = canonicalName(zone)
	if name == "" || name == zone {
		return zone
	}
	if strings.HasSuffix(name, "."+zone) {
		return name
	}
	return name + "." + zone
}

func relativeRecordName(name, zone string) (string, error) {
	name = canonicalName(name)
	zone = canonicalName(zone)
	if name == zone {
		return "", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(name, suffix) {
		return "", fmt.Errorf("DNS name %q is not in zone %q", name, zone)
	}
	return strings.TrimSuffix(name, suffix), nil
}

func canonicalTarget(recordType, target string) (string, error) {
	fields := strings.Fields(target)
	switch recordType {
	case "A":
		address, err := netip.ParseAddr(strings.TrimSpace(target))
		if err != nil || !address.Is4() {
			return "", fmt.Errorf("expected an IPv4 address")
		}
		return address.String(), nil
	case "AAAA":
		address, err := netip.ParseAddr(strings.TrimSpace(target))
		if err != nil || !address.Is6() {
			return "", fmt.Errorf("expected an IPv6 address")
		}
		return address.String(), nil
	case "CNAME", "NS":
		if len(fields) != 1 {
			return "", fmt.Errorf("expected one hostname")
		}
		return canonicalHostname(fields[0]), nil
	case "MX":
		if len(fields) != 2 {
			return "", fmt.Errorf("expected 'priority hostname'")
		}
		if _, err := dnsUint16(fields[0]); err != nil {
			return "", fmt.Errorf("priority: %w", err)
		}
		return fields[0] + " " + canonicalHostname(fields[1]), nil
	case "SRV":
		if len(fields) != 4 {
			return "", fmt.Errorf("expected 'priority weight port hostname'")
		}
		for i, label := range []string{"priority", "weight", "port"} {
			if _, err := dnsUint16(fields[i]); err != nil {
				return "", fmt.Errorf("%s: %w", label, err)
			}
		}
		hostname := canonicalHostname(fields[3])
		if hostname != "." {
			hostname += "."
		}
		return strings.Join([]string{fields[0], fields[1], fields[2], hostname}, " "), nil
	case "CAA":
		if len(fields) < 3 {
			return "", fmt.Errorf("expected 'flags tag value'")
		}
		flags, err := strconv.ParseUint(fields[0], 10, 8)
		if err != nil {
			return "", fmt.Errorf("flags must be an integer from 0 to 255")
		}
		if matched, _ := regexp.MatchString(`^[A-Za-z0-9]+$`, fields[1]); !matched {
			return "", fmt.Errorf("tag must contain only letters and digits")
		}
		return fmt.Sprintf("%d %s %s", flags, strings.ToLower(fields[1]), strings.Join(fields[2:], " ")), nil
	case "SSHFP":
		if len(fields) != 3 {
			return "", fmt.Errorf("expected 'algorithm fingerprint-type fingerprint'")
		}
		for i, label := range []string{"algorithm", "fingerprint type"} {
			value, err := strconv.ParseUint(fields[i], 10, 8)
			if err != nil || value == 0 {
				return "", fmt.Errorf("%s must be an integer from 1 to 255", label)
			}
		}
		if _, err := hex.DecodeString(fields[2]); err != nil {
			return "", fmt.Errorf("fingerprint must be hexadecimal")
		}
		return strings.Join([]string{fields[0], fields[1], strings.ToLower(fields[2])}, " "), nil
	default:
		return target, nil
	}
}

func vultrRecord(recordType, target string, ttl int) (*govultr.DomainRecordCreateReq, error) {
	recordType = strings.ToUpper(recordType)
	target, err := canonicalTarget(recordType, target)
	if err != nil {
		return nil, err
	}
	record := &govultr.DomainRecordCreateReq{Type: recordType, Data: target, TTL: ttl}
	fields := strings.Fields(target)

	switch recordType {
	case "MX":
		priority, _ := dnsUint16(fields[0])
		record.Priority = &priority
		record.Data = fields[1]
	case "SRV":
		priority, _ := dnsUint16(fields[0])
		record.Priority = &priority
		if fields[3] != "." {
			fields[3] = strings.TrimSuffix(fields[3], ".")
		}
		record.Data = strings.Join(fields[1:], " ")
	}
	return record, nil
}

func externalDNSTarget(record govultr.DomainRecord) (string, error) {
	switch record.Type {
	case "MX":
		return canonicalTarget(record.Type, fmt.Sprintf("%d %s", record.Priority, record.Data))
	case "SRV":
		return canonicalTarget(record.Type, fmt.Sprintf("%d %s", record.Priority, record.Data))
	case "TXT":
		return record.Data, nil
	default:
		return canonicalTarget(record.Type, record.Data)
	}
}

func dnsUint16(value string) (int, error) {
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("must be an integer from 0 to 65535")
	}
	return int(n), nil
}

type recordKey struct {
	name, recordType, data string
	priority               int
}

func indexRecords(records []govultr.DomainRecord) map[recordKey][]string {
	index := make(map[recordKey][]string, len(records))
	for _, record := range records {
		key := recordKey{name: canonicalName(record.Name), recordType: strings.ToUpper(record.Type), data: canonicalVultrData(record.Type, record.Data), priority: record.Priority}
		index[key] = append(index[key], record.ID)
	}
	return index
}

func keyForRequest(record *govultr.DomainRecordCreateReq) recordKey {
	priority := 0
	if record.Priority != nil {
		priority = *record.Priority
	}
	return recordKey{name: canonicalName(record.Name), recordType: strings.ToUpper(record.Type), data: canonicalVultrData(record.Type, record.Data), priority: priority}
}

func canonicalVultrData(recordType, data string) string {
	switch strings.ToUpper(recordType) {
	case "CNAME", "NS", "MX":
		return canonicalHostname(data)
	case "SRV":
		fields := strings.Fields(data)
		if len(fields) == 3 {
			fields[2] = canonicalHostname(fields[2])
			return strings.Join(fields, " ")
		}
	}
	return data
}

func containsDelete(changes []*VultrChange) bool {
	for _, change := range changes {
		if change.Action == vultrDelete {
			return true
		}
	}
	return false
}
