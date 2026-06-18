package vultr

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/vultr/govultr/v3"
	"golang.org/x/oauth2"
	"regexp"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"strings"
)

const (
	vultrCreate = "CREATE"
	vultrDelete = "DELETE"
	vultrTTL    = 3600
)

type VultrProvider struct {
	provider.BaseProvider
	client *govultr.Client

	zoneIDNameMapper provider.ZoneIDName
	domainFilter     endpoint.DomainFilter
	DryRun           bool
}

// VultrChanges differentiates between ChangActions.
type VultrChanges struct {
	Action string

	ResourceRecordSet *govultr.DomainRecordReq
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

func NewProvider(providerConfig *Configuration) *VultrProvider {
	config := &oauth2.Config{}
	ctx := context.TODO()
	ts := config.TokenSource(ctx, &oauth2.Token{AccessToken: providerConfig.APIKey})
	vultrClient := govultr.NewClient(oauth2.NewClient(ctx, ts))

	return &VultrProvider{
		client:       vultrClient,
		DryRun:       providerConfig.DryRun,
		domainFilter: GetDomainFilter(*providerConfig),
	}
}

// Zones returns list of hosted zones
func (p *VultrProvider) Zones(ctx context.Context) ([]govultr.Domain, error) {
	zones, err := p.fetchZones(ctx)
	if err != nil {
		return nil, err
	}

	return zones, nil
}

// Records returns the list of records.
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

		for _, r := range records {
			if provider.SupportedRecordType(r.Type) {
				name := fmt.Sprintf("%s.%s", r.Name, zone.Domain)

				// root name is identified by the empty string and should be
				// translated to zone name for the endpoint entry.
				if r.Name == "" {
					name = zone.Domain
				}

				key := endpointKey{name: name, recordType: r.Type}
				if ep, exists := endpointMap[key]; exists {
					ep.Targets = append(ep.Targets, r.Data)
				} else {
					endpointMap[key] = endpoint.NewEndpointWithTTL(name, r.Type, endpoint.TTL(r.TTL), r.Data)
				}
			}
		}
	}

	endpoints := make([]*endpoint.Endpoint, 0, len(endpointMap))
	for _, ep := range endpointMap {
		endpoints = append(endpoints, ep)
	}

	return endpoints, nil
}

func (p *VultrProvider) fetchRecords(ctx context.Context, domain string) ([]govultr.DomainRecord, error) {
	var allRecords []govultr.DomainRecord
	listOptions := &govultr.ListOptions{}

	for {
		records, meta, _, err := p.client.DomainRecord.List(ctx, domain, listOptions)
		if err != nil {
			return nil, err
		}

		allRecords = append(allRecords, records...)

		if meta.Links.Next == "" {
			break
		} else {
			listOptions.Cursor = meta.Links.Next
			continue
		}
	}

	return allRecords, nil
}

func (p *VultrProvider) fetchZones(ctx context.Context) ([]govultr.Domain, error) {
	var zones []govultr.Domain
	listOptions := &govultr.ListOptions{}

	for {
		allZones, meta, _, err := p.client.Domain.List(ctx, listOptions)
		if err != nil {
			return nil, err
		}

		for _, zone := range allZones {
			if p.domainFilter.Match(zone.Domain) {
				zones = append(zones, zone)
			}
		}

		if meta.Links.Next == "" {
			break
		} else {
			listOptions.Cursor = meta.Links.Next
			continue
		}
	}

	return zones, nil
}

func (p *VultrProvider) submitChanges(ctx context.Context, changes []*VultrChanges) error {
	if len(changes) == 0 {
		log.Infof("All records are already up to date")
		return nil
	}

	zones, err := p.Zones(ctx)
	if err != nil {
		return err
	}

	zoneChanges := separateChangesByZone(zones, changes)

	for zoneName, changes := range zoneChanges {
		for _, change := range changes {
			log.WithFields(log.Fields{
				"record": change.ResourceRecordSet.Name,
				"type":   change.ResourceRecordSet.Type,
				"ttl":    change.ResourceRecordSet.TTL,
				"action": change.Action,
				"zone":   zoneName,
			}).Info("Changing record.")

			switch change.Action {
			case vultrCreate:
				if _, _, err := p.client.DomainRecord.Create(ctx, zoneName, change.ResourceRecordSet); err != nil {
					return err
				}
			case vultrDelete:
				id, err := p.getRecordID(ctx, zoneName, change.ResourceRecordSet)
				if err != nil {
					return err
				}

				if err := p.client.DomainRecord.Delete(ctx, zoneName, id); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *VultrProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	combinedChanges := make([]*VultrChanges, 0, len(changes.Create)+len(changes.UpdateOld)+len(changes.UpdateNew)+len(changes.Delete))

	combinedChanges = append(combinedChanges, newVultrChanges(vultrCreate, changes.Create)...)
	combinedChanges = append(combinedChanges, newVultrChanges(vultrDelete, changes.UpdateOld)...)
	combinedChanges = append(combinedChanges, newVultrChanges(vultrCreate, changes.UpdateNew)...)
	combinedChanges = append(combinedChanges, newVultrChanges(vultrDelete, changes.Delete)...)

	return p.submitChanges(ctx, combinedChanges)
}

func newVultrChanges(action string, endpoints []*endpoint.Endpoint) []*VultrChanges {
	changes := make([]*VultrChanges, 0, len(endpoints))
	for _, e := range endpoints {
		ttl := vultrTTL
		if e.RecordTTL.IsConfigured() {
			ttl = int(e.RecordTTL)
		}

		for _, target := range e.Targets {
			change := &VultrChanges{
				Action: action,
				ResourceRecordSet: &govultr.DomainRecordReq{
					Type: e.RecordType,
					Name: e.DNSName,
					Data: target,
					TTL:  ttl,
				},
			}

			changes = append(changes, change)
		}
	}
	return changes
}

func separateChangesByZone(zones []govultr.Domain, changes []*VultrChanges) map[string][]*VultrChanges {
	change := make(map[string][]*VultrChanges)
	zoneNameID := provider.ZoneIDName{}

	for _, z := range zones {
		zoneNameID.Add(z.Domain, z.Domain)
		change[z.Domain] = []*VultrChanges{}
	}

	for _, c := range changes {
		zone, _ := zoneNameID.FindZone(c.ResourceRecordSet.Name)
		if zone == "" {
			log.Debugf("Skipping record %s because no hosted zone matching record DNS Name was detected", c.ResourceRecordSet.Name)
			continue
		}
		change[zone] = append(change[zone], c)
	}
	return change
}

func (p *VultrProvider) getRecordID(ctx context.Context, zone string, record *govultr.DomainRecordReq) (recordID string, err error) {
	listOptions := &govultr.ListOptions{}
	for {
		records, meta, _, err := p.client.DomainRecord.List(ctx, zone, listOptions)
		if err != nil {
			return "0", err
		}

		for _, r := range records {
			strippedName := strings.TrimSuffix(record.Name, "."+zone)
			if record.Name == zone {
				strippedName = ""
			}

			if r.Name == strippedName && r.Type == record.Type && r.Data == record.Data {
				return r.ID, nil
			}
		}
		if meta.Links.Next == "" {
			break
		} else {
			listOptions.Cursor = meta.Links.Next
			continue
		}
	}

	return "", fmt.Errorf("no record was found")
}

func (p *VultrProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	adjustedEndpoints := []*endpoint.Endpoint{}

	for _, ep := range endpoints {
		_, zoneName := p.zoneIDNameMapper.FindZone(ep.DNSName)
		adjustedTargets := endpoint.Targets{}
		for _, t := range ep.Targets {
			var adjustedTarget, producedValidTarget = p.makeEndpointTarget(zoneName, t)
			if producedValidTarget {
				adjustedTargets = append(adjustedTargets, adjustedTarget)
			}
		}

		ep.Targets = adjustedTargets
		adjustedEndpoints = append(adjustedEndpoints, ep)
	}

	return adjustedEndpoints, nil
}

func (p VultrProvider) makeEndpointTarget(domain, entryTarget string) (string, bool) {
	if domain == "" {
		return entryTarget, true
	}

	adjustedTarget := strings.TrimSuffix(entryTarget, `.`)
	adjustedTarget = strings.TrimSuffix(adjustedTarget, "."+domain)

	return adjustedTarget, true
}

func GetDomainFilter(config Configuration) endpoint.DomainFilter {
	var domainFilter endpoint.DomainFilter
	createMsg := "Creating Vultr provider with "

	if config.RegexDomainFilter != "" {
		createMsg += fmt.Sprintf("Regexp domain filter: '%s', ", config.RegexDomainFilter)
		if config.RegexDomainExclusion != "" {
			createMsg += fmt.Sprintf("with exclusion: '%s', ", config.RegexDomainExclusion)
		}
		domainFilter = endpoint.NewRegexDomainFilter(
			regexp.MustCompile(config.RegexDomainFilter),
			regexp.MustCompile(config.RegexDomainExclusion),
		)
	} else {
		if len(config.DomainFilter) > 0 {
			createMsg += fmt.Sprintf("zoneNode filter: '%s', ", strings.Join(config.DomainFilter, ","))
		}
		if len(config.ExcludeDomains) > 0 {
			createMsg += fmt.Sprintf("Exclude domain filter: '%s', ", strings.Join(config.ExcludeDomains, ","))
		}
		domainFilter = endpoint.NewDomainFilterWithExclusions(config.DomainFilter, config.ExcludeDomains)
	}

	createMsg = strings.TrimSuffix(createMsg, ", ")
	if strings.HasSuffix(createMsg, "with ") {
		createMsg += "no kind of domain filters"
	}
	log.Info(createMsg)
	return domainFilter
}
