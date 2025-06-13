// Package metaname implements a DNS record management client compatible
// with the libdns interfaces for Metaname.
package metaname

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Metaname
type Provider struct {
	APIKey           string `json:"api_key,omitempty"`
	AccountReference string `json:"account_reference,omitempty"`
	Endpoint         string `json:"endpoint,omitempty"`

	mutex sync.Mutex
}

// CustomRecord is a wrapper around libdns.Record to include Metadata.
type CustomRecord struct {
	libdns.Record
	Metadata map[string]string
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	metanameRecords, err := p.dns_zone(ctx, zone)
	if err != nil {
		return nil, err
	}

	var libRecords []libdns.Record
	for _, rec := range metanameRecords {
		switch rec.Type {
		case "A":
			ip, err := netip.ParseAddr(rec.Data)
			if err != nil {
				continue // Skip invalid IP addresses
			}
			libRecords = append(libRecords, libdns.Address{
				Name: rec.Name,
				TTL:  time.Duration(rec.Ttl) * time.Second,
				IP:   ip,
			})
		case "CNAME":
			libRecords = append(libRecords, libdns.CNAME{
				Name:   rec.Name,
				TTL:    time.Duration(rec.Ttl) * time.Second,
				Target: rec.Data,
			})
		case "TXT":
			libRecords = append(libRecords, libdns.TXT{
				Name: rec.Name,
				TTL:  time.Duration(rec.Ttl) * time.Second,
				Text: rec.Data,
			})
		default:
			continue // Skip unsupported types
		}
	}

	return libRecords, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record
	for _, rec := range records {
		switch r := rec.(type) {
		case libdns.Address:
			mrec := metanameRR{
				Name: r.Name,
				Type: "A",
				Ttl:  int(r.TTL.Seconds()),
				Data: r.IP.String(),
			}
			_, err := p.create_dns_record(ctx, zone, mrec)
			if err != nil {
				return nil, err
			}
			added = append(added, r)
		case libdns.CNAME:
			mrec := metanameRR{
				Name: r.Name,
				Type: "CNAME",
				Ttl:  int(r.TTL.Seconds()),
				Data: r.Target,
			}
			_, err := p.create_dns_record(ctx, zone, mrec)
			if err != nil {
				return nil, err
			}
			added = append(added, r)
		case libdns.TXT:
			mrec := metanameRR{
				Name: r.Name,
				Type: "TXT",
				Ttl:  int(r.TTL.Seconds()),
				Data: r.Text,
			}
			_, err := p.create_dns_record(ctx, zone, mrec)
			if err != nil {
				return nil, err
			}
			added = append(added, r)
		default:
			continue // Skip unsupported types
		}
	}
	return added, nil
}

// SetRecords sets the records in the zone, ensuring that only the input records exist for each (name, type) pair.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var updated []libdns.Record

	// Retrieve raw Metaname records directly
	rawRecords, err := p.dns_zone(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Define existingMap to map existing records by (type, name) pair
	existingMap := make(map[string]metanameRR)
	for _, rec := range rawRecords {
		key := rec.Name + "|" + rec.Type
		existingMap[key] = rec
	}

	// Create a map of input records by (type, name) pair
	inputMap := make(map[string]libdns.Record)
	for _, rec := range records {
		switch r := rec.(type) {
		case libdns.Address:
			key := r.Name + "|A"
			inputMap[key] = rec
		case libdns.CNAME:
			key := r.Name + "|CNAME"
			inputMap[key] = rec
		case libdns.TXT:
			key := r.Name + "|TXT"
			inputMap[key] = rec
		}
	}

	// Use a map to track records already added to the updated slice
	updatedMap := make(map[string]bool)

	// Process input records
	for key, inputRec := range inputMap {
		if existing, exists := existingMap[key]; exists {
			// Check if the existing record matches the input record
			if !recordsMatch(existing, inputRec) {
				// Update the existing record if it does not match the input record
				switch r := inputRec.(type) {
				case libdns.Address:
					metanameRec := metanameRR{Name: r.Name, Ttl: int(r.TTL.Seconds()), Type: "A", Data: r.IP.String()}
					if err := p.update_dns_record(ctx, zone, existing.Reference, metanameRec); err != nil {
						return nil, err
					}
				case libdns.CNAME:
					metanameRec := metanameRR{Name: r.Name, Ttl: int(r.TTL.Seconds()), Type: "CNAME", Data: r.Target}
					if err := p.update_dns_record(ctx, zone, existing.Reference, metanameRec); err != nil {
						return nil, err
					}
				case libdns.TXT:
					metanameRec := metanameRR{Name: r.Name, Ttl: int(r.TTL.Seconds()), Type: "TXT", Data: r.Text}
					if err := p.update_dns_record(ctx, zone, existing.Reference, metanameRec); err != nil {
						return nil, err
					}
				}
			}
			// Add the record to the updated slice if not already added
			if !updatedMap[key] {
				updated = append(updated, inputRec)
				updatedMap[key] = true
			}
		} else {
			// Create the record if it does not exist
			switch r := inputRec.(type) {
			case libdns.Address:
				metanameRec := metanameRR{Name: r.Name, Ttl: int(r.TTL.Seconds()), Type: "A", Data: r.IP.String()}
				_, err := p.create_dns_record(ctx, zone, metanameRec)
				if err != nil {
					return nil, err
				}
			case libdns.CNAME:
				metanameRec := metanameRR{Name: r.Name, Ttl: int(r.TTL.Seconds()), Type: "CNAME", Data: r.Target}
				_, err := p.create_dns_record(ctx, zone, metanameRec)
				if err != nil {
					return nil, err
				}
			case libdns.TXT:
				metanameRec := metanameRR{Name: r.Name, Ttl: int(r.TTL.Seconds()), Type: "TXT", Data: r.Text}
				_, err := p.create_dns_record(ctx, zone, metanameRec)
				if err != nil {
					return nil, err
				}
			}
			// Add the record to the updated slice if not already added
			if !updatedMap[key] {
				updated = append(updated, inputRec)
				updatedMap[key] = true
			}
		}
	}

	return updated, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record

	// Retrieve raw Metaname records directly
	rawRecords, err := p.dns_zone(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Iterate over the records to delete
	for _, rec := range records {
		switch r := rec.(type) {
		case libdns.Address:
			for _, raw := range rawRecords {
				if raw.Name == r.Name && raw.Type == "A" && raw.Data == r.IP.String() {
					_, err := p.delete_dns_record(ctx, zone, raw.Reference)
					if err != nil {
						return deleted, err
					}
					deleted = append(deleted, rec)
				}
			}
		case libdns.CNAME:
			for _, raw := range rawRecords {
				if raw.Name == r.Name && raw.Type == "CNAME" && raw.Data == r.Target {
					_, err := p.delete_dns_record(ctx, zone, raw.Reference)
					if err != nil {
						return deleted, err
					}
					deleted = append(deleted, rec)
				}
			}
		case libdns.TXT:
			// Validate TXT record: ensure Name and Text fields are populated
			if r.Name == "" || r.Text == "" {
				return nil, fmt.Errorf("invalid TXT record: missing required fields")
			}
			for _, raw := range rawRecords {
				if raw.Name == r.Name && raw.Type == "TXT" && raw.Data == r.Text {
					_, err := p.delete_dns_record(ctx, zone, raw.Reference)
					if err != nil {
						return deleted, err
					}
					deleted = append(deleted, rec)
				}
			}
		}
	}

	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

// Helper function to compare records
func recordsMatch(existing metanameRR, input libdns.Record) bool {
	switch r := input.(type) {
	case libdns.Address:
		return existing.Type == "A" && existing.Name == r.Name && existing.Ttl == int(r.TTL.Seconds()) && existing.Data == r.IP.String()
	case libdns.CNAME:
		return existing.Type == "CNAME" && existing.Name == r.Name && existing.Ttl == int(r.TTL.Seconds()) && existing.Data == r.Target
	case libdns.TXT:
		return existing.Type == "TXT" && existing.Name == r.Name && existing.Ttl == int(r.TTL.Seconds()) && existing.Data == r.Text
	default:
		return false
	}
}
