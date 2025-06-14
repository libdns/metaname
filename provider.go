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
		case "AAAA":
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
		rr := rec.RR()
		parsed, err := rr.Parse()
		if err != nil {
			return nil, fmt.Errorf("failed to parse record: %w", err)
		}
		if parsed == nil {
			return nil, fmt.Errorf("record is nil after parsing: %v", rec)
		}
		switch r := parsed.(type) {
		case libdns.Address:
			mrec := metanameRR{
				Name: r.Name,
				Type: rr.Type,
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
		rr := rec.RR()
		parsed, err := rr.Parse()
		key := rr.Name + "|" + rr.Type
		if err != nil {
			return nil, fmt.Errorf("failed to parse record: %w", err)
		}
		if parsed == nil {
			return nil, fmt.Errorf("record is nil after parsing: %v", rec)
		}
		inputMap[key] = parsed
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
					metanameRec := metanameRR{Name: r.Name, Ttl: int(r.TTL.Seconds()), Type: r.RR().Type, Data: r.IP.String()}
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
				metanameRec := metanameRR{Name: r.Name, Ttl: int(r.TTL.Seconds()), Type: r.RR().Type, Data: r.IP.String()}
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
		rr := rec.RR()
		parsed, err := rr.Parse()
		if err != nil {
			return nil, fmt.Errorf("failed to parse record: %w", err)
		}
		if parsed == nil {
			return nil, fmt.Errorf("record is nil after parsing: %v", rec)
		}
		switch r := parsed.(type) {
		case libdns.Address:
			for _, raw := range rawRecords {
				if raw.Name == r.Name && raw.Type == rr.Type && raw.Data == r.IP.String() {
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
		if existing.Type != input.RR().Type {
			return false
		}
		return existing.Name == r.Name && existing.Ttl == int(r.TTL.Seconds()) && existing.Data == r.IP.String()
	case libdns.CNAME:
		return existing.Type == "CNAME" && existing.Name == r.Name && existing.Ttl == int(r.TTL.Seconds()) && existing.Data == r.Target
	case libdns.TXT:
		return existing.Type == "TXT" && existing.Name == r.Name && existing.Ttl == int(r.TTL.Seconds()) && existing.Data == r.Text
	default:
		return false
	}
}
