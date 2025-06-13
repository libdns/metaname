package metaname

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

var (
	p    Provider
	ctx  context.Context = context.Background()
	zone string
)

// These tests expect the credentials to be in the environment variables api_key and account_reference (same as the
// official API implementations). It also expects the full name of the zone to be in the test_zone variable. If
// everything is working, all records created by the tests are also removed by them, but if it isn't it may be
// necessary to clear records from the control panel before running the tests again (notably CNAMEs cannot be
// recreated).
//
// The Metaname API occasionally returns unexpected failures on good calls, which makes the test suite slightly flaky,
// but it should succeed the overwhelming majority of the time. The test suite is hard-coded to use the test API
// endpoint.
func init() {
	p = Provider{
		APIKey:           os.Getenv("api_key"),
		AccountReference: os.Getenv("account_reference"),
		Endpoint:         "https://test.metaname.net/api/1.1",
	}
	zone = os.Getenv("test_zone")
}

func TestGetRecords(t *testing.T) {
	// Confirm no errors from retrieving records - actual contents
	// used in other tests, where some of the records are known already.
	_, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
}

// Helper function to confirm existence of record.
func expectRecord(t *testing.T, name string, record interface{}) {
	records, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range records {
		switch r := rec.(type) {
		case libdns.Address:
			if r.Name == name && r.IP.String() == record.(libdns.Address).IP.String() {
				found = true
			}
		case libdns.CNAME:
			if r.Name == name && r.Target == record.(libdns.CNAME).Target {
				found = true
			}
		case libdns.TXT:
			if r.Name == name && r.Text == record.(libdns.TXT).Text {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected to find record", name, record)
	}
}

// Helper function to confirm non-existence of record.
func expectNoSuchRecord(t *testing.T, name string, record interface{}) {
	records, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range records {
		switch r := rec.(type) {
		case libdns.Address:
			if r.Name == name && r.IP.String() == record.(libdns.Address).IP.String() {
				found = true
			}
		case libdns.CNAME:
			if r.Name == name && r.Target == record.(libdns.CNAME).Target {
				found = true
			}
		case libdns.TXT:
			if r.Name == name && r.Text == record.(libdns.TXT).Text {
				found = true
			}
		}
	}
	if found {
		t.Fatal("expected to find no record like", name, record)
	}
}

func TestAppendRecords(t *testing.T) {
	// Add a single Address record
	added, err := p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "provider-test-1", TTL: time.Duration(3600) * time.Second, IP: netip.MustParseAddr("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 {
		t.Fatalf("expected to add 1 record; added %d", len(added))
	}
	expectRecord(t, "provider-test-1", libdns.Address{Name: "provider-test-1", IP: netip.MustParseAddr("127.0.0.1")})

	// Add two records at once
	added, err = p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.CNAME{Name: "provider-test-2", TTL: time.Duration(300) * time.Second, Target: "provider-test-1"},
		libdns.TXT{Name: "provider-test-3", TTL: time.Duration(86400) * time.Second, Text: "initial stored txt value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 {
		t.Fatalf("expected to add 2 records; added %d", len(added))
	}
	expectRecord(t, "provider-test-2", libdns.CNAME{Name: "provider-test-2", Target: "provider-test-1"})
	expectRecord(t, "provider-test-3", libdns.TXT{Name: "provider-test-3", Text: "initial stored txt value"})
}

func TestSetRecords(t *testing.T) {
	// Add a single record to modify
	_, err := p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "provider-test-4", TTL: time.Duration(3600) * time.Second, IP: netip.MustParseAddr("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Update the previous record to hold a new value,
	// and simultaneously add a new TXT record.
	added, err := p.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "provider-test-4b", TTL: time.Duration(3600) * time.Second, IP: netip.MustParseAddr("0.0.0.0")},
		libdns.TXT{Name: "provider-test-5", Text: "abcd", TTL: time.Duration(600) * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 {
		t.Fatalf("expected to update/add 2 records; updated/added %d", len(added))
	}
	expectRecord(t, "provider-test-4b", libdns.Address{Name: "provider-test-4b", IP: netip.MustParseAddr("0.0.0.0")})
	expectRecord(t, "provider-test-5", libdns.TXT{Name: "provider-test-5", Text: "abcd"})
}

func TestDeleteRecords(t *testing.T) {
	// Add, then delete, a single record
	p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.CNAME{Name: "provider-test-6", TTL: time.Duration(7200) * time.Second, Target: "google.com."},
	})
	deleted, err := p.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.CNAME{Name: "provider-test-6", Target: "google.com."},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected to delete 1 record; deleted %d", len(deleted))
	}
	expectNoSuchRecord(t, "provider-test-6", libdns.CNAME{Name: "provider-test-6", Target: "google.com."})

	// Delete all provider-test-* records at once, by reference
	records, _ := p.GetRecords(ctx, zone)
	var todelete []libdns.Record
	for _, rec := range records {
		switch r := rec.(type) {
		case libdns.Address:
			if strings.HasPrefix(r.Name, "provider-test-") {
				todelete = append(todelete, r)
			}
		case libdns.CNAME:
			if strings.HasPrefix(r.Name, "provider-test-") {
				todelete = append(todelete, r)
			}
		case libdns.TXT:
			if strings.HasPrefix(r.Name, "provider-test-") {
				todelete = append(todelete, r)
			}
		}
	}
	deleted, err = p.DeleteRecords(ctx, zone, todelete)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != len(todelete) {
		t.Fatalf("expected to have deleted %d records but deleted %d", len(todelete), len(deleted))
	}

	// Confirm that no test records remain
	records, _ = p.GetRecords(ctx, zone)
	for _, rec := range records {
		switch r := rec.(type) {
		case libdns.Address:
			if strings.HasPrefix(r.Name, "provider-test-") {
				t.Fatalf("record %s should have been deleted already", r.Name)
			}
		case libdns.CNAME:
			if strings.HasPrefix(r.Name, "provider-test-") {
				t.Fatalf("record %s should have been deleted already", r.Name)
			}
		case libdns.TXT:
			if strings.HasPrefix(r.Name, "provider-test-") {
				t.Fatalf("record %s should have been deleted already", r.Name)
			}
		}
	}
}

// Refactor error test cases to use valid libdns.Record structs
func TestErrors(t *testing.T) {
	// Check that various error cases from the API don't crash and are relayed.
	_, err := p.GetRecords(ctx, "nosuch-"+zone+"-notTLD")
	if err == nil {
		t.Fatal("expected error from bad zone")
	}
	_, err = p.AppendRecords(ctx, zone, []libdns.Record{
		// Invalid record with missing fields
		libdns.TXT{},
	})
	if err == nil {
		t.Fatal("expected error from append missing record details")
	}
	_, err = p.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "provider-test-8"},
	})
	if err == nil {
		t.Fatal("expected error from delete missing record details")
	}
}
