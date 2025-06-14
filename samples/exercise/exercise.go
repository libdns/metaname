package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/metaname"
)

func printCurrent(provider *metaname.Provider, zone string) []libdns.Record {
	ctx := context.TODO()
	recs, err := provider.GetRecords(ctx, zone)
	if err != nil {
		fmt.Println("Error getting records:", err)
		return nil
	}
	fmt.Printf("%d records in zone:\n", len(recs))
	for _, r := range recs {
		switch rec := r.(type) {
		case libdns.Address:
			fmt.Printf("A \t%s\t%s\n", rec.Name, rec.IP)
		case libdns.CNAME:
			fmt.Printf("CNAME \t%s\t%s\n", rec.Name, rec.Target)
		case libdns.TXT:
			fmt.Printf("TXT \t%s\t%s\n", rec.Name, rec.Text)
		default:
			fmt.Printf("Unknown Record Type: %T\n", r)
			fmt.Printf("Record details: %+v\n", r)
		}
	}
	fmt.Println("")
	return recs
}

func main() {
	ctx := context.TODO()
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", os.Args[0], "<zone>")
		fmt.Println("This program adds, updates, and deletes specific records in the given zone.")
		fmt.Println("These changes may be destructive to existing data!")
		fmt.Println("Guesswork deletion is checked using a TXT record 'todelete' with value 'this will go away'")
		fmt.Println("Other records created/changed are 'test' and 'additional'.")
		os.Exit(1)
	}
	endpoint := "https://test.metaname.net/api/1.1"
	os.Setenv(("api_key"), "4kcwh9b7grz34bvjkpmhsc7sww4ny4rnskm6xb6n3x7b3kqm")
	os.Setenv(("account_reference"), "dmxn")
	provider := metaname.Provider{APIKey: os.Getenv("api_key"),
		AccountReference: os.Getenv("account_reference"),
		Endpoint:         endpoint}
	zone := os.Args[1]
	recs := printCurrent(&provider, zone)

	fmt.Println("")
	fmt.Println("Deleting all existing records for clean slate")
	// Delete all existing records for a clean slate
	_, err := provider.DeleteRecords(ctx, zone, recs)
	if err != nil {
		fmt.Println("Error deleting records:", err)
		return
	}
	fmt.Println("All existing records deleted successfully.")
	printCurrent(&provider, zone)

	fmt.Println("")
	fmt.Println("Adding A record 'test' with IP '8.8.8.8")
	added, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test", TTL: time.Duration(300) * time.Second, IP: netip.MustParseAddr("8.8.8.8")},
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Added record:", added)

	fmt.Println("Adding TXT record '_abc' with text 'xyz'")
	added, err = provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "_abc", TTL: time.Duration(300) * time.Second, Text: "xyz"},
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Added record:", added)

	fmt.Println("Adding CNAME record 'cn1' pointing to 'test'")
	added, err = provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.CNAME{Name: "cn1", TTL: time.Duration(300) * time.Second, Target: "test"},
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Added record:", added)

	fmt.Println("Adding TXT record '_def-rr' using RR format with value 'initial'")
	added, err = provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.RR{Type: "TXT", Name: "_def-rr", TTL: time.Duration(300) * time.Second, Data: "initial"},
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Added record:", added)
	printCurrent(&provider, zone)
	fmt.Println("")

	fmt.Println("Updating A record 'test' to IP '1.1.1.1'")
	fmt.Println("Creating CNAME record 'alias' pointing to 'test'")
	fmt.Println("Creating TXT record 'example' with text 'sample text'")
	fmt.Println("Updating TXT record '_def-rr' using RR with value 'updated'")

	// Test SetRecords functionality
	updated, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test", TTL: time.Duration(600) * time.Second, IP: netip.MustParseAddr("1.1.1.1")},
		libdns.CNAME{Name: "alias", TTL: time.Duration(600) * time.Second, Target: "test"},
		libdns.TXT{Name: "example", TTL: time.Duration(600) * time.Second, Text: "sample text"},
		libdns.RR{Name: "_def-rr", TTL: time.Duration(600) * time.Second, Type: "TXT", Data: "updated"},
	})
	if err != nil {
		fmt.Println("Error in SetRecords:", err)
	} else {
		fmt.Println("Updated records:", updated)
	}
	printCurrent(&provider, zone)
}
