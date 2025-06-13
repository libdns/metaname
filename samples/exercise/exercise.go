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
	provider := metaname.Provider{APIKey: os.Getenv("api_key"),
		AccountReference: os.Getenv("account_reference"),
		Endpoint:         endpoint}
	zone := os.Args[1]
	recs, _ := provider.GetRecords(ctx, zone)
	for _, r := range recs {
		switch rec := r.(type) {
		case libdns.Address:
			fmt.Printf("Address Record - Name: %s, IP: %s, TTL: %s\n", rec.Name, rec.IP, rec.TTL)
		case libdns.CNAME:
			fmt.Printf("CNAME Record - Name: %s, Target: %s, TTL: %s\n", rec.Name, rec.Target, rec.TTL)
		case libdns.TXT:
			fmt.Printf("TXT Record - Name: %s, Text: %s, TTL: %s\n", rec.Name, rec.Text, rec.TTL)
		default:
			fmt.Printf("Unknown Record Type: %T\n", r)
			fmt.Printf("Record details: %+v\n", r)
		}
	}
	added, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test", TTL: time.Duration(300) * time.Second, IP: netip.MustParseAddr("8.8.8.8")},
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Added record:", added)
	deleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "todelete", Text: "this will go away"},
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Deleted record:", deleted)

	// Test SetRecords functionality
	updated, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test", TTL: time.Duration(600) * time.Second, IP: netip.MustParseAddr("1.1.1.1")},
		libdns.CNAME{Name: "alias", TTL: time.Duration(600) * time.Second, Target: "test"},
		libdns.TXT{Name: "example", TTL: time.Duration(600) * time.Second, Text: "sample text"},
	})
	if err != nil {
		fmt.Println("Error in SetRecords:", err)
	} else {
		fmt.Println("Updated records:", updated)
	}
}
