package main

import (
	"context"
	"fmt"
	"os"

	"github.com/libdns/libdns"
	"github.com/libdns/metaname"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ", os.Args[0], "<zone>")
		os.Exit(1)
	}
	ctx := context.TODO()
	endpoint := "https://test.metaname.net/api/1.1"
	val, ok := os.LookupEnv("api_endpoint")
	if ok {
		endpoint = val
	}
	provider := metaname.Provider{APIKey: os.Getenv("api_key"),
		AccountReference: os.Getenv("account_reference"),
		Endpoint:         endpoint}
	zone := os.Args[1]
	recs, err := provider.GetRecords(ctx, zone)
	if err != nil {
		fmt.Println(err)
	}
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
		}
	}
}
