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
	if len(os.Args) < 5 {
		fmt.Println("Usage: ", os.Args[0], "<zone>", "<name>", "<type>", "<value>")
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
	name := os.Args[2]
	rtype := os.Args[3]
	value := os.Args[4]
	var record libdns.Record
	switch rtype {
	case "A":
		record = libdns.Address{Name: name, TTL: time.Duration(3600) * time.Second, IP: netip.MustParseAddr(value)}
	case "CNAME":
		record = libdns.CNAME{Name: name, TTL: time.Duration(3600) * time.Second, Target: value}
	case "TXT":
		record = libdns.TXT{Name: name, TTL: time.Duration(3600) * time.Second, Text: value}
	default:
		fmt.Println("Unsupported record type")
		os.Exit(1)
	}
	added, err := provider.AppendRecords(ctx, zone, []libdns.Record{record})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Added record:", added)
}
