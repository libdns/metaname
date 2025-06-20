package main

import (
	"context"
	"fmt"
	"os"

	"github.com/libdns/libdns"
	"github.com/libdns/metaname"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: ", os.Args[0], "<zone>", "<name>", "<value>")
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
	value := os.Args[3]
	deleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: name, Text: value}, // Example: Adjust based on the record type
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Deleted record:", deleted)
}
