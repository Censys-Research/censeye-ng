package main

import (
	"context"
	"fmt"
	"os"

	"github.com/censys-research/censeye-ng/pkg/censeye"
	censys "github.com/censys/censys-sdk-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <host>", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	c := censeye.New(
		censeye.WithClient(censys.New(
			censys.WithSecurity(os.Getenv("CENSYS_PLATFORM_TOKEN")),
			censys.WithOrganizationID(os.Getenv("CENSYS_PLATFORM_ORGID")))))

	res, err := c.Run(context.Background(), host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running censeye: %v\n", err)
		os.Exit(1)
	}

	for _, r := range res {
		fmt.Println(r.GetHost())
		for _, row := range r.GetData() {
			ptr := " "
			if row.GetIsInteresting() {
				ptr = "*"
			}
			fmt.Printf("%s%10d %s\n", ptr, row.GetCount(), row.GetCenqlQuery())
		}
	}
}
