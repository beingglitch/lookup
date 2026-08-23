package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/beingglitch/lookup"
)

func main() {

	qtype := flag.String("type", "A", "DNS record type to query (A, AAAA)")
	flag.Parse()

	domainName := flag.Arg(0) // positional arguments: flag.Arg()

	val, ok := lookup.RecordTypes[*qtype]

	if ok {
		ips, err := lookup.Resolve(domainName, val)
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		fmt.Printf("ip: %s\n", ips)
	} else {
		fmt.Println("invalid record type")
		os.Exit(1)
	}
}
