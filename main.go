package main

import (
	"fmt"
)

func main() {
	ips, err := resolve("bramer.com", 1)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("ip: %s\n", ips)
}
