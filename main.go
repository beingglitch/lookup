package main

import (
	"fmt"
)

func main() {
	ip := resolve("librarynear.com", 1)
	fmt.Printf("ip: %s\n", ip)
}
