package main

import (
	"fmt"
)

func main() {
	ip, err := resolve("librarynear.com", 1)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("ip: %s\n", ip)
}
