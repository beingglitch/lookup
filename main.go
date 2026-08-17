package main

import (
	"fmt"
)

func main() {
	query := encodeQuery("example.com", 1)
	fmt.Printf("query: %x\n", query)

	response := sendQuery("198.41.0.4", query)
	fmt.Printf("response: %x\n & response length: %x\n", response, len(response))

	message := decodeMessage(response)
	fmt.Printf("%+v\n", message)
}
