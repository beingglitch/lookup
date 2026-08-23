package lookup

import (
	"context"
	"fmt"
	"time"
)

var RecordTypes = map[string]uint16{
	"A":    1,
	"AAAA": 28,
}

func getGluedIPs(records []ResourceRecord) []string {

	var ips []string

	for _, record := range records {
		switch record.Type {
		case 0x01:
			data := record.Data
			ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3]))
		case 0x1C:
			data := record.Data
			ips = append(ips, fmt.Sprintf("[%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x]", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]))
		}
	}

	return ips
}

type queryResult struct {
	message Message
	err     error
}

func recursiveResolver(ctx context.Context, servers []string, query []byte) (Message, error) {

	if len(servers) == 0 {
		return Message{}, fmt.Errorf("no nameservers available to query")
	}

	ch := make(chan queryResult, len(servers))

	for _, server := range servers {

		go func(server string) {
			response, err := sendQuery(ctx, server, query)

			ch <- queryResult{
				message: decodeMessage(response),
				err:     err,
			}

		}(server)
	}

	var lastError error

	for range servers {
		select {
		case result := <-ch:
			if result.err != nil {
				fmt.Printf("%v", result.err)
				lastError = result.err
				break
			}

			message := result.message

			if len(message.Answers) > 0 {
				return message, result.err
			}

			return recursiveResolver(ctx, getGluedIPs(message.Additional), query)
		case <-ctx.Done():
			return Message{}, ctx.Err()
		}
	}
	return Message{}, lastError
}

func Resolve(name string, qtype uint16) ([]string, error) {
	query := encodeQuery(name, qtype)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// query to root servers; There are 13 root servers
	answer, err := recursiveResolver(ctx, rootServer, query)

	return getGluedIPs(answer.Answers), err
}
