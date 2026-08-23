package lookup

import (
	"context"
	"net"
)

func sendQuery(ctx context.Context, server string, query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", server+":53")

	if err != nil {
		return query, err
	}

	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	conn.Write(query)

	response := make([]byte, 512)

	n, err := conn.Read(response)

	return response[:n], err
}
