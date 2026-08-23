package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type Header struct {
	ID      uint16 // Used by resolver to verify recieved dns query wrt sent dns query
	Flags   uint16 // 15QR | (14-11)Opcode | 10AA | 9TC | 8RD | 7RA | (6-4)Z | (3-0)RCODE
	QCount  uint16 // How many Questions
	ACount  uint16 // How many Answers
	NSCount uint16 // How many Authorities
	ARCount uint16 // How many Additionals
}

// example.com.  172800  IN  NS  a.iana-servers.net.
// example.com.  172800  IN  NS  b.iana-servers.net.

func encodeHeader(h Header) []byte {
	buf := make([]byte, 12)

	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	binary.BigEndian.PutUint16(buf[2:4], h.Flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ACount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)

	return buf
}

func decodeHeader(data []byte) Header {
	return Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QCount:  binary.BigEndian.Uint16(data[4:6]),
		ACount:  binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func encodeName(name string) []byte {
	var buf []byte

	labels := strings.Split(name, ".")
	for _, label := range labels {
		buf = append(buf, byte((len(label))))
		buf = append(buf, []byte(label)...)
	}

	buf = append(buf, 0)

	return buf
}

func decodeName(data []byte, offset int) (string, int) {
	var label []string

	for {

		length := data[offset]

		if length == 0 {
			offset++
			break
		}

		// 0xC0 - 11000000, 0x3F - 00111111
		if length&0xC0 == 0xC0 {
			pointerOffset := (int(length)&0x3F)<<8 | int(data[offset+1])
			pointedName, _ := decodeName(data, pointerOffset)
			label = append(label, pointedName)
			offset += 2
			break
		}

		offset++
		label = append(label, string(data[offset:offset+int(length)]))
		offset += int(length)
	}

	return strings.Join(label, "."), offset
}

func encodeQuestion(q Question) []byte {
	buf := encodeName(q.Name)

	tempBuf := make([]byte, 4)

	binary.BigEndian.PutUint16(tempBuf[0:2], q.Type)
	binary.BigEndian.PutUint16(tempBuf[2:4], q.Class)

	buf = append(buf, tempBuf...)

	return buf
}

func decodeQuestion(data []byte, offset int) (Question, int) {

	name, offset := decodeName(data, offset)

	question := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
		Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
	}

	return question, offset + 4
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16 // always IN
	TTL   uint32
	Data  []byte
}

func decodeResourceRecord(data []byte, offset int) (ResourceRecord, int) {

	name, offset := decodeName(data, offset)

	rdLength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))

	resourceRecord := ResourceRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
		Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		TTL:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
		Data:  data[offset+10 : offset+10+rdLength],
	}

	return resourceRecord, offset + 10 + rdLength
}

type Message struct {
	Header     Header
	Questions  []Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
}

func decodeMessage(data []byte) Message {
	header := decodeHeader(data)

	var questions []Question
	var answers []ResourceRecord
	var authorities []ResourceRecord
	var additionals []ResourceRecord

	offset := 12
	for range header.QCount {
		var question Question
		question, offset = decodeQuestion(data, offset)
		questions = append(questions, question)
	}

	for range header.ACount {
		var answer ResourceRecord
		answer, offset = decodeResourceRecord(data, offset)
		answers = append(answers, answer)
	}

	for range header.NSCount {
		var authority ResourceRecord
		authority, offset = decodeResourceRecord(data, offset)
		authorities = append(authorities, authority)
	}

	for range header.ARCount {
		var additional ResourceRecord
		additional, offset = decodeResourceRecord(data, offset)
		additionals = append(additionals, additional)
	}

	return Message{
		Header:     header,
		Questions:  questions,
		Answers:    answers,
		Authority:  authorities,
		Additional: additionals,
	}
}

func encodeQuery(name string, qtype uint16) []byte {
	header := Header{
		ID:     1,
		Flags:  0,
		QCount: 1,
	}

	question := Question{
		Name:  name,
		Type:  qtype,
		Class: 1,
	}

	return append(encodeHeader(header), encodeQuestion(question)...)
}

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

var rootServer = []string{"198.41.0.4"}

func resolve(name string, qtype uint16) ([]string, error) {
	query := encodeQuery(name, qtype)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// query to root servers; There are 13 root servers
	answer, err := recursiveResolver(ctx, rootServer, query)

	return getGluedIPs(answer.Answers), err
}
