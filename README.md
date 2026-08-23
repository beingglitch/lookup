# lookup

A recursive DNS resolver build from scratch in Go. No `net.LookupHost`, no DNS libraries. Raw UDP sockets, hand-rolled packet encoding/decoding, and the full root to TLD to authoritive delegation walk, implemented from the wire format up.

## Install

##### As a CLI:

```
go install github.com/beingglitch/lookup/cmd/lookup@latest
```

##### As a library:

```
go get github.com/beingglitch/lookup
```

## Usage

##### CLI:
```
lookup example.com
lookup -type AAAA example.com
```

##### Library:
```go

import "github.com/beingglitch/lookup"
ips, err := lookup.Resolve("example.com", 1) // 1 = A record
```

## How it works

Starting from a harcoded root server, the resolver sends a raw UPD DNS query, decodes the response by hand (including DNS name compression pointers), and follow referrals through the Additional section's glue records until it reaches an authoritative answer.

Multiple candidate servers at each hop are queried concurently via goroutines and a channel, with the first successful response winning and failures retried against the remaining candidates, all bounded by a single `context.Context` deadling for the whole lookup

## What's built

- Hand-rolled DNS messge encoding/decoding, including name compression
- Raw UDP networking with context-based timeouts
- Full recursive delegation walk (root to TLD to authoritative)
- Concurrent server racing, with goroutines, channels and `select`
- Proper error propagation, no panics on expected failures like timeouts
- CLI (`flag`-based) and importable library, sharing one codebase

## Known limitations

- No support yet for out-of-bailwick nameservers (a referral whose nameserver has no glue record, because the nameservers lives outside the delegated zone). This causes some domains to fail to resolve
- No caching yet, every lookup re-walks the full chain.
- IPv6 (AAAA) glue records are parsed and formatted correctly, but this path has not been verified end to end and may depend on the resolving machine's own IPv6 connectivity.

## Roadmap

- [x] DNS message structs (Header, Question, ResourceRecord, Message)
- [x] Wire-format encoder (manual byte encoding, DNS name labels)
- [x] UDP networking with context-based timeouts
- [x] Response parser, including DNS name compression
- [x] Recursive delegation walk (root, TLD, authoritative)
- [x] Proper error propagation instead of panicking
- [x] Concurrent server racing (goroutines, channels, select)
- [x] Split into an importable library plus a CLI entry point
- [x] CLI with the flag package and correct exit codes
- [ ] Unit and table-driven tests (haven't started at all)
- [ ] Small interfaces (Resolver/Transport) for implicit satisfaction
- [ ] Out-of-bailiwick nameserver resolution
- [ ] TTL-aware, thread-safe cache (sync.Mutex)
- [ ] Benchmark tests (go test -bench)
- [ ] Fuzz testing the packet parser (go test -fuzz)
- [ ] Cross-compiled static binaries (Linux, Mac, Windows)

## License

[MIT](LICENSE)