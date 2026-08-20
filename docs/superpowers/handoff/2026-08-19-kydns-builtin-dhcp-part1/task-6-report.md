# Task 6 report: the conflict probe

## What changed

Created `internal/dhcpd/probe.go` and `internal/dhcpd/probe_test.go`.

`probe.go` defines:
- `Prober` interface with `InUse(ip netip.Addr) bool`, unchanged from the brief.
- `nopProber` (unexported), unchanged from the brief.
- `NewProber(iface string, budget time.Duration) Prober`, unchanged from the brief's signature
  and default-budget behavior (100ms when `budget <= 0`).
- `prober` (unexported), holding `iface` and `budget`.
- `probePort` (33434, arbitrary — the classic traceroute destination port, chosen only because
  it's an unremarkable, obviously-nobody's-listening constant).
- `(*prober).InUse`: sends a throwaway UDP datagram to the candidate address via `nudgeARP`,
  sleeps out the remainder of the budget, then reads and parses `/proc/net/arp`.
- `nudgeARP(ip netip.Addr)`: `net.Dial("udp4", ...)` + one `Write`, both errors ignored.
- `parseARPTable(table, iface string) map[netip.Addr]bool`: kept **exactly** as the brief wrote
  it (signature, body, and doc comment) per the correction — it was already correct.

## The correction, and how it changed the design

The brief's `icmpAnswers` used `net.DialTimeout("ip4:icmp", ...)`, which needs `CAP_NET_RAW`.
The task instructions were explicit that the service only ever has `CAP_NET_BIND_SERVICE` and
that raw sockets are out for good — not a temporary gap. I did not implement `icmpAnswers` at
all; there is no ICMP code in this file.

In its place: `nudgeARP` sends one throwaway UDP datagram to the candidate address on an
arbitrary port. Nothing needs to be listening — the point is the side effect, not the reply
(which is discarded; `InUse` never even attempts to read from the UDP socket). Sending forces
the kernel to resolve L2 for the destination, which populates a real kernel ARP entry — COMPLETE
(flag `0x2`) if something answered, INCOMPLETE or absent otherwise. `InUse` then reads that back
from `/proc/net/arp` through the same `parseARPTable` the brief specified, so the "is this
address alive" judgment is entirely the kernel's, not a heuristic layered on top of a passive
cache read (which, as the correction pointed out, would be close to useless for addresses this
host has never had reason to talk to).

Budget handling: `InUse` computes `deadline := time.Now().Add(p.budget)` before doing anything,
fires the UDP send, then sleeps out whatever's left of the budget before reading the ARP table.
This spends nearly the whole 100ms waiting for a possible ARP reply, which is the right trade-off
here since this is the *only* check performed (no second, ICMP, phase to save budget for). A
manual timed run (see Verification) confirms the whole call lands at ~100.5ms against a 100ms
budget — the ~0.5ms overshoot is the ARP-table read itself, not unbounded.

Errors are non-fatal everywhere in this path: `nudgeARP`'s dial/write errors are silently
dropped, and `InUse` returns `false` if `/proc/net/arp` can't be read. Comment in `InUse`
states why: a false negative just costs one address the client later declines (there's a
DHCPDECLINE path for that); refusing to OFFER because a probe misfired would be worse.

## Test-first process

1. Wrote `probe_test.go` with the two `parseARPTable` tests verbatim from the brief, and
   `TestNopProberNeverBlocks` with the timing assertion dropped (per the correction — kept only
   the "returns false" check).
2. Ran `go test ./internal/dhcpd/ -run 'ARPTable|NopProber' -v` and confirmed the expected
   compile failure:
   ```
   internal/dhcpd/probe_test.go:14:10: undefined: parseARPTable
   internal/dhcpd/probe_test.go:26:5: undefined: parseARPTable
   internal/dhcpd/probe_test.go:32:6: undefined: nopProber
   FAIL    github.com/yoshiofthewire/kydns-server/internal/dhcpd [build failed]
   ```
3. Wrote `probe.go` as described above.
4. Re-ran the full package test suite — all pass (see below).

## Verification commands and output

```
$ go test ./internal/dhcpd/ -v
... (full alloc_test.go and iface_test.go suites) ...
=== RUN   TestParseARPTable
--- PASS: TestParseARPTable (0.00s)
=== RUN   TestParseARPTableIgnoresOtherInterfaces
--- PASS: TestParseARPTableIgnoresOtherInterfaces (0.00s)
=== RUN   TestNopProberNeverBlocks
--- PASS: TestNopProberNeverBlocks (0.00s)
PASS
ok      github.com/yoshiofthewire/kydns-server/internal/dhcpd  0.003s

$ go vet ./internal/dhcpd/
(no output, exit 0)

$ gofmt -l internal/dhcpd/
(no output — nothing needs formatting)
```

### Manual proof against the real artifact (not committed as a test — see "not covered" below)

Per "prove it works, never a proxy," I wrote a throwaway `main.go` under a scratch directory in
the worktree, ran it with `go run`, and deleted it before finishing. It called the real,
unmodified `dhcpd.NewProber` / `InUse` against this dev machine's actual network:

```
p := dhcpd.NewProber("lo", 100*time.Millisecond)
loopback InUse: false   elapsed: 100.490941ms
unreachable InUse (203.0.113.77 via lo): false   elapsed: 100.267795ms

p := dhcpd.NewProber("wlan0", 100*time.Millisecond)
gateway InUse (192.168.20.1, this box's real default gateway): true   elapsed: 100.55953ms
probably-free InUse (192.168.20.250): false   elapsed: 100.467068ms
```

This confirms, against real kernel ARP behavior and not a mock: the probe correctly reports
`true` for a live host that answers ARP (the real gateway), `false` for addresses nothing
answers for, stays within budget in all four cases, and does not error or panic on loopback
(where ARP never applies) or an unreachable-but-routable address. The scratch file and its
directory were removed; `git status --short` shows only the two new tracked files.

## What in `InUse` is not covered by automated tests, and why

None of `nudgeARP`'s or `InUse`'s socket/file behavior is exercised by the committed test suite
— only `parseARPTable` (pure function) and `nopProber.InUse` (trivial constant) are. Specifically
uncovered:

- `nudgeARP`'s `net.Dial("udp4", ...)` and `Write` calls, and their silent-failure path.
- `InUse`'s `time.Sleep` / deadline arithmetic.
- `InUse`'s `os.ReadFile("/proc/net/arp")` call and its silent-failure path.
- The end-to-end wiring: a real UDP send actually causing a real ARP entry to appear that
  `parseARPTable` then finds.

This mirrors the brief's own stance on the ICMP path it originally specified ("needs a network
and privileges... the socket call itself is thin enough to read") and the task instructions'
constraint that tests must not depend on the network or CI host state. `net.Dial("udp4", ...)`
touches the real network stack and `/proc/net/arp` reflects real host/kernel state (interface
names, current neighbor entries) — neither is mockable through the interfaces this task is
allowed to introduce (`Prober`, `NewProber`, `nopProber`, `parseARPTable` are the only names
later tasks depend on; no fake filesystem or fake dialer was specified). Faking them would need
new seams not requested by the brief. I verified this path manually instead (above) as the
"prove it works" check, but that verification is not repeatable via `go test` and is not part of
the committed suite.

## Ambiguities and how I resolved them

- **"a high port"**: the correction didn't name one. I used 33434 (traceroute's traditional
  first probe port) as an arbitrary, obviously-inert constant — a nod to precedent rather than
  a functional requirement.
- **How much of the budget to spend waiting vs. reserving for the read**: resolved by computing
  the deadline up front and sleeping out whatever remains after the send, since there's now only
  one phase (no ICMP fallback) competing for the 100ms.
- **`TestNopProberNeverBlocks` naming**: the correction said to drop the timing assertion "if you
  keep it." I kept the test name and the "returns false" assertion, dropped only the
  `time.Since` check, matching the correction's own suggested minimum.

## Left alone

- `parseARPTable` — kept byte-for-byte as the brief specified, including its doc comment.
- `Prober`, `NewProber`, `nopProber` names/signatures — kept exactly as declared, since later
  tasks depend on them.
- No changes to `iface.go`, `alloc.go`, or their tests.
