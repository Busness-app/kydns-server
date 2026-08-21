# Final fix wave — report

Branch `worktree-dhcp-part1`, on top of `64616a0`. All sixteen findings in
`final-findings.md` are fixed. No test in this wave opens a socket.

## C2 + I4 — the rogue probe, and the listener a refused save used to kill

One fix, in three places.

- `internal/dhcpd/rogue.go` — `DetectForeign` and `collectForeign` no longer take
  `self`, and nothing is filtered as "ours". dnsmasq, ISC dhcpd and
  systemd-networkd all set option 54 to the address of the interface they
  answered on, so a co-resident server identifies itself as us; the filter could
  only ever hide the one deployment this feature most has to get right. The
  parameter is gone rather than passed empty, so it cannot come back by
  accident. Part 2's periodic probe, which is the only caller that could need a
  self filter, will have a bound listener to gate it on.
- `internal/app/dhcp.go` — `Reconcile` builds before it stops, and stops only on
  success (`fail()` keeps `current` describing the listener that is still up, so
  the next save retries). `needsProbe()` skips the rogue check when a listener
  is already bound to this interface: that segment was cleared when it started
  and it is holding the port now.
- Fail-open is untouched (R22): a probe that returns an error still refuses.

RED at `64616a0`:

    --- FAIL: TestREDCoResidentServerIsHidden
        collectForeign = [], want one entry: a server on this host is still a second server
    --- FAIL: TestREDRefusedBuildLeavesTheRunningListenerAlone
        a build that refused (interface "kydns-no-such-iface0": route ip+net: no such
        network interface) took the working listener down, with nothing to bring it back

Pinned by `TestCollectForeignReportsAServerSharingOurAddress`,
`TestBuildRefusesWhenAnotherServerAnswers`, `TestBuildRefusesWhenTheProbeCannotRun`
(R22), `TestBuildSkipsTheProbeWhenAListenerIsAlreadyBound`, `TestNeedsProbe`,
`TestARefusedBuildLeavesTheRunningListenerAlone`.

## C1 — one forged DECLINE destroyed any client's lease

`internal/dhcpd/alloc.go`: `Decline(mac string, ip netip.Addr) bool`. It drops
the lease only when `a.byIP[ip] == mac`, and quarantines only when
`a.inRange(ip)`. The bool keeps the store in step: `internal/dhcpd/server.go`
deletes the persisted row and calls `OnChange` only when a lease actually moved.

RED at `64616a0`:

    --- FAIL: TestREDDeclineFromAnotherClient
        leases after one spoofed DECLINE = 0, want the victim's lease intact
    --- FAIL: TestREDDeclineOutsideTheRange
        quarantine holds 1 addresses; 192.168.1.250 is not ours to quarantine

Pinned by `TestDeclineFromAnotherClientLeavesTheLeaseAlone` and
`TestDeclineOutsideTheRangeIsNotQuarantined`; `TestDeclineQuarantines` still
covers the legitimate case.

## I3 — the seam

`dhcpRunner` gained `qualifies`, `inspect` and `detectForeign`, nil meaning the
real one. That is what makes the five build tests above possible without an
interface, a socket or `CAP_NET_RAW`.

## I2 — the hostname check was not atomic with the commit

The arbitration moved inside `Allocator.allocate` under `a.mu`
(`nameTakenLocked`); the exported `NameTaken` had no other caller and is gone.
`Server.allocate` compares the hostname it asked for with the one it got, purely
to log the loser. RED at `64616a0`, run under `-race`:

    --- FAIL: TestREDConcurrentRequestsCannotShareAHostname
        round 7: 3 leases hold the hostname "laptop" at once

Pinned by `TestConcurrentRequestsCannotShareAHostname` (50 rounds, three
concurrent REQUESTs each) and `TestASecondClaimOnAHostnameGetsNoName`.

## I1 — map order into an order-sensitive digest

`Server.Leases()` sorts by address. RED at `64616a0`: `TestREDLeasesAreOrderedByAddress`
failed on poll 3 of 20 with an unchanged lease set. Pinned by
`TestLeasesAreOrderedByAddress`. `digest`'s comment in `internal/discovery/poller.go`
now states the requirement instead of describing only the file parser.

## I5 — a REQUEST we cannot satisfy got an ACK for a different address

`internal/dhcpd/server.go`: `askedFor(m)` reads option 50, then `ciaddr`. The
subnet check now covers both, and after `allocate` a named address that does not
match what we can give is NAKed. Two branches, exactly as prescribed; nothing
else needed to change.

RED at `64616a0`:

    --- FAIL: TestREDInSubnetOutOfPoolRequestIsNaked
        client asked for 192.168.1.50 in INIT-REBOOT; server replied ACK yiaddr=192.168.1.10
    --- FAIL: TestREDRenewalWeDoNotKnowIsNaked
        RENEWING client with ciaddr 192.168.1.11 got ACK yiaddr=192.168.1.10, want a NAK

Pinned by `TestRequestForAnInSubnetAddressOutsideThePoolIsNaked`,
`TestRenewalOfALeaseWeDoNotKnowIsNaked` and `TestRenewalOfALeaseWeDoKnowIsAcked`.

Known cost, small and self-healing: `allocate` has already committed by the time
the mismatch is seen, so the address it picked is held for one lease term. The
client re-DISCOVERs, rule 2 hands it that same address, and the REQUEST that
follows matches and is ACKed. Making this a dry run would have meant threading a
no-commit mode through the allocator, which is more than the finding asks for.

## The nine small items

| Finding | Change | Test |
| --- | --- | --- |
| `parseSetting` did not trim | `strings.TrimSpace` in `internal/app/dhcp.go` | `TestParseSettingNamesTheField` (padded case) |
| malformed `dhcp_secondary_dns` dropped silently | returns the named parse error | `TestBuildRefusesAMalformedSecondaryDNS` |
| `liveSettings()` not ok wrote seven zeroes | `internal/web/serversettings.go` aborts the save with a reason; the two `liveSettings` calls became one | `TestPostServerSettingsRefusesWhenTheCurrentValuesCannotBeRead` |
| dotted field names on the wire | `internal/settings/validate.go` uses `dhcp_enabled`, `dhcp_interface`, `dhcp_range_start`, `dhcp_range_end`, `dhcp_gateway`, `dhcp_secondary_dns`, `dhcp_lease_seconds` | `TestDHCPValidationRejects`, which now also rejects any dotted field |
| explicit `0.0.0.0` in option 54 | falls back to the source address | `TestCollectForeignFallsBackToTheSourceOnAnUnspecifiedServerID` |
| replica reported no reason | `roleRefusal` / `errReplicaNoDHCP`; the API already reports `running` and `error` separately | `TestReconcileOnAReplicaNeverStartsAndSaysWhy` |
| broadcast flag asserted as a struct field | asserts byte 10 of `ToBytes()` | `TestNewProbeDiscoveryAsksForABroadcastReply` |
| stale "requires a restart" heading | deleted from `docs/superpowers/specs/2026-08-13-kydns-settings-in-the-ui-design.md`, replaced with what `Apply` actually does | — |
| `digest` comment | see I1 | — |

RED at `64616a0` for the two with a behavioural claim:

    --- FAIL: TestREDReplicaSaysWhyItIsNotServing
        dhcp_enabled is true and the UI reports running=no with no reason at all
    --- FAIL: TestREDParseSettingTrims
        parseSetting(" 192.168.1.100") = invalid IP; the validator trims and accepts this
    --- FAIL: TestREDPostServerSettingsRefusesWhenTheCurrentValuesCannotBeRead
        the save was applied with all seven DHCP fields written as zero
    --- FAIL: TestREDUnspecifiedServerIDFallsBackToTheSource
        collectForeign = [0.0.0.0 (offering 192.168.1.64)], want the source named

## Deliberately not touched

Everything the brief listed as deferred or accepted: rule 1's missing freeness
check and the R18 `prev.IP == ip` guard, the Discovered page copy, `d.mu` across
`DetectForeign`, option 51 on an INFORM reply, `InUse` sleeping its full budget,
`Snapshot()` shipping node-local values, the `s.cancel` double-`Start`
overwrite, and the malformed-packet counter. No `dhcp_*` column was added to the
`cv_settings_u` trigger, no `cv_` trigger was put on the lease table, and
`dhcpWanted`'s `role != RoleReplica` gate (R1) is unchanged.

## Verification

    go build ./...            clean
    go vet ./...              clean
    gofmt -l internal/ cmd/   no output
    go test ./internal/dhcpd/... -count=1                ok
    go test ./internal/dhcpd/... -race -count=2          ok
    go test ./internal/app/... -count=1 -race            ok
    go test ./... -count=1    19 packages, 0 failures

## Concerns

One, minor: the I5 note above — a NAKed REQUEST leaves the address `allocate`
picked held for one lease term. It is reclaimed by the client's own re-DISCOVER
and expires otherwise.
