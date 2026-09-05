# Restoring KyDNS from a capsule

A restore needs three things at once, and no two of them are held by the same
party. That is the point.

| What | Where it comes from | Who holds it |
| --- | --- | --- |
| The sealed capsule | KyRecovery (Capsules → newest `KyDNS`), or **Settings → Disaster recovery → Download capsule**, or `kydns export-capsule --out path` | the operator |
| k custodian shares | printed cards, one line each, beginning `ky2-` | k of your custodians, in person |
| A machine to restore onto | any host with the `kydns` binary or the image | the operator |

The capsule alone is inert; k cards alone open nothing. Losing either side
loses the backup, so treat the cards as seriously as the server.

## What a capsule holds

| Member | What it is |
| --- | --- |
| `data/kydns.db` | the whole server: views, services, records, aliases, blacklist lists and rules, settings and local settings, the admin password hash, API tokens, SSO settings, DHCP leases, replication peers, and the audit log |
| `data/backup_key` | 32 bytes. The KyRecovery token stored sealed in the database opens **only** with this file; without it a restored node cannot talk to KyRecovery |
| `data/node_key` | this node's replication identity. Present only when the node has joined or hosted replication; a standalone node has none |
| `config/kydns.yaml` | a record of `data_dir`, `dns.listen` and `admin.listen` as they were. Reference only — it is not the file the server reads |

`data/recovery.pub`, the pinned KyRecovery public key, is **not** a capsule
member. See Step 4.

Everything above comes out of the capsule in the clear. The restore directory
is the live `data_dir`, containing an admin hash and every API token. Create it
mode 700, keep it on a disk you control, and delete it when you are done.

## Before you start

1. **Pick the capsule.** In KyRecovery, open Capsules, take the newest one for
   service `KyDNS`, and write down its id, `created_at` and digest. Anything
   older is a decision, not a default.
2. **Gather k custodians.** k is the threshold you set when you paired
   (Settings shows the pinned key id; KyRecovery shows k of n). Each custodian
   types their own share line — nobody reads a card out to a second person, and
   nobody collects the cards. Share lines begin `ky2-`.
3. **Prepare an empty directory**, mode 700, on the machine doing the restore:
   `mkdir -m 700 restored`. `kydns restore` refuses a directory that is not
   empty, before it asks for a single share.

## Step 1: open the capsule

    usage: kydns restore --capsule path --out directory
    custodian shares are read from stdin, one per line

Shares are read from standard input only. They are never arguments: argv is
visible in `ps` and lands in shell history.

Binary form:

```bash
kydns restore --capsule KyDNS.XXXXXXXX.kycap --out ./restored
```

Docker form — the target directory is created by you and the container runs as
you, so the files come out owned by you rather than by root:

```bash
mkdir -m 700 restored
docker compose run --rm --no-deps --user "$(id -u):$(id -g)" \
  -v "$PWD/cap.kycap:/cap.kycap:ro" -v "$PWD/restored:/restored" \
  kydns restore --capsule /cap.kycap --out /restored
```

Each custodian types their line and presses Enter. After the k-th line, press
Ctrl-D. The command prints the capsule's authenticated manifest — file count,
capsule id, service and version, creation time, recovery key id and payload
hash — and exits 0:

    Restored 3 files from capsule cap-KyDNS-1788609154776731567
      service:      KyDNS (vdrill)
      created:      2026-09-05T11:52:34Z
      recovery key: fe85c333...
      payload hash: 87419e2e...

### When it refuses

| What happened | What it prints |
| --- | --- |
| Fewer than k shares (here, one) | `kydns: shamir: fewer shares than the threshold requires: got 1` |
| Shares from two different splits | `kydns: shamir: shares belong to different splits` |
| The same card typed twice | `kydns: shamir: shares repeat an index` |
| A capsule sealed to a different recovery key | `kydns: capsule is sealed to a different recovery key` |
| A capsule belonging to another product | `kydns: capsule is for service "KyPost", this instance is "KyDNS"; pass -service to override` (there is no such flag on `kydns restore`; restore it with that product's binary) |
| The target directory is not empty | `kydns: restore directory must be empty` |
| A share passed as an argument | the usage text above, exit 2 |

All of these leave the target directory untouched.

The whole suite seals to one recovery key, so these shares would open a KySignOn
or KyPost capsule too. The command refuses one before it combines a single
share: the capsule's service name must be `KyDNS`. Restore another product's
capsule with that product's binary.

## Step 2: check what came out

```bash
ls -la restored/data restored/config
sqlite3 restored/data/kydns.db 'PRAGMA integrity_check; SELECT count(*) FROM services;'
```

`integrity_check` must print `ok`, and the service count should be roughly what
you remember. Compare the capsule id and creation time Step 1 printed against
the ones you noted in KyRecovery; that line is read out of the capsule's
authenticated manifest, so it cannot disagree with the bytes that were opened.

`data/kydns.db` should be mode 600, as should `data/backup_key`. If
`data/node_key` is absent, this node was standalone — that is not a fault.

## Step 3: put it in service

The restored `data/` becomes the contents of the `kydns-data` volume, which the
service mounts at `/var/lib/kydns`.

The runtime image is distroless: it holds the `kydns` binary and nothing else —
no shell, no `cp`, no `ls`. So every step below that has to look at or move
files uses a throwaway `busybox` container with the volume mounted, not the
KyDNS container.

**Find the volume's real name first.** Compose prefixes the project name, which
defaults to the directory name:

```bash
docker volume ls | grep kydns-data          # e.g. kydns-server_kydns-data
vol=$(docker volume ls --format '{{.Name}}' | grep -m1 kydns-data)
```

Everything below uses `$vol`. If nothing matches, the stack has never run here
and the volume does not exist yet; skip to the copy-in.

**Gate: the volume must be empty before you copy anything in.**

```bash
docker compose stop kydns
docker run --rm -v "$vol:/data:ro" busybox ls -A /data
```

That must print nothing. A leftover `kydns.db-wal` next to a restored
`kydns.db` is the hazard: SQLite replays the old write-ahead log into the
restored database on the first open, and you get a silent hybrid of two
servers instead of the one you restored.

If it printed anything, copy the old volume out **before** destroying it:

```bash
mkdir -m 700 old-data
docker run --rm -v "$vol:/data:ro" -v "$PWD/old-data:/old" busybox \
  sh -c 'cp -a /data/. /old/ && find /old -type f | wc -l'
sudo find old-data -type f | wc -l      # must match the count printed above
```

`busybox` runs as root, which is what lets it read a root-owned volume; the
files land in `old-data` owned by root, and mode 700 keeps them yours. Compare
the two counts yourself. Only when they match:

```bash
docker compose down -v                   # deletes the volume
docker volume create "$vol"              # recreate it empty, same name
```

Now copy the restored data in — again as root, because the volume is
root-owned and the KyDNS container drops every capability except
`NET_BIND_SERVICE`, so it has no `CAP_DAC_OVERRIDE` to fix ownership later:

```bash
docker run --rm -v "$vol:/data" -v "$PWD/restored/data:/new:ro" busybox \
  sh -c 'cp -a /new/. /data/ && ls -A /data'
docker compose up -d
docker compose logs kydns | head
```

The `ls -A` should list `kydns.db`, `backup_key`, and `node_key` if the capsule
had one — names only, never contents. The logs should show the DNS and admin
listeners coming up with **no setup token**: a setup token means the database
was not found, which means the copy went somewhere other than `$vol`.

## Step 4: prove it

- `dig @$KYDNS_IP kypost.home.arpa` — any private name you know should answer
  from the restored registry.
- Log in to the admin UI on port 8053 with the **old** password. The hash came
  from the capsule.
- Settings → Disaster recovery still shows the pinned key id and the URL: both live in
  the database, which the capsule carried.
- **Run drill** still passes: it seals and reopens with an ephemeral key and
  never needs the pinned one, so it is a good check that the restored database
  is whole.
- **Back up now** and **Download capsule** will nonetheless fail with `paired but
  the recovery public key is missing or does not match the pin; restore
  recovery.pub or re-pair`. `data/recovery.pub` is not a capsule member,
  so the pinned public key itself did not come across. Two ways back:
  copy `recovery.pub` from `old-data/` if you saved the old volume, or pair
  again with a fresh six-digit code from KyRecovery — `POST
  /api/v1/backup/pair-remote` with `recovery_url` and `pairing_code`, since the
  web form is hidden while the database still reports the server as paired.
  Re-pairing is accepted only to the key already pinned: a different key is
  refused with `already pinned to a different recovery key`, which is the
  guardrail working.
- With `data/backup_key` in place the KyRecovery token from the database opens
  and deposits resume. Without that file nothing will deposit, whatever the
  pairing says.
- Replication: a restored primary that has `data/node_key` keeps its identity
  and its replicas reconnect. A standalone node has no `node_key` and there is
  nothing here to prove.

## Step 5: decide what to trust

Everything you just restored is the world as of the capsule's `created_at`.
Changes made after it are gone unless you re-apply them.

- **Re-apply the gap.** If you saved the old volume, the old audit log lists
  what changed: `sqlite3 old-data/kydns.db "SELECT created_at, actor, action,
  resource FROM audit_events WHERE created_at > <capsule created_at as unix
  seconds> ORDER BY created_at;"`. Redo those by hand.
- **Sessions.** KyDNS sessions are server-side and in memory. The restored
  process starts with none, so every session anywhere is already gone. There is
  nothing to revoke.
- **API tokens.** The capsule carried them, so they still work. If the reason
  you are restoring is a compromise, regenerate each one in Settings; the old
  values in anyone's script keep working until you do.
- **`backup_key`.** Rotating it means unpairing and pairing again: the
  KyRecovery token in the database is sealed under the current key and nothing
  else opens it. Never delete this file while the server is paired — the token
  becomes unreadable and deposits stop.
- **`node_key`.** Rotate by removing this node from replication and joining
  again; the peers re-authorize the new identity.
- **There is no database encryption key in KyDNS.** `kydns.db` is a plain
  SQLite file, protected by file permissions and by the disk it sits on. Do not
  go looking for one to preserve or rotate — the only long-lived secrets are the
  two files above and the custodian shares.

## Afterwards

- `rm -rf restored` and, for the root-owned copy, `sudo rm -rf old-data`. Both
  contain the admin hash and every API token in the clear.
- The custodian cards are unchanged by a restore; combining shares does not
  consume them.
- If a card was exposed during the ceremony, that is a suite-wide event: the one
  recovery key protects every product's capsules, so it needs a new key ceremony
  and a re-pair everywhere, not a fix in KyDNS.
- Take a fresh backup once the restored server is the real one: Settings →
  **Back up now**.

## Drill it

`scripts/restore-drill.sh` runs this whole path against a throwaway 2-of-3 key
on every checkout — it proves the format, the CLI and the refusals in Step 1,
and it takes seconds. It cannot prove your cards.

Once a quarter, do Step 1 for real: pull the newest capsule, get k custodians in
a room, and restore to a scratch directory you delete afterwards. That is the
only test that proves the cards were printed correctly and that the custodians
still have them.

Between drills, Settings → **Run drill** (or `kydns backup-drill`) seals and
reopens a capsule with an ephemeral key inside the running server, which proves
collection and SQLite integrity without touching the recovery key.
