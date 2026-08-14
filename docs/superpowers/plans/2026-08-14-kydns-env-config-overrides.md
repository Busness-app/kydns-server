# Environment Overrides for the File-Owned Settings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the five settings the config file still owns at every start also be set from the environment, so a container gains a replication listener from one unRAID template field instead of a hand-made single-file bind mount.

**Architecture:** `config.Load` gains one step, `overlayEnv`, between unmarshalling the YAML and applying defaults. It walks a fixed table of five `{variable, field}` pairs and replaces the file's value when the variable is set and non-empty, recording which variables it applied. Because the overlay lands before `applyDefaults` and before `validate`, environment values suppress defaults and get exactly the same validation as file values — including the rule that a node is never both a primary and a replica.

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3`, stdlib `os`/`log/slog`, `t.Setenv` for tests. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-14-kydns-env-config-overrides-design.md`

## Global Constraints

- Exactly five variables, no more: `KYDNS_DATA_DIR`, `KYDNS_DNS_LISTEN`, `KYDNS_ADMIN_LISTEN`, `KYDNS_REPLICATION_LISTEN`, `KYDNS_REPLICATION_PRIMARY`.
- Naming is mechanical: `KYDNS_` + the YAML path with dots as underscores, uppercased.
- The environment wins over the file.
- An empty variable is **not** an override — it is skipped, leaving the file value standing.
- No secret is ever read from the environment. These five are paths and addresses only.
- `kydns.docker.yaml` and `Dockerfile` must not change. The image needing no rebuild is the point.
- Tests run with `make test`, which is `CGO_ENABLED=0 go test ./...`.
- `internal/config/config_test.go` uses no `t.Parallel`; do not add it, because `t.Setenv` is incompatible with parallel tests.

---

### Task 1: The overlay itself

**Files:**
- Modify: `internal/config/config.go` (add the table, `overlayEnv`, `EnvOverrides`, the `envApplied` field, and one line in `Load`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `func (c *Config) overlayEnv(getenv func(string) string)` — unexported, applies the table.
  - `func (c *Config) EnvOverrides() []string` — the variable names that replaced a file value, in table order. Task 2 and Task 3 both read this.
  - `func (c *Config) source(env string) string` — unexported, returns `env` if that variable was applied, otherwise the string `"the config file"`. Task 2 uses it.

- [ ] **Step 1: Write the failing tests**

Add to the end of `internal/config/config_test.go`:

```go
func TestEnvOverridesFileValues(t *testing.T) {
	t.Setenv("KYDNS_DATA_DIR", "/srv/kydns")
	t.Setenv("KYDNS_DNS_LISTEN", "0.0.0.0:5353")
	t.Setenv("KYDNS_ADMIN_LISTEN", "0.0.0.0:8053")
	t.Setenv("KYDNS_REPLICATION_LISTEN", "0.0.0.0:8443")

	c, err := Load(write(t, "data_dir: /var/lib/kydns\ndns:\n  listen: \":53\"\nadmin:\n  listen: \"127.0.0.1:8053\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/srv/kydns" {
		t.Errorf("DataDir = %q, want /srv/kydns", c.DataDir)
	}
	if c.DNS.Listen != "0.0.0.0:5353" {
		t.Errorf("DNS.Listen = %q, want 0.0.0.0:5353", c.DNS.Listen)
	}
	if c.Admin.Listen != "0.0.0.0:8053" {
		t.Errorf("Admin.Listen = %q, want 0.0.0.0:8053", c.Admin.Listen)
	}
	if c.Replication.Listen != "0.0.0.0:8443" {
		t.Errorf("Replication.Listen = %q, want 0.0.0.0:8443", c.Replication.Listen)
	}
}

// Tested apart from the four above, because a node is a primary or a replica
// and never both.
func TestEnvSetsTheReplicaPrimary(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_PRIMARY", "10.0.0.2:8443")

	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Replication.Primary != "10.0.0.2:8443" {
		t.Errorf("Replication.Primary = %q, want 10.0.0.2:8443", c.Replication.Primary)
	}
}

// An unRAID template field left blank must not demote a working primary to
// standalone, so an empty variable is not an override.
func TestEmptyEnvIsNotAnOverride(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_LISTEN", "")

	c, err := Load(write(t, "data_dir: /tmp/x\nreplication:\n  listen: \"0.0.0.0:8443\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Replication.Listen != "0.0.0.0:8443" {
		t.Errorf("Replication.Listen = %q, want the file value 0.0.0.0:8443", c.Replication.Listen)
	}
	if got := c.EnvOverrides(); len(got) != 0 {
		t.Errorf("EnvOverrides() = %v, want none", got)
	}
}

// The overlay runs before applyDefaults, or admin.listen's default would win
// over the operator's variable.
func TestEnvBeatsTheDefault(t *testing.T) {
	t.Setenv("KYDNS_ADMIN_LISTEN", "0.0.0.0:8053")

	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Admin.Listen != "0.0.0.0:8053" {
		t.Errorf("Admin.Listen = %q, want 0.0.0.0:8053", c.Admin.Listen)
	}
}

func TestEnvOverridesAreRecorded(t *testing.T) {
	t.Setenv("KYDNS_DNS_LISTEN", "0.0.0.0:5353")
	t.Setenv("KYDNS_REPLICATION_LISTEN", "0.0.0.0:8443")

	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"KYDNS_DNS_LISTEN", "KYDNS_REPLICATION_LISTEN"}
	if got := c.EnvOverrides(); !reflect.DeepEqual(got, want) {
		t.Errorf("EnvOverrides() = %v, want %v", got, want)
	}
}

// The overlay runs before validate, so a bad address fails the same way from
// either source.
func TestEnvAddressesAreValidated(t *testing.T) {
	for name, env := range map[string][2]string{
		"bad admin listen":       {"KYDNS_ADMIN_LISTEN", "localhost"},
		"bad replication listen": {"KYDNS_REPLICATION_LISTEN", "not-an-address"},
		"primary as a url path":  {"KYDNS_REPLICATION_PRIMARY", "10.0.0.2:8443/replica"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			if _, err := Load(write(t, "data_dir: /tmp/x\n")); err == nil {
				t.Fatalf("Load() error = nil, want error for %s=%s", env[0], env[1])
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/config/ -run 'TestEnv|TestEmptyEnv' -v`

Expected: FAIL to compile with `c.EnvOverrides undefined (type *Config has no field or method EnvOverrides)`.

- [ ] **Step 3: Add the table and the field**

In `internal/config/config.go`, add the `envApplied` field to `Config` (after `explicitEmptyDomain`, inside the same struct):

```go
	// envApplied names the environment variables that replaced a file value,
	// in table order. Startup logs them, and the mutual-exclusion error reads
	// them to say which source each key came from.
	envApplied []string
```

Then add, immediately after the `ReplicationConfig` type:

```go
// envOverride is one file-owned key and the variable that can replace it.
// Only the five keys the file still owns at every start are here: every other
// key seeds a fresh database once, so a variable for it would silently do
// nothing on a server that has already been configured.
//
// A slice, not a map: the applied list is logged and quoted in errors, and map
// iteration order would make both vary run to run.
type envOverride struct {
	name  string
	field func(*Config) *string
}

var envOverrideTable = []envOverride{
	{"KYDNS_DATA_DIR", func(c *Config) *string { return &c.DataDir }},
	{"KYDNS_DNS_LISTEN", func(c *Config) *string { return &c.DNS.Listen }},
	{"KYDNS_ADMIN_LISTEN", func(c *Config) *string { return &c.Admin.Listen }},
	{"KYDNS_REPLICATION_LISTEN", func(c *Config) *string { return &c.Replication.Listen }},
	{"KYDNS_REPLICATION_PRIMARY", func(c *Config) *string { return &c.Replication.Primary }},
}

// overlayEnv replaces file values with the environment. An empty variable is
// skipped rather than treated as an explicit clear: unRAID templates carry
// fields left blank, and clearing on blank would demote a working primary to
// standalone from a field nobody filled in. Turning replication off stays what
// it is — removing the key from the file.
func (c *Config) overlayEnv(getenv func(string) string) {
	for _, o := range envOverrideTable {
		v := getenv(o.name)
		if v == "" {
			continue
		}
		*o.field(c) = v
		c.envApplied = append(c.envApplied, o.name)
	}
}

// EnvOverrides names the environment variables that replaced a file value.
func (c *Config) EnvOverrides() []string {
	return append([]string(nil), c.envApplied...)
}

// source names where a key's value came from. It exists for the one error that
// involves two keys at once, which would otherwise send an operator grepping a
// file that holds only one of them.
func (c *Config) source(env string) string {
	for _, k := range c.envApplied {
		if k == env {
			return env
		}
	}
	return "the config file"
}
```

- [ ] **Step 4: Call it from Load**

In `internal/config/config.go`, in `Load`, insert the overlay between the domain probe and `applyDefaults`:

```go
	c.explicitEmptyDomain = probe.DNS.PrivateDomain != nil && *probe.DNS.PrivateDomain == ""

	c.overlayEnv(os.Getenv)
	c.applyDefaults()
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/config/ -v`

Expected: PASS, including the pre-existing `TestLoadAppliesDefaults`, `TestLoadRejects`, and `TestBothReplicationKeysIsAnError`.

`go vet` will flag `source` as unused until Task 2 wires it in. That is expected; do not delete it.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): read the five file-owned settings from the environment"
```

---

### Task 2: Mutual exclusion names its sources

**Files:**
- Modify: `internal/config/config.go:156-159` (the mutual-exclusion error in `validate`)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `func (c *Config) source(env string) string` from Task 1.
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
// The file holds one key and the environment the other, so an error naming
// only the two keys would send the operator grepping a file that has one.
func TestBothReplicationKeysAcrossSourcesNamesEachSource(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_PRIMARY", "10.0.0.2:8443")

	_, err := Load(write(t, "data_dir: /tmp/x\nreplication:\n  listen: \"0.0.0.0:8443\"\n"))
	if err == nil {
		t.Fatal("a node configured as both primary and replica started")
	}
	for _, want := range []string{"KYDNS_REPLICATION_PRIMARY", "the config file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/config/ -run TestBothReplicationKeysAcrossSources -v`

Expected: FAIL with `error "invalid config: replication.listen and replication.primary are mutually exclusive: ..." does not name KYDNS_REPLICATION_PRIMARY`.

- [ ] **Step 3: Attribute the sources in the error**

In `internal/config/config.go`, replace the mutual-exclusion branch in `validate`:

```go
	if c.Replication.Listen != "" && c.Replication.Primary != "" {
		return fmt.Errorf("replication.listen (from %s) and replication.primary (from %s) "+
			"are mutually exclusive: a node is a primary or a replica, never both",
			c.source("KYDNS_REPLICATION_LISTEN"), c.source("KYDNS_REPLICATION_PRIMARY"))
	}
```

`errors` stays imported — `validate` still uses `errors.New` for the `data_dir` check.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/config/ -v`

Expected: PASS. `TestBothReplicationKeysIsAnError` still passes: it asserts the message contains `replication.listen` and `replication.primary`, which the new wording keeps.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "fix(config): say which source set each replication key when both are set"
```

---

### Task 3: Startup says what the environment overrode

**Files:**
- Modify: `internal/app/serve.go` (add `logEnvOverrides`, call it in `Serve` after `config.Load`)
- Test: `internal/app/serve_test.go`, `internal/app/role_test.go`

**Interfaces:**
- Consumes: `func (c *config.Config) EnvOverrides() []string` from Task 1.
- Produces: `func logEnvOverrides(cfg *config.Config, logger *slog.Logger)` — unexported, logs one line when the list is non-empty and nothing when it is empty.

- [ ] **Step 1: Write the failing tests**

Add to `internal/app/serve_test.go`:

```go
// A variable set once and forgotten otherwise overrides the file forever with
// nothing in the log to say why the file is being ignored.
func TestLogEnvOverridesNamesTheVariables(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_LISTEN", "0.0.0.0:8443")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kydns.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logEnvOverrides(cfg, slog.New(slog.NewTextHandler(&buf, nil)))

	if !strings.Contains(buf.String(), "KYDNS_REPLICATION_LISTEN") {
		t.Errorf("log %q does not name the variable that was applied", buf.String())
	}
}

func TestLogEnvOverridesSaysNothingWhenThereAreNone(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kydns.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logEnvOverrides(cfg, slog.New(slog.NewTextHandler(&buf, nil)))

	if buf.Len() != 0 {
		t.Errorf("logged %q, want nothing when no variable was applied", buf.String())
	}
}
```

Add to `internal/app/role_test.go`, proving the value reaches the role decision rather than stopping at the struct:

```go
func TestEnvAloneMakesThisNodeAPrimary(t *testing.T) {
	t.Setenv("KYDNS_REPLICATION_LISTEN", "0.0.0.0:8443")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kydns.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := RoleFrom(cfg.Replication); got != RolePrimary {
		t.Errorf("RoleFrom() = %q, want %q", got, RolePrimary)
	}
}
```

`internal/app/role_test.go` already imports `config` and `testing`; add `os` and `path/filepath`. `internal/app/serve_test.go` already imports `os`, `path/filepath`, `strings` and `testing`; add `bytes`, `log/slog`, and `github.com/yoshiofthewire/kydns-server/internal/config`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/app/ -run 'TestLogEnvOverrides|TestEnvAloneMakes' -v`

Expected: FAIL to compile with `undefined: logEnvOverrides`. `TestEnvAloneMakesThisNodeAPrimary` should pass already — it exercises Task 1's overlay through `RoleFrom`, and is here to keep that path from regressing.

- [ ] **Step 3: Add the helper and call it**

In `internal/app/serve.go`, add after the `Serve` function:

```go
// logEnvOverrides records which file-owned settings the environment replaced.
// Without it, a variable set once and forgotten contradicts the operator's
// file at every start with nothing to say so.
func logEnvOverrides(cfg *config.Config, logger *slog.Logger) {
	keys := cfg.EnvOverrides()
	if len(keys) == 0 {
		return
	}
	logger.Info("configuration overridden from the environment",
		"variables", strings.Join(keys, " "),
		"note", "these replace the matching keys in the config file")
}
```

And call it in `Serve`, immediately after the `config.Load` error check:

```go
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err // fail fast: never run half-configured
	}
	logEnvOverrides(cfg, logger)
```

Check that `strings` is imported in `serve.go`; add it if not.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/app/ -run 'TestLogEnvOverrides|TestEnvAloneMakes' -v`

Expected: PASS, three tests.

- [ ] **Step 5: Run the whole suite**

Run: `make test`

Expected: PASS across all packages. This is the first point where every package sees the new `Load` behaviour.

- [ ] **Step 6: Commit**

```bash
git add internal/app/serve.go internal/app/serve_test.go internal/app/role_test.go
git commit -m "feat(app): log which settings the environment overrode"
```

---

### Task 4: Documentation

**Files:**
- Modify: `kydns.example.yaml:7-17` (the two-kinds-of-setting header)
- Modify: `README.md:96-110` (the file-owned settings table) and `README.md:586-596` (the unRAID section)
- Modify: `docker-compose.yml` (the Setup comment block at the end)

**Interfaces:**
- Consumes: the five variable names from Task 1.
- Produces: nothing code depends on.

- [ ] **Step 1: Update the config file's own header**

In `kydns.example.yaml`, after the paragraph ending "read at every start and changing them means restarting.", add:

```yaml
# Each of those five can also be set in the environment, which is how you
# configure a container without mounting a file over this one:
#
#   KYDNS_DATA_DIR  KYDNS_DNS_LISTEN  KYDNS_ADMIN_LISTEN
#   KYDNS_REPLICATION_LISTEN  KYDNS_REPLICATION_PRIMARY
#
# The variable wins over this file. A variable set to nothing is ignored, not
# treated as empty, so a blank field in a container template cannot silently
# switch off something this file turned on.
```

- [ ] **Step 2: Update the README's settings table**

In `README.md`, after the sentence "Setting both is a startup error. See [Replication](#replication).", add:

```markdown
All five can also come from the environment — `KYDNS_DATA_DIR`,
`KYDNS_DNS_LISTEN`, `KYDNS_ADMIN_LISTEN`, `KYDNS_REPLICATION_LISTEN`,
`KYDNS_REPLICATION_PRIMARY` — which is how a container is configured without
mounting a file. The variable wins over the file, and startup logs which
variables it applied. A variable set to nothing is ignored rather than treated
as empty, so a blank field in a container template cannot switch off something
the file turned on. Setting `replication.listen` in the file and
`KYDNS_REPLICATION_PRIMARY` in the environment is the same startup error as
setting both in the file, and the message says which source each came from.
```

- [ ] **Step 3: Fix the unRAID section, which is now wrong**

`README.md` currently claims "On Unraid there is no YAML to edit at all. All three file-owned keys are the container template's job" — true until you want replication, which has no port mapping to stand in for it. Replace that paragraph's second and third sentences so it reads:

```markdown
On Unraid there is no YAML to edit at all. The three keys a single server needs
are the container template's job: one volume mapping for `data_dir`, and two
port mappings for `dns.listen` and `admin.listen`. The baked-in
`kydns.docker.yaml` already sets the two that need it, and the template's
mappings decide where they land on the host.

Replication is the fourth, and it has no port mapping to stand in for it. Add
it as a template **Variable** rather than mounting a config file: Edit the
container, *Add another Path, Port, Variable...*, Config Type **Variable**, Key
`KYDNS_REPLICATION_LISTEN`, Value `0.0.0.0:8443` for a primary — or
`KYDNS_REPLICATION_PRIMARY` with the primary's `host:port` for a replica.
Apply, which restarts the container, which is what picking up a file-owned key
takes anyway. On a `br0` address that port needs no mapping; it is already on
the container's own LAN address.
```

- [ ] **Step 4: Note it in the compose file's setup block**

In `docker-compose.yml`, in the numbered Setup comment block, after step 2's explanation of the two settings to change, add:

```yaml
#    Or set them in the environment instead of mounting a file at all:
#    KYDNS_DATA_DIR, KYDNS_DNS_LISTEN, KYDNS_ADMIN_LISTEN, and for a second
#    server KYDNS_REPLICATION_LISTEN or KYDNS_REPLICATION_PRIMARY. A variable
#    beats the file, and an empty one is ignored.
```

- [ ] **Step 5: Verify the docs match the code**

Run: `grep -o 'KYDNS_[A-Z_]*' README.md kydns.example.yaml docker-compose.yml | sort -u`

Expected: exactly `KYDNS_ADMIN_LISTEN`, `KYDNS_DATA_DIR`, `KYDNS_DNS_LISTEN`, `KYDNS_REPLICATION_LISTEN`, `KYDNS_REPLICATION_PRIMARY`, plus the pre-existing compose variables (`KYDNS_CONFIG`, `KYDNS_GATEWAY`, `KYDNS_IP`, `KYDNS_NETWORK`, `KYDNS_NET_DRIVER`, `KYDNS_PARENT_IF`, `KYDNS_SUBNET`) and the CLI's `KYDNS_TOKEN` and `KYDNS_URL`. Any other `KYDNS_*` in the docs is a typo — the five must match `envOverrideTable` in `internal/config/config.go` exactly.

- [ ] **Step 6: Confirm the image is untouched**

Run: `git status --short kydns.docker.yaml Dockerfile`

Expected: no output. An image change here means the feature missed its point.

- [ ] **Step 7: Commit**

```bash
git add README.md kydns.example.yaml docker-compose.yml
git commit -m "docs: configure the file-owned settings from the environment"
```

---

### Task 5: Verify end to end against a real container

**Files:**
- No files change. This task confirms the feature does the thing it was built for.

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: nothing.

- [ ] **Step 1: Build the image with no config change**

Run: `docker build -t kydns:envtest .`

Expected: builds. `kydns.docker.yaml` inside it still has no `replication` key.

- [ ] **Step 2: Start it with the variable and nothing mounted**

Run:

```bash
docker run --rm -d --name kydns-envtest \
  -e KYDNS_REPLICATION_LISTEN=0.0.0.0:8443 \
  -e KYDNS_ADMIN_LISTEN=0.0.0.0:8053 \
  -p 18053:8053 kydns:envtest
```

Expected: starts. No config file is mounted, so the baked `kydns.docker.yaml` is in play and only the environment adds replication.

- [ ] **Step 3: Confirm the log says what it applied and that it is serving replicas**

Run: `docker logs kydns-envtest`

Expected: a line `configuration overridden from the environment` with `variables="KYDNS_ADMIN_LISTEN KYDNS_REPLICATION_LISTEN"` — table order, not the order the flags were typed — and a line `serving replicas` with `listen=0.0.0.0:8443`.

- [ ] **Step 4: Confirm the mutual-exclusion error crosses sources**

Run:

```bash
docker run --rm \
  -e KYDNS_REPLICATION_LISTEN=0.0.0.0:8443 \
  -e KYDNS_REPLICATION_PRIMARY=10.0.0.2:8443 kydns:envtest
```

Expected: exits non-zero, naming both variables as the sources.

- [ ] **Step 5: Clean up**

Run: `docker rm -f kydns-envtest && docker rmi kydns:envtest`

- [ ] **Step 6: Run the full suite one last time and push**

Run: `make test`

Expected: PASS.
