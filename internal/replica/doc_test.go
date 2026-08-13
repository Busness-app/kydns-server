package replica

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSnapshotRoundTrips(t *testing.T) {
	in := Snapshot{
		SchemaVersion: SchemaVersion,
		ConfigVersion: 41,
		NodeID:        "abc123",
		Config:        json.RawMessage(`{"services":[]}`),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ConfigVersion != 41 || out.NodeID != "abc123" {
		t.Fatalf("round trip lost fields: %+v", out)
	}
	if string(out.Config) != `{"services":[]}` {
		t.Fatalf("Config = %s, want the original bytes", out.Config)
	}
}

// SchemaVersion is the refusal gate in the pull loop. It is checked against
// the wire name rather than against a round trip, because renaming the tag on
// both sides at once round-trips perfectly and still refuses nothing.
func TestSchemaVersionSurvivesTheWire(t *testing.T) {
	b, err := json.Marshal(Snapshot{SchemaVersion: SchemaVersion, ConfigVersion: 41})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"schema_version":1`) {
		t.Fatalf("snapshot on the wire is %s, want a schema_version field", b)
	}

	var snap Snapshot
	if err := json.Unmarshal([]byte(`{"schema_version":1,"config_version":41,"node_id":"abc"}`), &snap); err != nil {
		t.Fatal(err)
	}
	var v VersionReply
	if err := json.Unmarshal([]byte(`{"schema_version":1,"config_version":41,"node_id":"abc"}`), &v); err != nil {
		t.Fatal(err)
	}
	if snap.SchemaVersion != SchemaVersion || v.SchemaVersion != SchemaVersion {
		t.Fatalf("decoded schema versions %d and %d, want %d; the refusal gate reads zero",
			snap.SchemaVersion, v.SchemaVersion, SchemaVersion)
	}
}

func TestSchemaVersionIsOne(t *testing.T) {
	if SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d; bumping it is a wire break and needs a "+
			"migration story, not a constant edit", SchemaVersion)
	}
}
