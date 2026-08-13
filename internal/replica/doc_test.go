package replica

import (
	"encoding/json"
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

func TestSchemaVersionIsOne(t *testing.T) {
	if SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d; bumping it is a wire break and needs a "+
			"migration story, not a constant edit", SchemaVersion)
	}
}
