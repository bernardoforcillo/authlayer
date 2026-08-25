package scope

import (
	"strings"
	"testing"
)

func TestDefaultIDGeneratorIsUUIDv7(t *testing.T) {
	id := defaultConfig().idgen()
	if len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Fatalf("default id %q is not a canonical UUID", id)
	}
	if id[14] != '7' {
		t.Fatalf("default id %q is not version 7 (char 14 = %q)", id, id[14])
	}
}

func TestWithIDGeneratorStillOverrides(t *testing.T) {
	c := defaultConfig()
	WithIDGenerator(func() string { return "fixed" })(&c)
	if got := c.idgen(); got != "fixed" {
		t.Fatalf("idgen() = %q, want %q", got, "fixed")
	}
}

func TestWithIDGeneratorIgnoresNil(t *testing.T) {
	c := defaultConfig()
	WithIDGenerator(nil)(&c)
	if got := c.idgen(); len(got) != 36 {
		t.Fatalf("nil generator replaced the default: got %q", got)
	}
}
