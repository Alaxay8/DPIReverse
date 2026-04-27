package cmd

import (
	"reflect"
	"testing"
)

func TestNormalizeScanArgsMovesPositionalResourceToFlag(t *testing.T) {
	args := normalizeScanArgs([]string{"youtube.com", "--profile", "quick"})
	want := []string{"--resource", "youtube.com", "--profile", "quick"}

	if !reflect.DeepEqual(args, want) {
		t.Fatalf("normalizeScanArgs() = %#v, want %#v", args, want)
	}
}

func TestResolveResourceAcceptsPositionalArgument(t *testing.T) {
	resource, err := resolveResource("", "", []string{"youtube.com"})
	if err != nil {
		t.Fatalf("resolveResource() error = %v", err)
	}

	if resource != "youtube.com" {
		t.Fatalf("resolveResource() = %q, want youtube.com", resource)
	}
}

func TestResolveResourceAcceptsResourceFlag(t *testing.T) {
	resource, err := resolveResource("", "youtube.com", nil)
	if err != nil {
		t.Fatalf("resolveResource() error = %v", err)
	}

	if resource != "youtube.com" {
		t.Fatalf("resolveResource() = %q, want youtube.com", resource)
	}
}

func TestResolveResourceRejectsConflictingFlags(t *testing.T) {
	_, err := resolveResource("youtube.com", "googlevideo.com", nil)
	if err == nil {
		t.Fatal("expected conflict error")
	}
}

func TestResolveResourceRejectsMultiplePositionals(t *testing.T) {
	_, err := resolveResource("", "", []string{"youtube.com", "google.com"})
	if err == nil {
		t.Fatal("expected error for multiple positional arguments")
	}
}
