package main

import (
	"reflect"
	"testing"
)

// The RTSP batch groups URLs by "host:port", while the database declares
// credentials per host — credsForGroups must bridge the two.
func TestCredsForGroups(t *testing.T) {
	groups := map[string][]string{
		"1.2.3.4:554":   {"rtsp://1.2.3.4:554/live"},
		"5.6.7.8:8554":  {"rtsp://5.6.7.8:8554/live"},
		"9.9.9.9:10554": {"rtsp://9.9.9.9:10554/live"},
	}
	byHost := map[string][]string{
		"1.2.3.4": {"admin:12345"},
		"5.6.7.8": {"root:root"},
	}

	got := credsForGroups(groups, byHost)
	want := map[string][]string{
		"1.2.3.4:554":  {"admin:12345"},
		"5.6.7.8:8554": {"root:root"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if credsForGroups(groups, nil) != nil {
		t.Error("no declared credentials should yield no per-group map")
	}
}
