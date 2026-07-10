package redact

import (
	"reflect"
	"testing"
)

func TestValueMasksSecrets(t *testing.T) {
	if got := Value("super-secret-token"); got != "***" {
		t.Errorf("Value(secret) = %q, want ***", got)
	}
	if got := Value(""); got != "" {
		t.Errorf("Value(empty) = %q, want empty", got)
	}
}

func TestKeysReturnsNamesNotValues(t *testing.T) {
	got := Keys(map[string]string{"authorization": "Bearer abc", "x-tenant": "acme"})
	want := []string{"authorization", "x-tenant"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Keys = %v, want %v (sorted names, no values)", got, want)
	}
	for _, k := range got {
		if k == "Bearer abc" || k == "acme" {
			t.Fatal("Keys leaked a secret value")
		}
	}
	if Keys(nil) != nil {
		t.Error("Keys(nil) should be nil")
	}
}
