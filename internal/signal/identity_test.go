package signal

import "testing"

func TestResourceIdentityKeepsDeploymentEnvironment(t *testing.T) {
	identity, ok := ResourceIdentity(map[string]string{
		"service.name":                "checkout",
		"deployment.environment.name": "production",
		"unbounded.custom.attribute":  "ignored",
	})
	if !ok ||
		identity["service.name"] != "checkout" ||
		identity["deployment.environment.name"] != "production" {
		t.Fatalf("identity=%v ok=%v", identity, ok)
	}
	if _, exists := identity["unbounded.custom.attribute"]; exists {
		t.Fatalf("unexpected custom identity=%v", identity)
	}
}
