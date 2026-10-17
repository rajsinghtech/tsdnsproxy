package main

import (
	"testing"

	"tailscale.com/ipn/store"
)

func TestKubeStateStoreRegistered(t *testing.T) {
	if !store.HasKnownProviderPrefix("kube:secret-name") {
		t.Fatal("kube: is not a registered state store provider")
	}
}
