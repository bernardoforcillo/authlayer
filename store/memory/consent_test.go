package memory_test

import (
	"testing"

	"github.com/bernardoforcillo/authlayer/consent"
	"github.com/bernardoforcillo/authlayer/consent/consenttest"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func TestConsentStoreSatisfiesTheContract(t *testing.T) {
	consenttest.RunStoreContract(t, func(*testing.T) consent.Store { return memory.NewConsentStore() })
}
