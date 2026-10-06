package memory_test

import (
	"testing"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/audit/audittest"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func TestAuditStoreSatisfiesTheContract(t *testing.T) {
	audittest.RunStoreContract(t, func(*testing.T) audit.Store { return memory.NewAuditStore() })
}
