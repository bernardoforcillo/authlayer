package audit

// SetMaintainBatch lowers the batch Reconcile and ApplyRetention work in, so a
// test can cross a batch boundary with a handful of events. It returns the
// restore function.
func SetMaintainBatch(n int) (restore func()) {
	old := maintainBatch
	maintainBatch = n
	return func() { maintainBatch = old }
}
