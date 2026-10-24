package plugins

// AllowUserOwnedForTests relaxes the root-ownership rule so tests in other
// packages can use files in a temp dir. Never called by the agent itself.
func AllowUserOwnedForTests() { allowUserOwned = true }
