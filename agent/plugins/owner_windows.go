package plugins

// On Windows the installer creates the config directory with an ACL that
// only Administrators and SYSTEM can write; the agent runs as LocalService.
func CheckOwnership(string) error { return nil }

var allowUserOwned = false
