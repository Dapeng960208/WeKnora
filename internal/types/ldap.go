package types

// LDAPIdentity is returned only after a trusted directory validates a password,
// account status, and email uniqueness within the configured directory scope.
type LDAPIdentity struct {
	DirectoryID string
	ID          string
	Username    string
	Email       string
	DisplayName string
}
