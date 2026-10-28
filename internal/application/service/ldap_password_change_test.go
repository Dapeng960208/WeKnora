package service

import (
	"context"
	"errors"
	"testing"
)

func TestChangePasswordLDAPGuardPreventsAccess(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
	// No repository is configured: the disabled path must return before lookup.
	svc := &userService{}
	if err := svc.ChangePassword(context.Background(), "user-1", "old", "new"); !errors.Is(err, ErrPasswordChangeDisabled) {
		t.Fatalf("ChangePassword error = %v, want ErrPasswordChangeDisabled", err)
	}
}

func TestAdminResetPasswordLDAPGuardPreventsAccess(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
	// No repository is configured: the disabled path must return before lookup.
	svc := &userService{}
	if err := svc.AdminResetPassword(context.Background(), "user-1", "new"); !errors.Is(err, ErrPasswordChangeDisabled) {
		t.Fatalf("AdminResetPassword error = %v, want ErrPasswordChangeDisabled", err)
	}
}
