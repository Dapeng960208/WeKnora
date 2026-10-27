package service

import (
	"context"
	"errors"
	"testing"

	apprepo "github.com/Tencent/WeKnora/internal/application/repository"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
)

func TestLDAPExistingUserAllowlist(t *testing.T) {
	t.Setenv("LDAP_EXISTING_USER_ALLOWLIST", " admin@example.com, Alice@example.com ")
	if !ldapExistingUserAllowed("alice@EXAMPLE.com") {
		t.Fatal("approved email not matched")
	}
	if ldapExistingUserAllowed("mallory@example.com") {
		t.Fatal("unapproved email matched")
	}
	t.Setenv("LDAP_EXISTING_USER_ALLOWLIST", "")
	if ldapExistingUserAllowed("alice@example.com") {
		t.Fatal("empty allowlist must reject")
	}
}

type ldapTestUserRepo struct {
	interfaces.UserRepository
	user  *types.User
	bound bool
}

func (r *ldapTestUserRepo) BindLDAPIdentity(_ context.Context, _, _, expectedID string, allowed, bootstrapAdmin bool) (*types.User, error) {
	if r.user == nil {
		return nil, apprepo.ErrUserNotFound
	}
	if expectedID != "" && expectedID != r.user.ID {
		return nil, apprepo.ErrLDAPIdentityConflict
	}
	if !r.bound && expectedID == "" && !allowed {
		return nil, apprepo.ErrLDAPIdentityConflict
	}
	r.bound = true
	if bootstrapAdmin {
		r.user.IsSystemAdmin = true
	}
	return r.user, nil
}
func (r *ldapTestUserRepo) GetUserByEmail(context.Context, string) (*types.User, error) {
	return r.user, nil
}
func (r *ldapTestUserRepo) GetUserByUsername(context.Context, string) (*types.User, error) {
	return nil, nil
}
func (r *ldapTestUserRepo) CreateUser(_ context.Context, user *types.User) error {
	r.user = user
	return nil
}
func (r *ldapTestUserRepo) UpdateUser(_ context.Context, user *types.User) error {
	r.user = user
	return nil
}

type ldapTestTokenRepo struct{ interfaces.AuthTokenRepository }

func (ldapTestTokenRepo) CreateToken(context.Context, *types.AuthToken) error { return nil }

func TestLDAPFirstLoginTenantless(t *testing.T) {
	t.Setenv("LDAP_ADMIN", "")
	repo := &ldapTestUserRepo{}
	svc := &userService{userRepo: repo, tokenRepo: ldapTestTokenRepo{}}
	result, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "guid", Username: "alice", Email: "alice@example.com"}, types.TenantProvisioningTenantless)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.User.TenantID != 0 || len(result.Memberships) != 0 || result.Token == "" || !repo.bound {
		t.Fatalf("tenantless result: %+v", result)
	}
	if result.User.IsSystemAdmin || result.User.CanAccessAllTenants {
		t.Fatal("new account received elevated permissions")
	}
}

func TestLDAPExistingAccountMustBeApproved(t *testing.T) {
	t.Setenv("LDAP_ADMIN", "")
	t.Setenv("LDAP_EXISTING_USER_ALLOWLIST", "")
	repo := &ldapTestUserRepo{user: &types.User{ID: "existing", Email: "admin@example.com", IsActive: true, IsSystemAdmin: true, TenantID: 7}}
	svc := &userService{userRepo: repo, tokenRepo: ldapTestTokenRepo{}}
	_, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "guid", Username: "admin", Email: "admin@example.com"}, types.TenantProvisioningTenantless)
	if !errors.Is(err, apprepo.ErrLDAPIdentityConflict) {
		t.Fatalf("unapproved account returned %v", err)
	}
}

func TestLDAPAdminFirstLoginRegistersWithoutSpace(t *testing.T) {
	t.Setenv("LDAP_ADMIN", "new@example.com")
	repo := &ldapTestUserRepo{}
	svc := &userService{userRepo: repo, tokenRepo: ldapTestTokenRepo{}}
	result, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "guid", Username: "new", Email: "new@example.com"}, types.TenantProvisioningTenantless)
	if err != nil {
		t.Fatal(err)
	}
	if !result.User.IsSystemAdmin || result.User.TenantID != 0 || result.User.CanAccessAllTenants || len(result.Memberships) != 0 {
		t.Fatal("new LDAP administrator was not initialized as tenantless")
	}
}

func TestLDAPAdminExplicitlyApprovesExistingUser(t *testing.T) {
	t.Setenv("LDAP_EXISTING_USER_ALLOWLIST", "")
	t.Setenv("LDAP_ADMIN", " ADMIN@example.com ")
	repo := &ldapTestUserRepo{user: &types.User{ID: "existing", Email: "admin@example.com", PasswordHash: "original", IsActive: true}}
	svc := &userService{userRepo: repo, tokenRepo: ldapTestTokenRepo{}}
	result, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "guid", Username: "admin", Email: "admin@example.com"}, types.TenantProvisioningTenantless)
	if err != nil {
		t.Fatal(err)
	}
	if !result.User.IsSystemAdmin || result.User.PasswordHash != "original" || result.User.CanAccessAllTenants {
		t.Fatal("LDAP administrator was not initialized safely")
	}
}

func TestLDAPAdminDoesNotApproveDifferentUser(t *testing.T) {
	t.Setenv("LDAP_EXISTING_USER_ALLOWLIST", "")
	t.Setenv("LDAP_ADMIN", "admin@example.com")
	repo := &ldapTestUserRepo{user: &types.User{ID: "other", Email: "other@example.com", IsActive: true}}
	svc := &userService{userRepo: repo, tokenRepo: ldapTestTokenRepo{}}
	_, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "other-guid", Username: "other", Email: "other@example.com"}, types.TenantProvisioningTenantless)
	if !errors.Is(err, apprepo.ErrLDAPIdentityConflict) || repo.user.IsSystemAdmin {
		t.Fatalf("other account was approved: %v", err)
	}
}
