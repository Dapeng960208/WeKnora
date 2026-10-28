package service

import (
	"context"
	"errors"
	"testing"

	apprepo "github.com/Tencent/WeKnora/internal/application/repository"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
)

type ldapTestUserRepo struct {
	interfaces.UserRepository
	user    *types.User
	bound   bool
	bindErr error
}

func (r *ldapTestUserRepo) BindLDAPIdentity(_ context.Context, _, _, expectedID string, allowed, bootstrapAdmin bool) (*types.User, error) {
	if r.bindErr != nil {
		return nil, r.bindErr
	}
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

type ldapCountingTokenRepo struct {
	interfaces.AuthTokenRepository
	writes int
}

func (r *ldapCountingTokenRepo) CreateToken(context.Context, *types.AuthToken) error {
	r.writes++
	return nil
}

func TestLDAPFirstLoginTenantless(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
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

func TestLDAPExistingAccountBindsWithoutAllowlist(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
	t.Setenv("LDAP_ADMIN", "")
	t.Setenv("LDAP_EXISTING_USER_ALLOWLIST", "")
	repo := &ldapTestUserRepo{user: &types.User{ID: "existing", Email: "admin@example.com", PasswordHash: "original", Avatar: "original-avatar", IsActive: true, IsSystemAdmin: true, CanAccessAllTenants: true}}
	svc := &userService{userRepo: repo, tokenRepo: ldapTestTokenRepo{}}
	result, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "guid", Username: "admin", Email: "admin@example.com"}, types.TenantProvisioningTenantless)
	if err != nil {
		t.Fatal(err)
	}
	if !repo.bound || result.User.ID != "existing" || !result.User.IsSystemAdmin || !result.User.CanAccessAllTenants || result.User.PasswordHash != "original" || result.User.Avatar != "original-avatar" || len(result.Memberships) != 0 {
		t.Fatal("existing account or permissions changed during LDAP login")
	}
	// The legacy allowlist variable must not silently block other verified users.
	t.Setenv("LDAP_EXISTING_USER_ALLOWLIST", "someone-else@example.com")
	if _, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "guid", Username: "admin", Email: "admin@example.com"}, types.TenantProvisioningTenantless); err != nil {
		t.Fatalf("subsequent LDAP login failed: %v", err)
	}
}

func TestLDAPAutoBindingFailsClosedOnConflict(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
	t.Setenv("LDAP_ADMIN", "")
	repo := &ldapTestUserRepo{bindErr: apprepo.ErrLDAPIdentityConflict}
	tokens := &ldapCountingTokenRepo{}
	svc := &userService{userRepo: repo, tokenRepo: tokens}
	result, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "conflicting-guid", Username: "alice", Email: "alice@example.com"}, types.TenantProvisioningTenantless)
	if !errors.Is(err, apprepo.ErrLDAPIdentityConflict) || result != nil || repo.bound || tokens.writes != 0 {
		t.Fatalf("identity conflict must not issue tokens or bind account: %v", err)
	}
}

func TestLDAPAutoBindingRejectsMissingEmail(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
	repo := &ldapTestUserRepo{user: &types.User{ID: "existing", IsActive: true}}
	tokens := &ldapCountingTokenRepo{}
	svc := &userService{userRepo: repo, tokenRepo: tokens}
	result, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "guid", Username: "alice"}, types.TenantProvisioningTenantless)
	if err == nil || result != nil || repo.bound || tokens.writes != 0 {
		t.Fatalf("missing email must not issue tokens or bind account: %v", err)
	}
}

func TestLDAPAdminFirstLoginRegistersWithoutSpace(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
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

func TestLDAPAdminBootstrapsExistingUser(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
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

func TestLDAPAdminDoesNotElevateDifferentUser(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
	t.Setenv("LDAP_EXISTING_USER_ALLOWLIST", "")
	t.Setenv("LDAP_ADMIN", "admin@example.com")
	repo := &ldapTestUserRepo{user: &types.User{ID: "other", Email: "other@example.com", IsActive: true}}
	svc := &userService{userRepo: repo, tokenRepo: ldapTestTokenRepo{}}
	result, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "other-guid", Username: "other", Email: "other@example.com"}, types.TenantProvisioningTenantless)
	if err != nil || result == nil || result.User.IsSystemAdmin || !repo.bound {
		t.Fatalf("ordinary user must bind without elevation: %v", err)
	}
}

func TestLDAPAdminHasNoEffectWhenLDAPDisabled(t *testing.T) {
	for _, enabled := range []string{"", "false"} {
		t.Run("enabled="+enabled, func(t *testing.T) {
			t.Setenv("LDAP_ENABLED", enabled)
			t.Setenv("LDAP_ADMIN", "admin@example.com")
			repo := &ldapTestUserRepo{user: &types.User{ID: "existing", Email: "admin@example.com", IsActive: true}}
			svc := &userService{userRepo: repo, tokenRepo: ldapTestTokenRepo{}}
			result, err := svc.LoginWithLDAP(context.Background(), &types.LDAPIdentity{DirectoryID: "company", ID: "guid", Username: "admin", Email: "admin@example.com"}, types.TenantProvisioningTenantless)
			if err == nil || result != nil || repo.bound || repo.user.IsSystemAdmin {
				t.Fatalf("disabled LDAP accepted or changed account: result=%v, error=%v, bound=%v, admin=%v", result, err, repo.bound, repo.user.IsSystemAdmin)
			}
		})
	}
}
