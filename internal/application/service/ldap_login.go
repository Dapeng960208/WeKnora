package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"os"
	"strings"

	apprepo "github.com/Tencent/WeKnora/internal/application/repository"
	"github.com/Tencent/WeKnora/internal/auth/ldapauth"
	"github.com/Tencent/WeKnora/internal/types"
)

type ldapIdentityRepository interface {
	BindLDAPIdentity(context.Context, string, string, string, bool, bool) (*types.User, error)
}

// LoginWithLDAP receives an identity only after the LDAP password, account
// status and trusted unique email have been validated by the server.
func (s *userService) LoginWithLDAP(ctx context.Context, identity *types.LDAPIdentity, provisioning types.TenantProvisioningMode) (*types.LoginResponse, error) {
	if !ldapauth.IsEnabled() {
		return nil, errors.New("LDAP authentication is disabled")
	}
	if identity == nil || identity.DirectoryID == "" || identity.ID == "" || identity.Username == "" {
		return nil, errors.New("invalid LDAP identity")
	}
	email := strings.TrimSpace(identity.Email)
	for _, ch := range email {
		if ch < 33 || ch > 126 {
			return nil, errors.New("invalid LDAP email")
		}
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 255 {
		return nil, errors.New("invalid LDAP email")
	}
	repo, ok := s.userRepo.(ldapIdentityRepository)
	if !ok {
		return nil, errors.New("LDAP identity repository unavailable")
	}
	hash := sha256.Sum256([]byte(identity.DirectoryID + "\x00" + identity.ID))
	key := hex.EncodeToString(hash[:])
	adminEmail := strings.TrimSpace(os.Getenv("LDAP_ADMIN"))
	bootstrapAdmin := adminEmail != "" && strings.EqualFold(email, adminEmail)
	// The handler only supplies identities after directory authentication and
	// trusted-email uniqueness checks; the repository still rejects conflicts.
	user, err := repo.BindLDAPIdentity(ctx, key, email, "", true, bootstrapAdmin)
	if errors.Is(err, apprepo.ErrUserNotFound) {
		// Existing registration policy chooses tenantless or a personal space.
		// The generated password is unknown to the directory user.
		password, passwordErr := generateRandomString(32)
		if passwordErr != nil {
			return nil, passwordErr
		}
		username := s.generateOIDCUsername(ctx, &types.OIDCUserInfo{Username: identity.Username, Email: email})
		user, err = s.Register(ctx, &types.RegisterRequest{Username: username, Email: email, Password: password, TenantProvisioning: provisioning})
		if err != nil {
			return nil, err
		}
		user, err = repo.BindLDAPIdentity(ctx, key, email, user.ID, false, bootstrapAdmin)
	}
	if err != nil {
		return nil, err
	}
	resolvedTenantID := s.resolveLoginTenantID(ctx, user)
	accessToken, refreshToken, err := s.generateTokensForTenant(ctx, user, resolvedTenantID)
	if err != nil {
		return nil, err
	}
	var tenant *types.Tenant
	if resolvedTenantID > 0 {
		tenant, _ = s.tenantService.GetTenantByID(ctx, resolvedTenantID)
	}
	return &types.LoginResponse{
		Success: true, Message: "Login successful", User: user,
		ActiveTenant: tenant, Memberships: s.buildMembershipsForUser(ctx, user, tenant),
		Token: accessToken, RefreshToken: refreshToken,
	}, nil
}
