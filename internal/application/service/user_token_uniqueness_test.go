package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	apprepo "github.com/Tencent/WeKnora/internal/application/repository"
	"github.com/Tencent/WeKnora/internal/types"
)

func TestSameSecondTokenIssuanceKeepsRevokedSessionsRevoked(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Tenant{}, &types.User{}, &types.AuthToken{}))
	user := &types.User{ID: "jwt-user", Username: "jwt-user", Email: "jwt@example.com", PasswordHash: "unused", IsActive: true}
	userRepo := apprepo.NewUserRepository(db)
	tokenRepo := apprepo.NewAuthTokenRepository(db)
	require.NoError(t, userRepo.CreateUser(ctx, user))
	svc := &userService{userRepo: userRepo, tokenRepo: tokenRepo}

	// Generate several pairs within one second, without assuming a particular
	// scheduling window; two pairs in the same second reproduce the old bug.
	var firstAccess, firstRefresh, secondAccess, secondRefresh string
	var firstIat float64
	for i := 0; i < 100; i++ {
		access, refresh, err := svc.generateTokensForTenant(ctx, user, 0)
		require.NoError(t, err)
		parsed, err := jwt.Parse(access, func(*jwt.Token) (interface{}, error) { return []byte(getJwtSecret()), nil })
		require.NoError(t, err)
		claims := parsed.Claims.(jwt.MapClaims)
		iat := claims["iat"].(float64)
		require.NotEmpty(t, claims["jti"])
		if firstAccess != "" && iat == firstIat {
			secondAccess, secondRefresh = access, refresh
			break
		}
		firstAccess, firstRefresh, firstIat = access, refresh, iat
	}
	require.NotEmpty(t, secondAccess, "expected two issuances in the same second")
	require.NotEqual(t, firstAccess, secondAccess)
	require.NotEqual(t, firstRefresh, secondRefresh)

	require.NoError(t, svc.RevokeToken(ctx, firstAccess))
	require.NoError(t, svc.RevokeToken(ctx, firstRefresh))
	_, _, err = svc.ValidateToken(ctx, firstAccess)
	require.ErrorContains(t, err, "revoked")
	_, _, err = svc.ValidateToken(ctx, secondAccess)
	require.NoError(t, err)
	_, _, err = svc.RefreshToken(ctx, firstRefresh)
	require.ErrorContains(t, err, "revoked")
	newAccess, newRefresh, err := svc.RefreshToken(ctx, secondRefresh)
	require.NoError(t, err)
	require.NotEqual(t, secondRefresh, newRefresh)
	_, _, err = svc.ValidateToken(ctx, newAccess)
	require.NoError(t, err)
	_, _, err = svc.ValidateToken(ctx, firstAccess)
	require.ErrorContains(t, err, "revoked")
}

func TestPreviouslyIssuedTokenWithoutJTIStillValidates(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Tenant{}, &types.User{}, &types.AuthToken{}))
	user := &types.User{ID: "legacy-user", Username: "legacy-user", Email: "legacy@example.com", PasswordHash: "unused", IsActive: true}
	userRepo := apprepo.NewUserRepository(db)
	tokenRepo := apprepo.NewAuthTokenRepository(db)
	require.NoError(t, userRepo.CreateUser(ctx, user))
	svc := &userService{userRepo: userRepo, tokenRepo: tokenRepo}
	legacy := signTestJWT(jwt.MapClaims{"user_id": user.ID, "type": "access", "exp": time.Now().Add(time.Hour).Unix()})
	require.NoError(t, tokenRepo.CreateToken(ctx, &types.AuthToken{ID: "legacy-token", UserID: user.ID, Token: legacy, TokenType: "access_token", ExpiresAt: time.Now().Add(time.Hour)}))
	_, _, err = svc.ValidateToken(ctx, legacy)
	require.NoError(t, err)
}
