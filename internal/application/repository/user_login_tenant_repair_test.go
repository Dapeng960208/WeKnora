package repository

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Reproduce the login/admin interleaving by updating the durable row after the
// login snapshot is read and before the tenant repair is persisted.
func TestRepairLoginTenantPreservesConcurrentAccountChanges(t *testing.T) {
	userStatusBackends(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		seedStatusUser(t, db, "alice", false, true)
		repo := &userRepository{db: db}
		oldHome, newHome, oldPreference := uint64(7), uint64(42), uint64(7)
		oldPrefs := types.UserPreferences{LastActiveTenantID: &oldPreference}
		require.NoError(t, db.Model(&types.User{}).Where("id = ?", "alice").Updates(map[string]interface{}{
			"tenant_id": oldHome, "preferences": oldPrefs,
		}).Error)
		stale, err := repo.GetUserByID(ctx, "alice")
		require.NoError(t, err)
		newPreference := uint64(33)
		search := "new instructions"
		latestPrefs := types.UserPreferences{LastActiveTenantID: &newPreference, BrowserSearchInstructions: &search}
		require.NoError(t, db.Model(&types.User{}).Where("id = ?", "alice").Updates(map[string]interface{}{
			"is_system_admin": true, "can_access_all_tenants": true,
			"password_hash": "updated-hash", "avatar": "updated-avatar", "preferences": latestPrefs,
		}).Error)
		clearedHome := uint64(0)
		require.NoError(t, repo.RepairLoginTenant(ctx, stale.ID, &oldHome, &clearedHome, &oldPreference))
		require.NoError(t, repo.RepairLoginTenant(ctx, stale.ID, &clearedHome, &newHome, nil))
		got, err := repo.GetUserByID(ctx, "alice")
		require.NoError(t, err)
		require.Equal(t, newHome, got.TenantID)
		require.True(t, got.IsSystemAdmin)
		require.True(t, got.CanAccessAllTenants)
		require.Equal(t, "updated-hash", got.PasswordHash)
		require.Equal(t, "updated-avatar", got.Avatar)
		require.Equal(t, &newPreference, got.Preferences.LastActiveTenantID)
		require.Equal(t, &search, got.Preferences.BrowserSearchInstructions)
	})
}

func TestRepairLoginTenantClearsOnlyMatchingPreference(t *testing.T) {
	userStatusBackends(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		seedStatusUser(t, db, "alice", false, true)
		repo := &userRepository{db: db}
		oldPreference := uint64(7)
		search := "keep this"
		prefs := types.UserPreferences{LastActiveTenantID: &oldPreference, BrowserSearchInstructions: &search}
		require.NoError(t, db.Model(&types.User{}).Where("id = ?", "alice").Update("preferences", prefs).Error)
		require.NoError(t, repo.RepairLoginTenant(ctx, "alice", nil, nil, &oldPreference))
		got, err := repo.GetUserByID(ctx, "alice")
		require.NoError(t, err)
		require.Nil(t, got.Preferences.LastActiveTenantID)
		require.Equal(t, &search, got.Preferences.BrowserSearchInstructions)
		// Preserve preferences unknown to this binary when clearing one key.
		require.NoError(t, db.Model(&types.User{}).Where("id = ?", "alice").UpdateColumn("preferences", `{"last_active_tenant_id":7,"future_setting":{"keep":true}}`).Error)
		require.NoError(t, repo.RepairLoginTenant(ctx, "alice", nil, nil, &oldPreference))
		var raw string
		require.NoError(t, db.Model(&types.User{}).Select("preferences").Where("id = ?", "alice").Scan(&raw).Error)
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(raw), &fields))
		require.NotContains(t, fields, "last_active_tenant_id")
		require.JSONEq(t, `{"keep":true}`, string(fields["future_setting"]))
	})
}

func TestRepairLoginTenantRejectsChangedHome(t *testing.T) {
	userStatusBackends(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		seedStatusUser(t, db, "alice", false, true)
		repo := &userRepository{db: db}
		oldHome, currentHome, desiredHome := uint64(7), uint64(33), uint64(0)
		require.NoError(t, db.Model(&types.User{}).Where("id = ?", "alice").Update("tenant_id", currentHome).Error)
		err := repo.RepairLoginTenant(ctx, "alice", &oldHome, &desiredHome, nil)
		require.True(t, errors.Is(err, ErrUserTenantChanged))
		got, err := repo.GetUserByID(ctx, "alice")
		require.NoError(t, err)
		require.Equal(t, currentHome, got.TenantID)
	})
}

func TestRepairLoginTenantWaitsForConcurrentAdminUpdate(t *testing.T) {
	userStatusBackends(t, func(t *testing.T, db *gorm.DB) {
		if db.Dialector.Name() != "postgres" {
			t.Skip("row-lock concurrency requires PostgreSQL")
		}
		ctx := context.Background()
		seedStatusUser(t, db, "alice", false, true)
		repo := &userRepository{db: db}
		tx := db.Begin()
		require.NoError(t, tx.Error)
		defer tx.Rollback()
		var locked types.User
		require.NoError(t, tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", "alice").First(&locked).Error)
		require.NoError(t, tx.Model(&types.User{}).Where("id = ?", "alice").Updates(map[string]interface{}{
			"is_system_admin": true, "can_access_all_tenants": true,
		}).Error)
		emptyHome, newHome := uint64(0), uint64(42)
		done := make(chan error, 1)
		go func() { done <- repo.RepairLoginTenant(ctx, "alice", &emptyHome, &newHome, nil) }()
		select {
		case err := <-done:
			t.Fatalf("login repair did not wait for the admin update: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		require.NoError(t, tx.Commit().Error)
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("login repair did not finish after admin update committed")
		}
		got, err := repo.GetUserByID(ctx, "alice")
		require.NoError(t, err)
		require.True(t, got.IsSystemAdmin)
		require.True(t, got.CanAccessAllTenants)
		require.Equal(t, newHome, got.TenantID)
	})
}
