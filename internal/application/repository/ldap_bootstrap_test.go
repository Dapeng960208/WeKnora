package repository

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestLDAPBootstrapExistingUserPreservesAccount(t *testing.T) {
	db, repo := ldapBindingTestDB(t)
	ldapBindingTestUser(t, db, "admin", "Admin@example.com", true)
	if err := db.Model(&types.User{}).Where("id = ?", "admin").Updates(map[string]interface{}{
		"password_hash": "existing-hash", "avatar": "existing-avatar", "can_access_all_tenants": true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	member := types.TenantMember{UserID: "admin", TenantID: 123, Role: types.TenantRoleAdmin, Status: types.TenantMemberStatusActive}
	if err := db.Create(&member).Error; err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	user, err := repo.BindLDAPIdentity(ctx, "admin-guid", "admin@example.com", "", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !user.IsSystemAdmin || !user.CanAccessAllTenants || user.PasswordHash != "existing-hash" || user.Avatar != "existing-avatar" {
		t.Fatalf("unexpected account state after bootstrap: %#v", user)
	}
	var got types.TenantMember
	if err := db.First(&got, member.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Role != member.Role || got.Status != member.Status || got.UserID != member.UserID || got.TenantID != member.TenantID {
		t.Fatalf("membership changed: %#v", got)
	}
	settings := NewSystemSettingRepository(db)
	if rows, err := settings.List(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("internal bootstrap settings exposed: %v, %v", rows, err)
	}
	if row, err := settings.Get(ctx, ldapBindingPrefix+"bootstrap.admin"); err != nil || row != nil {
		t.Fatalf("bootstrap marker exposed: %v, %v", row, err)
	}
}

func TestLDAPBootstrapNewlyProvisionedUser(t *testing.T) {
	db, repo := ldapBindingTestDB(t)
	ldapBindingTestUser(t, db, "new", "new@example.com", true)
	user, err := repo.BindLDAPIdentity(context.Background(), "new-guid", "new@example.com", "new", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !user.IsSystemAdmin || user.CanAccessAllTenants || user.TenantID != 0 {
		t.Fatalf("unexpected newly provisioned administrator: %#v", user)
	}
	var memberships int64
	if err := db.Model(&types.TenantMember{}).Where("user_id = ?", "new").Count(&memberships).Error; err != nil || memberships != 0 {
		t.Fatalf("unexpected space memberships %d: %v", memberships, err)
	}
}

func TestLDAPBootstrapIsOneTime(t *testing.T) {
	db, repo := ldapBindingTestDB(t)
	ctx := context.Background()
	ldapBindingTestUser(t, db, "first", "first@example.com", true)
	ldapBindingTestUser(t, db, "second", "second@example.com", true)
	if _, err := repo.BindLDAPIdentity(ctx, "first-guid", "first@example.com", "", true, true); err != nil {
		t.Fatal(err)
	}
	// A later administrative revocation must not be undone by logging in again.
	if err := db.Model(&types.User{}).Where("id = ?", "first").Update("is_system_admin", false).Error; err != nil {
		t.Fatal(err)
	}
	first, err := repo.BindLDAPIdentity(ctx, "first-guid", "first@example.com", "", false, true)
	if err != nil || first.IsSystemAdmin {
		t.Fatalf("revoked administrator regained access: %#v, %v", first, err)
	}
	// Changing the configured LDAP_ADMIN must not trigger another bootstrap.
	second, err := repo.BindLDAPIdentity(ctx, "second-guid", "second@example.com", "", true, true)
	if err != nil || second.IsSystemAdmin {
		t.Fatalf("second bootstrap succeeded: %#v, %v", second, err)
	}
}

func TestLDAPBootstrapRollsBackBindingWhenGrantFails(t *testing.T) {
	db, repo := ldapBindingTestDB(t)
	ldapBindingTestUser(t, db, "admin", "admin@example.com", true)
	if err := db.Exec(`CREATE TRIGGER fail_ldap_admin_grant BEFORE UPDATE OF is_system_admin ON users
		WHEN NEW.is_system_admin = 1 BEGIN SELECT RAISE(ABORT, 'test grant failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repo.BindLDAPIdentity(context.Background(), "guid", "admin@example.com", "", true, true); err == nil {
		t.Fatal("expected administrator grant failure")
	}
	assertNoLDAPBootstrap(t, db)
	var count int64
	if err := db.Model(&types.SystemSetting{}).Where("key LIKE ?", ldapBindingPrefix+"%").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("failed transaction persisted %d identity bindings or markers: %v", count, err)
	}
	var user types.User
	if err := db.First(&user, "id = ?", "admin").Error; err != nil {
		t.Fatal(err)
	}
	if user.IsSystemAdmin || user.PasswordHash != "hash" {
		t.Fatalf("failed transaction changed account: %#v", user)
	}
}

func TestLDAPBootstrapRequiresValidBinding(t *testing.T) {
	ctx := context.Background()
	t.Run("disabled user", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "disabled", "disabled@example.com", false)
		if _, err := repo.BindLDAPIdentity(ctx, "guid", "disabled@example.com", "", true, true); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("disabled login: %v", err)
		}
		assertNoLDAPBootstrap(t, db)
	})
	t.Run("duplicate email", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "first", "Admin@example.com", true)
		ldapBindingTestUser(t, db, "second", "admin@example.com", true)
		if _, err := repo.BindLDAPIdentity(ctx, "guid", "admin@example.com", "", true, true); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("duplicate email: %v", err)
		}
		assertNoLDAPBootstrap(t, db)
	})
	t.Run("existing identity conflict", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "first", "first@example.com", true)
		ldapBindingTestUser(t, db, "second", "second@example.com", true)
		if _, err := repo.BindLDAPIdentity(ctx, "guid", "first@example.com", "", true, false); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.BindLDAPIdentity(ctx, "guid", "second@example.com", "", true, true); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("reused identity: %v", err)
		}
		assertNoLDAPBootstrap(t, db)
	})
	t.Run("not selected for bootstrap", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "ordinary", "ordinary@example.com", true)
		user, err := repo.BindLDAPIdentity(ctx, "guid", "ordinary@example.com", "", true, false)
		if err != nil || user.IsSystemAdmin {
			t.Fatalf("ordinary user elevated: %#v, %v", user, err)
		}
		assertNoLDAPBootstrap(t, db)
	})
}

func assertNoLDAPBootstrap(t *testing.T, db *gorm.DB) {
	t.Helper()
	var count int64
	if err := db.Model(&types.User{}).Where("is_system_admin = ?", true).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("unexpected admin count %d: %v", count, err)
	}
	if err := db.Model(&types.SystemSetting{}).Where("key = ?", ldapBindingPrefix+"bootstrap.admin").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("unexpected bootstrap marker count %d: %v", count, err)
	}
}

func TestLDAPBootstrapConcurrentOnlyOneAdministrator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.db")
	db, err := gorm.Open(sqlite.Open(path+"?_journal_mode=WAL&_busy_timeout=5000"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&types.Tenant{}, &types.User{}, &types.SystemSetting{}); err != nil {
		t.Fatal(err)
	}
	ldapBindingTestUser(t, db, "first", "first@example.com", true)
	ldapBindingTestUser(t, db, "second", "second@example.com", true)
	repo := &userRepository{db: db}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"first", "second"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			<-start
			_, err := repo.BindLDAPIdentity(context.Background(), name+"-guid", name+"@example.com", "", true, true)
			results <- err
		}(name)
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatal("no concurrent bootstrap succeeded")
	}
	// A retried transaction after a SQLite lock failure cannot grant a second admin.
	for _, name := range []string{"first", "second"} {
		if _, err := repo.BindLDAPIdentity(context.Background(), name+"-guid", name+"@example.com", "", true, true); err != nil {
			t.Fatalf("retry %s: %v", name, err)
		}
	}
	var count int64
	if err := db.Model(&types.User{}).Where("is_system_admin = ?", true).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("admin count %d, want 1: %v", count, err)
	}
	var marker types.SystemSetting
	if err := db.Where("key = ?", ldapBindingPrefix+"bootstrap.admin").First(&marker).Error; err != nil {
		t.Fatal(err)
	}
	var markedID string
	if err := json.Unmarshal(marker.Value, &markedID); err != nil || markedID == "" {
		t.Fatalf("invalid bootstrap marker: %v", err)
	}
}
