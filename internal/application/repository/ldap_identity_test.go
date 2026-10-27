package repository

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func ldapBindingTestDB(t *testing.T) (*gorm.DB, *userRepository) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&types.Tenant{}, &types.User{}, &types.TenantMember{}, &types.SystemSetting{}); err != nil {
		t.Fatal(err)
	}
	return db, &userRepository{db: db}
}

func TestLDAPBindingHiddenFromSystemSettings(t *testing.T) {
	db, repo := ldapBindingTestDB(t)
	ldapBindingTestUser(t, db, "one", "alice@example.com", true)
	if _, err := repo.BindLDAPIdentity(context.Background(), "identity", "alice@example.com", "", true); err != nil {
		t.Fatal(err)
	}
	settings := NewSystemSettingRepository(db)
	rows, err := settings.List(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("internal settings listed: %v, %v", rows, err)
	}
	key := ldapBindingPrefix + "identity.identity"
	if row, err := settings.Get(context.Background(), key); err != nil || row != nil {
		t.Fatalf("internal setting visible: %v, %v", row, err)
	}
	if err := settings.Upsert(context.Background(), &types.SystemSetting{Key: key}); err == nil {
		t.Fatal("internal setting writable")
	}
	if _, err := settings.Delete(context.Background(), key); err == nil {
		t.Fatal("internal setting deletable")
	}
}

func TestLDAPBindingRejectsIncompleteOrDeletedAssociation(t *testing.T) {
	db, repo := ldapBindingTestDB(t)
	ldapBindingTestUser(t, db, "one", "alice@example.com", true)
	ctx := context.Background()
	if _, err := repo.BindLDAPIdentity(ctx, "identity", "alice@example.com", "", true); err != nil {
		t.Fatal(err)
	}
	if err := db.Where("key = ?", ldapBindingPrefix+"user.one").Delete(&types.SystemSetting{}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repo.BindLDAPIdentity(ctx, "identity", "alice@example.com", "", true); !errors.Is(err, ErrLDAPIdentityConflict) {
		t.Fatalf("partial association: %v", err)
	}
	if err := db.Delete(&types.User{}, "id = ?", "one").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repo.BindLDAPIdentity(ctx, "identity", "alice@example.com", "", true); !errors.Is(err, ErrLDAPIdentityConflict) {
		t.Fatalf("deleted user association: %v", err)
	}
}

func TestLDAPBindingConcurrentClaimsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings.db")
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
	ldapBindingTestUser(t, db, "one", "alice@example.com", true)
	repo := &userRepository{db: db}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, identity := range []string{"first", "second"} {
		wg.Add(1)
		go func(identity string) {
			defer wg.Done()
			<-start
			_, err := repo.BindLDAPIdentity(context.Background(), identity, "alice@example.com", "", true)
			results <- err
		}(identity)
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
	if successes != 1 {
		t.Fatalf("successful claims = %d, want 1", successes)
	}
	var count int64
	if err := db.Model(&types.SystemSetting{}).Where("key LIKE ?", ldapBindingPrefix+"%").Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("binding rows = %d, error %v", count, err)
	}
}

func ldapBindingTestUser(t *testing.T, db *gorm.DB, id, email string, active bool) {
	t.Helper()
	u := &types.User{ID: id, Username: id, Email: email, PasswordHash: "hash", IsActive: active}
	if err := db.Omit("tenant_id").Create(u).Error; err != nil {
		t.Fatal(err)
	}
	if !active {
		// GORM's default:true applies on insertion even when the field is false.
		if err := db.Model(u).Update("is_active", false).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestLDAPBindingRejectsUnsafeMatches(t *testing.T) {
	ctx := context.Background()
	t.Run("case insensitive email collision", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "one", "Alice@example.com", true)
		ldapBindingTestUser(t, db, "two", "alice@example.com", true)
		if _, err := repo.BindLDAPIdentity(ctx, "identity", "alice@example.com", "", true); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("got %v, want identity conflict", err)
		}
	})
	t.Run("existing user requires explicit approval", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "one", "alice@example.com", true)
		if _, err := repo.BindLDAPIdentity(ctx, "identity", "alice@example.com", "", false); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("got %v, want identity conflict", err)
		}
	})
	t.Run("disabled local account", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "one", "alice@example.com", false)
		if _, err := repo.BindLDAPIdentity(ctx, "identity", "alice@example.com", "", true); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("got %v, want identity conflict", err)
		}
	})
	t.Run("expected newly provisioned user mismatch", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "one", "alice@example.com", true)
		if _, err := repo.BindLDAPIdentity(ctx, "identity", "alice@example.com", "other", false); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("got %v, want identity conflict", err)
		}
	})
	t.Run("identity and user cannot be reassigned", func(t *testing.T) {
		db, repo := ldapBindingTestDB(t)
		ldapBindingTestUser(t, db, "one", "alice@example.com", true)
		ldapBindingTestUser(t, db, "two", "bob@example.com", true)
		if _, err := repo.BindLDAPIdentity(ctx, "first-guid", "alice@example.com", "", true); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.BindLDAPIdentity(ctx, "first-guid", "bob@example.com", "", true); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("reassign identity: got %v", err)
		}
		if _, err := repo.BindLDAPIdentity(ctx, "second-guid", "alice@example.com", "", true); !errors.Is(err, ErrLDAPIdentityConflict) {
			t.Fatalf("reassign user: got %v", err)
		}
	})
}

func TestLDAPBindingPreservesExistingPermissions(t *testing.T) {
	db, repo := ldapBindingTestDB(t)
	ldapBindingTestUser(t, db, "admin", "Admin@example.com", true)
	if err := db.Model(&types.User{}).Where("id = ?", "admin").Updates(map[string]interface{}{
		"is_system_admin": true, "can_access_all_tenants": true, "avatar": "existing-avatar",
	}).Error; err != nil {
		t.Fatal(err)
	}
	member := types.TenantMember{UserID: "admin", TenantID: 123, Role: types.TenantRoleAdmin, Status: types.TenantMemberStatusActive}
	if err := db.Create(&member).Error; err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	user, err := repo.BindLDAPIdentity(ctx, "stable-guid", "admin@example.com", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !user.IsSystemAdmin || !user.CanAccessAllTenants || user.Avatar != "existing-avatar" || user.Email != "Admin@example.com" {
		t.Fatalf("user permissions or profile changed: %#v", user)
	}
	if _, err := repo.BindLDAPIdentity(ctx, "stable-guid", "ADMIN@example.com", "", false); err != nil {
		t.Fatalf("existing binding did not persist: %v", err)
	}
	var got types.TenantMember
	if err := db.First(&got, member.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Role != member.Role || got.Status != member.Status || got.UserID != member.UserID || got.TenantID != member.TenantID {
		t.Fatalf("membership changed: %#v", got)
	}
}
