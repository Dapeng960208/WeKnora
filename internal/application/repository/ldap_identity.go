package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Tencent/WeKnora/internal/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrLDAPIdentityConflict = errors.New("LDAP identity conflict")

// These reserved keys reuse the unique key constraint of system_settings.
// They are not editable settings and must never be listed by the settings API.
const ldapBindingPrefix = "ldap.binding."

// BindLDAPIdentity atomically associates a trusted directory identity with the
// one local user having the same email. expectedUserID prevents a newly
// provisioned account from being confused with a concurrent registration.
func (r *userRepository) BindLDAPIdentity(ctx context.Context, key, email, expectedUserID string, allowExisting bool) (*types.User, error) {
	var result *types.User
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var users []types.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("LOWER(email) = ?", strings.ToLower(email)).Limit(2).Find(&users).Error; err != nil {
			return err
		}
		identityKey := ldapBindingPrefix + "identity." + key
		var identityBinding types.SystemSetting
		identityErr := tx.Where("key = ?", identityKey).First(&identityBinding).Error
		if identityErr != nil && !errors.Is(identityErr, gorm.ErrRecordNotFound) {
			return identityErr
		}
		if len(users) == 0 {
			if identityErr == nil {
				return ErrLDAPIdentityConflict
			}
			return ErrUserNotFound
		}
		if len(users) != 1 || (expectedUserID != "" && users[0].ID != expectedUserID) {
			return ErrLDAPIdentityConflict
		}
		user := &users[0]
		if !user.IsActive {
			return ErrLDAPIdentityConflict
		}
		userKey := ldapBindingPrefix + "user." + user.ID
		var userBinding types.SystemSetting
		userErr := tx.Where("key = ?", userKey).First(&userBinding).Error
		if userErr != nil && !errors.Is(userErr, gorm.ErrRecordNotFound) {
			return userErr
		}
		if identityErr == nil || userErr == nil {
			if identityErr != nil || userErr != nil {
				return ErrLDAPIdentityConflict
			}
			var storedUser, storedIdentity string
			if json.Unmarshal(identityBinding.Value, &storedUser) != nil || json.Unmarshal(userBinding.Value, &storedIdentity) != nil || storedUser != user.ID || storedIdentity != key {
				return ErrLDAPIdentityConflict
			}
			result = user
			return nil
		}
		if expectedUserID == "" && !allowExisting {
			return ErrLDAPIdentityConflict
		}
		// Both keys are unique and written in one transaction, so a racing
		// association cannot claim either identity or user for another party.
		userJSON, _ := json.Marshal(user.ID)
		identityJSON, _ := json.Marshal(key)
		for _, row := range []types.SystemSetting{
			{Key: identityKey, Value: types.JSON(userJSON), ValueType: "string", Category: "internal", IsSecret: true},
			{Key: userKey, Value: types.JSON(identityJSON), ValueType: "string", Category: "internal", IsSecret: true},
		} {
			if err := tx.Create(&row).Error; err != nil {
				return ErrLDAPIdentityConflict
			}
		}
		result = user
		return nil
	})
	return result, err
}
