package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLDAPLoginFailsClosedWithGenericResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &AuthHandler{}
	r := gin.New()
	r.POST("/auth/ldap/login", h.LDAPLogin)

	testCases := []struct {
		name, enabled, payload string
	}{
		{"disabled", "false", `{"username":"alice","password":"password"}`},
		{"empty password", "true", `{"username":"alice","password":""}`},
		{"empty username", "true", `{"username":"","password":"password"}`},
		{"invalid JSON", "true", `{"username":`},
		{"username too long", "true", `{"username":"` + strings.Repeat("a", 257) + `","password":"password"}`},
		{"password too long", "true", `{"username":"alice","password":"` + strings.Repeat("x", 1025) + `"}`},
		{"body too large", "true", `{"username":"alice","password":"password","extra":"` + strings.Repeat("x", 4096) + `"}`},
		{"configuration unavailable", "true", `{"username":"alice","password":"password"}`},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LDAP_ENABLED", tc.enabled)
			t.Setenv("LDAP_URL", "")
			req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", strings.NewReader(tc.payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized || w.Body.String() != `{"message":"Login failed","success":false}` {
				t.Fatalf("response = %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAuthConfigExposesOnlyLDAPEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("LDAP_ENABLED", "true")
	t.Setenv("LDAP_BIND_DN", "private-bind-dn")
	t.Setenv("LDAP_BIND_PASSWORD", "private-bind-password")
	t.Setenv("LDAP_BIND_PASSWORD_FILE", "private-secret-path")
	h := &AuthHandler{}
	r := gin.New()
	r.GET("/auth/config", h.GetAuthConfig)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ldap_enabled"] != true {
		t.Errorf("ldap_enabled = %v", body["ldap_enabled"])
	}
	for _, secret := range []string{"private-bind-dn", "private-bind-password", "private-secret-path"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("auth config contains %q", secret)
		}
	}
}
