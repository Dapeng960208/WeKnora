package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func TestLoggerOmitsLDAPLoginBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name     string
		path     string
		omitBody bool
	}{
		{name: "LDAP login", path: "/api/v1/auth/ldap/login", omitBody: true},
		{name: "LDAP login trailing slash", path: "/api/v1/auth/ldap/login/", omitBody: true},
		{name: "LDAP login case variant", path: "/api/v1/auth/LDAP/login", omitBody: true},
		{name: "password change", path: "/api/v1/auth/change-password", omitBody: true},
		{name: "password change trailing slash", path: "/api/v1/auth/change-password/", omitBody: true},
		{name: "admin password reset", path: "/api/v1/system/admin/users/reset-password", omitBody: true},
		{name: "admin password reset case variant", path: "/api/v1/system/admin/users/RESET-password", omitBody: true},
		{name: "ordinary route", path: "/api/v1/example", omitBody: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			log := logrus.New()
			log.SetOutput(&logs)
			log.SetFormatter(&logrus.JSONFormatter{})
			r := gin.New()
			r.ContextWithFallback = true
			r.Use(func(c *gin.Context) {
				ctx := context.WithValue(c.Request.Context(), types.LoggerContextKey, logrus.NewEntry(log))
				c.Request = c.Request.WithContext(ctx)
				c.Next()
			}, Logger())
			const requestBody = `{"payload":"request-marker"}`
			const responseBody = `{"payload":"response-marker"}`
			r.POST(tc.path, func(c *gin.Context) {
				body, err := io.ReadAll(c.Request.Body)
				if err != nil || string(body) != requestBody {
					t.Errorf("handler received body %q, error %v", body, err)
				}
				c.Data(http.StatusOK, "application/json", []byte(responseBody))
			})
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(requestBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK || w.Body.String() != responseBody {
				t.Fatalf("response status %d body %q", w.Code, w.Body.String())
			}
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatalf("decode log: %v; log %q", err, logs.String())
			}
			for field, want := range map[string]string{"request_body": requestBody, "response_body": responseBody} {
				got, exists := entry[field]
				if tc.omitBody && exists {
					t.Errorf("%s was logged: %v", field, got)
				} else if !tc.omitBody && (!exists || got != want) {
					t.Errorf("%s = %v, want %q", field, got, want)
				}
			}
		})
	}
}

func TestLoggerOmitsMalformedPasswordBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range []string{"/api/v1/auth/change-password", "/api/v1/system/admin/users/reset-password"} {
		t.Run(path, func(t *testing.T) {
			var logs bytes.Buffer
			log := logrus.New()
			log.SetOutput(&logs)
			log.SetFormatter(&logrus.JSONFormatter{})
			r := gin.New()
			r.ContextWithFallback = true
			r.Use(func(c *gin.Context) {
				ctx := context.WithValue(c.Request.Context(), types.LoggerContextKey, logrus.NewEntry(log))
				c.Request = c.Request.WithContext(ctx)
				c.Next()
			}, Logger())
			body := `{"new_password":"malformed-secret-` + strings.Repeat("x", maxBodySize)
			const response = `{"payload":"response-secret"}`
			r.POST(path, func(c *gin.Context) {
				got, err := io.ReadAll(c.Request.Body)
				if err != nil || string(got) != body {
					t.Error("handler did not receive the complete request body")
				}
				c.Data(http.StatusBadRequest, "application/json", []byte(response))
			})
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest || w.Body.String() != response {
				t.Fatalf("unexpected HTTP response status %d", w.Code)
			}
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatalf("decode log: %v", err)
			}
			if _, ok := entry["request_body"]; ok {
				t.Error("password request body was logged")
			}
			if _, ok := entry["response_body"]; ok {
				t.Error("password response body was logged")
			}
		})
	}
}
