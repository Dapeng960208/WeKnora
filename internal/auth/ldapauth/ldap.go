// Package ldapauth authenticates users against a trusted Active Directory.
package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

var ErrAuthentication = errors.New("LDAP authentication failed")
var ErrConflict = errors.New("LDAP identity conflict")

type Config struct {
	Enabled, StartTLS, TrustEmail                                                    bool
	URL, CAFile, BindDN, BindPassword, DirectoryID                                   string
	BaseDNs                                                                          []string
	EmailDomains                                                                     []string
	UserFilter, UsernameAttribute, EmailAttribute, DisplayNameAttribute              string
	IDAttribute, AccountStatusMode, AccountStatusAttribute, AccountStatusActiveValue string
	ConnectTimeout, OperationTimeout                                                 time.Duration
}

type Identity struct {
	ID, DN, Username, Email, DisplayName string
}

var attributeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// IsEnabled can be used by the public login configuration without reading secrets.
func IsEnabled() bool { return os.Getenv("LDAP_ENABLED") == "true" }

// ConfigFromEnv reads configuration at the point of use; secrets are never exposed by an API.
func ConfigFromEnv() (Config, error) {
	c := Config{Enabled: IsEnabled()}
	if !c.Enabled {
		return c, nil
	}
	c.URL = os.Getenv("LDAP_URL")
	c.StartTLS = env("LDAP_STARTTLS", "true") == "true"
	c.TrustEmail = os.Getenv("LDAP_TRUST_EMAIL") == "true"
	c.CAFile, c.BindDN = os.Getenv("LDAP_CA_FILE"), os.Getenv("LDAP_BIND_DN")
	c.DirectoryID = os.Getenv("LDAP_DIRECTORY_ID")
	c.BindPassword = os.Getenv("LDAP_BIND_PASSWORD")
	if path := os.Getenv("LDAP_BIND_PASSWORD_FILE"); path != "" {
		if c.BindPassword != "" {
			return c, errors.New("configure only one LDAP bind password source")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return c, errors.New("cannot read LDAP bind password file")
		}
		c.BindPassword = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	}
	for _, base := range strings.Split(os.Getenv("LDAP_USER_BASE_DNS"), ";") {
		if base = strings.TrimSpace(base); base != "" {
			c.BaseDNs = append(c.BaseDNs, base)
		}
	}
	for _, domain := range strings.Split(os.Getenv("LDAP_EMAIL_DOMAINS"), ",") {
		if domain = strings.ToLower(strings.TrimSpace(domain)); domain != "" {
			c.EmailDomains = append(c.EmailDomains, domain)
		}
	}
	c.UserFilter = env("LDAP_USER_FILTER", "(objectClass=user)")
	c.UsernameAttribute = env("LDAP_USERNAME_ATTRIBUTE", "sAMAccountName")
	c.EmailAttribute = env("LDAP_EMAIL_ATTRIBUTE", "mail")
	c.DisplayNameAttribute = env("LDAP_DISPLAY_NAME_ATTRIBUTE", "cn")
	c.IDAttribute = env("LDAP_ID_ATTRIBUTE", "objectGUID")
	c.AccountStatusMode = env("LDAP_ACCOUNT_STATUS_MODE", "ad")
	c.AccountStatusAttribute = env("LDAP_ACCOUNT_STATUS_ATTRIBUTE", "userAccountControl")
	c.AccountStatusActiveValue = os.Getenv("LDAP_ACCOUNT_STATUS_ACTIVE_VALUE")
	var err error
	if c.ConnectTimeout, err = time.ParseDuration(env("LDAP_CONNECT_TIMEOUT", "5s")); err != nil {
		return c, errors.New("invalid LDAP connect timeout")
	}
	if c.OperationTimeout, err = time.ParseDuration(env("LDAP_OPERATION_TIMEOUT", "10s")); err != nil {
		return c, errors.New("invalid LDAP operation timeout")
	}
	return c, c.validate()
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func (c Config) validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") || (u.Scheme == "ldap" && !c.StartTLS) {
		return errors.New("LDAP URL must use StartTLS or LDAPS")
	}
	if c.BindDN == "" || c.BindPassword == "" || c.DirectoryID == "" || !c.TrustEmail || len(c.BaseDNs) == 0 || len(c.EmailDomains) == 0 {
		return errors.New("incomplete LDAP configuration or email trust not enabled")
	}
	if c.ConnectTimeout <= 0 || c.OperationTimeout <= 0 {
		return errors.New("LDAP timeouts must be positive")
	}
	for _, base := range c.BaseDNs {
		if _, err := ldap.ParseDN(base); err != nil {
			return errors.New("invalid LDAP base DN")
		}
	}
	for _, attr := range []string{c.UsernameAttribute, c.EmailAttribute, c.DisplayNameAttribute, c.IDAttribute, c.AccountStatusAttribute} {
		if !attributeName.MatchString(attr) {
			return errors.New("invalid LDAP attribute")
		}
	}
	if c.AccountStatusMode != "ad" && (c.AccountStatusMode != "active-value" || c.AccountStatusActiveValue == "") {
		return errors.New("invalid LDAP account status configuration")
	}
	if _, err := ldap.CompileFilter(c.UserFilter); err != nil {
		return errors.New("invalid LDAP user filter")
	}
	return nil
}

// Authenticate validates credentials and returns only a unique, enabled AD identity.
func Authenticate(ctx context.Context, c Config, username, password string) (Identity, error) {
	if !c.Enabled || c.validate() != nil || username == "" || len(username) > 256 || password == "" || len(password) > 1024 {
		return Identity{}, ErrAuthentication
	}
	u, _ := url.Parse(c.URL)
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return Identity{}, ErrAuthentication
		}
	}
	tlsConfig := &tls.Config{ServerName: u.Hostname(), RootCAs: pool, MinVersion: tls.VersionTLS12}
	port := u.Port()
	if port == "" {
		if u.Scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	dialer := net.Dialer{Timeout: c.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return Identity{}, ErrAuthentication
	}
	deadline := time.Now().Add(c.OperationTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if u.Scheme == "ldaps" {
		secure := tls.Client(conn, tlsConfig)
		if err = secure.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return Identity{}, ErrAuthentication
		}
		conn = secure
	}
	l := ldap.NewConn(conn, u.Scheme == "ldaps")
	l.Start()
	defer l.Close()
	l.SetTimeout(c.OperationTimeout)
	if u.Scheme == "ldap" {
		if err = l.StartTLS(tlsConfig); err != nil {
			return Identity{}, ErrAuthentication
		}
	}
	if err = l.Bind(c.BindDN, c.BindPassword); err != nil {
		return Identity{}, ErrAuthentication
	}
	return authenticateDirectory(l, c, username, password)
}

type directory interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Bind(string, string) error
}

func authenticateDirectory(l directory, c Config, username, password string) (Identity, error) {
	filter := fmt.Sprintf("(&%s(%s=%s))", c.UserFilter, c.UsernameAttribute, ldap.EscapeFilter(username))
	entries, err := search(l, c.BaseDNs, filter, []string{c.UsernameAttribute, c.EmailAttribute, c.DisplayNameAttribute, c.IDAttribute, c.AccountStatusAttribute}, c.IDAttribute)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return Identity{}, ErrConflict
		}
		return Identity{}, ErrAuthentication
	}
	if len(entries) != 1 {
		if len(entries) > 1 {
			return Identity{}, ErrConflict
		}
		return Identity{}, ErrAuthentication
	}
	entry := entries[0]
	ids := entry.GetEqualFoldRawAttributeValues(c.IDAttribute)
	if len(ids) != 1 || len(ids[0]) == 0 || len(ids[0]) > 256 {
		return Identity{}, ErrAuthentication
	}
	guid := ids[0]
	statuses := entry.GetEqualFoldAttributeValues(c.AccountStatusAttribute)
	if len(statuses) != 1 {
		return Identity{}, ErrAuthentication
	}
	if c.AccountStatusMode == "ad" {
		flags, err := strconv.ParseUint(statuses[0], 10, 32)
		if err != nil || flags&2 != 0 {
			return Identity{}, ErrAuthentication
		}
	} else if statuses[0] != c.AccountStatusActiveValue {
		return Identity{}, ErrAuthentication
	}
	emails := entry.GetEqualFoldAttributeValues(c.EmailAttribute)
	if len(emails) != 1 {
		return Identity{}, ErrConflict
	}
	email := strings.TrimSpace(emails[0])
	// The local database and LDAP server must agree on email case folding.
	// Restrict automatic binding to ASCII, where their folding is predictable.
	for _, ch := range email {
		if ch < 33 || ch > 126 {
			return Identity{}, ErrConflict
		}
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || parsed.Name != "" || len(email) > 254 {
		return Identity{}, ErrConflict
	}
	parts := strings.Split(email, "@")
	allowed := false
	if len(parts) == 2 {
		for _, domain := range c.EmailDomains {
			if strings.EqualFold(parts[1], domain) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return Identity{}, ErrConflict
	}
	emailFilter := fmt.Sprintf("(%s=%s)", c.EmailAttribute, ldap.EscapeFilter(email))
	matches, err := search(l, c.BaseDNs, emailFilter, []string{c.IDAttribute}, c.IDAttribute)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return Identity{}, ErrConflict
		}
		return Identity{}, ErrAuthentication
	}
	if len(matches) != 1 || hex.EncodeToString(matches[0].GetEqualFoldRawAttributeValue(c.IDAttribute)) != hex.EncodeToString(guid) {
		return Identity{}, ErrConflict
	}
	if entry.DN == "" || l.Bind(entry.DN, password) != nil {
		return Identity{}, ErrAuthentication
	}
	return Identity{ID: hex.EncodeToString(guid), DN: entry.DN, Username: entry.GetEqualFoldAttributeValue(c.UsernameAttribute), Email: strings.ToLower(email), DisplayName: entry.GetEqualFoldAttributeValue(c.DisplayNameAttribute)}, nil
}

// search deduplicates overlapping base DNs using the immutable AD GUID.
func search(l directory, bases []string, filter string, attrs []string, idAttribute string) ([]*ldap.Entry, error) {
	entries := make(map[string]*ldap.Entry)
	for _, base := range bases {
		r, err := l.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
		if err != nil {
			return nil, err
		}
		for _, entry := range r.Entries {
			ids := entry.GetEqualFoldRawAttributeValues(idAttribute)
			if len(ids) != 1 || len(ids[0]) == 0 || len(ids[0]) > 256 {
				return nil, ErrConflict
			}
			id := ids[0]
			key := hex.EncodeToString(id)
			if previous, ok := entries[key]; ok {
				a, errA := ldap.ParseDN(previous.DN)
				b, errB := ldap.ParseDN(entry.DN)
				if errA != nil || errB != nil || !a.EqualFold(b) {
					return nil, ErrConflict
				}
			}
			entries[key] = entry
		}
	}
	result := make([]*ldap.Entry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry)
	}
	return result, nil
}
