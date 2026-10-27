package ldapauth

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func testConfig() Config {
	return Config{Enabled: true, StartTLS: true, TrustEmail: true, URL: "ldap://localhost:389", BindDN: "cn=service,dc=example,dc=com", BindPassword: "secret", DirectoryID: "corp", BaseDNs: []string{"ou=a,dc=example,dc=com", "ou=b,dc=example,dc=com"}, EmailDomains: []string{"example.com"}, UserFilter: "(objectClass=user)", UsernameAttribute: "sAMAccountName", EmailAttribute: "mail", DisplayNameAttribute: "cn", IDAttribute: "objectGUID", AccountStatusMode: "ad", AccountStatusAttribute: "userAccountControl", ConnectTimeout: time.Second, OperationTimeout: time.Second}
}

func testEntry(id, email, status string) *ldap.Entry {
	return ldap.NewEntry("cn="+id+",ou=a,dc=example,dc=com", map[string][]string{"objectGUID": {id}, "sAMAccountName": {"alice"}, "cn": {"Alice"}, "mail": {email}, "userAccountControl": {status}})
}

type fakeDirectory struct {
	users, emails map[string][]*ldap.Entry
	filters       []string
	bindError     error
	searchError   error
}

func (f *fakeDirectory) Bind(_, _ string) error { return f.bindError }
func (f *fakeDirectory) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.filters = append(f.filters, r.Filter)
	if f.searchError != nil {
		return nil, f.searchError
	}
	if strings.HasPrefix(r.Filter, "(&") {
		return &ldap.SearchResult{Entries: f.users[r.BaseDN]}, nil
	}
	return &ldap.SearchResult{Entries: f.emails[r.BaseDN]}, nil
}

func TestDirectoryAuthentication(t *testing.T) {
	c := testConfig()
	a := testEntry("1234567890123456", "Alice@Example.com", "512")
	b := testEntry("abcdefghijklmnop", "alice@example.com", "512")
	cases := []struct {
		name          string
		users, emails map[string][]*ldap.Entry
		bind          error
		want          error
	}{
		{"success", map[string][]*ldap.Entry{c.BaseDNs[0]: {a}}, map[string][]*ldap.Entry{c.BaseDNs[0]: {a}}, nil, nil},
		{"overlapping bases", map[string][]*ldap.Entry{c.BaseDNs[0]: {a}, c.BaseDNs[1]: {a}}, map[string][]*ldap.Entry{c.BaseDNs[0]: {a}, c.BaseDNs[1]: {a}}, nil, nil},
		{"duplicate username", map[string][]*ldap.Entry{c.BaseDNs[0]: {a}, c.BaseDNs[1]: {b}}, nil, nil, ErrConflict},
		{"duplicate email", map[string][]*ldap.Entry{c.BaseDNs[0]: {a}}, map[string][]*ldap.Entry{c.BaseDNs[0]: {a}, c.BaseDNs[1]: {b}}, nil, ErrConflict},
		{"missing email", map[string][]*ldap.Entry{c.BaseDNs[0]: {testEntry("1234567890123456", "", "512")}}, nil, nil, ErrConflict},
		{"non ASCII email", map[string][]*ldap.Entry{c.BaseDNs[0]: {testEntry("1234567890123456", "用户@example.com", "512")}}, nil, nil, ErrConflict},
		{"disabled", map[string][]*ldap.Entry{c.BaseDNs[0]: {testEntry("1234567890123456", "alice@example.com", "514")}}, nil, nil, ErrAuthentication},
		{"missing status", map[string][]*ldap.Entry{c.BaseDNs[0]: {testEntry("1234567890123456", "alice@example.com", "")}}, nil, nil, ErrAuthentication},
		{"wrong password", map[string][]*ldap.Entry{c.BaseDNs[0]: {a}}, map[string][]*ldap.Entry{c.BaseDNs[0]: {a}}, errors.New("invalid credentials"), ErrAuthentication},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDirectory{users: tc.users, emails: tc.emails, bindError: tc.bind}
			identity, err := authenticateDirectory(f, c, "a*)(x=*)", "password")
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if err == nil && (identity.ID != "31323334353637383930313233343536" || identity.Email != "alice@example.com") {
				t.Fatalf("identity = %+v", identity)
			}
			if !strings.Contains(f.filters[0], `a\2a\29\28x=\2a\29`) {
				t.Fatalf("filter not escaped: %s", f.filters[0])
			}
		})
	}
}

func TestDisabledAndTransportFailures(t *testing.T) {
	c := testConfig()
	if _, err := Authenticate(context.Background(), c, "alice", ""); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("empty password: %v", err)
	}
	c.StartTLS = false
	if _, err := Authenticate(context.Background(), c, "alice", "pw"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("plaintext: %v", err)
	}
	c.StartTLS = true
	c.URL = "ldap://127.0.0.1:1"
	if _, err := Authenticate(context.Background(), c, "alice", "pw"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unavailable: %v", err)
	}
	s := httptest.NewTLSServer(nil)
	defer s.Close()
	c.URL = "ldaps://" + strings.TrimPrefix(s.URL, "https://")
	if _, err := Authenticate(context.Background(), c, "alice", "pw"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("untrusted TLS: %v", err)
	}
}

func TestStartTLSFailureDoesNotBind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf) // Receive the StartTLS request, then reject it by closing.
		}
		close(accepted)
	}()
	c := testConfig()
	c.URL = "ldap://" + listener.Addr().String()
	if _, err := Authenticate(context.Background(), c, "alice", "pw"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("StartTLS failure: %v", err)
	}
	<-accepted
}

func TestConfigTrustAndStatus(t *testing.T) {
	c := testConfig()
	c.TrustEmail = false
	if c.validate() == nil {
		t.Fatal("missing trust accepted")
	}
	c = testConfig()
	c.AccountStatusMode = "active-value"
	c.AccountStatusAttribute = "status"
	c.AccountStatusActiveValue = "active"
	a := testEntry("1234567890123456", "alice@example.com", "512")
	a.Attributes = append(a.Attributes, ldap.NewEntryAttribute("status", []string{"active"}))
	f := &fakeDirectory{users: map[string][]*ldap.Entry{c.BaseDNs[0]: {a}}, emails: map[string][]*ldap.Entry{c.BaseDNs[0]: {a}}}
	if _, err := authenticateDirectory(f, c, "alice", "pw"); err != nil {
		t.Fatal(err)
	}
}
