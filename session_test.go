package sessions

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testRequest(t *testing.T, h http.Handler, cookie string) (string, string) {
	rr := httptest.NewRecorder()

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		r.Header.Add("Cookie", cookie)
	}

	h.ServeHTTP(rr, r)

	body := rr.Body.String()
	cookie = rr.Header().Get("Set-Cookie")

	return body, cookie
}

func TestEnable(t *testing.T) {
	s := New([]byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4"))
	s.Lifetime = time.Second

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Put(r, "foo", "bar")
		w.WriteHeader(200)
	})

	_, cookie := testRequest(t, s.Enable(h), "")

	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s.GetString(r, "foo"))
	})

	body, _ := testRequest(t, s.Enable(h), cookie)

	if body != "bar" {
		t.Errorf("got %q: expected %q", body, "bar")
	}

	time.Sleep(time.Second)

	body, _ = testRequest(t, s.Enable(h), cookie)

	if body != "" {
		t.Errorf("got %q: expected %q", body, "")
	}
}

func TestDestroy(t *testing.T) {
	s := New([]byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4"))

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Put(r, "foo", "bar")
		s.Destroy(r)
		w.WriteHeader(200)
	})

	_, cookie := testRequest(t, s.Enable(h), "")

	if !strings.HasPrefix(cookie, fmt.Sprintf("%s=;", cookieName)) {
		t.Errorf("got %q: expected prefix %q", cookie, fmt.Sprintf("%s=;", cookieName))
	}
	if !strings.Contains(cookie, "Expires=Thu, 01 Jan 1970 00:00:01 GMT") {
		t.Errorf("got %q: expected to contain %q", cookie, "Expires=Thu, 01 Jan 1970 00:00:01 GMT")
	}
	if !strings.Contains(cookie, "Max-Age=0") {
		t.Errorf("got %q: expected to contain %q", cookie, "Max-Age=0")
	}

	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Destroy(r)
		s.Put(r, "foo", "bar")
		w.WriteHeader(200)
	})

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	testRequest(t, s.Enable(h), "")
}

func TestKeyCycling(t *testing.T) {
	s := New([]byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4"))

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Put(r, "foo", "bar")
		w.WriteHeader(200)
	})

	_, cookie := testRequest(t, s.Enable(h), "")

	s2 := New([]byte("9y5Vlur8YvODJEhgOY8m9JVE4u46IpCV"), []byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4"))

	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s2.GetString(r, "foo"))
	})

	body, _ := testRequest(t, s2.Enable(h), cookie)

	if body != "bar" {
		t.Errorf("got %q: expected %q", body, "bar")
	}
}

func TestInvalidCookies(t *testing.T) {
	s := New([]byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4"))

	cookie := &http.Cookie{
		Name:  cookieName,
		Value: "",
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	body, _ := testRequest(t, s.Enable(h), cookie.String())
	if body != "OK" {
		t.Errorf("got %q: expected %q", body, "OK")
	}

	cookie = &http.Cookie{
		Name:  cookieName,
		Value: "`",
	}

	body, _ = testRequest(t, s.Enable(h), cookie.String())
	if body != "OK" {
		t.Errorf("got %q: expected %q", body, "OK")
	}
}

func TestLongCookie(t *testing.T) {
	s := New([]byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4"))
	s.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Write([]byte("Internal Server Error"))
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		randomData := make([]byte, 5000)
		rand.Read(randomData)
		s.Put(r, "foo", randomData)
		w.WriteHeader(200)
	})

	body, _ := testRequest(t, s.Enable(h), "")

	if body != "Internal Server Error" {
		t.Errorf("got %q: expected %q", body, "Internal Server Error")
	}
}

func TestOnlySendCookieIfModified(t *testing.T) {
	s := New([]byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4"))
	s.Lifetime = time.Hour
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Put(r, "foo", "bar")
		w.WriteHeader(200)
	})

	_, cookie := testRequest(t, s.Enable(h), "")

	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s.GetString(r, "foo"))
	})

	_, cookie = testRequest(t, s.Enable(h), cookie)

	if cookie != "" {
		t.Errorf("got %q: expected %q", cookie, "")
	}
}

func TestOldKeyCookieReissuedWithNewKey(t *testing.T) {
	oldKey := []byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4")
	newKey := []byte("9y5Vlur8YvODJEhgOY8m9JVE4u46IpCV")

	s := New(oldKey)
	s.Lifetime = time.Hour

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Put(r, "foo", "bar")
		w.WriteHeader(200)
	})

	_, cookie := testRequest(t, s.Enable(h), "")
	if cookie == "" {
		t.Fatal("expected a session cookie to be set")
	}

	original := parseSetCookie(t, cookie)

	s2 := New(newKey, oldKey)
	s2.Lifetime = time.Hour

	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s2.GetString(r, "foo"))
	})

	body, cookie := testRequest(t, s2.Enable(h), cookie)

	if body != "bar" {
		t.Errorf("got %q: expected %q", body, "bar")
	}
	if cookie == "" {
		t.Fatal("expected the cookie to be transparently re-issued")
	}

	reissued := parseSetCookie(t, cookie)

	if !reissued.Expires.Equal(original.Expires) {
		t.Errorf("got expires %v: expected %v", reissued.Expires, original.Expires)
	}
	if reissued.Path != original.Path || reissued.HttpOnly != original.HttpOnly || reissued.SameSite != original.SameSite {
		t.Errorf("cookie attributes not preserved: got %q", cookie)
	}

	var newKeyArray, oldKeyArray [32]byte
	copy(newKeyArray[:], newKey)
	copy(oldKeyArray[:], oldKey)

	_, keyIndex, err := decrypt(reissued.Value, [][32]byte{newKeyArray, oldKeyArray})
	if err != nil {
		t.Fatal(err)
	}
	if keyIndex != 0 {
		t.Errorf("got key index %d: expected %d", keyIndex, 0)
	}

	// The re-issued cookie must not be re-issued again on subsequent
	// unmodified requests.
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s2.GetString(r, "foo"))
	})

	_, cookie = testRequest(t, s2.Enable(h), cookie)
	if cookie != "" {
		t.Errorf("got %q: expected %q", cookie, "")
	}
}

func TestExpiredCookieNotReissued(t *testing.T) {
	oldKey := []byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4")
	newKey := []byte("9y5Vlur8YvODJEhgOY8m9JVE4u46IpCV")

	s := New(oldKey)
	s.Lifetime = time.Second

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Put(r, "foo", "bar")
		w.WriteHeader(200)
	})

	_, cookie := testRequest(t, s.Enable(h), "")

	time.Sleep(time.Second)

	s2 := New(newKey, oldKey)

	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	_, cookie = testRequest(t, s2.Enable(h), cookie)
	if cookie != "" {
		t.Errorf("got %q: expected %q", cookie, "")
	}
}

func TestBadTokenNotReissued(t *testing.T) {
	oldKey := []byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4")
	newKey := []byte("9y5Vlur8YvODJEhgOY8m9JVE4u46IpCV")

	s := New(oldKey)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Put(r, "foo", "bar")
		w.WriteHeader(200)
	})

	_, cookie := testRequest(t, s.Enable(h), "")

	// Tamper with the token so it can no longer be authenticated.
	c := parseSetCookie(t, cookie)
	c.Value = c.Value[:len(c.Value)-1] + "A"
	if c.Value == parseSetCookie(t, cookie).Value {
		c.Value = c.Value[:len(c.Value)-1] + "B"
	}

	s2 := New(newKey, oldKey)

	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	body, cookie := testRequest(t, s2.Enable(h), c.String())
	if body != "OK" {
		t.Errorf("got %q: expected %q", body, "OK")
	}
	if cookie != "" {
		t.Errorf("got %q: expected %q", cookie, "")
	}
}

func parseSetCookie(t *testing.T, setCookie string) *http.Cookie {
	t.Helper()
	res := http.Response{Header: http.Header{"Set-Cookie": []string{setCookie}}}
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies: expected 1", len(cookies))
	}
	return cookies[0]
}

func TestNewPanicsOnInvalidKeyLength(t *testing.T) {
	assertPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("%s: expected a panic", name)
			}
		}()
		f()
	}

	assertPanic("short key", func() { New([]byte("short")) })
	assertPanic("long key", func() { New(make([]byte, 33)) })
	assertPanic("short old key", func() {
		New([]byte("u46IpCV9y5Vlur8YvODJEhgOY8m9JVE4"), []byte("short"))
	})
}
