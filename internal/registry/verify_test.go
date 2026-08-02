package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	message := "htmx.org@2.0.10:sha512-example"
	digest := sha256.Sum256([]byte(message))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(
		base64.StdEncoding.EncodeToString(encodedKey),
		base64.StdEncoding.EncodeToString(signature),
		message,
	) {
		t.Fatal("valid signature was rejected")
	}
	if VerifySignature(base64.StdEncoding.EncodeToString(encodedKey), "invalid", message) {
		t.Fatal("invalid signature was accepted")
	}
}

func TestSafeTarballURL(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.10.tgz", true},
		{"http://registry.npmjs.org/pkg.tgz", false},
		{"https://registry.npmjs.org.evil.test/pkg.tgz", false},
		{"https://user@registry.npmjs.org/pkg.tgz", false},
		{"https://registry.npmjs.org:443/pkg.tgz", false},
		{"https://registry.npmjs.org/pkg.tgz?token=secret", false},
		{"https://registry.npmjs.org/pkg.tgz#fragment", false},
	}
	for _, test := range tests {
		parsed, err := url.Parse(test.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := safeTarballURL(parsed); got != test.want {
			t.Errorf("safeTarballURL(%q) = %v, want %v", test.raw, got, test.want)
		}
	}
}

func TestValidSHA512Integrity(t *testing.T) {
	body := []byte("canonical tarball")
	digest := sha512.Sum512(body)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
	if !validSHA512Integrity(body, integrity) {
		t.Fatal("valid integrity was rejected")
	}
	if validSHA512Integrity([]byte("modified"), integrity) {
		t.Fatal("modified body passed integrity")
	}
}

func TestVerifyVersionUsesSignedExactMetadata(t *testing.T) {
	privateKey, encodedKey := testSigningKey(t)
	name, version := "htmx.org", "2.0.10"
	integrity := "sha512-example"
	message := name + "@" + version + ":" + integrity
	digest := sha256.Sum256([]byte(message))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	keyID := "SHA256:test-key"
	client := NewClient(filepath.Join(t.TempDir(), "cache"))
	client.writeCache(client.cachePath(name), &Packument{
		Name: name,
		Versions: map[string]VersionMetadata{
			version: {Dist: Dist{
				Integrity: integrity,
				Tarball:   "https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.10.tgz",
				Signatures: []Signature{{
					KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature),
				}},
			}},
		},
	})
	keys, err := json.Marshal(map[string]any{"keys": []SigningKey{{KeyID: keyID, Key: encodedKey}}})
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(bytesReader(keys)),
			Header:     make(http.Header),
		}, nil
	})
	verified, err := client.VerifyVersion(name, version)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Integrity != integrity || verified.SignatureKeyID != keyID {
		t.Fatalf("verified = %+v", verified)
	}
	if _, err := client.VerifyVersion(name, "2.0.9"); !errors.Is(err, ErrVersionMissing) {
		t.Fatalf("missing version error = %v", err)
	}
}

func TestFetchTarballEnforcesBodyIntegrity(t *testing.T) {
	body := []byte("canonical npm tarball")
	digest := sha512.Sum512(body)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
	client := NewClient(filepath.Join(t.TempDir(), "cache"))
	client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Hostname() != "registry.npmjs.org" {
			t.Fatalf("unexpected host %s", request.URL.Hostname())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(bytesReader(body)),
			Header:     make(http.Header),
		}, nil
	})
	got, err := client.FetchTarball("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", integrity)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("body = %q", got)
	}
	if _, err := client.FetchTarball(
		"https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
		"sha512-"+base64.StdEncoding.EncodeToString(make([]byte, sha512.Size)),
	); !errors.Is(err, ErrTarballIntegrityMismatch) {
		t.Fatalf("integrity error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func bytesReader(body []byte) *strings.Reader {
	return strings.NewReader(string(body))
}

func testSigningKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, base64.StdEncoding.EncodeToString(encodedKey)
}
