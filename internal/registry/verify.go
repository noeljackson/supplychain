package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxTarballBytes = 50 * 1024 * 1024

var (
	ErrVersionMissing           = errors.New("registry: version is not published")
	ErrSignatureInvalid         = errors.New("registry: no valid npm signature")
	ErrTarballURLUnsafe         = errors.New("registry: unsafe npm tarball URL")
	ErrTarballIntegrityMismatch = errors.New("registry: npm tarball integrity mismatch")
	ErrTarballTooLarge          = errors.New("registry: npm tarball exceeds 50 MiB")
)

// VerifiedVersion is registry metadata whose ECDSA signature has been checked
// against the npm public signing-key endpoint.
type VerifiedVersion struct {
	Name           string
	Version        string
	Integrity      string
	Tarball        string
	SignatureKeyID string
}

// VerifyVersion resolves an exact published version and verifies at least one
// npm registry signature over its distribution integrity.
func (c *Client) VerifyVersion(name, version string) (VerifiedVersion, error) {
	result := VerifiedVersion{Name: name, Version: version}
	packument, err := c.Get(name)
	if err != nil {
		return result, err
	}
	metadata, ok := packument.Versions[version]
	if !ok {
		return result, ErrVersionMissing
	}
	result.Integrity = metadata.Dist.Integrity
	result.Tarball = metadata.Dist.Tarball
	keys, err := c.SigningKeys()
	if err != nil {
		return result, fmt.Errorf("registry signing keys: %w", err)
	}
	message := name + "@" + version + ":" + metadata.Dist.Integrity
	for _, signature := range metadata.Dist.Signatures {
		for _, key := range keys {
			if key.KeyID != signature.KeyID {
				continue
			}
			if VerifySignature(key.Key, signature.Sig, message) {
				result.SignatureKeyID = key.KeyID
				return result, nil
			}
		}
	}
	return result, ErrSignatureInvalid
}

// VerifySignature checks one npm ECDSA registry signature.
func VerifySignature(encodedKey, encodedSignature, message string) bool {
	der, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(message))
	return ecdsa.VerifyASN1(publicKey, digest[:], signature)
}

// FetchTarball downloads a public npm-registry tarball without following a
// redirect outside the registry and verifies its SHA-512 integrity before
// returning any bytes to the caller.
func (c *Client) FetchTarball(rawURL, integrity string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || !safeTarballURL(parsed) {
		return nil, ErrTarballURLUnsafe
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("registry tarball request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")

	client := *c.HTTP
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !safeTarballURL(req.URL) {
			return ErrTarballURLUnsafe
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry tarball download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry tarball download: %s", resp.Status)
	}
	limited := io.LimitReader(resp.Body, maxTarballBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("registry tarball read: %w", err)
	}
	if len(body) > maxTarballBytes {
		return nil, ErrTarballTooLarge
	}
	if !validSHA512Integrity(body, integrity) {
		return nil, ErrTarballIntegrityMismatch
	}
	return body, nil
}

func safeTarballURL(value *url.URL) bool {
	return value != nil &&
		value.Scheme == "https" &&
		strings.EqualFold(value.Hostname(), "registry.npmjs.org") &&
		value.Port() == "" &&
		value.User == nil &&
		value.RawQuery == "" &&
		value.Fragment == "" &&
		strings.HasPrefix(value.EscapedPath(), "/")
}

func validSHA512Integrity(body []byte, integrity string) bool {
	if !strings.HasPrefix(integrity, "sha512-") {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(integrity, "sha512-"))
	if err != nil || len(want) != sha512.Size {
		return false
	}
	got := sha512.Sum512(body)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
