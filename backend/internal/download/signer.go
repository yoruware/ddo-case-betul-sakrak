package download

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

var (
	ErrExpired      = errors.New("bağlantının süresi dolmuş")
	ErrBadSignature = errors.New("imza geçersiz")
)

type Signer struct {
	key []byte
	TTL time.Duration
}

func NewSigner(key string, ttl time.Duration) *Signer {
	return &Signer{key: []byte(key), TTL: ttl}
}

func (s *Signer) mac(nodeID, userID string, exp int64) []byte {
	m := hmac.New(sha256.New, s.key)
	fmt.Fprintf(m, "dl\n%s\n%s\n%d", nodeID, userID, exp)
	return m.Sum(nil)
}

func (s *Signer) SignAt(nodeID, userID string, exp int64) string {
	return base64.RawURLEncoding.EncodeToString(s.mac(nodeID, userID, exp))
}

func (s *Signer) Sign(nodeID, userID string, now time.Time) (int64, string) {
	exp := now.Add(s.TTL).Unix()
	return exp, s.SignAt(nodeID, userID, exp)
}

// Verify: önce imza (sabit zamanlı karşılaştırma), sonra süre. Süre bilgisi
// yalnızca geçerli imzalı bağlantılarda ifşa olur.
func (s *Signer) Verify(nodeID, userID string, exp int64, sig string, now time.Time) error {
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(nodeID, userID, exp)) {
		return ErrBadSignature
	}
	if now.Unix() > exp {
		return ErrExpired
	}
	return nil
}
