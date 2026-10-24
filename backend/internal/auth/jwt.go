package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TypeAccess  = "access"
	TypeRefresh = "refresh"
)

type Claims struct {
	Role string `json:"role"`
	Type string `json:"typ"`
	jwt.RegisteredClaims
}

type TokenService struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewTokenService(secret string, accessTTL, refreshTTL time.Duration) *TokenService {
	return &TokenService{secret: []byte(secret), accessTTL: accessTTL, refreshTTL: refreshTTL}
}

func (s *TokenService) Issue(userID, role, typ string) (string, error) {
	ttl := s.accessTTL
	if typ == TypeRefresh {
		ttl = s.refreshTTL
	}
	now := time.Now()
	claims := Claims{
		Role: role,
		Type: typ,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

func (s *TokenService) Parse(token, wantType string) (*Claims, error) {
	var c Claims
	t, err := jwt.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) {
		return s.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !t.Valid {
		return nil, errors.New("geçersiz token")
	}
	if c.Type != wantType {
		return nil, errors.New("yanlış token türü")
	}
	return &c, nil
}