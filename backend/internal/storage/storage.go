package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idRe  = regexp.MustCompile(`^[0-9a-f-]{36}$`)
)

type Store struct{ root string }

func New(root string) (*Store, error) {
	for _, d := range []string{"tmp", "blobs", "quarantine", "trash"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			return nil, err
		}
	}
	return &Store{root: root}, nil
}

func (s *Store) NewTemp() (*os.File, error) {
	return os.CreateTemp(filepath.Join(s.root, "tmp"), "up-*")
}

// Yol yalnızca doğrulanmış SHA-256 onaltılık metninden türer; kullanıcı girdisi içermez.
func (s *Store) blobPath(sha string) (string, error) {
	if !shaRe.MatchString(sha) {
		return "", errors.New("geçersiz sha256")
	}
	return filepath.Join(s.root, "blobs", sha[:2], sha), nil
}

func (s *Store) Exists(sha string) bool {
	p, err := s.blobPath(sha)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Commit geçici dosyayı içerik adresli yerine taşır (tmpPath kapalı olmalı).
// Aynı içerik zaten varsa geçici dosya silinir: tek kopya.
func (s *Store) Commit(tmpPath, sha string) (existed bool, err error) {
	dst, err := s.blobPath(sha)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(dst); err == nil {
		_ = os.Remove(tmpPath)
		return true, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return false, err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		if _, serr := os.Stat(dst); serr == nil { // yarış: başka yükleme aynı içeriği yazdı
			_ = os.Remove(tmpPath)
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (s *Store) Open(sha string) (*os.File, error) {
	p, err := s.blobPath(sha)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (s *Store) Quarantine(tmpPath, id string) error {
	if !idRe.MatchString(id) {
		return errors.New("geçersiz karantina kimliği")
	}
	return os.Rename(tmpPath, filepath.Join(s.root, "quarantine", id))
}

func (s *Store) trashDir() string { return filepath.Join(s.root, "trash") }

func (s *Store) inTrash(p string) bool {
	return strings.HasPrefix(filepath.Clean(p), s.trashDir()+string(filepath.Separator))
}

// Trash blobu çöp klasörüne taşır (geri alınabilir). Dosya yoksa ("", nil) döner.
func (s *Store) Trash(sha string) (string, error) {
	src, err := s.blobPath(sha)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	rnd := make([]byte, 8)
	if _, err := rand.Read(rnd); err != nil {
		return "", err
	}
	dst := filepath.Join(s.trashDir(), sha+"."+hex.EncodeToString(rnd))
	if err := os.Rename(src, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// Restore çöpteki blobu yerine geri koyar (transaction commit edilemediğinde).
func (s *Store) Restore(trashPath, sha string) error {
	if !s.inTrash(trashPath) {
		return errors.New("geçersiz çöp yolu")
	}
	dst, err := s.blobPath(sha)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	return os.Rename(trashPath, dst)
}

// Purge çöpteki blobu kalıcı olarak siler (transaction commit edildikten sonra).
func (s *Store) Purge(trashPath string) error {
	if !s.inTrash(trashPath) {
		return errors.New("geçersiz çöp yolu")
	}
	return os.Remove(trashPath)
}
