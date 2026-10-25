package upload

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

const CodeMalware = "malware_detected"

type Reject struct {
	Status  int
	Code    string
	Message string
}

func (e *Reject) Error() string { return e.Message }

func reject(status int, code, msg string) *Reject {
	return &Reject{Status: status, Code: code, Message: msg}
}

type Limits struct {
	MaxFileBytes  int64
	ZipMaxEntries int
	ZipMaxTotal   int64 // arşivin açılmış toplam üst sınırı
	ZipMaxRatio   int64 // açılmış/sıkıştırılmış üst sınırı
}

func DefaultLimits() Limits {
	return Limits{MaxFileBytes: 25 << 20, ZipMaxEntries: 1000, ZipMaxTotal: 100 << 20, ZipMaxRatio: 100}
}

type fileKind int

const (
	kBinary fileKind = iota
	kText
	kZip
)

type rule struct {
	mime  string // saklanan/gösterilen MIME
	sniff string // DetectContentType çıktısının beklenen öneki
	kind  fileKind
	magic func([]byte) bool
	ooxml bool
}

func prefixAny(prefixes ...[]byte) func([]byte) bool {
	return func(head []byte) bool {
		for _, p := range prefixes {
			if bytes.HasPrefix(head, p) {
				return true
			}
		}
		return false
	}
}

var (
	zipMagic  = prefixAny([]byte("PK\x03\x04"))
	jpegMagic = prefixAny([]byte{0xFF, 0xD8, 0xFF})
)

var rules = map[string]rule{
	"pdf":  {"application/pdf", "application/pdf", kBinary, prefixAny([]byte("%PDF-")), false},
	"png":  {"image/png", "image/png", kBinary, prefixAny([]byte("\x89PNG\r\n\x1a\n")), false},
	"jpg":  {"image/jpeg", "image/jpeg", kBinary, jpegMagic, false},
	"jpeg": {"image/jpeg", "image/jpeg", kBinary, jpegMagic, false},
	"gif":  {"image/gif", "image/gif", kBinary, prefixAny([]byte("GIF87a"), []byte("GIF89a")), false},
	"txt":  {"text/plain", "text/", kText, nil, false},
	"csv":  {"text/csv", "text/", kText, nil, false},
	"md":   {"text/markdown", "text/", kText, nil, false},
	"zip":  {"application/zip", "application/zip", kZip, zipMagic, false},
	"docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip", kZip, zipMagic, true},
	"xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip", kZip, zipMagic, true},
	"pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/zip", kZip, zipMagic, true},
}

func IsArchive(ext string) bool { return rules[ext].kind == kZip && rules[ext].mime != "" }
func IsOOXML(ext string) bool   { return rules[ext].ooxml }

// ValidateName: dosya adını doğrular ve küçük harfli uzantıyı döndürür.
func ValidateName(name string) (string, *Reject) {
	bad := reject(http.StatusBadRequest, "invalid_name", "Geçersiz dosya adı")
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 255 {
		return "", bad
	}
	if name != strings.TrimSpace(name) || strings.HasSuffix(name, ".") {
		return "", bad
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' || r == ':' {
			return "", bad
		}
	}
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return "", reject(http.StatusUnsupportedMediaType, "unsupported_extension", "Dosya uzantısı gerekli")
	}
	ext := strings.ToLower(name[i+1:])
	if _, ok := rules[ext]; !ok {
		return "", reject(http.StatusUnsupportedMediaType, "unsupported_extension", "Bu dosya türüne izin verilmiyor")
	}
	return ext, nil
}

func textOK(head []byte) bool {
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	// Dilim çok baytlı bir karakteri ortadan kesmiş olabilir.
	for i := 0; i < 4 && i <= len(head); i++ {
		if utf8.Valid(head[:len(head)-i]) {
			return true
		}
	}
	return false
}

// CheckContent: dosya imzasını (magic byte) ve sezilen MIME türünü uzantıyla karşılaştırır.
func CheckContent(ext string, head []byte) (string, *Reject) {
	r, ok := rules[ext]
	if !ok {
		return "", reject(http.StatusUnsupportedMediaType, "unsupported_extension", "Bu dosya türüne izin verilmiyor")
	}
	mismatch := reject(http.StatusUnsupportedMediaType, "content_mismatch", "Dosya içeriği uzantısıyla uyuşmuyor")
	detected := http.DetectContentType(head)
	if !strings.HasPrefix(detected, r.sniff) {
		return "", mismatch
	}
	if r.kind == kText {
		if !textOK(head) {
			return "", mismatch
		}
	} else if !r.magic(head) {
		return "", mismatch
	}
	return r.mime, nil
}

func unsafeEntry(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || (len(name) > 1 && name[1] == ':') {
		return true
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// CheckZip: ZIP bombası, zip-slip, sembolik bağlantı, parolalı arşiv ve gömülü zararlı imza kontrolü.
// Başlıktaki boyutlara güvenilmez: gerçekten açılan bayt sayılır ve sınırda kesilir.
func CheckZip(ra io.ReaderAt, size int64, lim Limits, ooxml bool) *Reject {
	bad := func(msg string) *Reject { return reject(http.StatusUnprocessableEntity, "archive_rejected", msg) }

	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return bad("Geçersiz veya bozuk ZIP yapısı")
	}
	if len(zr.File) > lim.ZipMaxEntries {
		return bad("Arşivde çok fazla dosya var")
	}

	limit := size * lim.ZipMaxRatio
	if limit < 1<<20 { // küçük arşivlere 1 MB'a kadar serbestlik
		limit = 1 << 20
	}
	if limit > lim.ZipMaxTotal {
		limit = lim.ZipMaxTotal
	}

	var total int64
	hasContentTypes := false
	for _, f := range zr.File {
		if unsafeEntry(f.Name) {
			return bad("Arşiv güvensiz yol içeriyor")
		}
		if f.Name == "[Content_Types].xml" {
			hasContentTypes = true
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return bad("Arşiv sembolik bağlantı içeriyor")
		}
		if f.Flags&0x1 != 0 {
			return bad("Parola korumalı arşivler taranamaz")
		}
		rc, err := f.Open()
		if err != nil {
			return bad("Arşiv girdisi okunamadı")
		}
		sig, n, serr := Scan(io.LimitReader(rc, limit-total+1))
		_ = rc.Close()
		total += n
		if sig != "" {
			return reject(http.StatusUnprocessableEntity, CodeMalware, "Arşiv zararlı içerik imzası taşıyor: "+sig)
		}
		if serr != nil {
			return bad("Arşiv girdisi bozuk")
		}
		if total > limit {
			return bad("Arşiv açıldığında izin verilen boyutu aşıyor (ZIP bombası şüphesi)")
		}
	}
	if ooxml && !hasContentTypes {
		return bad("Office belgesi geçerli bir yapıya sahip değil")
	}
	return nil
}
