package upload

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"testing/iotest"
)

func code(r *Reject) string {
	if r == nil {
		return ""
	}
	return r.Code
}

func TestValidateName(t *testing.T) {
	cases := []struct{ name, ext, code string }{
		{"rapor.pdf", "pdf", ""},
		{"RAPOR.PDF", "pdf", ""},
		{"arşiv.txt", "txt", ""},
		{"a.b.c.docx", "docx", ""},
		{"../etc/passwd.txt", "", "invalid_name"},
		{"a/b.pdf", "", "invalid_name"},
		{`a\b.pdf`, "", "invalid_name"},
		{"..", "", "invalid_name"},
		{"", "", "invalid_name"},
		{"x:akis.txt", "", "invalid_name"},
		{"a\x01.pdf", "", "invalid_name"},
		{"a.pdf ", "", "invalid_name"},
		{"a.pdf.", "", "invalid_name"},
		{strings.Repeat("a", 300) + ".pdf", "", "invalid_name"},
		{"virus.exe", "", "unsupported_extension"},
		{"uzantisiz", "", "unsupported_extension"},
		{".pdf", "", "unsupported_extension"},
		{"betik.sh", "", "unsupported_extension"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ext, rej := ValidateName(c.name)
			if code(rej) != c.code || ext != c.ext {
				t.Fatalf("beklenen (%q,%q), gelen (%q,%q)", c.ext, c.code, ext, code(rej))
			}
		})
	}
}

func TestCheckContent(t *testing.T) {
	pad := make([]byte, 32)
	pdf := []byte("%PDF-1.7\n1 0 obj")
	png := append([]byte("\x89PNG\r\n\x1a\n"), pad...)
	jpg := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, pad...)
	zipHead := append([]byte("PK\x03\x04"), pad...)
	exe := append([]byte("MZ\x90\x00"), pad...)
	elf := append([]byte("\x7fELF"), pad...)
	text := []byte("merhaba dünya,1,2\n")
	md := []byte("<!-- not -->\n# Başlık")

	cases := []struct {
		name, ext string
		head      []byte
		want      string
	}{
		{"pdf gerçek", "pdf", pdf, ""},
		{"png gerçek", "png", png, ""},
		{"jpg gerçek", "jpg", jpg, ""},
		{"jpeg gerçek", "jpeg", jpg, ""},
		{"docx zip imzalı", "docx", zipHead, ""},
		{"zip gerçek", "zip", zipHead, ""},
		{"txt gerçek", "txt", text, ""},
		{"csv gerçek", "csv", text, ""},
		{"md html yorumu ile", "md", md, ""},
		{"exe başlıklı pdf", "pdf", exe, "content_mismatch"},
		{"jpg başlıklı png", "png", jpg, "content_mismatch"},
		{"zip başlıklı pdf", "pdf", zipHead, "content_mismatch"},
		{"ikili veri txt", "txt", exe, "content_mismatch"},
		{"elf başlıklı png", "png", elf, "content_mismatch"},
		{"pdf başlıklı txt", "txt", pdf, "content_mismatch"},
		{"boş pdf", "pdf", []byte{}, "content_mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, rej := CheckContent(c.ext, c.head)
			if code(rej) != c.want {
				t.Fatalf("beklenen %q, gelen %q", c.want, code(rej))
			}
		})
	}
	if m, _ := CheckContent("pdf", pdf); m != "application/pdf" {
		t.Fatalf("MIME beklenmedik: %q", m)
	}
}

func TestScan(t *testing.T) {
	if sig, _, err := Scan(bytes.NewReader(bytes.Repeat([]byte("temiz veri "), 10000))); err != nil || sig != "" {
		t.Fatalf("temiz veri zararlı görünmemeli: %q %v", sig, err)
	}
	if sig, _, _ := Scan(bytes.NewReader(EICAR())); sig == "" {
		t.Fatal("EICAR bulunmalıydı")
	}
	if sig, _, _ := Scan(strings.NewReader("xx KASADOC-TEST-MALWARE yy")); sig == "" {
		t.Fatal("test imzası bulunmalıydı")
	}
	pad := bytes.Repeat([]byte("a"), 64<<10-5) // imza 64 KB parça sınırına denk gelir
	data := append(append([]byte(nil), pad...), EICAR()...)
	if sig, _, _ := Scan(bytes.NewReader(data)); sig == "" {
		t.Fatal("parça sınırındaki imza bulunmalıydı")
	}
	if sig, _, _ := Scan(iotest.OneByteReader(bytes.NewReader(EICAR()))); sig == "" {
		t.Fatal("bayt bayt okunan imza bulunmalıydı")
	}
}

type ent struct {
	name string
	data []byte
}

func makeZip(t *testing.T, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range ents {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCheckZip(t *testing.T) {
	lim := Limits{MaxFileBytes: 25 << 20, ZipMaxEntries: 5, ZipMaxTotal: 4 << 20, ZipMaxRatio: 100}
	check := func(b []byte, ooxml bool) *Reject {
		return CheckZip(bytes.NewReader(b), int64(len(b)), lim, ooxml)
	}

	t.Run("normal arşiv", func(t *testing.T) {
		if r := check(makeZip(t, ent{"a.txt", []byte("merhaba")}), false); r != nil {
			t.Fatal(r)
		}
	})
	t.Run("geçerli OOXML", func(t *testing.T) {
		z := makeZip(t, ent{"[Content_Types].xml", []byte("<x/>")}, ent{"word/document.xml", []byte("<d/>")})
		if r := check(z, true); r != nil {
			t.Fatal(r)
		}
	})
	t.Run("OOXML yapısı eksik", func(t *testing.T) {
		if c := code(check(makeZip(t, ent{"a.txt", []byte("x")}), true)); c != "archive_rejected" {
			t.Fatalf("archive_rejected bekleniyordu: %q", c)
		}
	})
	t.Run("ZIP bombası", func(t *testing.T) {
		z := makeZip(t, ent{"sifir.bin", make([]byte, 10<<20)})
		if c := code(check(z, false)); c != "archive_rejected" {
			t.Fatalf("archive_rejected bekleniyordu: %q", c)
		}
	})
	t.Run("zip-slip", func(t *testing.T) {
		if c := code(check(makeZip(t, ent{"../../evil.txt", []byte("x")}), false)); c != "archive_rejected" {
			t.Fatalf("archive_rejected bekleniyordu: %q", c)
		}
	})
	t.Run("çok fazla girdi", func(t *testing.T) {
		var es []ent
		for i := 0; i < 10; i++ {
			es = append(es, ent{string(rune('a'+i)) + ".txt", []byte("x")})
		}
		if c := code(check(makeZip(t, es...), false)); c != "archive_rejected" {
			t.Fatalf("archive_rejected bekleniyordu: %q", c)
		}
	})
	t.Run("arşiv içinde zararlı imza", func(t *testing.T) {
		if c := code(check(makeZip(t, ent{"gizli.txt", EICAR()}), false)); c != CodeMalware {
			t.Fatalf("%s bekleniyordu: %q", CodeMalware, c)
		}
	})
	t.Run("bozuk arşiv", func(t *testing.T) {
		if c := code(check([]byte("PK\x03\x04bozuk"), false)); c != "archive_rejected" {
			t.Fatalf("archive_rejected bekleniyordu: %q", c)
		}
	})
}