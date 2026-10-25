package upload

import (
	"bytes"
	"io"
	"strings"
)

// EICAR dizisi kaynakta bitişik yazılmaz: antivirüs yazılımları kaynağı veya
// derlenmiş ikiliyi yanlışlıkla zararlı sayabilir. Çalışma anında birleştirilir.
var eicarParts = []string{`X5O!P%@AP`, `[4\PZX54(P^)7CC)7}$`, `EICAR-STANDARD-`, `ANTIVIRUS-TEST-FILE!`, `$H+H*`}

// EICAR: standart antivirüs test dizisi (yalnızca test ve simülasyon için).
func EICAR() []byte { return []byte(strings.Join(eicarParts, "")) }

type signature struct {
	name    string
	pattern []byte
}

var signatures = []signature{
	{"EICAR-Test-File", EICAR()},
	{"KasaDoc-Test-Malware", []byte("KASADOC-TEST-MALWARE")},
}

// Scan akışı parça parça tarar; parça sınırına denk gelen imzaları da yakalar.
// Bulunan imzanın adını (yoksa ""), okunan bayt sayısını ve hatayı döndürür.
func Scan(r io.Reader) (sig string, n int64, err error) {
	maxLen := 0
	for _, s := range signatures {
		if len(s.pattern) > maxLen {
			maxLen = len(s.pattern)
		}
	}
	buf := make([]byte, 64<<10)
	var carry []byte
	for {
		m, rerr := r.Read(buf)
		if m > 0 {
			n += int64(m)
			window := make([]byte, 0, len(carry)+m)
			window = append(window, carry...)
			window = append(window, buf[:m]...)
			for _, s := range signatures {
				if bytes.Contains(window, s.pattern) {
					return s.name, n, nil
				}
			}
			keep := maxLen - 1
			if len(window) < keep {
				keep = len(window)
			}
			carry = append(carry[:0], window[len(window)-keep:]...)
		}
		if rerr == io.EOF {
			return "", n, nil
		}
		if rerr != nil {
			return "", n, rerr
		}
	}
}