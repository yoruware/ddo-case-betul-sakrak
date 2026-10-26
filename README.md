# KasaDoc — Güvenli Doküman Yönetim Sistemi

**Geliştirici:** Betül Şakrak

KasaDoc, kurumsal belgelerin güvenli biçimde saklanması, sürümlenmesi, paylaşılması ve denetlenmesi amacıyla geliştirilmiş bir doküman yönetim sistemi prototipidir.

Proje; rol tabanlı erişim kontrolü, hiyerarşik yetkilendirme, güvenli dosya saklama ve denetim kayıtları gibi konulara odaklanır.

## Teknolojiler

- **Backend:** Go
- **Veritabanı:** PostgreSQL 16
- **Frontend:** Alpine.js
- **Dağıtım:** Docker ve Docker Compose

## Özellikler

- Klasör ve dosya yönetimi, sürümleme ve sürüme geri dönme
- Etiketleme, arama ve filtreleme
- Rol ve klasör hiyerarşisine dayalı yetkilendirme
- Kişi, grup ve süreli bağlantı üzerinden paylaşım
- Dosya bütünlüğü için SHA-256 tabanlı içerik adresli saklama
- Saklama politikaları, hukuki bekletme ve imha
- Onay iş akışı ve denetim kayıtları
- Test verisi üreten simülatör

## Kurulum

Gereksinimler: Docker ve Docker Compose.

```bash
git clone https://github.com/yoruware/ddo-case-betul-sakrak.git
cd ddo-case-betul-sakrak
cp .env.example .env
```

`.env` dosyasındaki gerekli ayarları kontrol ettikten sonra:

```bash
docker compose up --build
```

Servis adresleri:

- **Frontend:** http://localhost:3000
- **Backend:** http://localhost:8080
- **Sağlık kontrolü:** http://localhost:8080/health

Veritabanı, Compose ağı üzerinden erişilecek şekilde yapılandırılmıştır.

## Test ve Doğrulama

Testleri ve doğrulama senaryolarını çalıştırmak için:

```bash
docker compose --profile verify run --rm verify
```

Performans testinin belgelenen komutu (`backend` klasöründe, Docker ve veritabanı çalışırken):

```bash
set PERF=1
go test ./internal/permissions/ -run TestPerf -v -timeout 10m
```

## Mimari Yaklaşım

Hiyerarşik yetki kontrollerinde ata kimliklerini saklayan `ancestor_ids` yaklaşımı kullanılır. Dosyalar SHA-256 özeti üzerinden adreslenir; süreli indirme bağlantılarında HMAC imzalama yaklaşımından yararlanılır.

## Bilinen Sınırlamalar

- Dosya araması ad üzerinden yapılır; tam metin araması bulunmaz.
- Onay iş akışı henüz dosya erişimini veya imha sürecini kısıtlamaz.
- İmha işlemi yedekleri, PostgreSQL WAL dosyalarını ve disk artıklarını kapsamaz.
- Yetki performansı ölçümü, belirtilen test verisi ve ortamla sınırlıdır.

Diğer sınırlamalar ve mimari için [DECISIONS.md](DECISIONS.md) dosyasına bakın.


## T-1 Performans Kanıtı

Komut (Docker açıkken, `backend` klasöründe):

    set PERF=1
    go test ./internal/permissions/ -run TestPerf -v -timeout 10m

Çıktıdan:

    veri hazır: 100000 düğüm, 55500 yetki kaydı, derinlik 10
    sıralı (1 istemci):    n=3000 p50=336µs p95=770µs  p99=1.06ms
    eşzamanlı (8 istemci): n=4000 p50=997µs p95=1.11ms p99=1.99ms max=33ms

`EXPLAIN (ANALYZE, BUFFERS)`: `Index Scan using nodes_pkey` + `Bitmap Index Scan on idx_acl_node`,
Execution Time 0.143 ms, 28 tampon isabeti.

**Sınırlamalar:** Ağaç 10.000 bağımsız zincirden oluşuyor (dallanma yok). Ölçüm yalnızca yetki
sorgusunu kapsıyor, HTTP katmanını değil. Dizüstü bilgisayarda Docker içinde ve ısınmış önbellekle
yapıldı. Eşzamanlı çalıştırmada tek bir istek 33 ms'ye çıktı, p95'i etkilemedi.

JWT
Token iptal edilemez. Çıkış yapılsa bile token süresi dolana kadar (access 15 dk, refresh 7 gün) geçerli kalır. Çalınırsa sunucu tarafında kapatılamaz.
Refresh token’ı tek kullanımlık değil, daha güvenli bir tasarımda refresh token’ın hash’i veritabanında tutulur, her yenilemede döndürülür (rotation) ve çıkışta silinir. Zamanın yetmediği için eklenmedi.
localStorage XSS’e açıktır. Sayfaya kötü bir script girerse tokenı okuyabilir. Alternatif HttpOnly çerezdir, ama CORS ve CSRF ayarı gerektirir. 
Rol, access token içinde. Rol değişirse 15 dakika boyunca eski rol geçerli olabilir. Yenileme ucunda rolü veritabanından aldığımız için en geç yenilemede düzelir. Dosya yetkileri ise token’da değil, her istekte veritabanından hesaplandığı için anında geçerli olur.

“T-2 Güvenlik Katmanları”

Virüs taraması bir simülatör: yalnızca EICAR ve KASADOC-TEST-MALWARE imzalarını bulur, gerçek bir antivirüsün yerini tutmaz.
İç içe arşivler açılıp taranmaz (yalnızca bir seviye). PDF ve Office makroları incelenmez.
Metin dosyalarında yalnızca ilk 8 KB UTF-8 ve NUL kontrolü yapılır. UTF-16 dosyalar reddedilir.
PDF başlığı dosyanın ilk baytında olmalı, öncesinde artık veri olan PDF’ler reddedilir.
Sahipsiz geçici dosyalar (sunucu çökerse tmp/ altında kalır) henüz temizlenmiyor.
Dosyaya yeni sürüm yükleme (F-2) henüz yok, file_versions tablosu buna hazır.

“T-3 Bilinen Sınırlamalar”:
İstemci adresi doğrudan TCP bağlantısından alınır, X-Forwarded-For kullanılmaz. Ters vekil arkasında herkes tek adres görünür.
Genel adres sınırı aşıldığında olay denetim kaydına yazılmaz (kaydı şişirme saldırısını önlemek için), diğer tüm reddedilen denemeler yazılır.
Parola tabanlı bağlantı doğrulaması 64 MB bellek kullanır. Eşzamanlı saldırı bellek baskısı yaratabilir, hız sınırı bunu azaltır.
Bilinmeyen token ile bilinen token arasındaki yanıt süresi farkı ölçülmedi.

“T-4 Bilinen Sınırlamalar”:

İmha mantıksal ve dosya sistemi düzeyindedir. Yedekler, PostgreSQL WAL dosyaları ve disk artıkları kapsam dışıdır, kriptografik silme yoktur.
Dosya adı, mezar taşında ve denetim kaydında kalır (kanıt amacıyla bilinçli seçim). Kişisel veri içeren adlar için ayrı bir politika gerekir.
Saklama süresi, düğümün oluşturulma tarihinden başlar. Dosyaya sonradan eklenecek sürümler sayacı yeniden başlatmaz.
Klasörler imha edilmez, yalnızca dosyalar.
Zamanlanmış job tek bir uygulama örneği varsayar (çok örnekli çalışmada da güvenli ama iş tekrarlanır).

“F-2 / F-3 / F-6 Bilinen Sınırlamalar”:

Yeni sürüm, dosyayla aynı uzantıda olmak zorunda. Tür değiştirmek yeni dosya yüklemektir.
Arama ad üzerinde ILIKE '%...%' kullanır (indekssiz). 100.000 düğümde çalışır ama tam metin araması yoktur (bonus kapsamında).
Onay iş akışı tek aşamalı ve kurala bağlı değil: hangi belgenin onay gerektirdiğini sistem zorlamaz, onay sonucu dosya erişimini etkilemez.
Onaylayan, dosyada okuma yetkisi sahibi olmak zorunda değil (rol bazlı karar). Belge içeriğini görmeden karar verebilir.
Tek bir dosya için aynı anda yalnızca bir bekleyen talep olabilir.