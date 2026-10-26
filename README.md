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

## Eksikler
- Kapsamlı front end
- make load ile k6 yük testi
- `Idempotency-Key` başlığı desteği
- F-1 yeniden adlandırma ve silme

## T-1 Performans Kanıtı (ilk test)

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

## JWT
Token iptal edilemez. Çıkış yapılsa bile token süresi dolana kadar (access 15 dk, refresh 7 gün) geçerli kalır. Çalınırsa sunucu tarafında kapatılamaz.
Refresh token’ı tek kullanımlık değil, daha güvenli bir tasarımda refresh token’ın hash’i veritabanında tutulur, her yenilemede döndürülür (rotation) ve çıkışta silinir. Zamanın yetmediği için eklenmedi.
localStorage XSS’e açıktır. Sayfaya kötü bir script girerse tokenı okuyabilir. Alternatif HttpOnly çerezdir, ama CORS ve CSRF ayarı gerektirir. 
Rol, access token içinde. Rol değişirse 15 dakika boyunca eski rol geçerli olabilir. Yenileme ucunda rolü veritabanından aldığımız için en geç yenilemede düzelir. Dosya yetkileri ise token’da değil, her istekte veritabanından hesaplandığı için anında geçerli olur.

## T-2 Güvenlik Katmanları

Virüs taraması bir simülatör: yalnızca EICAR ve KASADOC-TEST-MALWARE imzalarını bulur, gerçek bir antivirüsün yerini tutmaz.
İç içe arşivler açılıp taranmaz (yalnızca bir seviye). PDF ve Office makroları incelenmez.
Metin dosyalarında yalnızca ilk 8 KB UTF-8 ve NUL kontrolü yapılır. UTF-16 dosyalar reddedilir.
PDF başlığı dosyanın ilk baytında olmalı, öncesinde artık veri olan PDF’ler reddedilir.
Sahipsiz geçici dosyalar (sunucu çökerse tmp/ altında kalır) henüz temizlenmiyor.
Dosyaya yeni sürüm yükleme (F-2) henüz yok, file_versions tablosu buna hazır.

## T-3 Bilinen Sınırlamalar:
İstemci adresi doğrudan TCP bağlantısından alınır, X-Forwarded-For kullanılmaz. Ters vekil arkasında herkes tek adres görünür.
Genel adres sınırı aşıldığında olay denetim kaydına yazılmaz (kaydı şişirme saldırısını önlemek için), diğer tüm reddedilen denemeler yazılır.
Parola tabanlı bağlantı doğrulaması 64 MB bellek kullanır. Eşzamanlı saldırı bellek baskısı yaratabilir, hız sınırı bunu azaltır.
Bilinmeyen token ile bilinen token arasındaki yanıt süresi farkı ölçülmedi.

## T-4 Bilinen Sınırlamalar:

İmha mantıksal ve dosya sistemi düzeyindedir. Yedekler, PostgreSQL WAL dosyaları ve disk artıkları kapsam dışıdır, kriptografik silme yoktur.
Dosya adı, mezar taşında ve denetim kaydında kalır (kanıt amacıyla bilinçli seçim). Kişisel veri içeren adlar için ayrı bir politika gerekir.
Saklama süresi, düğümün oluşturulma tarihinden başlar. Dosyaya sonradan eklenecek sürümler sayacı yeniden başlatmaz.
Klasörler imha edilmez, yalnızca dosyalar.
Zamanlanmış job tek bir uygulama örneği varsayar (çok örnekli çalışmada da güvenli ama iş tekrarlanır).

## F-2 / F-3 / F-6 Bilinen Sınırlamalar:

Yeni sürüm, dosyayla aynı uzantıda olmak zorunda. Tür değiştirmek yeni dosya yüklemektir.
Arama ad üzerinde ILIKE '%...%' kullanır (indekssiz). 100.000 düğümde çalışır ama tam metin araması yoktur (bonus kapsamında).
Onay iş akışı tek aşamalı ve kurala bağlı değil: hangi belgenin onay gerektirdiğini sistem zorlamaz, onay sonucu dosya erişimini etkilemez.
Onaylayan, dosyada okuma yetkisi sahibi olmak zorunda değil (rol bazlı karar). Belge içeriğini görmeden karar verebilir.
Tek bir dosya için aynı anda yalnızca bir bekleyen talep olabilir.

## Doğrulama Soruları

1. En zorlandığın görev hangisiydi? Hangi alternatif çözümleri düşündün ve neden eledin?

En zorlandığım görev, klasör hiyerarşisinde erişim yetkilerinin doğru ve verimli biçimde hesaplanmasıydı. Çünkü bir kullanıcının erişimi yalnızca dosyanın kendi izinlerine değil, üst klasörlerden devralınan izinlere de bağlıdır. Ayrıca deny kuralının allow kuralına üstün gelmesi gerekir.

Alternatif olarak her istekte klasör ağacını uygulama katmanında dolaşmayı, izinleri önbelleğe almayı ve hiyerarşiyi veritabanında sorgulanabilir bir yapıyla temsil etmeyi değerlendirdim. Her istekte ağacı yeniden dolaşmak büyük veri kümelerinde maliyet oluşturabileceğinden, mevcut çözümde veritabanı sorgularından ve dizinlerden yararlanan yaklaşımı tercih ettim.

Bu yaklaşımın doğruluğunu yalnızca performans ölçümüyle değil; üst klasörden izin devri, açık ret, doğrudan izin ve yetkisiz erişim senaryolarıyla da değerlendirmek gerekir.

2. Çözümünün kırıldığı ya da yetersiz kaldığı bir senaryo bul ve nedenini açıkla (bilinen sınırlama).

Bilinen sınırlamalardan biri, dosya aramasının ILIKE '%...%' kullanmasıdır. Bu yöntem kısmi ad eşleşmelerini destekler; ancak normal bir B-tree dizini bu sorgu biçimini genel olarak hızlandıramaz. Büyük veri kümelerinde arama maliyeti artabilir. 

Yedeklerdeki verilerin imhası: Uygulama, belgelerin saklama süresi dolduğunda imha edilmesini ve imha tutanağı üretilmesini hedefliyor. Ancak veritabanı kayıtlarının veya ana depodaki dosyanın silinmesi, yedekler, PostgreSQL WAL kayıtları ve diğer kalıcı kopyalardaki verilerin de fiziksel olarak yok edildiğini tek başına kanıtlamaz. Bu nedenle mevcut çözüm, yedekler dâhil tüm kopyalarda kriptografik veya fiziksel imha garantisi sunuyor denemez.

3. Veritabanına eklediğin dizinlerden ikisini seç: hangi sorgu için, dizinsiz/dizinli ölçüm farkı nedir?

Yetki kontrolü sorgusunda performans açısından önemli iki indeks şunlardır:

**nodes_pkey**: nodes tablosunda bir düğümü id primary keyi üzerinden bulur. Yetki sorgusu hedef düğümün ancestor_ids bilgisini bu kayıt üzerinden elde eder.

**idx_acl_node**: acl_entries(node_id) indeksi, hedef düğümün ve üst düğümlerinin kimlikleri üzerinden erişim kurallarını aramayı hızlandırır. Yetki sorgusunda a.node_id = ANY(n.ancestor_ids) koşulu kullanılır.

Ölçümler, 1.000 yetki kontrolü üzerinden iki durumda gerçekleştirilmiştir:

1. İlgili ACL indeksleri açıkken.
2. `idx_acl_node` indeksi ve aynı aramayı destekleyen bileşik `UNIQUE` kısıtının oluşturduğu indeks geçici olarak kaldırılmışken.

Her iki durumda da `EXPLAIN (ANALYZE, BUFFERS)` kullanılarak sorgu planı incelenmiştir.

| Ölçüm | İndeksler açık | İlgili indeksler kapalı |
|---|---:|---:|
| p50 | 239,6 µs | 1,334 ms |
| p95 | 998 µs | 2,139 ms |
| p99 | 1,001 ms | 2,511 ms |
| Maksimum | 1,433 ms | 3,592 ms |

**Sorgu planının incelenmesi:**

- **İndeksler açıkken:** PostgreSQL, düğümü bulmak için `nodes_pkey`, ilgili ACL kayıtlarını bulmak için `idx_acl_node` indeksini kullanmıştır. İncelenen planda ilgili ACL araması 4 satırla sonuçlanmıştır.
- **İlgili indeksler kapalıyken:** PostgreSQL, özne bilgilerine yönelik `idx_acl_subject` indeksini kullanmaya devam etmiştir. Ancak daha fazla ACL kaydını düğümün hiyerarşisiyle eşleştirmesi gerekmiştir. Planda 5.500 satırın eşleştirme filtresinden çıkarıldığı görülmüştür.

**Sonuç:** İlgili ACL indeksleri açıkken p95 süresi 998 µs, indeksler devre dışıyken 2,139 ms olarak ölçülmüştür. İndekslerin devre dışı bırakıldığı durumda p95 yaklaşık 2,14 kat daha yüksek gerçekleşmiştir.

Bu karşılaştırma, veritabanındaki tüm indekslerin kaldırıldığı bir test değildir. Düğümün birincil anahtar indeksi ve `idx_acl_subject` gibi diğer indeksler korunmuştur. Dolayısıyla sonuçlar, özellikle ACL kayıtlarının düğüm kimliği üzerinden aranmasını destekleyen indekslerin etkisini göstermektedir.

Test sonunda geçici olarak kaldırılan bileşik `UNIQUE` kısıtı ve `idx_acl_node` indeksi yeniden oluşturulmuş, istatistikler güncellenmiş ve sorgu planı tekrar kontrol edilmiştir.

**Not:** Ölçümler tek bir test çalıştırmasından elde edilmiştir. Gerçek performans; veri dağılımı, donanım, önbellek durumu, eşzamanlılık ve PostgreSQL yapılandırmasına göre değişebilir.


4. Yapay zekâ kullandıysan, reddettiğin ya da düzelttiğin bir çıktıyı (önce/sonra) göster ve neden yanlış olduğunu açıkla.

Geliştirme sırasında yapay zekâdan kod üretme ve hata ayıklama desteği aldım. Üretilen kodu doğrudan doğru kabul etmek yerine derleme, lint ve test sonuçları üzerinden kontrol etmek gerektiğini gördüm.

Örneğin statik analiz, bazı Close() çağrılarının hata değerlerinin kontrol edilmediğini bildirdi. İlk yaklaşımda kapatma hatası göz ardı ediliyordu. Düzeltilen yaklaşımda hata kontrol edilerek uygun biçimde raporlanması sağlandı.

Önce:

defer f.Close()

Sonra:

defer func() {
    if err := f.Close(); err != nil {
        slog.Error("dosya kapatılamadı", "err", err)
    }
}()

Bu düzeltme, kaynak kapatma hatalarının sessizce göz ardı edilmesini önlemeye yardımcı olur.

5. “Hiyerarşik yetki modeli” görevindeki çözümünün doğru çalıştığını nasıl kanıtladın? Komutu ve çıktısını yaz.

Hiyerarşik yetki modelini doğrulamak için otomatik testler ve performans testi (T1de sonuçlar belirtildi) kullanılır. Testlerin farklı izin senaryolarını kapsaması gerekir: üst klasörden izin devri, doğrudan izin, deny önceliği ve yetkisiz erişim.

(Docker açık ve terminal backend klasöründe iken) Performans testi için kullanılan komut: 

PERF=1 go test ./internal/permissions/ -run TestPerf -v -timeout 10m

Sonuç (son test):

veri hazır (5.843s): 100000 düğüm, 55500 yetki kaydı, derinlik 10
sonuç dağılımı: 1408 izinli, 1592 reddedilen
sıralı (1 istemci): n=3000 p50=510.9µs p95=552.1µs p99=699.6µs max=1.5227ms
eşzamanlı (8 istemci): n=4000 p50=997.6µs p95=1.0051ms p99=1.0851ms max=31.7114ms
Execution Time: 0.125 ms
--- PASS: TestPerfEtkinYetki100kDugum (10.81s)
PASS

Bu ölçüm, 100.000 düğümlü veri kümesinde yetki sorgusunun performansını gösterir; tek başına yetki modelinin mantıksal olarak doğru olduğunu kanıtlamaz. Ayrıca test ağacının 10.000 bağımsız zincirden oluştuğu ve ölçümün HTTP katmanını kapsamadığı dikkate alınmalıdır.