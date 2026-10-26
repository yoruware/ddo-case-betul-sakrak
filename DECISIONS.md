# Mimari Karar Kayıtları

## ADR-001: Hiyerarşik yetki sorgusu için `ancestor_ids` dizisi
**Bağlam.** Klasör ağacında yetki mirası, grup üyelikleri ve açık "reddet" kuralı gerekiyor.
100.000 dosyalı, 10 seviye derinliğindeki ağaçta yetki kontrolü p95 < 30 ms olmalı. Liste
ekranlarında her satır için yetki hesaplandığı için kontrol hem tekil hem toplu çalışabilmeli.

**Seçenekler.**
1. `parent_id` + özyinelemeli CTE: şema sade ve normalize. Ancak her kontrol derinlik kadar
   yinelemeye ihtiyaç duyar; liste sorgularında satır başına tekrarlanır.
2. PostgreSQL `ltree`: yol sorguları güçlü. Ek uzantı bağımlılığı getirir ve UUID'lerin etiket
   biçimine dönüştürülmesi gerekir.
3. Closure table: okuma hızlı. 100.000 düğüm × derinlik kadar ek satır tutar, ağaç değişince
   bakımı pahalıdır.
4. `ancestor_ids uuid[]` + GIN indeksi: her düğüm kökten kendisine kadar atalarını saklar;
   yetki kayıtları tek `node_id = ANY(ancestor_ids)` birleşimiyle bulunur.
5. Yetki sonucunu önbelleğe almak: hızlı, ancak yetki iptalinden sonra eski yetkiyle erişim
   riski doğurur. Gereksinim bunu açıkça yasaklıyor.

**Karar.** Seçenek 4 uygulandı, önbellek kullanılmıyor. Her istekte tek sorguyla güncel
kayıtlar okunur ve `permissions.Resolve` saf fonksiyonuyla hesaplanır.

**Sonuç.**
- (+) Derinlikten bağımsız tek sorgu, ek tablo yok, yetki değişikliği anında geçerli.
- (+) Hesap mantığı veritabanından ayrı olduğu için birim testi kolay.
- (−) Denormalizasyon: bir klasör taşınırsa alt ağacın `ancestor_ids` değerleri yeniden
  yazılmalı. Taşıma henüz yok; eklendiğinde alt ağaç tek `UPDATE` ile güncellenecek.
- (−) Dizi yalnızca `createNode` içinde üretiliyor; `CHECK` kısıtı sadece son elemanın
  düğümün kendisi olduğunu doğrular.


- Doğrulama (ölçüldü): 100.000 düğüm (10.000 zincir × 10 seviye), 55.500 yetki kaydı, derinlik 10.
  Yetki kontrolü p95 = 0,77 ms (1 istemci) ve 1,11 ms (8 eşzamanlı istemci); hedef < 30 ms.
  Plan: `nodes_pkey` ile tek satır + `idx_acl_node` ile bitmap taraması, yürütme süresi 0,14 ms.





  ## ADR-003: İçerik adresli disk saklama ve kullanıcıya bağlı HMAC imzalı indirme

**Bağlam.** Yüklenen dosyalar tekilleştirilmeli (aynı içerik tek kopya), yetkiler dosya başına
ayrı kalmalı, indirme süreli bağlantılarla yapılmalı ve yetki iptali anında etkili olmalı.

**Seçenekler.** (1) İçeriği PostgreSQL `bytea` / large object olarak tutmak. (2) Dosya başına
rastgele adla diske yazmak. (3) SHA-256 ile adreslenmiş blobları diske yazıp meta veriyi
veritabanında tutmak. İndirme için: (a) depolamaya doğrudan açık URL, (b) veritabanında
bağlantı tablosu, (c) durumsuz HMAC imzalı bağlantı.

**Karar.** (3) ve (c). Blob yolu yalnızca sunucunun hesapladığı SHA-256'dan türer; kullanıcı
adı diske yazılmaz. Bağlantı `HMAC(anahtar, düğüm | kullanıcı | bitiş)` ile imzalanır, sabit
zamanlı karşılaştırılır. İndirme anında kullanıcının `read` yetkisi yeniden hesaplanır ve
denetim zincirine yazılır; kayıt yazılamazsa indirme yapılmaz.

**Sonuç.** (+) Aynı içerik tek kopya; yol gezinmesi yapısal olarak imkânsız; iptal edilen
yetkiyle önceden verilmiş bağlantı çalışmaz. (−) Blob dosyası ile veritabanı satırı tek
transaction değil: dosya, transaction commit'inden hemen önce taşınır ve nadir bir commit
hatasında sahipsiz blob kalabilir (T-4 imha işi temizler). Bağlantı süresi dolana kadar
bağlantıyı tek başına iptal etmenin yolu yok; yetkiyi kaldırmak yeterli. Anahtar rotasyonu yok.

## ADR-004: Paylaşım bağlantıları: hash'li token, atomik sayaç, bellek içi hız sınırı

**Bağlam.** Oturum açmamış kişilere süreli, parolalı, sayı sınırlı indirme verilecek. Veritabanı
sızarsa bağlantılar kullanılamamalı, eşzamanlı isteklerde sınır aşılmamalı, parola denemeleri
engellenmeli ve her erişim izlenebilmeli.

**Seçenekler.** Token için: (1) düz metin saklamak, (2) hash saklamak. Sayaç için: (a) oku-karşılaştır-yaz,
(b) `SELECT ... FOR UPDATE`, (c) koşullu `UPDATE ... RETURNING`. Hız sınırı için: (i) bellekte sayaç,
(ii) veritabanında deneme tablosu, (iii) Redis.

**Karar.** (2), (c), (i). Token 256 bit rastgeledir ve yalnızca SHA-256'sı saklanır. Parola argon2id'dir.
Sayaç, koşulları WHERE içinde taşıyan tek UPDATE ile artırılır. Hız sınırı üç katmandır: adres başına genel
sınır, bağlantı+adres başına 5 hatalı parola ve bağlantı başına 30 hatalı parola (15 dk pencere).
Bağlantı, oluşturanın dosyadaki `read` yetkisine bağlıdır.

**Sonuç.** (+) Sızan veritabanından geçerli token çıkmaz; eşzamanlı 20 istekte sınır 3 ile kesin tutulur
(testle kanıtlı). (−) Sınırlayıcı belleğtedir: yeniden başlatmada sıfırlanır, çok örnekli kurulumda paylaşılmaz.
(−) Bağlantı başına sınır, saldırganın bağlantıyı 15 dakika kilitlemesine izin verir (hizmet aksatma ile
güvenlik arasında bilinçli seçim). (−) Sayaç istek başlayınca artar; yarıda kesilen indirme hakkı tüketir.

## ADR-005: Saklama, hukuki bekletme ve kanıtlanabilir imha

**Bağlam.** Belgeler türüne göre belirli süre saklanıp imha edilmeli, hukuki bekletme imhayı kesin
engellemeli, imha tekrar ve eşzamanlı çalıştırmada aynı sonucu vermeli ve her imha kanıtlanabilir
olmalı. İçerik adresli saklamada aynı blob birden çok dosyaya bağlı olabilir.

**Seçenekler.** Silme: (a) satırı fiziksel silmek, (b) mezar taşı (tombstone) bırakmak. Blob silme:
(i) transaction içinde doğrudan silmek, (ii) commit sonrası silmek, (iii) önce çöp klasörüne taşıyıp
commit sonrası silmek. Eşzamanlılık: (1) satır kilitleri, (2) tek advisory kilit.
Bekletme kapsamı: (A) yalnızca işaretlenen düğüm, (B) alt ağaç (`ancestor_ids`).

**Karar.** (b), (iii), (2), (B). İmha, belge başına tek transaction'dır. Kilit altında koşullar yeniden
okunur, bekletme yeniden kontrol edilir, sürümler ve boşta kalan blob silinir, paylaşım bağlantıları
kapatılır, tutanak hash'i denetim zincirine yazılır. Yükleme, bekletme ve imha aynı advisory kilidi kullanır
(yükleme paylaşımlı, diğerleri özel). Bekletme klasöre konunca altındaki tüm dosyaları kapsar.

**Sonuç.** (+) Aynı job tekrar veya eşzamanlı çalışsa her belge tam bir kez imha edilir (testle kanıtlı).
(+) Commit başarısız olursa blob geri konur, veri kaybı olmaz. (+) Tutanağın hash'i değiştirilemez
zincirde olduğu için sonradan düzeltilemez. (−) Mezar taşı adı saklar; aynı klasörde aynı ad
yeniden kullanılamaz. (−) Global kilit, imha ve bekletme işlemlerini sıraya dizer; hacim büyürse
düğüm başına kilide geçilmeli. (−) Saklama kaydı bir kez atanır; hatalı atama yalnızca veritabanından düzeltilir.

## ADR-006: Eklemeli sürümleme ve görev ayrılığı zorunlu onay akışı

**Bağlam.** Dosya sürümleri geri alınabilmeli ama geçmiş silinmemeli. Onay akışında talep sahibi kendi
talebini onaylayamamalı ve eşzamanlı kararlar çakışmamalı.

**Seçenekler.** Geri dönüş: (a) eski sürümü "güncel" işaretlemek, (b) eski içeriği yeni sürüm olarak eklemek.
Görev ayrılığı: (1) yalnızca uygulama kodunda, (2) uygulama + veritabanı kısıtı. Karar çakışması:
(i) oku-kontrol et-yaz, (ii) koşullu tek UPDATE.

**Karar.** (b), (2), (ii). Sürümler yalnızca eklenir, geri dönüş yeni sürüm üretir; numara, dosya satırı
`FOR UPDATE` ile kilitlenerek verilir. Onay kararı `WHERE status='pending' AND requested_by <> karar_veren`
koşullu UPDATE'idir; ayrıca tabloda `CHECK (decided_by <> requested_by)` bulunur.

**Sonuç.** (+) Geri dönüş denetlenebilir ve kendisi de geri alınabilir; eşzamanlı 10 karardan yalnızca biri
kazanır (testle kanıtlı). (+) Uygulama hatası olsa bile veritabanı kendi onayını reddeder. (−) Her geri dönüş
yeni sürüm satırı ekler. (−) Onay akışı şimdilik bilgi amaçlıdır: onay, dosya erişimini veya imhayı kısıtlamaz.