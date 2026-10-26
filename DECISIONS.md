# Mimari Karar Kayıtları (DECISIONS.md)

Bu belgede KasaDoc geliştirilirken alınan temel mimari kararlar, değerlendirilen alternatifler ve bilinen ödünleşimler açıklanmaktadır.

## ADR-001: Hiyerarşik Yetkilendirme

**Bağlam:** Klasörler iç içe bulunabilir ve kullanıcıların yetkileri üst klasörlerden alt klasörlere aktarılabilir. Her dosya için bütün klasör ağacını yeniden dolaşmak performans maliyetine neden olabilir.

**Alternatifler:**
- Her istekte klasör ağacını baştan dolaşmak.
- Üst klasörlerin kimliklerini saklayarak yetki kontrolünü hızlandırmak.

**Karar:** Klasörlerin ata kimliklerini `ancestor_ids` alanında tutan yaklaşım kullanıldı. Yetki değerlendirmesinde kullanıcı ve grup izinleri ile açık ret kuralları dikkate alınır.

**Sonuç:** Yetki kontrolleri hızlanabilir. Ancak klasör hiyerarşisi değiştiğinde ata bilgilerinin tutarlı tutulması gerekir. Mevcut tasarımda klasör taşıma desteği bulunmaması bu alanın bir sınırlamasıdır.

- Doğrulama (ölçüldü): 100.000 düğüm (10.000 zincir × 10 seviye), 55.500 yetki kaydı, derinlik 10.
  Yetki kontrolü p95 = 0,77 ms (1 istemci) ve 1,11 ms (8 eşzamanlı istemci); hedef < 30 ms.
  Plan: `nodes_pkey` ile tek satır + `idx_acl_node` ile bitmap taraması, yürütme süresi 0,14 ms.

## ADR-002: İçerik Adresli Dosya Saklama

**Bağlam:** Aynı dosyanın birden fazla kullanıcı tarafından yüklenmesi depolama alanını gereksiz yere artırabilir. Dosya bütünlüğünün de kontrol edilebilmesi gerekir.

**Alternatifler:**
- Her yüklemeyi ayrı bir dosya olarak saklamak.
- Dosyanın SHA-256 özetini kullanarak içerik adresli saklama yapmak.

**Karar:** Dosyalar SHA-256 özeti üzerinden adreslenir. Aynı içeriğin tekrar saklanmasını önlemek hedeflenir; erişim izinleri dosya içeriğinden ayrı yönetilir.

**Sonuç:** Depolama tekrarları azaltılabilir ve içerik bütünlüğü kontrol edilebilir. Ancak dosya içeriğinin ortak olması, kullanıcıların birbirlerinin belgelerine erişebileceği anlamına gelmemelidir. Yetkilendirme her erişimde ayrıca yapılmalıdır.

## ADR-003: Süreli Paylaşım Bağlantıları

**Bağlam:** Belgelerin sisteme hesap açmadan erişilebilecek şekilde paylaşılması gerekebilir. Bu bağlantıların tahmin edilmesi veya izinsiz kullanılması engellenmelidir.

**Alternatifler:**
- Yalnızca oturum açmış kullanıcılarla paylaşım yapmak.
- Süre ve erişim sınırları olan paylaşım bağlantıları sunmak.

**Karar:** Süreli paylaşım bağlantıları yaklaşımı benimsendi. Güvenli tasarımda tokenların kriptografik olarak rastgele üretilmesi ve veritabanında yalnızca token özetinin saklanması gerekir. Token 256 bit rastgeledir ve yalnızca SHA-256'sı saklanır. Parola argon2id'dir.
Sayaç, koşulları WHERE içinde taşıyan tek UPDATE ile artırılır. Hız sınırı üç katmandır: adres başına genel
sınır, bağlantı+adres başına 5 hatalı parola ve bağlantı başına 30 hatalı parola (15 dk pencere).
Bağlantı, oluşturanın dosyadaki `read` yetkisine bağlıdır.

**Sonuç.** (+) Sızan veritabanından geçerli token çıkmaz; eşzamanlı 20 istekte sınır 3 ile kesin tutulur
(testle kanıtlı). (−) Sınırlayıcı belleğtedir: yeniden başlatmada sıfırlanır, çok örnekli kurulumda paylaşılmaz.
(−) Bağlantı başına sınır, saldırganın bağlantıyı 15 dakika kilitlemesine izin verir (hizmet aksatma ile
güvenlik arasında bilinçli seçim). (−) Sayaç istek başlayınca artar; yarıda kesilen indirme hakkı tüketir.

## ADR-004: Saklama, hukuki bekletme ve kanıtlanabilir imha

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

## ADR-005: Eklemeli sürümleme ve görev ayrılığı zorunlu onay akışı

**Bağlam.** Dosya sürümleri geri alınabilmeli ama geçmiş silinmemeli. Onay akışında talep sahibi kendi
talebini onaylayamamalı ve eşzamanlı kararlar çakışmamalı.

**Seçenekler.** Geri dönüş: (a) eski sürümü "güncel" işaretlemek, (b) eski içeriği yeni sürüm olarak eklemek.

**Karar.** (b) Sürümler yalnızca eklenir, geri dönüş yeni sürüm üretir; numara, dosya satırı
`FOR UPDATE` ile kilitlenerek verilir. Onay kararı `WHERE status='pending' AND requested_by <> karar_veren`
koşullu UPDATE'idir; ayrıca tabloda `CHECK (decided_by <> requested_by)` bulunur.

**Sonuç.** (+) Geri dönüş denetlenebilir ve kendisi de geri alınabilir; eşzamanlı 10 karardan yalnızca biri
kazanır (testle kanıtlı). (+) Uygulama hatası olsa bile veritabanı kendi onayını reddeder. (−) Her geri dönüş
yeni sürüm satırı ekler. (−) Onay akışı şimdilik bilgi amaçlıdır: onay, dosya erişimini veya imhayı kısıtlamaz.