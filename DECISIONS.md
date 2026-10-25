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