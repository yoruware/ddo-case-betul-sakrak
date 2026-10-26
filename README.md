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