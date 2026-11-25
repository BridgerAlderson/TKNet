# Sürüm doğrulaması

## 25 Kasım 2026 doğrulaması

Sekiz disk paylaşımı sunan yerel SMB2 sunucusunda aynı hesapla üç sürüm karşılaştırıldı. Testte v1.0, v1.1 ve güncel tarayıcı kaynaklarının TCP bağlantısı, sunucunun `127.0.0.1` üzerindeki geçici portuna yönlendirildi. Her iki senaryoda paylaşım adları ve izinleri aynıydı. `IPC$` disk paylaşımı sayısına dahil edilmedi.

| Sunucunun listeyi gönderme şekli | v1.0 | v1.1 | Güncel |
| --- | ---: | ---: | ---: |
| Tek sayfa | 8/8 | 8/8 | 8/8 |
| Üç sayfa | 2/8 | 2/8 | 8/8 |

Çok sayfalı yanıtta eski sürümler ilk sayfayı aldı. Güncel sürüm iki devam sayfasını da istedi ve sekiz adın tamamını döndürdü. Daha büyük SMB2 testinin üç tekrarında da beklenen 134 kaynak listelendi. Sunucu ikinci sayfada erişimi reddettiğinde ilk sayfadan bilinen 39 kaynak `Partial` durumuyla raporlandı. Ayrı bir 995 hedef simülasyonunda, geçici bağlantı hataları farklı hedeflere dağıtıldığında da üç koşunun her birinde aynı 911 hedefte aynı 2.733 paylaşım bulundu.

Windows 11 x64 üzerinde (derleme 26200) yayınlanan uygulama penceresi açıldı, yanıt verdi ve normal kapandı. Gömülü motorun yerel TCP keşfi, sekiz sentetik SMB senaryosu ve TXT/JSON çıktıları doğrulandı. 751 arayüz doğrulamasının 70’i kaydırmayı kapsadı. Windows Dosya Gezgini ile gerçek bir SMB paylaşımını açma ve GitHub üzerindeki ilk CI çalışması bekleyen kontrollerdir. Linux ve Windows paketlerinin SHA-256 özetleri ve test kapsamı kayıtlıdır. [Paket manifesti](quality/package-manifest.json)
