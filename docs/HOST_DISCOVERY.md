# Host discovery sonuçları ve dışa aktarma

Varsayılan discovery görünümü yalnız `IsAlive=true` kayıtları içerir.
ARP-only, TCP refusal, yanıtsız ve prob hatalı kayıtlar otomatik olarak canlı
listeye eklenmez. Doğrulanmış bir hostun isteğe bağlı başka probunda hata olması
onu listeden çıkarmaz. `Show all checked IP addresses` ile bütün kayıtlar
tanılama amacıyla görülebilir; tam JSON raporunda da korunurlar.

Tarama başarıyla tamamlanınca **Export → Alive IPs (TXT)** ve **Alive IPs (JSON)**
açılır. Durdurulan, hata ile biten veya hâlâ süren tarama tamamlanmış hedef
listesi olarak dışa aktarılamaz. Tam rapor kısmi sonuçları saklamaya devam eder.

- TXT: başlık/açıklama/BOM olmadan, her satırda tek IPv4 adresi.
- JSON: yalnız IP dizisi; örneğin `["192.0.2.9", "192.0.2.10"]`.
- İki biçim de yinelenen adresleri kaldırır ve sayısal IP sırasını kullanır.
- Ekran filtresi, seçili sekme ve tüm adresleri gösterme tercihi çıktıyı değiştirmez.
- Kaydetme penceresi açıkken yeni tarama başlasa bile seçilen taramanın listesi korunur.
- Tamamlanmış taramada doğrulanmış host yoksa TXT boş, JSON `[]` olur.

Nmap için TXT: `nmap -iL alive_ips.txt`. Yeniden host discovery yapılmasını
istemiyorsanız `nmap -Pn -iL alive_ips.txt` kullanabilirsiniz. JSON doğrudan
Nmap hedef dosyası değildir. [Resmi hedef listesi biçimi](https://nmap.org/book/man-target-specification.html).

`Confirmed`, gözlem anında doğrulanan IP yanıtıdır. Cihazın daha sonra açık
kalacağını garanti etmez; yanıt vermemek de kapalı olduğunun kanıtı değildir.

## Sonuçların anlamı

| Durum | Anlamı |
|---|---|
| `Confirmed` | Hedef IP'den başarılı ICMP echo, başarılı TCP bağlantısı veya doğrulanmış NetBIOS durum yanıtı alındı. |
| `Unconfirmed (ARP only)` | Bir adres/MAC eşlemesi görüldü, fakat IP üzerinden canlılık doğrulanamadı. `IsAlive=false`; ayrı durum ve sayaçla gösterilir. |
| `No response` | Etkin yöntemlerden doğrulayıcı yanıt alınamadı; cihazın kapalı olduğu anlamına gelmez. Bu adresler de saklanır; `Show all checked IPs` ile tabloda ve her zaman tam raporda yer alır. |
| `Unconfirmed (TCP refusal)` | Bağlantı reddi gözlendi; açık port veya kesin aktif cihaz olarak sayılmaz. |
| `Incomplete (probe errors)` / `Error` | Ayar, yerel araç veya protokol doğrulama sorunu. Günlük, sonuç satırı ve tam raporda gösterilir. |

ARP tek başına doğrulama sayılmaz; özellikle Windows SendARP önbellekten dönebilir. [Microsoft SendARP belgesi](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp) bu davranışı açıklar. ARP-only cihazları kesin aktif saymamak bilinçli, temkinli bir tercihtir; ICMP/TCP/NetBIOS yanıtı engellenen gerçek cihazlar bu grupta kalabilir.

TCP bağlantı reddi, zaman aşımı, yönlendirme hatası, DNS/PTR kaydı, ARP eşlemesi ve bozuk NetBIOS paketleri tek başına `IsAlive=true` üretmez. ICMP başarılıysa TCP fallback çalıştırılmaz; boş TCP sütunu “tüm portlar kapalı” anlamına gelmez. Bu özellik tam port taraması değildir.

İsim/MAC üreticisi ek bilgidir. PTR kaydı güncel olmayabilir; OUI veritabanı tüm üreticileri içermez. Ağ geçidinin/proxy'nin hedef adına yanıt vermesi veya paket kaybı gibi durumlar nedeniyle genel ağlarda hem yüzde yüz kapsama hem sıfır yanlış pozitif garantisi verilemez. `Confirmed`, tarama anında doğrulanan IP yanıtını ifade eder; fiziksel cihaz kimliği garantisi değildir.

## Ağ bağlantısı ve denemeler

Doğrulayıcı yanıt alınamayan hedeflerde varsayılan deneme sayısı 2’dir. Ayarlardan 1–3 deneme seçilebilir. Her sonuç deneme sayısını ve gözlem zamanını içerir. Tam JSON raporu seçilen yöntemleri, sonuçlarını ve taramanın tamamlanma durumunu kaydeder.

Linux, ARP için çekirdeğin hedefe seçtiği yerel arayüzü kullanır. Yönlendirici ve yayın desteği olmayan tüneller üzerinden ARP uygulanmaz. ICMP için `ping`, ARP için `iproute2`, desteklenen bir `arping` ve gerekli işletim sistemi izinleri gerekir. Eksik araç veya izin günlükte görünür. Diğer etkin yöntemler çalışmaya devam eder.

Kaydedilmiş sonuçları bağımsız olarak doğrulanmış bir hedef listesiyle karşılaştırabilirsiniz. [Keşif kabul testleri](DISCOVERY_ACCEPTANCE.md)
