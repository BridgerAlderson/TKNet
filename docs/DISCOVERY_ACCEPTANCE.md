# Keşif kabul testleri

## Test senaryoları

| Senaryo | Doğrulama | Sonuç |
|---|---|---|
| İlk ICMP yanıtı kayıp | Sahte prob ilk denemede sessiz, ikinci denemede geçerli echo | İkinci denemede Confirmed |
| İlk TCP bağlantısı zaman aşımı | Sahte prob ilk denemede timeout, ikinci denemede başarılı bağlantı | İkinci denemede Confirmed |
| İlk NetBIOS yanıtı kayıp | Sahte prob ilk denemede timeout, ikinci denemede geçerli yanıt | İkinci denemede Confirmed |
| Aynı ARP eşlemesi ve bağlantı reddi tekrar ediyor | İki deneme boyunca yalnız belirsiz bulgular | IsAlive=false; açık port listesine eklenmez |
| Yerel araç tamamen çalışmıyor | Tek etkin yöntemde araç hatası | Incomplete; gereksiz yeniden deneme yok |
| Tekrardan önce iptal | Backoff sırasında context iptali | Sonraki deneme çalışmaz |
| Çok sayıda host ve port | 12 sahte host × 3 port, ortak sınır 2 | En fazla 2 eşzamanlı prob, hepsi tamamlanır |
| Ethernet/Wi-Fi aynı subnette | Sentetik arayüzler ve seçilen kaynak adresi | Doğru kaynak adresinin arayüzü seçilir |
| VPN yerel subnet rotasının önüne geçiyor | Sentetik tun arayüzü ve rota/kaynak verisi | Ethernet'e ARP uygulanmaz |
| Yönlendirici arkasındaki ağ, network/broadcast, kapalı arayüz | Rota ve arayüz birim testleri | Yerel ARP arayüzü seçilmez |
| Host yanıt vermiyor | Sahte ping ile headless motor ve üç hedef | Üç negatif kayıt da son olaydan önce iletilir |
| Arayüz negatif kaydı alıyor | İzole sahte motor alt süreci | No response ve Incomplete kayıtları korunur |
| Ölçüm dosyası eksik/çelişkili | Python değerlendirme testleri | Başarı puanı üretmek yerine hata |
| Linux loopback ICMP ve yerel TCP | Güncel motor, `127.0.0.1` ve geçici TCP dinleyicisi | İlk denemede Confirmed; loopback rotasında ARP atlanır |

Paket kaybı ve rota seçimi senaryoları kontrollü test verileri kullanır. Fiziksel ağdaki başarı, aynı kapsamdaki cihazların bağımsız olarak doğrulanan durumlarıyla ölçülür.

## Testleri yeniden çalıştırma

```sh
go test -race -count=1 ./...
go vet ./...
dotnet run --project tests/TKNetUI.Tests/TKNetUI.Tests.csproj
python3 -m unittest discover -s tests/discovery -v
```

## Gerçek başarıyı ölçme

1. Aynı kabul kapsamındaki her IP'nin açık/kapalı durumunu cihaz konsolu, laboratuvar güç durumu veya bağımsız yönetim sistemi üzerinden doğrulayın. DNS, ping veya başka bir tarayıcı çıktısını tek başına ground truth olarak kullanmayın.
2. Her araç için aynı kapsamı, ağ bağlantısını ve cihaz durumunu koruyun. Paket kaybı gibi değişken koşullarda testleri tekrarlayın; gözlem zamanlarını kaydedin.
3. TKNet taramasını tamamlayıp **Export discovery evidence (JSON)** kullanın. Aktif IP listesinden ibaret bir dosya, eksik sonuç ve taranmamış adres ayrımını koruyamaz.
4. Doğrulanan gerçek durumu aşağıdaki şemayla kaydedin. Örnek IP'ler belgeleme adresleridir, gerçek ölçüm değildir.

```json
{
  "Source": "Lab konsolundan bağımsız durum doğrulaması",
  "ObservedAt": "2026-10-08T12:00:00+03:00",
  "Scenario": "Ethernet / Wi-Fi / VPN: kullanılan gerçek koşulu yazın",
  "Hosts": [
    {"IP": "192.0.2.10", "Alive": true},
    {"IP": "192.0.2.11", "Alive": false}
  ]
}
```

Mevcut raporları ağ trafiği üretmeden karşılaştırın:

```sh
python3 tools/discovery_compare.py \
  --truth reports/truth.json \
  --report TKNet=reports/tknet-report.json \
  --output reports/comparison.json
```

Birden fazla kaydedilmiş TKNet/normalize edilmiş rapor `--report Etiket=dosya.json` ile eklenebilir. Normalize edilmiş raporda `Completed=true` ve her kontrol edilen IP için `Results` dizisinde `IP`/`IsAlive` boolean alanları bulunmalıdır. SoftPerfect'in bilinmeyen CSV sütunları otomatik tahmin edilmez; eldeki gerçek dışa aktarım biçimi bu şemaya doğru şekilde dönüştürülmelidir.

Nmap XML için ayrıca o taramada kullanılan tam IPv4 kapsamını bir JSON dizi dosyasında verin (örneğin `["192.0.2.10", "192.0.2.11"]`):

```sh
python3 tools/discovery_compare.py \
  --truth reports/truth.json \
  --report TKNet=reports/tknet-report.json \
  --nmap reports/recorded-nmap.xml \
  --nmap-scope reports/recorded-nmap-scope.json \
  --output reports/comparison.json
```

Araç yalnız mevcut dosyaları okur. XML'in başarıyla tamamlanma bilgisi, toplam hedef sayısı ve aktif host kayıtlarının tutarlılığı denetlenir. XML alanları için temel: [Nmap resmi XML çıktı belgesi](https://nmap.org/book/output-formats-xml-output.html). Verilen kapsamın gerçekten o taramaya ait olduğunu kullanıcı doğrulamalıdır; toplam sayının eşitliği tek başına bunu kanıtlamaz.

Çıktıda yanlış pozitif IP'ler, kaçırılan açık IP'ler, precision ve recall ayrı gösterilir. Değerlendirilen adresler arasında raporun aktif sınıflandırdığı IP yoksa precision `null` olur; bu sıfır yanlış pozitif iddiasından yüzde yüz başarı üretmeyi önler. Bağımsız doğrulamada açık cihaz yoksa recall `null` olur. Gerçek durumu bilinmeyen IP'ler otomatik olarak kapalı sayılmaz. Eksik kapsam ve yarım raporlar ölçüm olarak reddedilir.

## Açık sınırlar

- Tamamen sessiz bir açık cihazın kapalı cihazdan kesin ayrılması mümkün değildir; belirsizliği `IsAlive=true` yaparak gizlemiyoruz.
- Bir geçit/proxy hedef adına IP yanıtı verebilir. Mevcut doğrulama, fiziksel cihaz kimliğinin kriptografik kanıtı değildir.
- Mevcut ürün IPv4 içindir. IPv6 desteği eklenmedi.
- Yerel ARP, farklı VLAN/VPN üzerinden yönlendirilmiş cihazların fiziksel adresini belirleyemez.
- Daha çok deneme kayıp yanıtları telafi edebilir; filtrelenmiş bütün trafiği yanıtlı hale getirmez.
