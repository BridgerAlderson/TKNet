# SMB sonuçlarının yorumlanması

Paylaşım sayıları karşılaştırılırken önce her hedefin TCP bağlantı durumu ve
listelemenin tamamlanma durumu dikkate alınır. Listelemesi iki taramada da
tamamlanan hedeflerin paylaşım adları IP ve ada göre karşılaştırılabilir.
`Completed` taramanın bittiğini, `EnumerationStatus` ilgili hedefin listeleme
sonucunu bildirir. İzin kontrollerinin sonucu ayrıca kaydedilir.

| `EnumerationStatus` | Hedefte gözlenen sonuç |
| --- | --- |
| `Complete` | Sunucunun oturuma sunduğu paylaşım listesinin sonuna ulaşıldı. |
| `Partial` | Listeleme kesilmeden önce alınan adlar raporda korundu. |
| `Failed` | Paylaşım listesi alınamadı. Hata metni nedeni gösterir. |
| `Not attempted` | Tarama paylaşım listeleme aşamasına ulaşamadı. Bağlantı ve oturum bilgileri nedeni açıklayabilir. |

## Paylaşım türü ve izinler

Sunucunun bildirdiği `ShareType` raporda korunur. Disk paylaşımlarında kök dizin için `ReadCheck` ve `WriteCheck` ayrı kaydedilir. Kök dizinin listelenmesi reddedilirse paylaşım adı görünür ve yazma kontrolü atlanır. Yazıcı, aygıt ve IPC türlerinde dosya işlemi yapılmaz. Özel `IPC$` adı listenin dışında tutulur. Sunucunun disk paylaşımı olarak sunduğu `print$` diğer disk paylaşımları gibi incelenebilir. [Microsoft SHARE_INFO_1](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_1)

## Bağlantı ve oturum

Sunucu `srvsvc` kanalını açarken meşgul yanıtı verebilir. Bu durumda
paylaşım listesinin ilk sayfası henüz istenmemiştir.

`STATUS_INSTANCE_NOT_AVAILABLE` (0xc00000ab), `STATUS_PIPE_NOT_AVAILABLE`
(0xc00000ac) ve `STATUS_PIPE_BUSY` (0xc00000ae) için yalnız pipe açma işlemi,
aynı IPC$ tree ve kimliği doğrulanmış SMB oturumunda en fazla dört kez denenir.
Beklemeler 250, 500 ve 1000 ms; iptal edilebilirdir. ACL, giriş reddi, olmayan
pipe veya kopmuş oturum için bu döngü uygulanmaz. Devam etmekte olan RPC
listelemesi baştan oynatılmaz; başarısızlıkta bilinen adlar korunur.

Kaynak: [Microsoft named-pipe durum kodları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/8f11e0f3-d545-46cc-97e6-f00569e3e1bc).

### TCP bağlantısı

İlk geçişteki üç TCP denemesi korunur. İlk geçiş bittikten sonra, yalnız TCP
bağlantısı hiç kurulamamış ve tekrar denenebilir hata almış hedefler için
**tek ek TCP denemesi** yapılır. Eşzamanlılık `min(Threads, 8)` olur; seçilen
timeout aynen kullanılır. Girişe başlamış hedef bu geçişe alınmaz.

Başarılı TCP bağlantısı doğrudan ilk SMB oturumuna verilir. İlk geçiş sonucu
bekletildiği için IP başına tek nihai kayıt yayımlanır; sayaç, ilerleme ve JSON
çift kayıt içermez. `ConnectionAttempts`, `ConnectionErrors` iki geçişi de
kapsar; `ConnectionRecoveryAttempted` son geçişin uygulandığını bildirir.
Yeni ayarlar ve son doğrulama aşaması Activity'de görünür. Kalıcı hata hâlâ
hata olarak kalır. Özellikle çok sayıda timeout varsa tarama süresi uzar.

SMB taraması doğrudan TCP 445 kullanır. Yapılandırılan hesap hedef başına en fazla bir kez denenir. Paylaşım izninin reddedilmesi yeni giriş başlatmaz. Ayrı Guest oturumunun kullanıldığı durum raporda belirtilir.

Rapor sunucu adresleri, paylaşım adları ve erişim sonuçları içerir. Alanları ve sürümler arası doğrulamayı incelemek için [sürüm doğrulamasına](RELEASE_READINESS.md) bakabilirsiniz.
