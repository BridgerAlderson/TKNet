# SMB paylaşımlarını Dolphin ile açma

## Geçerli akış

1. SMB taraması, ayarlardaki kullanıcı, domain ve parolayı motorun standart girişine gönderir. Motor bunları SMB oturumu için kullanır. Guest sonucu, sağlanan hesapla erişimin kanıtı sayılmaz.
2. Linux'ta paylaşım/host çift tıklaması veya **Open** eylemi, o andaki ayarlardan kimlik bilgilerini alır. Paylaşım ve sunucu kökü için `smb://[DOMAIN;]user[:password]@host/share` biçimi korunur; bileşenler ayrı ayrı URL kodlanır.
3. Parola içeren bağlantı, `DolphinSmbLauncher` üzerinden doğrudan Dolphin pencere arayüzünün `openDirectories` metoduna gönderilir. Açık ve yanıt veren pencere varsa kullanılır. Yoksa `dolphin --new-window file:///...` ile yerel klasörde başlatılır; TKNet, D-Bus bağlantısının PID bilgisini ve çalışan dosyanın sistemde kurulu Dolphin ile aynı aygıt/inode kimliğine sahip olduğunu doğrular. Paylaşım, pencere hazır olduğunda doğrulanan benzersiz bağlantıya bir kez aktarılır.
4. Günlük ve durum satırı yalnız paylaşım yolunu gösterir. Panoya kopyalanan SMB URL'si kimlik bilgisi içermez. TKNet'in başlattığı süreçte parola argümanı yoktur. Kimlik bilgileri elbette TKNet/Dolphin belleğinde ve yerel oturum iletişiminde bulunur; Dolphin/KIO'nun kendi oturum, geçmiş ve cüzdan davranışlarını TKNet yönetmez.
5. Başarılı D-Bus yanıtı yalnız açma isteğinin teslim edildiği anlamına gelir. Sunucuya bağlanma ve kimlik doğrulama sonucu Dolphin/KIO tarafından gösterilir. TKNet teslimatı “paylaşıma erişim doğrulandı” diye sunmaz.
6. Dolphin veya oturum iletişimi kullanılamazsa hata gösterilir. Kullanıcı bilgisi olan bir açma isteği, bilgileri atılarak sessizce başka dosya yöneticisine aktarılmaz. Başlatma/aktarım beklemesi sınırlıdır ve uygulama kapanırken iptal edilir.

Kullanıcı adı yoksa mevcut Dolphin/varsayılan dosya yöneticisi davranışı korunur. Hash modunda hash hiçbir zaman Dolphin'e parola olarak aktarılmaz; kullanıcı/domain gönderilir, parola veya kayıtlı Dolphin oturumu gerekir. Windows'ta Explorer mevcut Windows oturumunu kullanır.

## Erişim reddi

Tarayıcı, oturum açıldıktan sonra paylaşım izni reddedildiğinde aynı hesapla tekrar giriş yapmaz. Dolphin'e yapılan her açma isteği ayrı bir kullanıcı eylemidir. Sunucunun döndürdüğü erişim veya kimlik doğrulama hatasını Dolphin/KIO gösterir. Hesap kilitleme ilkesi sunucuda ya da etki alanında uygulanır.

## Kullanılan arayüzler

Pencere yolu, servis adı ve yöntem, Dolphin'in kendi [pencere arayüzü](https://github.com/KDE/dolphin/blob/master/src/dolphinmainwindow.h) ve [pencere bulma/açma uygulaması](https://github.com/KDE/dolphin/blob/master/src/global.cpp) ile karşılaştırıldı. Genel `FileManager1.ShowFolders` yolu, Dolphin kapalıyken URL'yi yeni süreç argümanlarına aktarabildiği için kimlik bilgili açılışta kullanılmadı.
