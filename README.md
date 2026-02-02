# CryptoBox

CryptoBox, dosya ve klasörleri kalite kaybı olmadan,
**parola + kurtarma anahtarı** ile şifreleyip çözebilen,
tamamen **offline**, tek EXE olarak publish edilebilen,
güvenlik ve kullanım kolaylığı dengesi iyi kurulmuş
profesyonel bir .NET Console uygulamasıdır.

Bu proje:

> “Kurulumla uğraşmadan, başka bilgisayara taşıyıp
> aynı parola ile dosyalarımı güvenle açabileyim”
> diyenler için geliştirilmiştir.

## Özellikler

- **Dosya ve klasör şifreleme**: Tek dosyayı veya bir klasördeki tüm dosyaları (alt klasörler dahil) şifreler.
- **İki ayrı açma yöntemi**:
  - **Parola** ile çözme
  - **Kurtarma anahtarı** ile çözme (parola unutulsa bile)
- **Parola yenileme (recover)**: Kurtarma anahtarıyla `.enc` dosyanın parolasını değiştirir.
  - Dosya içeriği **yeniden şifrelenmez**; mevcut içerik anahtarı korunur, sadece parola “kilidi” güncellenir.
- **İlerleme göstergesi**: Yüzde + hız + ETA.
- **Paralel işlem**: Klasör işlemlerinde otomatik veya `--threads` ile ayarlanabilir paralellik.
- **Dry-run**: `--dry-run` ile planı gösterir, değişiklik yapmaz.
- **Opsiyonel doğrulama**: `--verify` ile `.enc` doğrulaması yapar (HMAC kontrolü).
- **Güvenli parola karşılaştırma**: Parola tekrarında sabit-zaman karşılaştırma kullanır.
- **Geçici dosya ile güvenli yazma**: `.tmp` yazıp atomik `move` ile hedefe taşır.

## İçindekiler

- **Genel Tanım**
- **Temel Tasarım Kararları**
- **Neler Yapabilir / Yapamaz**
- **Şifreleme Mantığı**
- **Parola Sistemi**
- **Kurtarma Anahtarı**
- **Bilgisayar / OS Bağımsızlığı**
- **Dosya & Klasör İşleme**
- **Thread (Paralellik) Yönetimi**
- **Progress / Hız / ETA**
- **Verify (Bütünlük Kontrolü)**
- **Menü Modu**
- **CLI Modu**
- **Tüm CLI Parametreleri**
- **Örnek Senaryolar**
- **Güvenlik Notları**
- **Publish / EXE Davranışı**
- **Edge-Case’ler**
- **Lisans**

## Genel Tanım

CryptoBox:

- **Tek dosya** veya **klasör** şifreler
- Çıktı olarak **`.enc`** üretir
- Çözülünce **orijinal dosya birebir** geri gelir
- Parola unutulsa bile **kurtarma anahtarı** ile erişim sağlar

Hiçbir işlem:

- Sessizce
- Kullanıcıdan habersiz
- Geri dönüşü olmayan şekilde

yapılmaz; kritik işlemler öncesi sorularla onay alır (örn. kaynak silme).

## Temel Tasarım Kararları

- ❌ **Registry kullanılmaz**
- ❌ **Parola diske yazılmaz** (yalnızca RAM’de kullanılır)
- ❌ **Makineye/sunucuya bağlanmaz** (tamamen offline çalışır)
- ❌ **Online bağımlılık yok**
- ✅ **Stream tabanlı okuma/yazma**
- ✅ **Büyük dosyalarda stabil**
- ✅ **Tek EXE** (self-contained publish ile tek dosya dağıtılabilir)

## Neler Yapabilir?

- **Dosya ve klasör şifreleme**
- **Parola ile çözme**
- **Kurtarma anahtarı ile çözme**
- **Parola unutulunca parola yenileme (recover)**
- **Başka bilgisayarda çözme** (format ve kripto motoru makine bağımsız)
- **Otomatik thread yönetimi**
- **Progress (%), hız ve kalan süre (ETA) gösterimi**
- **CLI ve menü (interaktif) desteği**

## Neler Yapmaz?

- **Parola kurtarma anahtarı olmadan parola kurtarmaz**
- **Yanlış parolayla bozuk dosya üretmez** (HMAC ile tespit eder, hata fırlatır)
- **RAM’i doldurmaz** (sabit boyutlu buffer ile stream okur/yazar)
- **Arka planda veri toplamaz / dışarı veri sızdırmaz**
- **Şifrelenmiş dosyayı “yarım” bırakmaz** (önce `.tmp` üretir, sonra atomik `move`)

## Komutlar

Uygulama argümansız çalıştırılırsa menü açar (çift tık kullanımını destekler).

- `encrypt`: Dosya/klasörü `.enc` olarak şifreler
- `decrypt`: `.enc` dosyalarını parola veya kurtarma anahtarıyla çözer
- `recover`: Kurtarma anahtarıyla `.enc` dosyaya yeni parola tanımlar
- `help`, `--help`, `-h`, `/?`: Yardım
- `version`: Sürümü yazdırır (**CryptoBox 2.3.0**)

## Kullanım

```bash
CryptoBox encrypt <path> [seçenekler]
CryptoBox decrypt <path> [seçenekler]
CryptoBox recover <path> [seçenekler]
CryptoBox --help
CryptoBox version
```

## Seçenekler

### Ortak seçenekler

- `--out <path>`: Çıktı kök klasörü.
  - Verilmezse ve `--inplace` yoksa otomatik olarak `<base>/_crypto_out` oluşturur.
- `--inplace`: Çıktıyı kaynakla aynı yerde üretir.
  - `encrypt` için: `dosya -> dosya.enc`
  - `decrypt` için: çıktı, `.enc` dosyasının yanına ve **orijinal göreli yol** korunarak yazılır.
- `--delete-source`: İşlem başarılı olunca kaynağı siler
  - `encrypt`: orijinal dosyayı siler
  - `decrypt`: `.enc` dosyasını siler
- `--keep-source`: Kaynağı kesinlikle tutar
- `--threads <n>`: Paralellik (1..64). Verilmezse iş yüküne göre otomatik seçer.
- `--dry-run`: Sadece planı yazdırır, dosya üretmez/silmez.
- `--verify`: İşlem sonrası `.enc` doğrulaması yapar (HMAC).
- `--yes`: İnteraktif soruları sormadan varsayılanlarla ilerler.
- `--recovery-key <key>`: Kurtarma anahtarı (format: `CBX-RK1-....`)

### `decrypt` için ek seçenek

- `--mode password|recovery`: Çözme modu. Verilmezse sorar.

## Örnekler

### Şifreleme

```bash
# Klasörü şifrele, çıktı başka yerde
CryptoBox encrypt "C:\Data" --out "D:\Encrypted"

# Tek dosyayı aynı yerde şifrele (C:\Data\video.mp4.enc)
CryptoBox encrypt "C:\Data\video.mp4" --inplace

# Planı gör (dosya yazmaz)
CryptoBox encrypt "C:\Data" --dry-run
```

### Çözme

```bash
# Klasörü çöz, parola modunda
CryptoBox decrypt "D:\Encrypted" --out "D:\Decrypted" --mode password

# Tek .enc dosyayı aynı yerde çöz, kurtarma anahtarı modunda
CryptoBox decrypt "C:\Data\video.mp4.enc" --inplace --mode recovery
```

### Parola yenileme (recover)

```bash
# Klasördeki tüm .enc dosyaların parolasını, kurtarma anahtarıyla yenile
CryptoBox recover "D:\Encrypted"

# Tek dosya + recovery key parametreyle
CryptoBox recover "C:\Data\video.mp4.enc" --recovery-key "CBX-RK1-...."
```

## Çıktı formatı (.enc) ve güvenlik notları

- **Format kimliği**: Dosyalar `CBX2` “magic” ve **v2** sürümü ile başlar.
- **İçerik şifreleme**: Dosya içeriği, rastgele üretilen bir **data key** ile **AES-CTR (ECB tabanlı sayaç)** akışına XOR yapılarak şifrelenir.
- **Bütünlük/yanlış anahtar tespiti**: Header + IV + ciphertext üzerinde **HMAC-SHA256** bulunur. Yanlış parola/anahtar ya da bozuk dosya durumunda çözme hata verir.
- **Data key sarmalama (iki kilit)**:
  - Paroladan türetilen KEK ile (PBKDF2-SHA256, varsayılan 200k iterasyon) **AES-GCM** ile sarılır
  - Kurtarma anahtarından türetilen KEK ile ayrıca **AES-GCM** ile sarılır
- **Orijinal yol bilgisi**: `.enc` içinde dosyanın “orijinal göreli yolu” saklanır; klasör çözümlerinde dizin yapısı geri kurulur.

> Not: Kurtarma anahtarını kaybedersen ve parolayı unutursan dosyayı açamazsın. Anahtarı güvenli bir yerde saklayın.

## Şifreleme Mantığı

- Her dosya **ayrı ayrı** şifrelenir.
- Şifreleme **stream tabanlıdır**; dosya boyutu ne olursa olsun RAM kullanımı sabit kalır (1 MB buffer).
- Dosya içeriği **byte-byte** korunur:
  - JPG → JPG
  - MP4 → MP4
  - ZIP → ZIP
- Hiçbir **kalite veya veri kaybı** olmaz; CryptoBox **genel amaçlı bir ikili veri şifreleyicidir**.

## Parola Sistemi

- Şifreleme sırasında **parola zorunludur**.
- Parola:
  - **Diske yazılmaz** (hash olarak bile)
  - Sadece RAM içinde, anahtar türetme için kullanılır.
- Parola tekrar kontrolü, `FixedTimeEquals` ile **sabit-zamanlı** yapılır (timing attack’e karşı).
- Yanlış parola girilirse:
  - Çözme iptal edilir ve **dosya bozulmaz**.
  - Hata mesajı ile dönülür, `.enc` dosyası aynı kalır.

## Kurtarma Anahtarı (Recovery Key)

- Şifreleme sırasında:
  - CLI’de:
    - Mevcut kurtarma anahtarı verilebilir (`--recovery-key`)
    - Verilmezse isteğe bağlı olarak yeni bir **CBX-RK1-...** formatında anahtar üretilir.
  - Menü modunda:
    - İstersen mevcut kurtarma anahtarını girersin
    - İstersen program senin için yeni bir kurtarma anahtarı üretir ve ekranda gösterir.
- Kurtarma anahtarı:
  - 32 bayt rastgele veri + **CRC16** doğrulama içerir.
  - Base32 ile kodlanır, `CBX-RK1-XXXX-XXXX-...` formatında gösterilir.
  - Yanlış yazılırsa veya bozulursa, CRC sayesinde **geçersiz** sayılır.

## Bilgisayar / OS Bağımsızlığı

- CryptoBox, **.NET 8** ile derlenmiş bir console uygulamasıdır.
- `.enc` formatı:
  - **Platform bağımsızdır** (endianness vs. gözetilmiştir).
  - Farklı Windows makineleri arasında, hatta farklı OS’ler arasında taşınabilir.
- Aynı sürüm CryptoBox ile:
  - Bir makinede şifrelediğin dosyayı, başka makinede **aynı parola veya kurtarma anahtarı** ile açabilirsin.

## Dosya & Klasör İşleme

- **Tek dosya**:
  - `encrypt`: `file -> file.enc`
  - `decrypt`: `file.enc -> file` (orijinal isim geri gelir)
- **Klasör**:
  - Tüm alt klasörler dahil **recursive** taranır.
  - `.enc` içinde her dosyanın **orijinal göreli yolu** saklanır.
  - Çözme sırasında aynı dizin yapısı otomatik kurulur.

## Thread (Paralellik) Yönetimi

- Klasör işlemlerinde, dosya sayısı ve ortalama dosya boyuna göre
  **otomatik thread sayısı** seçilir:
  - Çok az dosyada tek thread
  - Küçük fakat çok sayıda dosyada daha fazla thread
  - Çok büyük dosyalarda thread sayısı sınırlandırılır
- İstersen `--threads <n>` ile manuel değer verebilirsin (1–64).

## Progress / Hız / ETA

- İşlem sırasında:
  - Toplam ilerleme: **%**
  - İşlenen veri: `işlenen / toplam`
  - Anlık hız: `MB/s` (yaklaşık)
  - Kalan süre: `ETA hh:mm:ss`
- Klasör işlemlerinde:
  - Şifreleme için toplam byte sayısı, dosya boylarının toplamından hesaplanır.
  - Çözmede ise **header içindeki orijinal dosya boyu** kullanılarak ETA daha doğru hesaplanır.

## Verify (Bütünlük Kontrolü)

- `--verify` parametresi ile:
  - `encrypt` sonrası `.enc` dosyası **HMAC-SHA256** ile doğrulanır.
  - `decrypt` sonrası isteğe bağlı SHA-256 hesaplanabilir (progress çıktısını bozmamak için ekrana yazmaz).
- Bu sayede:
  - Yanlış parola / kurtarma anahtarı
  - Bozulmuş dosya
  - Kopyalama hataları
  yüksek olasılıkla tespit edilir.

## Menü Modu

- Program **argümansız** çalıştırıldığında interaktif menü açılır:
  - `1) Şifrele (encrypt)`
  - `2) Çöz (decrypt)`
  - `3) Parola kurtar/değiştir (recover)`
  - `4) Help`
  - `0) Çıkış`
- Bu mod, **çift tıklayıp** kullanan son kullanıcılar için tasarlanmıştır.

## CLI Modu

- Komut satırından tüm işlemler,
  script’lenebilir şekilde yapılabilir:
  - Backup script’leri
  - Otomatik job’lar
  - Batch işlemler

## Tüm CLI Parametreleri (Özet)

- **Komutlar**:
  - `encrypt <path> [seçenekler]`
  - `decrypt <path> [seçenekler]`
  - `recover <path> [seçenekler]`
  - `version`
  - `help` / `--help` / `-h` / `/?`
- **Ortak**:
  - `--out <path>`
  - `--inplace`
  - `--delete-source`
  - `--keep-source`
  - `--threads <n>`
  - `--dry-run`
  - `--verify`
  - `--yes`
  - `--recovery-key <key>`
- **Sadece decrypt**:
  - `--mode password|recovery`

Detaylar için aşağıdaki **Kullanım** ve **Seçenekler** bölümlerine bakabilirsin.

## Örnek Senaryolar

- **Harici diskte arşiv şifreleme**:
  - `CryptoBox encrypt "E:\Arsiv" --out "E:\Arsiv_Enc" --delete-source --verify`
- **Sadece belli bir klasörü hızlıca kilitleme**:
  - `CryptoBox encrypt "C:\Kisisel" --inplace`
- **Parolayı unuttun, kurtarma anahtarı elinde**:
  - `CryptoBox recover "D:\Encrypted" --recovery-key "CBX-RK1-...."`
- **Başka bilgisayarda açma**:
  - `.enc` dosyalarını ve kurtarma anahtarını yanına al,
  - Aynı veya uyumlu CryptoBox sürümünü çalıştır,
  - `decrypt` veya `recover` komutlarıyla eriş.

## Güvenlik Notları

- Kurtarma anahtarını **çok iyi** sakla:
  - Parola + kurtarma anahtarı **ikisi birden** kaybolursa dosyalar açılamaz.
- Şifreleme/çözme sırasında:
  - Ani elektrik kesintisi vb. durumlarda
  - Orijinal dosyanın silinmesi, ancak işlem başarıyla tamamlandıktan sonra yapılır.
- `--delete-source` kullanırken:
  - Geri dönüşü olmayan silme işlemleri yaptığın için,
  - Önce küçük bir test klasörüyle denemen önerilir.

## Çıkış kodları

- `0`: Başarılı
- `2`: Argüman/komut hatası
- `3`: Kripto hatası (yanlış parola/anahtar, bozuk dosya vb.)
- `4`: IO / erişim hatası

## Geliştirme

- **Platform**: .NET 8 (`net8.0`)
- **Proje**: `CryptoBox/CryptoBox.csproj`

## Publish / EXE Davranışı

- CryptoBox, **self-contained single-file** olarak publish edilebilir:
  - Tek `.exe` dosyasını alıp istediğin Windows makinede,
    kurulum gerektirmeden çalıştırabilirsin.
- Örnek (dotnet CLI):

```bash
dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

## Edge-Case’ler

- **Seçilen dosya/klasör yoksa**: IO hatası verir, işlem yapılmaz.
- **`decrypt` ve hedefte `.enc` yoksa**:
  - Klasör modunda “Klasörde .enc dosyası yok.” mesajı verip çıkar.
- **Yanlış kurtarma anahtarı**:
  - CRC16 ve AES-GCM/HMAC kontrolleri nedeniyle,
  - Parola/kurtarma hatası veya dosya bozukluğu olarak hata verir.
- **İzin hataları (permission)**:
  - Okuma/yazma yetkisi olmayan dosyalarda, ilgili hata mesajını yazdırır ve işlem kodları ile döner.

## Lisans

Bu depo içinde açık bir lisans dosyası bulunmadığı için,
projenin lisans koşulları **açıkça belirtilmemiştir**.
Kendi projende kullanmadan önce, lütfen depo sahibinin
belirlediği lisans/politikayı kontrol et.
