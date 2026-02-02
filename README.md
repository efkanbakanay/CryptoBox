# 🔐 CryptoBox

**CryptoBox**, dosya ve klasörleri **kalite kaybı olmadan**,  
**parola + kurtarma anahtarı** ile şifreleyip çözebilen,  
tamamen **offline**, **tek EXE** olarak çalışan,  
güvenlik ve kullanım kolaylığı dengesi iyi kurulmuş  
profesyonel bir **.NET Console** uygulamasıdır.

Bu proje:
> “Kurulumla uğraşmadan, başka bilgisayara taşıyıp  
> aynı parola ile dosyalarımı güvenle açabileyim”  
diyenler için geliştirilmiştir.

---

# 📌 İçindekiler

- Genel Tanım
- Temel Tasarım Kararları
- Neler Yapabilir / Yapamaz
- Şifreleme Mantığı
- Parola Sistemi
- Kurtarma Anahtarı
- Bilgisayar / OS Bağımsızlığı
- Dosya & Klasör İşleme
- Thread (Paralellik) Yönetimi
- Progress / Hız / ETA
- Verify (Bütünlük Kontrolü)
- Menü Modu
- CLI Modu (TAM)
- Tüm CLI Parametreleri
- Örnek Senaryolar
- Güvenlik Notları
- Publish / EXE Davranışı
- Edge-Case’ler
- Lisans

---

## 🧭 Genel Tanım

CryptoBox:
- Tek dosya veya klasör şifreler
- Çıktı olarak `.enc` üretir
- Çözülünce orijinal dosya **birebir** geri gelir
- Parola unutulsa bile **kurtarma anahtarı** ile erişim sağlar

Hiçbir işlem:
- Sessizce
- Kullanıcıdan habersiz
- Geri dönüşü olmayan şekilde  
yapılmaz.

---

## 🧱 Temel Tasarım Kararları

- ❌ Registry kullanılmaz
- ❌ Parola diske yazılmaz
- ❌ Makineye bağlanmaz
- ❌ Online bağımlılık yok
- ✅ Stream tabanlı okuma/yazma
- ✅ Büyük dosyalarda stabil
- ✅ Tek EXE (self-contained)

---

## ✅ Neler Yapabilir?

- Dosya ve klasör şifreleme
- Parola ile çözme
- Kurtarma anahtarı ile çözme
- Parola unutulunca parola yenileme
- Başka bilgisayarda çözme
- Otomatik thread yönetimi
- Progress (%), hız ve kalan süre gösterimi
- CLI ve Menü desteği

---

## ❌ Neler Yapmaz?

- Parola kurtarma anahtarı olmadan **asla** kurtarma yapmaz
- Yanlış parola ile “bozuk dosya üretmez”
- RAM’i doldurmaz
- Arka planda veri toplamaz
- Şifrelenmiş dosyayı “yarım” bırakmaz

---

## 🔐 Şifreleme Mantığı (Özet)

- Her dosya **ayrı ayrı** şifrelenir
- Şifreleme stream tabanlıdır
- Dosya boyutu ne olursa olsun RAM sabittir
- Dosya içeriği byte-byte korunur

> JPG → JPG  
> MP4 → MP4  
> ZIP → ZIP  

Hiçbir kalite veya veri kaybı olmaz.

---

## 🔑 Parola Sistemi

- Şifreleme sırasında parola **zorunludur**
- Parola:
  - Hash olarak bile diske yazılmaz
  - Sadece RAM içinde kullanılır
- Yanlış parola girilirse:
  - Çözme işlemi **iptal edilir**
  - Dosya bozulmaz

---

## 🧯 Kurtarma Anahtarı (Recovery Key)

Şifreleme sırasında otomatik üretilir:

