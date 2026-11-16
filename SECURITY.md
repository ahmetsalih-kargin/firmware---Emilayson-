# FirmAE Güvenlik Değerlendirmesi

> **Durum:** Bulgular 2026-11-04'te `master` (`653565b`) üzerinde statik analizle bulundu.
> Hiçbir yazılım için mutlak güvenlik garantisi verilemez; bu belge tespit edilen riskleri,
> uygulanan/önerilen önlemleri ve kalan riskleri listeler.
>
> **Durum özeti (2026-11-16, yerel `refactor/hardening` dalı; ikinci sağlamlaştırma turu
> commit edilmemiş — `git status`).** Ayrıntılı ölçümler: `TEST_REPORT.md`; değişiklikler:
> `CHANGELOG.md`. Bu tur: iki turlu geliştirme + sıfır bağlamlı bağımsız denetim; birim test 181 → 428.

| Durum | Bulgular |
|---|---|
| **Giderildi** | S1, S2, S3, S4 (yalnızca yeni kurulumlar; mevcut kurulumda `pg_hba.conf` elle), S5, S6, S12, S13, S14 (extractor + getArch), S17, S18 (kaynak; hazır `console.*` ikilileri yeniden derlenmedi), **S19, S20, S21, S22, S23, S24, S25** (ikinci tur) |
| **Kısmen** | S8: ilk emülasyonda `restrict=on`, `hostfwd`/soketler loopback'te, TAP modunda iptables/ip6tables kuralları; **DHCP modu hiç çalıştırılmadı**, L2 (ARP) kapsam dışı; TAP adları/güvenlik duvarı etiketi host genelinde tek ad alanı; `ip6tables` yoksa IPv6 sessizce yalıtılmaz |
| **Açık** | S7 (`--privileged`), S9 (çıkarım root + sandbox'sız), S10 (debug shell), S11 (root Chrome `--no-sandbox`), S15 (indirmelerde checksum yok), S16 (eski bağımlılıklar) |

## 1. Tehdit modeli

| Varsayım | Değer |
|---|---|
| Çalışma ortamı | Tek kullanıcılı, izole lab makinesi (WSL2 Ubuntu 24.04) |
| Yetki | `run.sh` root ile çalışır (loop device, mount, TAP, chroot gerektiriyor) |
| **Güvenilmeyen girdi** | Firmware dosyası, içindeki tüm dosya adları/içerikleri/symlink'ler, guest'in ağ trafiği ve serial log çıktısı |
| Güvenilen girdi | `firmae.config`, komut satırı argümanları (kullanıcının kendisi) |
| Saldırgan | Kötü niyetli veya bozuk bir firmware imajı hazırlayan taraf |
| Korunacak varlıklar | Host bütünlüğü (root), host'un ağı/LAN, diğer analizlerin doğruluğu |

Tek kullanıcılı model nedeniyle "yerel başka kullanıcı" saldırıları (S2, S12) P1'e indirildi;
firmware kaynaklı saldırılar P0 olarak kalır.

## 2. Bulgular

| # | Öncelik | Bulgu | Kanıt | Düzeltme |
|---|---|---|---|---|
| S1 | **P0** | Firmware içindeki dosya adları `shell=True` komutlara tırnaksız giriyor → host'ta root komut çalıştırma (ör. `a;<komut>;cgi` adlı dosya) | `analyses/fuzzer/fuzzer.py:78-85,134-135,147-149,346-350` | Argüman listesi + `shell=False`; `find`/`strings`/`grep` yerine Python ile dosya tarama |
| S3 | **P0** | `tarfile.extract()` filtresiz ve sabit `/tmp/<IID>` hedefi → `../` içeren üye root olarak host'a yazılır; symlink ön-yerleştirme | `scripts/getArch.py:46-74` | Diske çıkarmadan `extractfile()` ile bellekte/geçici dosyada `file`; `tempfile.mkdtemp`; üye yolu doğrulama |
| S5 | P1 | Firmware kontrollü mutlak symlink'ler host tarafında takip edilir: `cp … ${IMAGE_DIR}/bin/a`, init dosyasına `open(...,"a")` → host'ta dosya yazma (içerik sabit olduğu için P1; PoC yapılmadı) | `scripts/makeImage.sh:126`, `scripts/makeNetwork.py:582-591,821-826` | Yazmadan önce `realpath` hedefin mount noktası içinde kaldığını doğrula (`os.open(..., O_NOFOLLOW)` + dizin kontrolü); PoC ile test |
| S8 | P1 | Ağ izolasyonu yok: `-netdev user` kısıtsız (firmware internete/LAN'a çıkar), `hostfwd` 0.0.0.0:80/443, `-netdev socket,listen=:2000-2003` tüm arayüzlerde | `makeNetwork.py:282,294,304`, `scripts/run.*.sh:29-31` | `restrict=on`, `127.0.0.1` bind, boş port; Faz 5'te analiz başına netns |
| S9 | P1 | Firmware çıkarımı root olarak, sandbox'sız (binwalk `--run-as=root`, harici çıkarıcılar, kaynağı belgelenmemiş 32-bit `core/unstuff`) | `sources/extractor/extractor.py:445`, `install.sh:39` | Çıkarımı ayrık kullanıcı/namespace içinde çalıştırmayı değerlendir; `unstuff` kaynağını belgele veya kaldır |
| S11 | P1 | Root olarak `--no-sandbox` headless Chrome, güvenilmeyen web UI'yi render ediyor | `analyses/initializer.py:46-47` | Chrome'u root olmayan kullanıcıyla ve sandbox açık çalıştır |
| S6 | P1 | `docker-helper.py` her yerde `shell=True` + dosya/konteyner adı birleştirme | `docker-helper.py:32,42,47-70,155,164-165` | Argüman listesi |
| S7 | P1 | `--privileged=true -v /dev:/dev` → konteyner izolasyon sağlamaz | `docker-helper.py:48-51` | Belgeleme; gerekli minimum cihaz/capability seti araştırılacak |
| S2 | P1 | `chmod -R a+rwx scratch/IID`; içindeki `run.sh` root ile çalıştırılıyor | `run.sh:128`, `makeImage.sh:35,50` | `0750`, root sahipliği, umask 077 |
| S4 | P1 | PostgreSQL `host all all 172.17.0.1/24 trust` → docker0 ağındaki her konteyner parolasız superuser (`COPY … PROGRAM` ile host'ta komut) | `install.sh:19-20` | `scram-sha-256`; yalnızca `firmware` DB / `firmadyne` kullanıcısı; tek IP |
| S10 | P2 | Debug modunda guest'te kimlik doğrulamasız `nc -e sh` (31337) ve `telnetd -l sh` (31338) | `makeNetwork.py:70-73` | Tasarım gereği; yalnızca host-only ağdan erişilebilir olmalı (S8 ile birlikte) |
| S12 | P2 | QEMU monitor soketi tahmin edilebilir `/tmp/qemu.IID` (monitor = QEMU yetkisiyle komut) | `makeNetwork.py:88` | `scratch/IID/run/` (0700) |
| S13 | P2 | Sabit kodlu DB parolası `firmadyne` | `scripts/util.py:23`, `tar2db.py:108`, `getArch.py:83`, `extractor.py`, `install.sh:16` | Ortam değişkeni (`FIRMAE_DB_PASSWORD`), varsayılan geriye uyumlu |
| S14 | **P1** (denetimde yükseltildi) | SQL dize birleştirme. **`update_database("kernel_version", desc)`: `desc` binwalk'un firmware içeriğinden ürettiği metin ve tırnak içinde SQL'e yapıştırılıyordu → firmware kaynaklı SQL enjeksiyonu** (ilk raporda "girdiler iç kaynaklı" demiştim; yanlıştı) | `sources/extractor/extractor.py:357-375`, `:645`; `getArch.py`, `tar2db.py:37`, `util.py:35,46` | **Uygulandı:** extractor'da parametreli sorgu + alan beyaz listesi, getArch parametreli. `tar2db.py`/`util.py` sorguları yalnızca md5/IID (hex/sayı) içeriyor, değişmedi |
| S15 | P2 | İndirmelerde checksum/imza yok; `apt-key` (kullanımdan kalktı); chromedriver 2.38 (2018) | `download.sh`, `install.sh:28,46,60`, `core/Dockerfile:42` | SHA-256 listesi; `signed-by` keyring; Selenium Manager |
| S16 | P2 | Bilinen zafiyet kaydı olan bağımlılıklar (aşağıda) ve `ubuntu:20.04` Docker tabanı | `requirements.txt`, `core/Dockerfile:1` | Kontrollü yükseltme (Faz 7) |
| S17 | P3 | `debug.py` `os.system` + etkileşimli kullanıcı girdisi | `debug.py:86,92` | Argüman listesi |
| S18 | P3 | `console.c:17` operatör önceliği hatası (tesadüfen çalışıyor) | `sources/console/console.c:17` | Parantez düzeltmesi (binary yeniden derlenmeli) |
| S19 | **P1** (denetimde bulundu) | `util/compare.py` (değerlendirme aracı): firmware ağacındaki dosya adları `os.system("cp " + filepath + ...)` ile komuta yapışıyordu (S1 ile aynı sınıf komut enjeksiyonu); `loop0` sabit kodluydu ve sonda `losetup -d /dev/loop0` **başkasının loop device'ını çözebilirdi** | `util/compare.py` (`attach_loop` satır 122; mount satır 210) | **Giderildi (ikinci tur).** Kabuksuz yeniden yazıldı, symlink izlenmez, yalnızca kendi loop aygıtını çözer, `ro,nodev,nosuid,noexec` mount. Testler: `tests/unit/test_compare_py.py`. Ana akışta zaten kullanılmıyordu |
| S20 | **P0** (ikinci turda bulundu) | Misafirin seri logundan okunan arayüz/köprü adları, VLAN kimlikleri, IP/MAC değerleri doğrulanmadan üretilen **root** script'ine (`scratch/<IID>/run.sh`) giriyordu → firmware kaynaklı komut enjeksiyonu | `scripts/makeNetwork.py` (`IFNAME_RE`/`MAC_RE`/`IPV4_RE` satır 37-40, `checkQemuCmdInputs` satır 745) | **Giderildi.** Ayrıştırmada katı desenler (`\Z`: sondaki satır sonu reddedilir), üretimden önce `checkQemuCmdInputs` ile ikinci denetim, `re.escape`, aşırı uzun sayı satırı atlatır. Testler: `tests/unit/test_makenetwork_security.py` |
| S21 | P1 (ikinci turda bulundu) | İmaja yazma yolları (init betiği, `network_type`, `net_bridge`, `net_interface`, `debug.sh`) çalışma sonrası misafirin bıraktığı symlink/FIFO/aygıt dosyasını izleyerek **host'a root olarak yazabiliyordu** (S5'in çalışma-zamanı karşılığı) | `scripts/makeNetwork.py` (`firmadyneFile` 139, `openImageFile` 149, mount 325-328), üretilen `run.sh` şablonundaki 16 satırlık denetim bloğu, `firmae.config` `mount_partition` (~372) | **Giderildi.** Symlink/normal-olmayan dosya reddi (`O_NOFOLLOW` + `lstat`); mount `nodev,nosuid`; init betiği bayt bayt geri yazılır |
| S22 | P1 (ikinci turda bulundu) | `inferDefault.py` imajdaki symlink'i izleyip host dosyalarını (ör. `/proc/kcore`) okuyabiliyor; `nvram_files` kopyası symlink izliyordu | `scripts/inferDefault.py:26-32` (`O_NOFOLLOW`), `:209-217` (güvenli yazma) | **Giderildi.** Symlink/normal olmayan dosya okunmaz, dosya başına 64 MiB sınır, kopya symlink izlemez |
| S23 | P2 (ikinci turda bulundu) | Misafir kaynaklı kaynak tüketimi: karesel süreli desenler/ayrıştırma, sınırsız seri log, ağ, arayüz ve port sayısı | `scripts/makeNetwork.py:46-53` (sınırlar), `scripts/inferDefault.py:17-22`, `analyses/fuzzer/fwscan.py:39` (`_printable_tail`) | **Giderildi.** Seri log ≤ 64 MB, ≤ 4 ağ, ≤ 64 arayüz kaydı, ≤ 32 ek hostfwd portu (port 0 reddedilir), `inferDefault` ≤ 600 sn, ≤ 10.000 NVRAM anahtarı / 256 bayt; ölçüm: 40k anahtar 7,62 → 0,59 sn, 80 KB yazdırılabilir blok 16,8 sn → doğrusal |
| S24 | P1 (ikinci turda bulundu) | Temizlik, başka bir kurulumun/kullanıcının QEMU'sunu durdurabiliyordu (ad desenine göre eşleme) | `firmae.config` `qemu_pids` (satır 420) | **Giderildi.** `/proc/<pid>/cmdline` içinde bu kurulumun tam `scratch/<IID>/image.raw` yolu aranır; gerçek çalıştırmada ilgisiz `qemu-system-arm`/`-mipsel` hayatta kaldı |
| S25 | P2 (ikinci turda bulundu) | Eşzamanlı çalıştırmada kilit yok: aynı firmware/IID iki kez çalışınca birbirinin kaynağını (loop, mount, TAP, QEMU) bozabiliyordu | `firmae/pipeline.py:121` (`scratch/.locks/<md5>.lock`), `:139` (`scratch/<IID>/.firmae.lock`), `firmae/errors.py` (`BUSY = 75`) | **Giderildi.** `flock` ile iki kilit; alınamazsa çıkış 75, hiçbir şeye dokunulmaz. Kalan: `.locks/*.lock` dosyaları birikir |

## 3. Bağımlılık taraması

2026-11-04 tarihinde `requirements.txt`'deki sabit sürümler OSV.dev veritabanında sorgulandı
(`/v1/querybatch`, PyPI ekosistemi). Sayılar OSV kayıt sayısıdır; aynı açık için GHSA/PYSEC
takma adları ayrı sayılabildiğinden **tekil açık sayısından yüksek olabilir.** `pip-audit`
çalıştırılamadı (WSL'de `python3-venv` yok, kurulum sudo gerektiriyor).

| Paket | Sürüm | OSV kaydı | | Paket | Sürüm | OSV kaydı |
|---|---|---|---|---|---|---|
| scrapy | 2.5.0 | 24 | | paramiko | 2.7.2 | 5 |
| werkzeug | 2.0.3 | 21 | | Flask | 2.0.1 | 4 |
| cryptography | 3.4.7 | 20 | | requests | 2.32.3 | 4 |
| urllib3 | 2.2.3 | 16 | | future, pycryptodome, pytest | — | 2'şer |

Kayıt bulunmayanlar: coloredlogs, beautifulsoup4, bluepy, psycopg2, pysnmp, python_magic,
selenium. Not: `urllib3 2.2.3` son commit'te (`653565b`) yükseltilmiş olmasına rağmen kayıtları var.

## 4. Kalan / kabul edilen riskler

- Tam sistem emülasyonu root gerektirir; QEMU'nun kendisindeki bir guest→host kaçış açığı bu
  mimaride host root'u demektir. Azaltma: QEMU'yu güncel tutmak, ağ izolasyonu, (ileride)
  QEMU'yu `-runas` ile düşük yetkiye indirmek.
- Debug modu bilinçli olarak kimlik doğrulamasız shell açar.
- Kernel ve guest binary'leri (busybox, libnvram, console, strace, gdb) bu repodan değil,
  GitHub release'lerinden önceden derlenmiş olarak indiriliyor; kaynakla eşleştikleri
  doğrulanmadı.

**İkinci turdan sonra güncel liste (2026-11-16)** — hepsi kodda/çalıştırmada doğrulanmış
durumlardır; "doğrulanmadı" yazanlar gerçek çalıştırmayla denenmedi.

- **TAP adları ve iptables etiketi host genelinde tek ad alanı:** `tap<IID>_<n>` ve
  `firmae:<IID>` etiketi kurulumdan bağımsızdır; aynı IID'li iki ayrı kurulum (farklı
  klasör) birbirinin arayüzünü/kurallarını bozar. (`firmae.config` `_isolation_rules`.)
- **IPv6 yalıtımı sessiz düşebilir:** `ip6tables` yoksa yalnızca `iptables` kuralları
  uygulanır ve uyarı basılmaz; durum yalnızca `scratch/<IID>/isolation` dosyasındaki
  `applied: ...` satırından anlaşılır (uyarı yalnızca HİÇBİR araç çalışmazsa basılır).
- **`findPorts` gerçek 4.1 çekirdek log biçimini tanımıyor** (bilinen; DHCP modunda tam port
  keşfi bilerek bekletildi, bkz. `CHANGELOG.md` 2.10).
- **Doğrulanmadı (gerçek çalıştırma yok):** DHCP modu, analiz modu (`-a`), debug/run/boot
  modları, Docker modu, `install.sh`. `makeImage.sh`'in FIFO/symlink (`/bin/a`) yolu yalnızca
  sahte ağaçta denendi.
- **`scratch/.locks/*.lock` dosyaları birikir** (silinmez; boş, zararsız).
- **`get_scratch` hâlâ global `IID` değişkenini kullanıyor** (`firmae.config`, `get_scratch`):
  argümanı doğrulayıp başka bir değişkeni kullanıyor; çağıranlar IID'yi ayarlamak zorunda.
- **Açık bulgular:** S7, S9, S10, S11, S15, S16 (yukarıdaki tablo). Peripheral emülasyonu
  (Faz 6) ve bağımlılık/kurulum (Faz 7) hiç başlanmadı.
- `analyses_all.sh` `result` dosyasına koşulsuz `true` yazar; adım durumları
  `analysis_log/steps` içindedir.
