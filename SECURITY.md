# FirmAE Güvenlik Değerlendirmesi

> **Durum:** Bulgular 2026-11-04'te `master` (`653565b`) üzerinde statik analizle bulundu.
> Hiçbir yazılım için mutlak güvenlik garantisi verilemez; bu belge tespit edilen riskleri,
> uygulanan/önerilen önlemleri ve kalan riskleri listeler.
>
> **Durum özeti (2026-11-17, `refactor/hardening` dalı, HEAD `d9aaee7`; hepsi commit edilmiş ve
> `origin/refactor/hardening`'e push edilmiş, dalda 136 commit).** Ayrıntılı ölçümler: `TEST_REPORT.md`; değişiklikler:
> `CHANGELOG.md`. Bu tur: iki turlu geliştirme + sıfır bağlamlı bağımsız denetim; birim test 181 → 1076 (Faz 6.1 ve grup 1 dahil).

| Durum | Bulgular |
|---|---|
| **Giderildi** | S1, S2, S3, S4 (yalnızca yeni kurulumlar; mevcut kurulumda `pg_hba.conf` elle), S5, S6, S12, S13, S14 (extractor + getArch), S17, S18 (kaynak; hazır `console.*` ikilileri yeniden derlenmedi), **S19, S20, S21, S22, S23, S24, S25** (ikinci tur) |
| **Kısmen** | S8: ilk emülasyonda `restrict=on`, `hostfwd`/soketler loopback'te, TAP modunda iptables/ip6tables kuralları; DHCP/user-net modunda hostfwd host portları 127.0.0.1'de dinamik (10000-19999) ve host'un kendi 80 portu yüzünden oluşan yanlış pozitif `web=true` kapandı (kod + birim test; **DHCP modu gerçek firmware/QEMU ile hiç çalıştırılmadı**); **açık kalan:** DHCP modunda analiz araçlarının (`nmap.sh`/`analyses_all.sh`, `initializer.py`, `debug.py`, `run_mode.sh`) `127.0.0.1`'i = host'u hedeflemesi (REFACTORING_PLAN.md "Takip gerekir"); L2 (ARP) kapsam dışı; TAP adları/güvenlik duvarı etiketi host genelinde tek ad alanı; `ip6tables` yoksa IPv6 sessizce yalıtılmaz |
| **Açık** | S7 (`--privileged`), S9 (çıkarım root + sandbox'sız), S10 (debug shell), S11 (root Chrome `--no-sandbox`), S15 (indirmelerde checksum yok), S16 (eski bağımlılıklar) |
| **Yeni yüzey** | S26 (donanım profilleyicisi): bağımsız denetim (2026-11-17) 8 bulgu verdi, hepsi düzeltildi; **düzeltme sonrası ikinci bir bağımsız denetim yapılmadı**, gerçek iki firmware koşusunda doğrulandı (TEST_REPORT.md "Faz 6.1") |

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
| S8 | P1 | Ağ izolasyonu yok: `-netdev user` kısıtsız (firmware internete/LAN'a çıkar), `hostfwd` 0.0.0.0:80/443, `-netdev socket,listen=:2000-2003` tüm arayüzlerde | `makeNetwork.py:282,294,304`, `scripts/run.*.sh:29-31` | `restrict=on`, `127.0.0.1` bind, boş port; Faz 5'te analiz başına netns. **2026-11-17:** DHCP modunda host portu dinamik (10000-19999, IID başına 40'lık blok, bind ile sınanmış, `scratch/<IID>/hostfwd`), `check_emulation.sh` yalnız eşlenen porta gider (host'un 80'i `web=true` vermez; DHCP'de ping = web, başarıda `ip=127.0.0.1`); yalnız birim testli, gerçek DHCP koşusu yok. **Denetimde bulundu, düzeltildi (gerçek DHCP koşusunda doğrulanmadı):** (1) seçilen host portunu YABANCI bir süreç tutarken QEMU başlamıyor ama web denetimi o sürecin yanıtını `web=true` sayıyordu (denetçi `python3 -m http.server` ile kanıtladı); `scripts/hostfwd_check.sh` artık emülasyonun yaşadığını ve portun sahibinin bu IID'nin QEMU'su olduğunu (`ss -Htlnp`) doğrular, `ss` yoksa/pid okunamıyorsa `web=false` + uyarı; slirp dinleyicisinin `ss -p`'de QEMU pid'iyle göründüğü **doğrulanmadı**. (2) root çalışan tarama/istismar araçları host'un kendi localhost servislerine yönelebiliyordu: `run_mode.sh` DHCP imajında analyze'ı araç çalıştırmadan reddeder (çıkış 60), debug'ı reddeder (çıkış 50), run modu yalnız eşlenen porta bakar. **Açık:** `debug.py`, `analyses/*` (`nmap.sh`, `analyses_all.sh`, `initializer.py`, fuzzer) ve `util/collect_result.py` DHCP desteği olmadan kalıyor (doğrudan çağrılırsa host'u hedefler); `firmae/pipeline.py`'deki "Network reachable on 127.0.0.1" mesajı DHCP'de yanıltıcı. Ayrıca `firmae.qemu` (`run.<arch>.sh`) `FIRMAE_NET`/`FIRMAE_KERNEL` değerlerini artık komut olarak çalıştırmaz, yalnız `true`/`false` kabul eder (`firmae.config` `get_kernel` ve `makeNetwork.py` `checkVariable` ayrı yollardır; `get_kernel` hâlâ `(${FIRMAE_KERNEL})` değerlendirir). Eski betikte `FIRMAE_NET=yes` `/usr/bin/yes`'i çalıştırıp takılıyordu; baştaki sıfırlı IID (`08`/`09`) ve `true`/`false` dışı değerler artık reddedilir. Sarmalayıcı `python3 -I` ile çalışır: cwd'deki sahte bir `firmae/` paketi artık yüklenmez (denetim bulgusu). TOCTOU (port boşluk sınaması ile QEMU bind'i arası) kabul edildi; run.sh portları yeniden sınar |
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
| S25 | P2 (ikinci turda bulundu) | Eşzamanlı çalıştırmada kilit yok: aynı firmware/IID iki kez çalışınca birbirinin kaynağını (loop, mount, TAP, QEMU) bozabiliyordu | `firmae/pipeline.py:139` (`scratch/.locks/<md5>.lock`), `:157` (`scratch/<IID>/.firmae.lock`), `firmae/errors.py` (`BUSY = 75`) | **Giderildi.** `flock` ile iki kilit; alınamazsa çıkış 75, hiçbir şeye dokunulmaz. Kalan: `.locks/*.lock` dosyaları birikir |
| S26 | P2 (yeni yüzey, 2026-11-16) | **Donanım profilleyicisi** (`firmae/hwprofile.py`, `firmae/hwserial.py`) güvenilmeyen firmware tarball'unu ve guest'in seri logunu okur; çıktısı (`hw_profile.json`) firmware kaynaklı dizeler içerir ve özet satırı terminale basılır. Riskler: tarball üye adıyla yol geçişi/symlink, zip-bomb benzeri aşırı üye/bayt, sınırsız seri log, JSON'a giren kontrol/ANSI karakterleri ile terminal enjeksiyonu, sonsuz süre | `firmae/pipeline.py` (`_hwprofile_step`, `_hwprofile_static`, `_hw_summary_line`, `stage_timeout`); profilleyicinin kendisi: `firmae/hwprofile.py`, `firmae/hwserial.py` | **Tasarım önlemleri:** tarball diske açılmaz, yalnızca akış olarak okunur; üye adı hiçbir zaman dosya yolu olarak kullanılmaz; üye sayısı, bayt ve süre sınırı (`--timeout`; boru hattı ayrıca dış zaman aşımı + süreç grubu sonlandırması uygular); seri log okuması sınırlıdır; JSON'a giren dizeler temizlenir. **Boru hattı tarafı (bu tur, testli):** adım ölümcül değildir; log `O_NOFOLLOW` ile açılır; özet profili `O_NOFOLLOW`, normal dosya, ≤ 8 MiB (profilleyici dosyayı ≤ 2 MiB ile sınırlar; bu yalnızca okuma koruması), JSON hatasına dayanıklı okur ve **yalnızca bilinen anahtarları ve bilinen `status` değerlerini** basar (ANSI kaçışlı anahtar/değer, dev dosya, symlink, FIFO, bozuk JSON testlenmiştir: `tests/unit/test_pipeline_hwprofile.py`). Gerçek modüllerle bütünleşme testi: `tests/unit/test_hwprofile_integration.py`.<br>**Bağımsız denetim (2026-11-17) bulguları ve durumları** — her biri için: *bu turda düzeltildi; düzeltme sonrası ikinci bir bağımsız denetim YAPILMADI.* (1) Sparse tar başlığıyla bellek patlaması (2 MB girdi, 43 sn'de 2,6 GB): düzeltme uygulandı; ölçüm: 3,93 GB RSS/`MemoryError` → 27 MB, 0,2 s (yalnız `RLIMIT_AS` ile 1,53 GB'ta durdu, 21 s); ayrıntı TEST_REPORT.md "Faz 6.1" B. (2) xz sözlüğü 3,1 GB bellek isteyebiliyordu: düzeltme uygulandı (profilleyici bellek sınırı `--mem-limit-mb`); ölçüm: 610 KB girdi için 2,1 GB (denetçi: 3,1 GB) → 17 MB, 0,04 s; TEST_REPORT.md "Faz 6.1" B. (3) İç içe pax başlık zinciri `RecursionError` ile çöküyordu: düzeltme uygulandı (14 KB girdi: traceback/çıkış 1 → kısmi profil/çıkış 0; TEST_REPORT.md "Faz 6.1" B). (4) Örnek sınırı yüzünden kaçan `failing` (seri logda hata var, profil bunu raporlamıyordu): düzeltme uygulandı. (5) Seri log yanlış pozitifleri ve çift sayım: düzeltme uygulandı. (6) Zaman aşımı tutarsızlığı (`FIRMAE_TIMEOUT_HWPROFILE` < 60 iken iç `--timeout` dış sınırı aşıyordu): iç süre artık dış sınırın %80'i, sınırsızken 240 sn (`firmae/pipeline.py`); `FIRMAE_TIMEOUT_*` değerleri için 7 gün üst sınırı ve çok uzun sayıların işlenmemiş `ValueError`'u kapatıldı. (7) Bayat profil: statik adım başarısız olsa da önceki koşunun `hw_profile.json`'u özetleniyor ve güncelleniyordu: eski dosya statik adımdan önce silinir, statik adım başarısızsa dinamik adım ve özet atlanır. (8) Özet satırı 4 MiB'tan büyük/bozuk profilde sessizce kayboluyordu: sabit metinli `[hw] profil okunamadı (...)` uyarısı basılır (dosyadan gelen hiçbir dize basılmaz). Ölçümlerin tamamı: TEST_REPORT.md "Faz 6.1" B (ör. profil 6,27 → 1,08 MiB; 64 MiB seri log 0,2 s).<br>**Denetimde sorun bulunmayan alanlar:** diske yazma yok (tarball açılmaz); çıktı dosyası `O_EXCL\|O_NOFOLLOW` ile yazılır; terminal çıktısı beyaz listelidir; düzenli ifadelerin çalışma süresi girdi boyutuyla doğrusaldır. **Gerçek koşu:** düzeltme sonrası kodla DIR-868L (ARM) ve WNAP320 (MIPS) emülasyonu, ağ-hatası yolu ve Ctrl-C denendi; bitişte sızıntı sayaçları 0 (TEST_REPORT.md "Faz 6.1" C). Kısıt: gerçek firmadyne iz biçimini taklit eden guest genel hata türlerini gizleyebilir (panic/segfault/modül hataları gizlenemez). **Doğrulanmadı:** düzeltmelerden sonra yeni bağımsız denetim yok; Python 3.8, analyze/debug/run/boot ve Docker modları, daha geniş firmware seti |

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
  (Faz 6): yalnızca 6.1 (S26, `firmae/hwprofile.py`, `firmae/hwserial.py`, bilgi amaçlı profil) uygulandı, 6.2–6.5 açık, mock yok; bağımlılık/kurulum (Faz 7) hiç başlanmadı.
- `analyses_all.sh` `result` dosyasına koşulsuz `true` yazar; adım durumları
  `analysis_log/steps` içindedir.
