# FirmAE Refactoring Planı

> **Tamamlanma durumu (2026-11-08).** Bu belge planı olduğu gibi tutar; gerçek durum aşağıda.
> Ayrıntılı kanıt: `TEST_REPORT.md`, değişiklikler: `CHANGELOG.md`.

| Faz | Durum | Yapılmayanlar / not |
|---|---|---|
| 0 Ölçüm | ✅ | — |
| 1 Test iskeleti | ✅ | Kapsam: ağ çıkarımı, QEMU komutları, yaşam döngüsü, boru hattı (181 test). `extractor.py` ve `analyses/` büyük ölçüde testsiz |
| 2 Güvenlik/işlevsel | ✅ 2.1–2.9, 2.11, 2.12 | **2.10 yapılmadı** (port keşfi: dinamik `hostfwd` portları olmadan zararlı) |
| 3 Süreç/kaynak | ✅ | Plandaki ayrı `proc/resources` paketi yerine `firmae.config` + `scripts/procgroup.py`. **cgroup sınırları, eşzamanlılık kilidi yok** |
| 4 Python orkestrasyonu | **kısmen** | ✅ 4.1, 4.6 (aşama orkestrasyonu, çıkış kodları, loglama). ❌ 4.2–4.5 (`makeImage.sh`, `makeNetwork.py`, `run.<arch>.sh`, `check_emulation.sh` hâlâ Bash/eski Python), ❌ 4.7 (kilitler, metrikler) |
| 5 Ağ izolasyonu | **kısmen** | ✅ 5.1–5.3; 5.4 ağ namespace'i yerine iptables kuralları. **DHCP modu gerçek testsiz**, L2 (ARP) kapsam dışı |
| **6 Peripheral (Problem 1)** | **❌ hiç başlanmadı** | I2C/SPI/GPIO ölçümü ve mock yok |
| **7 Bağımlılık/kurulum** | **❌ hiç başlanmadı** | Eski bağımlılıklar, `download.sh` checksum, `apt-key`, chromedriver 2.38, `ubuntu:20.04`, Ubuntu 24.04'te `install.sh` |

Üç ana problem: **Problem 1 (peripheral)** hiç ele alınmadı; **Problem 2 (monolitik Bash)** kısmen
(orkestrasyon taşındı, aşama script'leri taşınmadı); **Problem 3 (kaynak/zombi)** büyük ölçüde çözüldü
(ölçüldü), kaynak sınırları ve eşzamanlılık kilidi eksik.

## Çalışma kuralları

- Her adım **tek mantıksal değişiklik**, ayrı bir commit; `refactor/hardening` dalında.
  Geri alma = o commit'in `git revert`'ü. Commit/push ancak sizin onayınızla.
- Her adımdan sonra ilgili testler çalıştırılır; başarısız test atlanmaz/devre dışı bırakılmaz.
- Her fazın sonunda size rapor: değişen dosyalar, giderilen sorunlar, mimari değişiklikler,
  güvenlik iyileştirmeleri, çalıştırılan testler ve sonuçları, kalan riskler. Sonraki faza
  onayınızla geçilir.
- Davranış değişikliği yaratan her adım aşağıdaki tablolarda **DD** ile işaretlidir ve
  uygulanmadan önce tekrar açıklanır.

## Faz 0 — Test ortamı ve temel çizgi (kod değişikliği yok)

WSL2 Ubuntu 24.04'te şu an eksik olanlar (sudo parolası gerektiği için sizin kurmanız gerekiyor):

```bash
sudo apt install -y python3-venv python3-pip qemu-system-arm qemu-system-mips qemu-utils postgresql busybox-static bash-static kpartx uml-utilities vlan bc
```

| Adım | İçerik |
|---|---|
| 0.1 | `install.sh` + `download.sh` ile kurulum (proje ayrı bir Linux dizinine, ör. `~/FirmAE`, kopyalanır — `/mnt/c` üzerinde loop/chroot performansı ve izinler sorunlu) |
| 0.2 | **Değişiklik öncesi ölçüm:** README'deki örnek firmware (DIR-868L) + 1 ARM firmware ile `-c` modu; her senaryo sonrası `losetup -a`, `ip -o link`, `findmnt`, QEMU süreç sayısı, `/tmp` ve `scratch/` boyutu kaydedilir |
| 0.3 | Ctrl-C ile yarıda kesme, eşzamanlı 2 çalıştırma ve bozuk firmware senaryolarının bugünkü sonuçları kaydedilir (sızan kaynak sayıları = iyileştirmenin ölçütü) |
| 0.4 | Açık soru: ARM `virt`'te ttyS1/`/tmp/qemu.IID.S1` çalışıyor mu? |

## Faz 1 — Güvenlik ağı (davranış değişikliği yok)

| Adım | Dosyalar | İçerik |
|---|---|---|
| 1.1 | `tests/conftest.py`, `tests/fixtures/` | pytest iskeleti; root/QEMU yoksa testler gerekçeli SKIP |
| 1.2 | `tests/unit/test_network_parse.py` | `makeNetwork.py` saf parse fonksiyonları için karakterizasyon testleri (bugünkü çıktıyı kilitler) |
| 1.3 | `tests/unit/test_qemu_argv.py` | Bugünkü 4 QEMU komutunun beklenen argümanları (Faz 4 için referans) |
| 1.4 | — | `shellcheck` raporu (yalnızca rapor, düzeltme yok) |

Karar gerekiyor: `pytest==6.2.4` Python 3.12 ile uyumlu değil (beklenen; Faz 0'da
doğrulanacak). Seçenek: test bağımlılıklarını ayrı `requirements-dev.txt`'de güncel pytest ile
tutmak (çalışma zamanı bağımlılıklarına dokunmaz).

## Faz 2 — P0/P1 güvenlik ve işlevsel düzeltmeler (küçük, izole)

| Adım | Dosyalar | Bulgu | DD |
|---|---|---|---|
| 2.1 | `analyses/fuzzer/fuzzer.py` | S1 — `command()` yerine argüman listesi, Python ile dosya tarama | — |
| 2.2 | `scripts/getArch.py` | S3 — diske çıkarmadan tarama, `mkdtemp` | — |
| 2.3 | `scripts/makeImage.sh`, `scripts/makeNetwork.py` | S5 — symlink'in mount dışına çıkmasını engelle; dışarı işaret ediyorsa hata + log | DD: böyle bir firmware artık "image fail" ile durur |
| 2.4 | `run.sh`, `scripts/makeImage.sh` | S2 — izinler `a+rwx` → `0750`/`0660` | DD: root olmayan kullanıcı `scratch/` içeriğini okuyamaz/yazamaz |
| 2.5 | `install.sh` | S4 — `trust` → `scram-sha-256`, kapsam daraltma | DD: mevcut kurulumlar için elle `pg_hba.conf` güncellemesi gerekir (belgelenir) |
| 2.6 | `docker-helper.py` | S6 — argüman listeleri | — |
| 2.7 | `analyses/nmap.sh` | Çalışmayan IP tespiti (`GUESTIP=`) ve eksik `/`; XML çıktısını fuzzer'ın okuduğu `nmap_log.txt`'ye yaz | DD: nmap ve fuzzer port keşfi ilk kez gerçekten çalışır (analiz süresi uzar) |
| 2.8 | `scripts/delete.sh`, `util/cleanup.sh` | `0 .. 4` döngüsü, tırnaklı glob, IID alt-dizgi eşleşmesi; `cleanup.sh` yalnızca FirmAE konteyner/loop'larını hedefler | DD: `cleanup.sh` artık FirmAE dışı konteynerleri silmez |
| 2.9 | `run.sh`, `check_emulation.sh`, `makeNetwork.py` | `2>&1 > file` → `> file 2>&1` | DD: hata mesajları terminal yerine log dosyalarına gider |
| 2.10 | `scripts/makeNetwork.py` | `findPorts()` kernel'in gerçek `proto:SOCK_X, port:N` biçimini de tanısın (eski biçim korunur) — Faz 1'de ölçüldü | DD: DHCP modunda firmware'in açtığı diğer portlar da hostfwd edilir (Faz 5'te `127.0.0.1`'e bağlanana kadar bu portlar da tüm arayüzlerde dinler — 2.10, 5.1'den sonra uygulanabilir) |
| 2.11 | `scripts/makeNetwork.py` | Regex'ler raw string (`rb"…"`); Python 3.12 `SyntaxWarning`'leri biter | — |
| 2.12 | `.gitattributes` (yeni) | `*.sh`, `firmae.config`, `scripts/*` için `eol=lf` — Windows checkout'larında script'ler çalışır kalır | — |

## Faz 3 — Süreç ve kaynak yaşam döngüsü (Problem 3)

| Adım | Dosyalar | İçerik | DD |
|---|---|---|---|
| 3.1 | `firmae/proc.py`, `firmae/resources.py`, `firmae/signals.py` + testler | Yeni kod; henüz hiçbir yerden çağrılmaz. `fake_qemu.py` ile timeout/SIGTERM-yok-sayma/çökme/zombie testleri | — |
| 3.2 | üretilen `scratch/IID/run.sh` şablonu (`makeNetwork.py`) | Ara çözüm: QEMU `-pidfile`; `trap cleanup EXIT INT TERM` ile STOP_NET + umount + losetup -d; TAP oluşturma idempotent | — |
| 3.3 | `check_emulation.sh`, `run.sh` | `ps \| grep \| kill` → pidfile ile hedefli SIGTERM→SIGKILL; arka plan süreçleri `wait` | DD: paralel çalışan diğer QEMU'lar artık öldürülmez |
| 3.4 | `firmae.config` (`add_partition`) | `losetup --find --show --partscan`, sınırlı bekleme (30 sn) + hata | — |
| 3.5 | `run.sh`, `makeNetwork.py` | `timeout` çağrılarına `-k 15` (SIGKILL'e yükseltme) | — |

## Faz 4 — Modüler Python orkestrasyonu (Problem 2)

Her adımda eski Bash dosyası ince bir sarmalayıcı olarak kalır; aynı girdiyle eski ve yeni yol
karşılaştırılır (Faz 0 temel çizgisi + Faz 1 karakterizasyon testleri).

| Adım | İçerik |
|---|---|
| 4.1 | `firmae/config.py`, `errors.py`, `log.py`, `state.py` |
| 4.2 | `firmae/qemu.py` → `run.<arch>.sh` üçü de `python3 -m firmae qemu-initial` çağırır |
| 4.3 | `firmae/storage.py` + `stages/image.py` → `makeImage.sh` host tarafı (chroot script'leri aynen) |
| 4.4 | `stages/infer_network.py` → `makeNetwork.py` (parse fonksiyonları taşınır, Bash şablonu kalkar; `scratch/IID/run.sh` tek satırlık çağrıya döner) |
| 4.5 | `stages/check.py` → `check_emulation.sh` |
| 4.6 | `stages/extract.py`, `arch.py`, `modes.py`, `__main__.py`; `run.sh` → sarmalayıcı. **DD:** anlamlı exit code'lar (bkz. `ARCHITECTURE.md` §7); toplu modda bir firmware'in hatası diğerlerini durdurmaz |
| 4.7 | `firmae/metrics.py`, eşzamanlılık kilitleri, opsiyonel `systemd-run` sınırları |

## Faz 5 — Ağ izolasyonu

| Adım | İçerik | DD |
|---|---|---|
| 5.1 | `-netdev user,restrict=on`; `hostfwd` → `127.0.0.1:<boş port>`; DHCP kontrolü o portu hedefler (yanlış pozitif düzeltmesi) | DD: firmware dış ağa çıkamaz; web UI yalnızca localhost'tan erişilir |
| 5.2 | Yer tutucu socket NIC'leri `127.0.0.1` + boş port | — |
| 5.3 | Monitor/serial soketleri `scratch/IID/run/`; `debug.py` yeni yolu okur; `/tmp` symlink'i bir sürüm boyunca | — |
| 5.4 | Analiz başına `ip netns` (tasarım + prototip; ayrı onay) | DD |

## Faz 6 — Peripheral (Problem 1)

| Adım | İçerik |
|---|---|
| 6.1 | `firmae/hwprofile.py` statik tarama + sınıflandırma + `hw_profile.json`; birim testleri sentetik rootfs ile |
| 6.2 | Profil modu: guest'te `/firmadyne/strace` ile `open/ioctl` izleme |
| 6.3 | Faz 0 firmware seti üzerinde rapor: hangi cihazlar `UNSUPPORTED`, emülasyon sonucu ile ilişkisi |
| 6.4 | **Karar noktası (ayrı onay):** veriler gerektiriyorsa `libhwmock` (I2C/SPI işlem seviyesi) — çapraz derleme toolchain kararı dahil |

## Faz 7 — Bağımlılıklar ve kurulum

`requirements.txt` kontrollü yükseltme (her paket ayrı, analiz modülleriyle test), `download.sh`
SHA-256 doğrulaması, `apt-key` → `signed-by`, chromedriver 2.38 kaldırılması, Docker tabanının
`ubuntu:24.04`'e taşınması.

## Kapsam dışı (bilinçli)

- Kernel'in (`FirmAE_kernel-v*`) ve QEMU'nun değiştirilmesi/yeniden derlenmesi.
- `sources/scraper/` (analiz hattının parçası değil).
- routersploit submodule'ü (yalnızca çağrılış biçimi).
