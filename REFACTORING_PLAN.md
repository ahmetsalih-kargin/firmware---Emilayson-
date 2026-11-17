# FirmAE Refactoring Planı

> **Tamamlanma durumu (2026-11-17, "grup 1" değişiklikleri çalışma ağacında, commit edilmedi).** Bu belge planı olduğu gibi tutar (aşağıdaki Faz 0–7 bölümleri
> *plandır*, yapılanın kaydı değildir); gerçek durum bu başlıktaki iki tabloda. Kod `refactor/hardening`
> dalında HEAD `d9aaee7` (commit edilmiş, `origin/refactor/hardening`'e push edilmiş); bu belgedeki 2.10, 5.1 ve 4.2 satırları
> ise çalışma ağacındaki **commit edilmemiş** değişikliklere dayanır.
> Güncel birim test sayısı: **1076** (WSL Ubuntu 24.04, Python 3.12, root değil). Ayrıntılı kanıt: `TEST_REPORT.md`,
> değişiklikler: `CHANGELOG.md`.

## Adım bazında dürüst durum (kodla karşılaştırılarak)

TAMAM = kodda var ve en az birim testli; KISMEN = planın bir kısmı ya da plandan farklı yolla; YOK = yapılmadı;
DOĞRULANMADI = kod var ama gerçek çalıştırmada denenmedi.

| Adım | Durum | Not |
|---|---|---|
| 0.1 | KISMEN | Kurulum WSL'de elle yapıldı; `install.sh` ve `download.sh` **hiç gerçek koşulmadı** |
| 0.2, 0.3 | TAMAM | Temel çizgi ve Ctrl-C / bozuk firmware senaryoları ölçüldü (`TEST_REPORT.md` Faz 0, Faz 3) |
| 0.4 | YOK | ARM `virt`'te ttyS1/`/tmp/qemu.IID.S1` çalışıyor mu sorusu **hiç yanıtlanmadı** |
| 1.1, 1.2 | TAMAM | `tests/conftest.py`, `tests/fixtures/`, `test_network_parse.py` |
| 1.3 | KISMEN | Plandaki `test_qemu_argv.py` yok; karşılığı `test_qemu_cmd.py` + `test_config_and_initial_qemu.py` |
| 1.4 | TAMAM | ShellCheck raporu (`TEST_REPORT.md` Faz 1) |
| (Faz 1) `tests/integration/` | YOK | root gerektiren testler için dizin yok |
| 2.1, 2.2, 2.6, 2.8, 2.9, 2.11, 2.12 | TAMAM | Birim testli |
| 2.3 | DOĞRULANMADI | Birim testli (sahte ağaç); uçtan uca firmware imajıyla denenmedi |
| 2.4 | TAMAM | İzinler daraltıldı (`tests/unit/test_workdir_perms.py`) |
| 2.5 | KISMEN | `install.sh` `md5` yazıyor (`scram-sha-256` değil; `md5` scram parolalarını da kabul eder) ve `trust` kaldırıldı; `install.sh` **hiç gerçek koşulmadı** |
| 2.7 | DOĞRULANMADI | `analyses/nmap.sh` düzeltmesi birim testli; **gerçek nmap/fuzzer koşusu yok** |
| 2.10 | TAMAM | `findPorts` gerçek 4.1 çekirdek biçimini (`inet_bind[PID: n (ad)]: proto:SOCK_X, port:N`) ve eski biçimi ayrıştırır; port 0 ve >= 32768 atılır, (proto, port) çiftine göre tekrar elenir, en çok `MAX_PORTS=256`. Gerçek iki fixture ile birim testli |
| 3.1 | KISMEN | `firmae/proc.py`/`resources.py`/`signals.py` yok; yerine `scripts/procgroup.py` (`run_with_timeout`, `raise_on_sigterm`) ve `firmae.config` |
| 3.2, 3.3 | KISMEN | `-pidfile` **yok**; yerine `firmae.config` `qemu_pids` (`/proc/*/cmdline` + `image.raw` tam yol eşlemesi) ile hedefli sonlandırma; temizlik `trap` ile (`check_emulation.sh`, üretilen `run.sh`) |
| 3.4 | TAMAM | `add_partition` sınırlı bekleme (birim testli) |
| 3.5 | KISMEN | `timeout -k 15` yok; yerine `run_with_timeout` (SIGINT, `grace` sonra SIGKILL) |
| (Faz 3) cgroup, `FIRMAE_MAX_PARALLEL`/slot | YOK | Kaynak sınırı ve global eşzamanlılık sınırı yok |
| 4.1 | TAMAM | `firmae/config.py`, `errors.py`, `log.py`, `state.py` |
| 4.2 | TAMAM | `firmae/qemu.py` (`build_initial_argv`, `main`); `run.<arch>.sh` üçü ince sarmalayıcı, çağrı `exec python3 -I <kurulum>/firmae/qemu.py initial <arch> "$@"`; 54 durumluk altın argv + Bash↔Python eşdeğerlik testleri. **Gerçek QEMU ile ölçüldü (2026-11-17, WSL2; A/B/C/G/H, bkz. `TEST_REPORT.md` bölüm H)**: TAP modunda `run.sh` tabanla aynı, Ctrl-C temiz; DHCP modu gerçek firmware ile hâlâ doğrulanmadı |
| 4.3 | TAMAM (asgari kapsam) | `scripts/makeImage.sh` → `firmae/image.py`; **aynı dış araçlar** (losetup, kpartx, mkfs, mount, tar, chroot) çağrılır; yerel loop/mount/`tarfile` (seçenek B) **yapılmadı**. Host tarafı yazmalar symlink izlemez (`resolve_in_root` + `O_NOFOLLOW`/`O_EXCL`, fd tabanlı). Gerçek emülasyonla ölçüldü (2026-11-17, bkz. `TEST_REPORT.md` "Grup 2") |
| 4.4 | TAMAM (asgari kapsam, kullanıcı kararı) | `makeNetwork.py` doğrulanmış `scratch/<IID>/emulation.conf` yazar; `scratch/<IID>/run.sh` sabit bir sarmalayıcıdır ve statik `scripts/emulate.sh`'yi `exec` eder. Bash kodu **üretilmez**. Tam Python başlatıcı (seçenek B) **yapılmadı**. Ölçüldü (2026-11-17) |
| 4.5 | TAMAM | `check_emulation.sh` → `firmae/check.py` + `firmae/procutil.py` + `firmae/hostfwd.py`; betik ince sarmalayıcı. Bash `check_network`/`qemu_pids`/`hostfwd_check.sh` `run_mode.sh` için kalır; eşdeğerlik `tests/unit/test_check_py.py` ile sabitlenmiştir. Ölçüldü (2026-11-17) |
| 4.6 | KISMEN | Aşama orkestrasyonu, çıkış kodları, loglama **hepsi `firmae/pipeline.py` içinde**; `stages/`, `arch.py`, `modes.py` yok. `_run_mode` hâlâ `scripts/run_mode.sh`'i çağırır. `ExitCode.ANALYSIS = 60` tanımlı ama hiçbir yerde kullanılmıyor |
| 4.7 | KISMEN | `scratch/.locks/<md5>.lock` + `scratch/<IID>/.firmae.lock` (çıkış 75) ve aşama zaman aşımları var; `metrics.py` ve `systemd-run` sınırları **yok** |
| 5.1 | TAMAM (kod) | `restrict=on`, `127.0.0.1`; DHCP/user-net modunda host portları 10000-19999 aralığından, IID başına 40'lık bloktan (`hostfwdBlock`, IID'nin tamamı kullanılır), boşluğu sınanarak seçilir; eşleme `scratch/<IID>/hostfwd`; `check_emulation.sh` yalnız eşlenen porta gider (host'un 80'i yanlış pozitif vermez). **DHCP modu gerçek firmware/QEMU ile hiç koşulmadı: DOĞRULANMADI.** Analiz araçları hâlâ eski varsayımda — bkz. "Takip gerekir" |
| 5.2 | TAMAM | Yer tutucu NIC soketleri loopback'te IID'ye göre ayrılmış portlarda |
| 5.3 | KISMEN | Soketler `scratch/IID/run/` altında, `debug.py` yeni yolu okur; **`/tmp` uyumluluk symlink'i yok** |
| 5.4 | KISMEN | `ip netns` yerine iptables/ip6tables kuralları; `ip6tables` yoksa IPv6 sessizce yalıtılmaz |
| 6.1, 6.1b | DOĞRULANMADI | Uygulandı, iki firmware ile gerçek koşuda denendi (DIR-868L ARM, WNAP320 MIPS); ikinci bağımsız denetim ve analyze/debug/run/boot/Docker modlarında doğrulama yok |
| 6.2 | DOĞRULANMADI | "Komut satırı izi" kapsamında uygulandı (guest içi `strace` yapılmadı); iki gerçek analyze logunda ölçüldü, gerçek emülasyon yeniden koşulmadı |
| 6.3 | DOĞRULANMADI | Asgari `firmae.hwreport` uygulandı (birim testli); gerçek bir firmware setinde çalıştırılmadı |
| 6.4, 6.5 | YOK | Açık (`libhwmock` kararı, kernel kanca hataları) |
| 7 | KISMEN | Karar gerektirmeyen kısım uygulandı (kod + birim test; `install.sh`/`core/Dockerfile` çalıştırılmadı); hash'ler `UNKNOWN`, geri kalanı kullanıcı kararı bekliyor |
| Modlar | DOĞRULANMADI | analyze (`-a`), debug, run, boot, Docker ve DHCP modları **hiç gerçek koşulmadı** |
| `mount.sh`/`umount.sh` | — | Depoda hiçbir yerden çağrılmıyor (yalnızca kullanım metni/yorum) |

## Faz özeti

| Faz | Durum | Yapılmayanlar / not |
|---|---|---|
| 0 Ölçüm | **kısmen** | 0.4 yanıtsız; `install.sh` koşulmadı |
| 1 Test iskeleti | **kısmen** | Kapsam: ağ çıkarımı, QEMU komutları, yaşam döngüsü, boru hattı, kilitler, ikinci tur ve Faz 6.1 testleri (**1076 test**; ilk tamamlanışta 181). `tests/integration/` (root gerektiren) **yok** |
| 2 Güvenlik/işlevsel | ✅ 2.1–2.4, 2.6, 2.8–2.12; **2.5, 2.3, 2.7 kısmen/doğrulanmadı** | 2.10 tamam (5.1'in dinamik portlarıyla birlikte) |
| 3 Süreç/kaynak | **kısmen** | Plandaki ayrı `proc/resources` paketi yerine `firmae.config` + `scripts/procgroup.py`; `-pidfile` yerine `qemu_pids`. **cgroup sınırları ve `FIRMAE_MAX_PARALLEL`/slot sınırı yok.** Eşzamanlılık kilidi **var** (`scratch/.locks/<md5>.lock` + `scratch/<IID>/.firmae.lock`, çıkış 75); `.locks/*.lock` dosyaları birikir |
| 4 Python orkestrasyonu | **kısmen** | ✅ 4.1, 4.2 (gerçek QEMU ile TAP modunda ölçüldü, 2026-11-17), 4.3 (asgari: `firmae/image.py`, aynı dış araçlar), 4.4 (asgari: `emulation.conf` + statik `emulate.sh`, Bash üretimi yok), 4.5 (`firmae/check.py`) — üçü de 2026-11-17'de gerçek emülasyonla ölçüldü; 4.6'nın orkestrasyon kısmı ve 4.7'nin kilit/zaman aşımı kısmı. ❌ tam Python başlatıcı ve yerel loop/mount/`tarfile` (4.3/4.4 seçenek B), ❌ `stages/`/`arch.py`/`modes.py`, ❌ metrikler ve `systemd-run` |
| 5 Ağ izolasyonu | **kısmen** | 5.1 (DHCP `hostfwd` dinamik loopback portları; analiz araçları hâlâ eski varsayımda), 5.2, 5.3 (symlink yok), 5.4 (iptables). **DHCP modu gerçek testsiz**, L2 (ARP) kapsam dışı; TAP adları/güvenlik duvarı etiketi host genelinde tek ad alanı |
| İkinci sağlamlaştırma turu (2026-11-16, plan dışı) | ✅ | İki tur + bağımsız denetim: `SECURITY.md` S19-S25 (seri logdan komut enjeksiyonu P0 dahil), kilitler, zaman aşımları, sınırlar, `tar2db`/`util`/`extractor`/`docker-helper` hata yönetimi. Commit edilmiş ve push edilmiştir. Ayrıntı: `CHANGELOG.md`, `TEST_REPORT.md` |
| **6 Peripheral (Problem 1)** | **kısmen** | 6.1 + seri log kanıtı **uygulandı ve iki firmware ile gerçek koşuda doğrulandı (2026-11-17)** (profil bilgi amaçlıdır, emülasyon sonucunu etkilemez); 6.2 (komut satırı izi) ve 6.3 (asgari `firmae.hwreport`) **uygulandı, birim testli** (gerçek firmware setinde rapor çalıştırılmadı); 6.4 (`libhwmock`, toolchain + kernel preload sorusu) ve 6.5 (kernel kanca kayıt hataları) açık. Mock yok |
| **7 Bağımlılık/kurulum** | **❌ hiç başlanmadı** | Eski bağımlılıklar, `download.sh` checksum, `apt-key`, chromedriver 2.38, `ubuntu:20.04`, Ubuntu 24.04'te `install.sh` |

Üç ana problem: **Problem 1 (peripheral)** yalnızca ölçüm tarafında başladı (donanım profili, iki firmware ile gerçek koşuda doğrulandı; mock yok); **Problem 2 (monolitik Bash)** kısmen
(orkestrasyon taşındı, aşama script'leri taşınmadı); **Problem 3 (kaynak/zombi)** büyük ölçüde çözüldü
(ölçüldü; ikinci turda IID/firmware kilidi eklendi), kaynak (cgroup) sınırları ve metrikler eksik.

## Takip gerekir: DHCP/user-net modunda hâlâ `127.0.0.1` + sabit port varsayan yerler

DHCP modunda `check_emulation.sh` `scratch/<IID>/ip` dosyasına `127.0.0.1` yazar (host'un kendisi; guest'e yalnızca
`scratch/<IID>/hostfwd` içindeki loopback portlarıyla erişilir). Denetim sonrası durum (çalışma ağacı, kodda doğrulandı):

- **Kapatıldı:** `scripts/run_mode.sh`: `isDhcp` dosyası `true` ise analyze araç çalıştırmadan reddedilir (çıkış 60,
  `ExitCode.ANALYSIS`; `firmae/pipeline.py` bu kodu `ExitCode`'a çevirir), debug reddedilir (çıkış 50, 31337-31339 ve gdbserver
  portları user-net'te iletilmez), run modu yalnız eşlenen porta bakar (`scripts/hostfwd_check.sh`); TAP dalları değişmedi.
  Yalnız birim testli (`tests/unit/test_run_mode_dhcp.py`), gerçek DHCP koşusu yok.
- **AÇIK:** `debug.py` (31337/31338/31339 ve gdbserver portları, hedef `ip` dosyası), `analyses/initializer.py`
  (`http://<ip>`, portsuz), `analyses/nmap.sh` + `analyses/analyses_all.sh` (`sudo nmap <hedef>`; hedef `127.0.0.1`
  ise host taranır), `analyses/fuzzer/fuzzer.py` (nmap raporunu okur) ve `util/collect_result.py` DHCP desteği olmadan
  kalıyor; `run_mode.sh` artık bunlara DHCP'de ulaşmıyor ("ret ile kapatıldı"), ama doğrudan çağrılırlarsa hâlâ
  `127.0.0.1`'i = host'u hedefler.
- **AÇIK:** `firmae/pipeline.py` ~565: `"Network reachable on %s!"` mesajı DHCP'de `127.0.0.1` yazar; bu adres guest değil
  host'tur, mesaj yanıltıcıdır.
- DHCP'de `ping` = web kararı (ICMP iletilmez) korundu.

DHCP modunda erişim: `http://127.0.0.1:<host portu>` (`scratch/<IID>/hostfwd`). Bunun dışındaki kullanım doğrulanmadı.

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
| 4.2 | `firmae/qemu.py` → `run.<arch>.sh` üçü de `python3 -I <kurulum>/firmae/qemu.py initial <arch> <IID> <QEMU_INIT>` çağırır |
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
| 6.1 | `firmae/hwprofile.py` statik tarama + sınıflandırma + `hw_profile.json`; birim testleri sentetik rootfs ile. **Uygulandı ve iki firmware ile gerçek koşuda doğrulandı (2026-11-17)** (uygulama 2026-11-16; ölçümler: TEST_REPORT.md "Faz 6.1"): `firmae/pipeline.py` `hwprofile` adımını mimari tespitinden sonra, `hwprofile-dynamic` adımını `makeNetwork`'ten sonra çağırır; bilgi amaçlıdır, emülasyon sonucunu/çıkış kodunu etkilemez (`FIRMAE_HWPROFILE=0` ile kapanır). Boru hattı tarafı sahte CLI ile ve ayrıca gerçek `firmae.hwprofile` ile (sentetik tarball + kayıtlı seri log, `test_hwprofile_integration.py`) birim testli; gerçek QEMU koşusunda DIR-868L (ARM) ve WNAP320 (MIPS) ile denendi (iki tur, ağ-hatası yolu, Ctrl-C; sonuçlar ve `run.sh` profil adımından etkilenmedi). Bağımsız denetim (2026-11-17) bulguları (profilleyici bellek/özyineleme, yanlış pozitifler, zaman aşımı tutarsızlığı, bayat profil) düzeltildi — düzeltme sonrası ikinci bir bağımsız denetim yapılmadı (**açık**); ağ çıkarımı başarısızken de dinamik adım çalışır, eski profil statik adımdan önce silinir (SECURITY.md S26). **Açık maddeler:** sayaçların log başına ayrı raporlanması (şimdi ilk+son logun toplamı); ikinci bağımsız denetim; Python 3.8, analyze/debug/run/boot ve Docker modlarında doğrulama |
| 6.1b | **Seri log kanıtı** (`qemu.initial/final.serial.log` → `--update`): **uygulandı ve gerçek koşuda doğrulandı (2026-11-17)** |
| 6.2 | **Uygulandı, kullanıcı onaylı kapsam "komut satırı izi" (2026-11-17).** Ölçüm: analyze modu (`firmadyne.syscall=32`) `open`/`openat`/`ioctl` **kaydetmiyor**, yalnızca `execve` (`[ANALYZE] [PID: n (comm)]: argv`) ve `sys_reboot` kaydediyor. `firmae/hwserial.py` bu satırları `dynamic.exec` altına ayrıştırır (`commands`, `device_args`, `hw_tools`, `truncated`); `firmae/hwprofile.py` bunları kanıt olarak kullanır: yalnızca exec kanıtı → `referenced`; i2c/spi için yalnızca exec kanıtı → `unsupported`; asla `covered` yapmaz; `failing` ve statik sonuçları değiştirmez. Boru hattı değişmedi; elle ekleme: `python3 -m firmae.hwprofile --update --out scratch/<IID>/hw_profile.json --serial-log scratch/<IID>/qemu.initial.serial.log --serial-log scratch/<IID>/qemu.final.serial.log`. Komut satırı ≠ başarılı donanım erişimi. **Yapılmadı:** guest içi `strace` (seçenek B; `/firmadyne/strace` hâlâ çağrılmıyor). İki gerçek analyze logunda ölçüldü (TEST_REPORT.md "Faz 6.2 / 6.3 / 7"); gerçek emülasyon yeniden koşulmadı |
| 6.3 | **Asgari sürüm uygulandı:** `python3 -m firmae.hwreport [--scratch DIR] [--format md\|csv\|json] [--out FILE] [--force]` (`scratch/<IID>/` altını salt okunur tarar; bkz. `ARCHITECTURE.md` 9.2.1c, SECURITY.md S32). Birim testli; **gerçek bir firmware setinde (Faz 0 seti dahil) çalıştırılmadı**, dolayısıyla "hangi cihazlar `UNSUPPORTED`, emülasyon sonucu ile ilişkisi" sorusu gerçek veriyle yanıtlanmadı |
| 6.4 | **Karar noktası (ayrı onay):** veriler gerektiriyorsa `libhwmock` (I2C/SPI işlem seviyesi) — **açık.** Çapraz derleme toolchain kararı dahil; ayrıca `LD_PRELOAD`'ı bu depo değil hazır enstrümante kernel yüklüyor, ikinci bir preload kütüphanesi kernel değişikliği ya da başka bir yükleme yolu gerektirebilir. Gerçek bir libc interposer olmalı (statik ikililer ve doğrudan syscall'lar kapsanmaz). Keşifte I2C/SPI kullanan firmware bulunmadı; ihtiyaç gösterilmedi |
| 6.5 | **Yeni, açık:** her iki mimaride (ARM: `watchdog`, `wdt`; MIPS: `gpio`, `watchdog`, `wdt`) firmadyne kernel kancalarının `Cannot register character device` hatasının incelenmesi — kernel stub'larının gerçekte çalışıp çalışmadığı belirsiz |

## Faz 7 — Bağımlılıklar ve kurulum

Karar gerektirmeyen kısım uygulandı (kod + birim test; `install.sh` ve `core/Dockerfile` **çalıştırılmadı/derlenmedi**):

| Adım | Durum |
|---|---|
| 7.1 `delete.sh` psql parolası (`PGPASSWORD`), scraper `pipelines.py` parolası | TAMAM (S13) |
| 7.2 `install.sh`: kendi dizinine `cd`, binwalk alt kabukta ve yalnızca bu çalıştırmada indirildiyse temizlenir, PostgreSQL yeniden başlatması yapılandırma düzenlemelerinden sonra (+ `systemctl start docker`), `groupadd` korumalı, `tee --append` idempotent, PEP 668 algılayıp açıklamayla `exit 1` | TAMAM (kod, statik test; gerçek kurulum koşulmadı). `set -e`/`set -u` bilerek eklenmedi |
| 7.3 `analyses/initializer.py`: `--no-sandbox` yalnızca root veya `FIRMAE_CHROME_NO_SANDBOX=1` | TAMAM; S11 **açık** (hat root çalışıyor) |
| 7.4 `requirements.txt`: `pytest` çıkarıldı, kullanım yerine göre başlıklar; başka paket değişmedi | TAMAM |
| 7.5 `core/Dockerfile`: `apt-key` → `signed-by` keyring + `gnupg`, `chmod 755 /usr/bin/sudo` | TAMAM (kod; docker build çalıştırılmadı) |
| 7.6 `download.sh` doğrulama mekanizması + `binaries.sha256` (`FIRMAE_VERIFY_DOWNLOADS=warn\|strict`) | TAMAM (mekanizma); **hash'ler `UNKNOWN`** |

Karar/onay bekleyenler (Faz 6.4/6.5 de ayrıca onay bekler):
- `binaries.sha256` hash'lerini doldurmak (indirme gerekir) ve ardından varsayılanı `strict` yapmak; `install.sh`'in üç indirmesi (binwalk arşivi, Chrome `.deb`, chromedriver) için de aynısı.
- PEP 668: venv mi `--break-system-packages` mı (`install.sh` şimdilik durup soruyor). `sasquatch` + GCC 13 sorunu (Ubuntu 24.04) çözülmedi.
- `requirements.txt` kontrollü yükseltme (her paket ayrı, analiz modülleriyle test) ve S16.
- chromedriver 2.38'in kaldırılması (Selenium Manager'a geçiş).
- Docker tabanının `ubuntu:24.04`'e taşınması.
- S11: Chrome'u root olmayan kullanıcıyla çalıştırmak.

## Kapsam dışı (bilinçli)

- Kernel'in (`FirmAE_kernel-v*`) ve QEMU'nun değiştirilmesi/yeniden derlenmesi.
- `sources/scraper/` (analiz hattının parçası değil).
- routersploit submodule'ü (yalnızca çağrılış biçimi).
