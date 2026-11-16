# FirmAE Mimarisi — Mevcut Durum ve Önerilen Tasarım

> **Durum (2026-11-16 itibarıyla gerçek durum):** Bu belge Aşama 3'te yazılmış bir
> **tasarım önerisidir**; yalnızca küçük bir kısmı uygulandı. "Mevcut" bölümler 2026-11-04
> tarihli `master` (`653565b`) üzerindeki koda dayanır ve `refactor/hardening` dalında
> değişti (aşağıdaki "Gerçek durum" notları).
>
> - **Uygulandı:** `firmae/` paketi yalnızca şu modüllerle: `__main__.py`, `config.py`,
>   `errors.py`, `log.py`, `pipeline.py`, `state.py` (aşama orkestrasyonu, çıkış kodları,
>   loglama, `scratch/<IID>/*` dosyalarına erişim); `run.sh` ince sarmalayıcıdır;
>   `scripts/procgroup.py` ile süreç grubu sonlandırma; IID ve firmware kilidi (§6);
>   aşama zaman aşımları; soketler `scratch/<IID>/run/` altında; `restrict=on`, loopback
>   `hostfwd`; TAP modunda iptables/ip6tables yalıtımı.
> - **Hâlâ öneri (uygulanmadı):** `proc.py`, `resources.py` (ResourceStack + journal),
>   `signals.py`, `storage.py`, `qemu.py`, `network.py`, `metrics.py`, `hwprofile.py`,
>   `stages/*`; `QemuSpec` tek QEMU oluşturucu; `-pidfile`; `FIRMAE_MAX_PARALLEL` / slot
>   kilitleri; `systemd-run` kaynak sınırları; `ip netns` yalıtımı; peripheral emülasyonu
>   (§9); `tests/integration/`. Üretilen `scratch/<IID>/run.sh` hâlâ tam bir Bash
>   şablonudur (`makeNetwork.py` üretir), tek satırlık Python çağrısı değil.
> - Güvenlik ve test durumu: `SECURITY.md`, `TEST_REPORT.md`, `CHANGELOG.md`.
>
> Kararlar: tek kullanıcılı lab makinesi tehdit modeli, WSL2 (Ubuntu 24.04) test ortamı,
> hibrit Python geçişi (host tarafı Python, guest tarafı shell).

---

## 1. Mevcut mimari (özet)

```
run.sh ──source──> firmae.config  (ayarlar + 29 Bash fonksiyonu)
  ├─ sources/extractor/extractor.py   rootfs/kernel çıkarımı (binwalk, root)
  ├─ scripts/util.py, getArch.py, inferKernel.py, tar2db.py
  ├─ scripts/makeImage.sh             raw disk + losetup + mount + chroot yamaları
  ├─ scripts/makeNetwork.py           ön emülasyon → log parse → scratch/IID/run.sh ÜRETİR
  │     └─ scripts/run.<arch>.sh      ön emülasyon QEMU'su (3 kopya)
  │     └─ scripts/check_emulation.sh scratch/IID/run.sh & → ping/curl → ps|grep|kill
  └─ analyses/analyses_all.sh         initializer, nmap, fuzzer, routersploit
```

Temel özellikler ve sorunlar (ayrıntı: `SECURITY.md`, Aşama 1 raporu):

| Konu | Mevcut |
|---|---|
| Veri aktarımı | `scratch/IID/*` altındaki ~20 tek-satırlık dosya, şemasız |
| Süreç yönetimi | `&` ile arka plan, `ps aux \| grep qemu-system-<arch> \| kill` (tüm QEMU'lar) |
| Temizlik | `trap` yok; yalnızca "mutlu yol"da `umount`/`del_partition`/`STOP_NET` |
| Hata yönetimi | `return` → exit 0; `set -e` beklenmeyen hatada toplu işi keser; `2>&1 > file` stderr'i kaybeder |
| Loglama | renkli `echo`, zaman damgası/aşama/IID yok |
| QEMU komutu | 4 kopya (`run.armel.sh`, `run.mipseb.sh`, `run.mipsel.sh`, `makeNetwork.py` şablonu) |
| Test | yok |


> **Gerçek durum (bu tablo `master`'ı anlatır):** `refactor/hardening`'de süreç yönetimi `qemu_pids` (bu kurulumun `image.raw` yolu) + süreç grubu ile, temizlik `release_emulation` ve `trap` ile, hata kodları `firmae/errors.py` ile, loglama `firmae/log.py` ile değişti; QEMU komutu hâlâ 4 kopya, test yalnızca `tests/unit` (428 test).
---

## 2. Tasarım ilkeleri

1. **Davranışı koru, arayüzü koru.** `sudo ./run.sh -c|-a|-r|-d|-b <brand> <fw>` ve
   `docker-helper.py` komutları aynı kalır. `scratch/IID/` altındaki dosya adları
   (`ip`, `web`, `ping`, `result`, `time_*` …) korunur; `util/collect_result.py`
   değişmeden çalışmaya devam eder (not: `util/compare.py` ikinci turda kabuksuz yeniden yazıldı; çıktısı karşılaştırılmadı, doğrulanmadı).
2. **Guest tarafı shell kalır.** `preInit.sh`, `network.sh`, `run_service.sh`,
   `inferFile.sh`, `fixImage.sh`, `injectionChecker.sh` firmware içinde/chroot'ta busybox ile
   çalışır; Python'a taşınmaz.
3. **Yeni bağımlılık yok.** Host modülleri yalnızca Python stdlib + mevcut `psycopg2`
   kullanır. Kullanılan sistem araçları zaten kurulu olanlardır (`losetup`, `ip`, `mount`,
   `qemu-*`, `fdisk`/`sfdisk`, `mkfs.ext2`).
4. **Shell yok.** Tüm `subprocess` çağrıları argüman listesiyle, `shell=False`.
5. **Her edinilen kaynak, edinildiği anda kayda girer** ve hangi yoldan çıkılırsa çıkılsın
   (normal, hata, timeout, Ctrl-C, SIGTERM) ters sırada bırakılır.
6. **Desteklenmeyeni başarılı gösterme.** Ölçülemeyen/simüle edilemeyen her şey sonuçta açıkça
   işaretlenir.

---

## 3. Önerilen klasör yapısı

> **Gerçek durum:** bu ağaçtan yalnızca `firmae/{__main__,config,errors,log,pipeline,state}.py` var;
> geri kalan modüller ve `stages/` önerilmiştir, yazılmamıştır. `tests/` altında yalnızca `unit/` ve `fixtures/` var (`integration/` yok).

```
FirmAE/
├── run.sh                    # İNCE SARMALAYICI: argümanları `python3 -m firmae` 'ye iletir
├── firmae.config             # KORUNUR: kullanıcı ayarlarının tek kaynağı (FIRMAE_*, TIMEOUT)
├── firmae/                   # YENİ: host orkestrasyon paketi
│   ├── __main__.py           # CLI (run.sh ile birebir aynı argümanlar)
│   ├── config.py             # firmae.config'i okur → Config dataclass
│   ├── errors.py             # FirmAEError hiyerarşisi + exit code tablosu
│   ├── log.py                # merkezi logging (konsol + scratch/IID/firmae.log)
│   ├── proc.py               # süreç başlatma/izleme/sonlandırma (timeout, SIGTERM→SIGKILL)
│   ├── resources.py          # ResourceStack + diskteki kaynak günlüğü (journal)
│   ├── signals.py            # SIGINT/SIGTERM/SIGHUP → Cancelled istisnası
│   ├── state.py              # scratch/IID/* dosyalarına tipli erişim (aynı dosya adları)
│   ├── storage.py            # raw imaj, loop device, partition, mount
│   ├── qemu.py               # QemuSpec → argv (tek QEMU komut oluşturucu)
│   ├── network.py            # TAP/VLAN oluşturma-silme, user-net ayarları
│   ├── metrics.py            # RSS/CPU/fd/disk ölçümü → scratch/IID/metrics.json
│   ├── hwprofile.py          # donanım bağımlılık profilleyici (Problem 1)
│   └── stages/
│       ├── extract.py        # extractor.py çağrısı + IID
│       ├── arch.py           # getArch mantığı (güvenli tar okuma)
│       ├── image.py          # makeImage.sh'in host tarafı
│       ├── infer_network.py  # makeNetwork.py (saf parse fonksiyonları korunur)
│       ├── check.py          # check_emulation.sh
│       └── modes.py          # run / check / analyze / debug / boot
├── scripts/                  # guest/chroot script'leri burada KALIR; host script'leri
│                             # geçiş süresince sarmalayıcı olarak korunur
├── tests/                    # YENİ (bkz. §11)
└── ARCHITECTURE.md, SECURITY.md, REFACTORING_PLAN.md
```

Neden tek paket, neden bu kadar modül? Her modülün **tek sorumluluğu** var ve her biri
root gerektirmeden birim test edilebilir (dış komutlar `proc.py` üzerinden geçtiği için
testte sahte süreçle değiştirilebilir). Daha az modül sorumlulukları yeniden karıştırır;
daha fazlası (ör. ayrı servis, mesaj kuyruğu, veritabanı katmanı) bu proje için gereksiz
karmaşıklık olur.

---

## 4. Modüller arası iletişim

```
__main__ ─► config ─► modes.<mod>(ctx)
                         │
          AnalysisContext (IID, Config, logger, ResourceStack, StateDir)
                         │
   ┌──────────┬──────────┼────────────┬─────────────┬────────────┐
 extract     arch      image     infer_network     check      analyze
                         │            │               │
                      storage       qemu ◄── network  proc
                         └────────────┴───────────────┘
                                  resources (hepsi buraya kaydolur)
```

- Aşamalar birbirini çağırmaz; `modes.py` sırayla çağırır ve aralarına **yalnızca**
  `AnalysisContext` + `state.py` girer. Bugünkü örtük dosya trafiği aynen sürer ama
  okuma/yazma tek bir modülde ve tipli olur (`state.ip`, `state.web = True` …).
- Bir aşama başarısız olduğunda `FirmAEError(stage=..., code=...)` fırlatır; `modes.py` onu
  yakalar, `result` dosyasını bugünkü metinle yazar (`"extraction fail"` vb.) ve bir sonraki
  firmware'e geçer.

---

## 5. Süreç yaşam döngüsü (Problem 3)

> **Gerçek durum:** `proc.py`, `signals.py` ve `ResourceStack` yazılmadı. Karşılığı: `scripts/procgroup.py` (`run_with_timeout`: süreç grubu, SIGINT sonra SIGKILL; `raise_on_sigterm`), `firmae/pipeline.py` + `firmae/__main__.py` (aşama zaman aşımları, çıkış 130/143) ve `firmae.config` (`release_emulation`, `qemu_pids`). Aşağıdaki tablo ve kod bloğu tasarımdır.

`proc.py` tek giriş noktasıdır:

```
spawn(argv, stage, timeout, grace=10s)  ─►  ManagedProcess
    start_new_session=True   → kendi süreç grubu (PGID = PID)
    stdout/stderr            → scratch/IID/<stage>.log (ikisi birden)
    ResourceStack'e kaydolur

ManagedProcess.stop():
    killpg(PGID, SIGTERM) ─► grace kadar wait() ─► gerekirse killpg(PGID, SIGKILL) ─► wait()
    (wait() = zombie kalmaz; killpg = alt süreçler de durur; hiçbir zaman `ps | grep` yok)

run(argv, stage, timeout)  = spawn + wait(timeout) + stop() + exit code kontrolü
```

| Durum | Davranış |
|---|---|
| Normal bitiş | `wait()` ile toplanır, exit code loglanır |
| Timeout | SIGTERM → bekle → SIGKILL; `FirmAEError(TIMEOUT)` |
| QEMU beklenmedik kapanma | exit code + serial log'un son satırları loglanır |
| Ctrl-C / SIGTERM / SIGHUP | `signals.py` → `Cancelled` → ResourceStack ters sırada boşalır → exit 130/143 |
| Orkestratör SIGKILL ile ölürse | Python çalışamaz; **journal** (aşağıda) bir sonraki çalıştırmada temizlenir |

> **Gerçek durum:** `-pidfile` **uygulanmadı** (kodda yok). Bugün bu kurulumun QEMU'ları `firmae.config`'teki `qemu_pids` ile
> `/proc/<pid>/cmdline` içinde tam `scratch/<IID>/image.raw` yolu aranarak bulunur; süreç grubu `scripts/procgroup.py` ile durdurulur.

(Öneri, uygulanmadı) QEMU ayrıca `-pidfile scratch/IID/run/qemu.pid` ile başlatılır; böylece elle başlatılan
`scratch/IID/run.sh` de hedefli olarak durdurulabilir.

## 6. Kaynak yönetimi ve temizlik

> **Gerçek durum:** `resources.py`, journal (`resources.json`) ve `python3 -m firmae cleanup` **uygulanmadı**. Temizlik `release_emulation <IID>` (`firmae.config`, `delete.sh`) ile yapılır; kilitler alındıktan sonra eski kalıntılar bir kez temizlenir. Aşağısı tasarımdır.

`resources.py`:

```python
with ResourceStack(iid) as rs:                 # contextlib.ExitStack tabanlı
    loop = rs.acquire(LoopDevice(image))       # 1) diskteki journal'a yazılır
    mnt  = rs.acquire(Mount(loop.part1, dir))  # 2) sonra kaynak edinilir
    ...
# çıkışta: ters sıra, her release ayrı try içinde; hata LOGLANIR, yutulmaz,
# diğer kaynakların bırakılması devam eder; en sonda toplu hata raporu
```

| Kaynak türü | Edinme | Bırakma | Kimlik |
|---|---|---|---|
| `TempDir` | `tempfile.mkdtemp(dir=scratch/IID/tmp)` | `shutil.rmtree` | yol |
| `LoopDevice` | `losetup --find --show --partscan <img>` (cihaz adı doğrudan döner; "en yeni mapper" tahmini yok) | `losetup -d <dev>` | `/dev/loopN` + backing file |
| `Mount` | `mount <dev> <dir>` | `umount` (gerekirse `umount -l` + uyarı) | dizin |
| `TapInterface` / `Vlan` | `ip tuntap add … mode tap` / `ip link add … type vlan` | `ip link del` | arayüz adı |
| `ManagedProcess` | `proc.spawn` | `stop()` | PID/PGID + başlangıç zamanı |
| `UnixSocket` | QEMU | `unlink` | yol (`scratch/IID/run/`) |

**Journal** (`scratch/IID/run/resources.json`): edinmeden önce kayıt, bırakınca silme.
Aynı IID için yeni bir çalıştırma başlarken journal varsa önce **eski kaynakları temizler**
(TAP zaten var → bugünkü "sonraki tüm çalıştırmalar başarısız" zincirini kırar). Ayrıca
`python3 -m firmae cleanup <IID>` elle kurtarma sağlar. PID kaydında başlangıç zamanı da
tutulur; böylece PID yeniden kullanılmışsa yanlış süreç öldürülmez.

> **Gerçek durum (uygulandı, öneriden farklı):** `firmae/pipeline.py` iki `fcntl.flock` kilidi alır:
> `scratch/.locks/<firmware md5>.lock` ilk çıkarımdan ÖNCE (IID henüz bilinmiyor) ve
> `scratch/<IID>/.firmae.lock` IID bilindikten sonra. Alınamazsa çıkış kodu 75 (`BUSY`) ve hiçbir şeye dokunulmaz;
> kilitler alındıktan sonra o IID'nin eski kaynakları bir kez temizlenir. `scratch/IID/run/lock` ve
> `scratch/.slots/` **yoktur**; `FIRMAE_MAX_PARALLEL`/slot sınırı **uygulanmadı**; `.locks/*.lock` dosyaları birikir.
> Yer tutucu NIC soketleri loopback'te IID'ye göre ayrılır (`20000 + 4*(IID % 10000) + n`); `hostfwd` 80/443 sabit kalır (yalnızca 127.0.0.1).

(Öneri, uygulanmadı) **Eşzamanlılık:** her IID için `scratch/IID/run/lock` (`fcntl.flock`) → aynı firmware iki kez
paralel çalışamaz. Global eşzamanlılık sınırı `FIRMAE_MAX_PARALLEL` (varsayılan: CPU/2) ile
`scratch/.slots/` kilitleri üzerinden. Sabit portlar (2000-2003, hostfwd 80/443) kaldırılır
(bkz. §8).

**Kaynak sınırları:** `systemd-run --scope -p MemoryMax=… -p CPUQuota=…` mevcutsa QEMU
bunun içinde başlatılır; mevcut değilse sınır **uygulanmadığı loglanır** (sessizce
varsayılmaz). `metrics.py` her aşama sonunda QEMU RSS, CPU süresi, açık fd sayısı ve
`scratch/IID` disk kullanımını `metrics.json`'a yazar.

---

## 7. Merkezi hata yönetimi ve loglama

**Exit code tablosu** (`errors.py`):

| Kod | Anlam | Bugünkü `result` metni (korunur) |
|---|---|---|
| 0 | Başarılı (check modunda web erişilebilir) | `true` |
| 2 | Kullanım hatası | — |
| 3 | Root yetkisi yok / yapılandırma bulunamadı | — |
| 10 | Çıkarım başarısız | `extraction fail` |
| 11 | IID alınamadı (DB boş döndü) | — |
| 12 | Veritabanına ulaşılamadı / sorgu hatası | — |
| 20 | Mimari tespit edilemedi / desteklenmiyor | `get architecture fail` / `not valid architecture : X` |
| 30 | İmaj oluşturma başarısız | — (yeni) |
| 40 | Ağ çıkarımı başarısız | — (yeni) |
| 50 | Emülasyon erişilemez (web yok) | `false` |
| 60 | Analiz başarısız | — |
| 75 | Başka bir FirmAE çalıştırması bu firmware'i/imajı işliyor (`BUSY`, atlanır) | — |
| 124 | Timeout | — |
| 130 / 143 | Kullanıcı iptali (SIGINT) / SIGTERM | — |
| 1 | Beklenmeyen iç hata (traceback log dosyasında) | — |

Dizin (toplu) modunda her firmware bağımsızdır; bir firmware'in hatası diğerlerini durdurmaz.
Sürecin exit code'u, en az bir firmware başarısızsa sıfırdan farklıdır (**davranış
değişikliği**, bkz. `REFACTORING_PLAN.md`).

**Log formatı:**
```
2026-11-04T12:00:01.123 INFO  [iid=42][image] loop device /dev/loop7 attached
```
- Konsol: INFO ve üzeri (renkli çıktı korunabilir); dosya `scratch/IID/firmae.log`: DEBUG.
- Dış komutların stdout **ve** stderr'i aşama log dosyalarına gider (bugünkü
  `tar2db.log`, `makeImage.log`, `makeNetwork.log` adları korunur).
- Parola ve bağlantı dizesi loglanmaz.

---

## 8. QEMU ve ağ mimarisi

> **Gerçek durum:** `qemu.py`/`QemuSpec` yoktur; QEMU komutu hâlâ `scripts/run.<arch>.sh` (ön emülasyon) ve `makeNetwork.py` şablonunda (son emülasyon) ayrı ayrı üretilir. Tablonun "Mevcut" sütunu `master`'ı gösterir. `refactor/hardening`'de uygulananlar: soketler `scratch/IID/run/` altında (0700), `restrict=on`, `hostfwd` ve yer tutucu NIC'ler 127.0.0.1'de, TAP modunda iptables/ip6tables kuralları (netns yerine). Uygulanmayanlar: `ip tuntap` (üretilen `run.sh` hâlâ `tunctl` kullanır), dinamik `hostfwd` portları, `ip netns`. DHCP modu gerçek çalıştırmayla doğrulanmadı.

`qemu.py` tek bir `QemuSpec` → `argv` dönüştürücüsü sağlar; arch tabloları (makine, kernel,
disk, NIC modeli) `firmae.config`'teki `get_*` fonksiyonlarının birebir karşılığıdır.

| Ayar | Mevcut | Önerilen | Neden |
|---|---|---|---|
| Monitor/serial soketleri | `/tmp/qemu.IID[.S1]` | `scratch/IID/run/` (0700) + uyumluluk için `/tmp` symlink'i (1 sürüm) | tahmin edilebilir `/tmp` yolu |
| `-netdev user` | kısıtsız | `restrict=on` (dışarı çıkış yok) | güvenilmeyen firmware |
| `hostfwd` | `tcp::80-:80` (0.0.0.0) | `tcp:127.0.0.1:<boş port>-:80` | LAN'a açılma, port çakışması, yanlış pozitif |
| `-netdev socket,listen=:200x` | 0.0.0.0, sabit port | yer tutucu NIC'ler **korunur** (eth0–eth3 numaralandırması bozulmamalı); yalnızca backend `127.0.0.1` + boş porta bağlanır | çakışma/açılma |
| TAP | `sudo tunctl` | `ip tuntap` (iproute2), idempotent | uml-utilities bağımlılığı azalır |
| İzolasyon (Faz 5) | yok | analiz başına `ip netns` | paralel analiz + host izolasyonu |

> **Gerçek durum:** `scratch/IID/run.sh` hâlâ `makeNetwork.py`'nin ürettiği **tam Bash şablonudur** (QEMU komutu, TAP/mount/temizlik trap'i, 16 satırlık imaj dosyası denetim bloğu); tek satırlık Python çağrısı **uygulanmadı**.

(Öneri, uygulanmadı) `scratch/IID/run.sh` **üretilmeye devam eder** (kullanıcılar elle çalıştırıyor), ancak
içeriği tek satırlık bir çağrı olur: `exec python3 -m firmae emulate <IID> --mode "$(basename "$0")"`.
`run_debug.sh`, `run_analyze.sh`, `run_boot.sh` symlink'leri aynı kalır.

---

## 9. Peripheral emülasyon mimarisi (Problem 1)

### 9.1 Bugünkü katmanlar (doğrulanmış)

| Katman | Kapsam | Kaynak |
|---|---|---|
| QEMU yerleşik | UART (malta 16550; virt PL011 — FirmAE kernel'inde `ttyS`, major 4 / minor 64 olarak kayıtlı), IDE/virtio disk, e1000/virtio NIC, RTC | QEMU, `FirmAE_kernel-v4.1/drivers/tty/serial/amba-pl011.c` |
| Kernel `firmadyne` modülü (`devfs=1`) | 12 stub: `/dev/acos_nat_cli`, `brcmboard`, `dsl_cpe_api`, `gpio`, `nvram`, `pib`, `sc_led`, `tca0`, `ticfg`, `watchdog`, `wdt`, `zybtnio` — `open/write/ioctl` başarılı, `read` → `"0\0"` | `FirmAE_kernel-v4.1/drivers/firmadyne/devfs_stubs.c` (bu repoda değil) |
| Kernel `nandsim` | MTD (boş NAND) | `makeNetwork.py:85` |
| LD_PRELOAD `libnvram` | NVRAM key/value | `sources/libnvram` |
| Dosya tabanlı düğümler | `/dev/gpio/in`, `/dev/mtd*` düğümleri | `scripts/fixImage.sh` |
| **Yok** | I2C (`/dev/i2c-*`), SPI (`/dev/spidev*`), `gpiochip` (karakter cihaz API), vendor'a özgü diğer düğümler | — |

Kalan belirsizlik: ARM `virt` makinesinde ikinci UART (ttyS1 → `/tmp/qemu.IID.S1`) olup
olmadığı — WSL2'de dinamik test ile doğrulanacak.

### 9.2 Önerilen yaklaşım: önce ölç, sonra yalnızca gerekeni taklit et

```
            ┌─────────────── hwprofile.py ────────────────┐
 rootfs ──► │ statik: ELF'lerde "/dev/..." dizgileri,      │
            │         .ko listesi, init script'lerinde      │──► scratch/IID/hw_profile.json
 guest  ──► │ dinamik (profil modu): web servisi            │
            │         /firmadyne/strace -f -e open,ioctl    │
            └──────────────────────────────────────────────┘
                              │ her cihaz için sınıf:
     covered:kernel-stub | covered:nandsim | covered:libnvram | covered:file-node |
     covered:qemu | UNSUPPORTED (+ erişen binary, hata kodu)
```

- **Statik analiz firmware kodunu çalıştırmaz** (yalnızca bayt okuma).
- Dinamik kısım repoda zaten bulunan `strace` binary'sini kullanır (`firmae.config:25`);
  yeni bağımlılık yok. Yalnızca ayrı bir "profil" modunda çalışır; normal analizi
  yavaşlatmaz.
- Sonuç raporu her `UNSUPPORTED` cihazı açıkça listeler; emülasyon "başarılı" olsa bile.

**Taklit (mock) katmanları — veri gerektirirse, bu sırayla:**

1. *Dosya tabanlı düğüm* (mevcut desen, en ucuz): yalnızca `read` bekleyen basit
   kullanımlar.
2. *`libhwmock` (LD_PRELOAD, libnvram ile aynı desen):* `/dev/i2c-*` için `I2C_SLAVE`,
   `I2C_RDWR`, `I2C_SMBUS`; `/dev/spidev*` için `SPI_IOC_MESSAGE(n)`, `SPI_IOC_RD/WR_*`;
   tablo dosyasından (`/firmadyne/hwmock/*.conf`) yanıt. **Seviye: işlem (transaction)
   seviyesi**, register seviyesi değil.
   *Risk:* firmware'ler eski uClibc/glibc sürümleriyle derlenmiş; `libnvram`'ı üreten
   çapraz derleme zinciri repoda yok. Bu katmana ancak profil verisi gerekliliği gösterirse
   ve uyumlu toolchain kararı alındıktan sonra geçilir.
3. *Kernel stub listesini genişletme veya QEMU cihaz modeli:* ayrı kernel/QEMU reposunda
   değişiklik ve yeniden derleme gerektirir — kapsam dışı, yalnızca belgelenmiş ihtiyaçla.

### 9.3 Gerçek donanım ile mock farkları (her mock için belgelenecek)

| Gerçek donanım | Mock |
|---|---|
| Sensör/EEPROM gerçek değerler döndürür | Sabit/tablo değerleri |
| Bus hataları (NACK, timeout) olabilir | Her işlem başarılı (yapılandırılmadıkça) |
| Kesmeler (IRQ), zamanlama | Yok |
| Kernel sürücüsü (`.ko`) yüklenir | Yüklenmez (jenerik kernel, vermagic) |
| Yazılan değer donanımı etkiler | Yazma yutulur (`devfs_stubs` ile aynı) |

---

## 10. Mevcut ve önerilen mimarinin karşılaştırılması

| Konu | Mevcut | Önerilen |
|---|---|---|
| Orkestrasyon dili | Bash + Python (Bash üreten şablonlar) | Python paketi; guest tarafı shell |
| Ayar kaynağı | `firmae.config` (ayar + kod) | `firmae.config` (yalnızca ayar olarak okunur) |
| QEMU komutu | 4 kopya | 1 oluşturucu |
| Süreç sonlandırma | `ps \| grep \| kill` | PGID + SIGTERM→SIGKILL + `wait()` |
| Temizlik | yalnızca mutlu yol | ExitStack + journal, her çıkış yolunda |
| Hata kodu | her zaman 0 | aşama başına anlamlı kod |
| Log | dağınık `echo` | zaman/IID/aşama/seviye, tek dosya + aşama logları |
| Eşzamanlılık | çakışan portlar, global kill | IID kilidi, slot sınırı, dinamik port, netns |
| Peripheral | ölçüm yok | profil → sınıflandırma → hedefli mock |
| Test | yok | birim + root gerektiren entegrasyon (WSL2) |

---

## 11. Test mimarisi

```
tests/
├── conftest.py              # fixture'lar; root/QEMU yoksa ilgili testleri SKIP (açık nedenle)
├── fixtures/
│   ├── fake_qemu.py         # SIGTERM'i yok sayan / hemen çöken / log yazan sahte QEMU
│   ├── serial_logs/         # gerçek initial serial log örnekleri (parse testleri)
│   └── tarballs/            # path traversal, symlink, bozuk tar örnekleri (bellekte üretilir)
├── unit/                    # root gerekmez
│   ├── test_network_parse.py   # findPorts, findNonLoInterfaces, checkNetwork …
│   ├── test_qemu_argv.py       # mevcut run.<arch>.sh komutlarıyla birebir eşitlik
│   ├── test_proc.py            # timeout, SIGTERM→SIGKILL, zombie yok, süreç grubu
│   ├── test_resources.py       # ters sıra, hata altında temizlik, journal kurtarma
│   └── test_security.py        # dosya adı enjeksiyonu, tar traversal regresyonları
└── integration/             # @pytest.mark.root — WSL2'de sudo ile
    ├── test_image_lifecycle.py # loop/mount sayısı önce = sonra (normal/hata/SIGINT)
    ├── test_network_lifecycle.py
    └── test_emulation_smoke.py # gerçek firmware + binaries/ gerekir
```

Kaynak sızıntısı doğrulaması her entegrasyon testinde aynı yöntemle yapılır: test öncesi ve
sonrası `losetup -a`, `ip -o link`, `findmnt`, `/proc` altındaki alt süreçler, açık fd sayısı
ve `scratch/IID/tmp` karşılaştırılır; fark sıfır olmalıdır.
