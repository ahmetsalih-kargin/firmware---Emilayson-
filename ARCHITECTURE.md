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
>   (§9); `tests/integration/`. Faz 4.3–4.5 asgari kapsamda uygulandı: `firmae/image.py`
>   (makeImage host tarafı), `firmae/check.py` + `procutil.py` + `hostfwd.py`
>   (emülasyon denetimi), `scratch/<IID>/emulation.conf` + statik `scripts/emulate.sh`
>   (üretilen `run.sh` sabit sarmalayıcıdır; Bash kodu üretilmez). Tam Python başlatıcı
>   ve yerel loop/mount/`tarfile` yapılmadı.
> - **Grup 4 (2026-11-18):** Docker modu `ubuntu:24.04` üzerinde ve `--privileged`'sız; opt-in çıkarım ve Chrome kullanıcıları (`firmae/extractuser.py`, `analyses/browser_user.sh`); bkz. §12.
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
  ├─ scripts/makeImage.sh             ince sarmalayıcı → firmae/image.py (raw disk + losetup + mount + chroot yamaları; aynı dış araçlar)
  ├─ scripts/makeNetwork.py           ön emülasyon → log parse → scratch/IID/emulation.conf + sabit run.sh YAZAR
  │     └─ scripts/run.<arch>.sh      ön emülasyon QEMU'su (ince sarmalayıcı → firmae/qemu.py)
  │     └─ scripts/emulate.sh         scratch/IID/run.sh'nin exec ettiği statik betik (emulation.conf'u okur)
  │     └─ scripts/check_emulation.sh ince sarmalayıcı → firmae/check.py: scratch/IID/run.sh & → ping/curl → sonlandırma
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
│       ├── image.py          # makeImage.sh'in host tarafı (4.3: asgari kapsamda firmae/image.py olarak uygulandı)
│       ├── infer_network.py  # makeNetwork.py (saf parse fonksiyonları korunur)
│       ├── check.py          # check_emulation.sh (4.5: firmae/check.py olarak uygulandı)
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
> Yer tutucu NIC soketleri loopback'te IID'ye göre ayrılır (`20000 + 4*(IID % 10000) + n`); DHCP/user-net modunda `hostfwd` host portları artık dinamiktir (aşağıdaki "Durum" paragrafı ve §8).

(Öneri, uygulanmadı) **Eşzamanlılık:** her IID için `scratch/IID/run/lock` (`fcntl.flock`) → aynı firmware iki kez
paralel çalışamaz. Global eşzamanlılık sınırı `FIRMAE_MAX_PARALLEL` (varsayılan: CPU/2) ile
`scratch/.slots/` kilitleri üzerinden. Sabit portlar (2000-2003, hostfwd 80/443) kaldırılır
(bkz. §8). **Durum: kısmen.** Slot/`FIRMAE_MAX_PARALLEL` hâlâ yok. Sabit hostfwd portları kaldırıldı (kod + birim test; gerçek DHCP koşusu yok): host portları `127.0.0.1`'de 10000-19999 aralığından, IID başına 40'lık bloktan (`hostfwdBlock(IID)` * 40'tan başlayarak, IID'nin tamamı kullanılır: 250'nin katı kadar farklı IID aynı bloğa düşmez; blok 80, 443 ve en çok 32 ek port için yeter), her biri bind edilerek boşluğu sınanarak seçilir (`makeNetwork.py` `chooseHostPorts`). Eşleme `scratch/<IID>/hostfwd` dosyasına, satır başına `<tcp|udp> <guest portu> <host portu>` biçiminde, symlink izlenmeden yazılır; `check_emulation.sh` onu katı doğrular. Yer tutucu NIC soketleri 20000-59999 aralığındadır, hostfwd aralığıyla çakışmaz. Boşluk sınaması ile QEMU'nun bind'i arasında yarış (TOCTOU) **kabul edilmiştir**: üretilen `run.sh` TCP portlarını QEMU'dan önce yeniden sınar, port o arada alınmışsa QEMU zaten başlamaz. Çoklu NIC: hostfwd yalnız NIC yerleşimi bittikten sonra gerçekten yerleşmiş, DHCP IP'li tek user NIC'e verilir (`qemuNetworkConfigAndHostfwd`; aynı host portu iki kez iletilemez). `scratch/<IID>/hostfwd` o kurallardan değil, üretilen `run.sh`'nin `-netdev` satırlarından geri okunarak yazılır (`hostfwdRulesIn`): dosya varsa kurallar QEMU argümanlarında da vardır. Web denetimi (`scripts/hostfwd_check.sh`, `check_emulation.sh` ve `run_mode.sh` ortak): her denemeden önce emülasyonun yaşadığı (`qemu_pids`, `run.sh` pid'i, zombi denetimi) ve başarılı yanıttan sonra portun sahibinin bu IID'nin QEMU'su olduğu (`ss -Htlnp`) doğrulanır; `ss` yoksa ya da pid okunamıyorsa güvenli tarafta `web=false` + uyarı. slirp dinleyicisinin `ss -p`'de QEMU pid'iyle göründüğü gerçek QEMU ile **doğrulanmadı**.

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

> **Gerçek durum (Faz 4.2, 2026-11-17):** `firmae/qemu.py` vardır ama `QemuSpec` yoktur: yalnızca **ilk (ön) emülasyonu** (`build_initial_argv`, `main`; `python3 -I <kurulum>/firmae/qemu.py initial <arch> <IID> <QEMU_INIT>`) ve ortak yardımcıları (arch tabloları, kernel yolu, çekirdek komut satırı, soket tabanı) içerir; `scripts/run.<arch>.sh` üçü ince sarmalayıcıdır (kurulum kökü betiğin ağacından bulunur; `-I` ile cwd ve `PYTHON*` değişkenleri modül arama yoluna girmez, `qemu.py` kurulum kökünü `sys.path`'in SONUNA ekler, yani kullanıcı `PYTHONPATH` ile `firmae`'yi yönlendiremez; `exec python3 -I ...`, sonra `os.execvpe` ile QEMU süreci yerine geçer; arada kabuk/Python süreci kalmaz). **Son emülasyon (4.4) artık Bash üretmez: `makeNetwork.py` `emulation.conf` yazar, statik `scripts/emulate.sh` okuyup QEMU'yu çalıştırır**; QEMU komutu hâlâ iki yerde kurulur (ön emülasyon için `qemu.py`, son emülasyon için `emulate.sh`). Altın argv testi ve gerçek QEMU durumu: `TEST_REPORT.md`. Tablonun "Mevcut" sütunu `master`'ı gösterir. `refactor/hardening`'de uygulananlar: soketler `scratch/IID/run/` altında (0700), `restrict=on`, `hostfwd` ve yer tutucu NIC'ler 127.0.0.1'de, TAP modunda iptables/ip6tables kuralları (netns yerine). Dinamik `hostfwd` host portları da uygulandı (kod + birim test, DHCP gerçek koşusu yok). Uygulanmayanlar: `ip tuntap` (üretilen `run.sh` hâlâ `tunctl` kullanır), `ip netns`. DHCP modu gerçek çalıştırmayla doğrulanmadı.

`qemu.py` tek bir `QemuSpec` → `argv` dönüştürücüsü sağlar; arch tabloları (makine, kernel,
disk, NIC modeli) `firmae.config`'teki `get_*` fonksiyonlarının birebir karşılığıdır.

| Ayar | Mevcut | Önerilen | Neden |
|---|---|---|---|
| Monitor/serial soketleri | `/tmp/qemu.IID[.S1]` | `scratch/IID/run/` (0700) + uyumluluk için `/tmp` symlink'i (1 sürüm) | tahmin edilebilir `/tmp` yolu |
| `-netdev user` | kısıtsız | `restrict=on` (dışarı çıkış yok) | güvenilmeyen firmware |
| `hostfwd` | `tcp::80-:80` (0.0.0.0) | `tcp:127.0.0.1:<boş port>-:80` (**uygulandı**: 10000-19999, bkz. §7 "Durum") | LAN'a açılma, port çakışması, yanlış pozitif |
| `-netdev socket,listen=:200x` | 0.0.0.0, sabit port | yer tutucu NIC'ler **korunur** (eth0–eth3 numaralandırması bozulmamalı); yalnızca backend `127.0.0.1` + boş porta bağlanır | çakışma/açılma |
| TAP | `sudo tunctl` | `ip tuntap` (iproute2), idempotent | uml-utilities bağımlılığı azalır |
| İzolasyon (Faz 5) | yok | analiz başına `ip netns` | paralel analiz + host izolasyonu |

> **Gerçek durum (Faz 4.3–4.5, asgari kapsam, 2026-11-17 gerçek emülasyonla ölçüldü):**
>
> - **`run.sh` ve `emulation.conf` (4.4).** `makeNetwork.py` artık Bash üretmez. `scratch/<IID>/run.sh` sabit bir sarmalayıcıdır (bayt bayt `tests/fixtures/generated/run_sh_wrapper.expected`); statik `scripts/emulate.sh`'yi `exec` eder, yani emülasyonun pid'i `check_emulation`/`run_mode.sh`'nin başlattığı pid olarak kalır (araya süreç girmez). İmaja bağlı her şey `scratch/<IID>/emulation.conf` içindedir: `KEY=value` satırları `FORMAT`, `IID`, `ARCH`, `ENDIAN`, `NETWORK_TYPE`, `NET_BRIDGE`, `NET_INTERFACE`, `QEMU_INIT`, `GEN_FIRMAE_NET` ve tekrarlanabilen `NET=`, `NIC=`, `HOSTFWD=` kayıtları. Dosya seri logdan türeyen değerler taşıdığı ve betik root çalıştığı için **asla `source`/`eval` edilmez**: Python (yazarken ve okurken) ve Bash (`emulate.sh`) aynı katı dilbilgisiyle satırları açık karakter listeleriyle doğrular, değerler hep tırnaklı genişletilir; ayrıştırılamayan dosya hiçbir şeye dokunulmadan çıkış 1 ile durdurulur. `run.sh`/`emulation.conf` yazılırken symlink hedefleri reddedilir. Tam Python başlatıcı (seçenek B) **yapılmadı**.
> - **`check_emulation` (4.5).** `scripts/check_emulation.sh` ince sarmalayıcıdır; süreç olarak `firmae/check.py` çalışır (artık arada bir `check_emulation.sh` bash'i kalmaz). Süreç yardımcıları `firmae/procutil.py`, DHCP web denetimi `firmae/hostfwd.py`. Bash `check_network`/`qemu_pids`/`hostfwd_check.sh` `run_mode.sh` için korunur; Python ile eşdeğerlik `tests/unit/test_check_py.py` ile sabitlenmiştir. Durum dosyaları `O_NOFOLLOW`/`O_EXCL` ile yazılır, başlangıçta eski `ping`/`time_ping`/`ip`/`web`/`time_web` silinir.
> - **`makeImage` (4.3).** `scripts/makeImage.sh` ince sarmalayıcıdır; iş `firmae/image.py` içindedir ve aynı dış araçları (losetup, kpartx, mkfs, mount, tar, chroot) çağırır; yerel loop/mount/`tarfile` (seçenek B) **yapılmadı**. Her dış komut kendi **koruma süreç grubunda** (ek bir `/bin/sh` bekçisi; stdin `/dev/null`, `PR_SET_PDEATHSIG`) çalışır; ebeveyn SIGKILL ile ölürse chroot/tar çocukları yetim kalmaz. Temizlik bütçesi en çok **47 sn** (umount 10 sn, sonra `umount -l`, ...) ve boru hattının `STAGE_GRACE = 60` sn'sinin altında kalır (`test_cleanup_fits_in_the_pipeline_grace`). Host tarafı yazmalar (`init`, `service`, `/firmadyne/*`, `/bin/a`) `resolve_in_root` + `O_NOFOLLOW`/`O_EXCL` ile fd tabanlı yapılır.

**Port keşfi (`findPorts`, Faz 2.10):** seri logdaki `inet_bind` satırları iki biçimde okunur: gerçek 4.1 çekirdek biçimi (`inet_bind[PID: n (ad)]: proto:SOCK_X, port:N`; adres loglanmaz, `0.0.0.0` varsayılır) ve eski biçim (`ip:port: 0x<adres>:<port>`). Port 0 (çekirdek seçer) ve >= 32768 (geçici/ephemeral aralık) atılır; (proto, port) çiftine göre tekrarlar elenir, ilk bind sırası korunur; en çok `MAX_PORTS=256`. `hostfwd` için ayrıca 80/443 çıkarılır ve en çok `MAX_FORWARD_PORTS=32` ek port iletilir.

(Kısmen uygulandı, bkz. yukarıdaki "Gerçek durum") `scratch/IID/run.sh` **üretilmeye devam eder** (kullanıcılar elle çalıştırıyor); içeriği artık sabit bir sarmalayıcıdır ve `scripts/emulate.sh`'yi çağırır. Öneri olarak kalan: tek satırlık `exec python3 -m firmae emulate <IID> --mode "$(basename "$0")"` çağrısı (tam Python başlatıcı).
`run_debug.sh`, `run_analyze.sh`, `run_boot.sh` symlink'leri aynı kalır.

---

## 9. Peripheral emülasyon mimarisi (Problem 1)

### 9.1 Bugünkü katmanlar (doğrulanmış)

| Katman | Kapsam | Kaynak |
|---|---|---|
| QEMU yerleşik | UART (malta 16550; virt PL011 — FirmAE kernel'inde `ttyS`, major 4 / minor 64 olarak kayıtlı), IDE/virtio disk, e1000/virtio NIC, RTC | QEMU, `FirmAE_kernel-v4.1/drivers/tty/serial/amba-pl011.c` |
| Kernel `firmadyne` modülü (`devfs=1`) | 12 stub: `/dev/acos_nat_cli`, `brcmboard`, `dsl_cpe_api`, `gpio`, `nvram`, `pib`, `sc_led`, `tca0`, `ticfg`, `watchdog`, `wdt`, `zybtnio` — `open/write/ioctl` başarılı, `read` → `"0\0"` | `FirmAE_kernel-v4.1/drivers/firmadyne/devfs_stubs.c` (bu repoda değil) |
| Kernel `nandsim` | MTD (boş NAND) | `nandsim.parts=...` kernel komut satırı, `scripts/makeNetwork.py` (`qemuCmd`) ve `scripts/emulate.sh` (eski `run.sh` şablonu 4.4'te `emulate.sh`'ye taşındı) |
| `libnvram` (LD_PRELOAD ile yüklenir) | NVRAM key/value. **libc `open`/`ioctl` çağrılarını YAKALAMAZ**: firmware'in kendi nvram API sembollerinin (`nvram_get`, `nvram_set`, ... ve `alias.c`'deki takma adlar) yerine geçer. Bu yüzden `/dev/nvram` açmaya çalışan bir ikili bu kütüphaneden etkilenmez | `sources/libnvram/nvram.c`, `alias.c` |
| Dosya tabanlı düğümler | `/dev/gpio/in`, `/dev/mtd*` düğümleri | `scripts/fixImage.sh` |
| **Yok** | I2C (`/dev/i2c-*`), SPI (`/dev/spidev*`), `gpiochip` (karakter cihaz API), vendor'a özgü diğer düğümler | — |

**LD_PRELOAD'ı bu depo yüklemez.** `libnvram.so`'yu `LD_PRELOAD` ile yükleyen, indirilen
hazır **enstrümante kernel**'dir (`init/main.c` değişikliği; `sources/libnvram/README.md:48-49`).
Bu repoda o kodu değiştirmek mümkün değil; dolayısıyla ikinci bir preload kütüphanesi
(`libhwmock`, bkz. 9.2) kernel değişikliği ya da başka bir yükleme yolu (ör. imajdaki
`/etc/ld.so.preload`, init sarmalayıcısı) gerektirebilir; hangisinin çalıştığı **denenmedi**.

**Kullanılmayan bileşen:** `strace` ikilileri `firmae.config:28` (`BINARIES`) üzerinden
`makeImage.sh` tarafından imaja `/firmadyne/strace` olarak kopyalanır, ancak depodaki hiçbir
script onu çağırmaz (`grep` ile doğrulandı; yalnızca `download.sh` indirir). Dinamik izleme
için hazır bir altyapı yoktur; yalnızca ikili hazırdır.

Kalan belirsizlik: ARM `virt` makinesinde ikinci UART (ttyS1 → `/tmp/qemu.IID.S1`) olup
olmadığı — WSL2'de dinamik test ile doğrulanacak.

### 9.2 Donanım profili: önce ölç, sonra yalnızca gerekeni taklit et

> **Durum (2026-11-17):** 9.2.1 (statik profil + seri log kanıtı) `firmae/hwprofile.py`,
> `firmae/hwserial.py` (profil üreticisi ve seri log ayrıştırıcısı) ile `firmae/pipeline.py`
> (boru hattı bağlantısı) üzerinden eklendi ve **iki firmware (DIR-868L ARM, WNAP320 MIPS) ile
> gerçek emülasyon koşusunda doğrulandı** (ölçümler: TEST_REPORT.md "Faz 6.1"). Doğrulanmayanlar:
> Python 3.10/3.11 çalışma zamanı (3.8 artık desteklenmiyor, bkz. §12), ikinci bağımsız denetim, analyze/debug/run/boot ve Docker modları, daha geniş
> firmware seti. Komut satırı izi (9.2.1b) ve asgari toplu rapor (9.2.1c) birim testli eklendi (iki gerçek analyze logunda ölçüldü; rapor gerçek sette çalıştırılmadı). Guest içi strace ile dinamik izleme ve `libhwmock` (9.2.3) **yapılmadı.**

#### 9.2.1 Profil akışı (uygulandı, iki firmware ile gerçek koşuda doğrulandı)

```
 images/IID.tar.gz ──► [1] statik tarama (hwprofile --tar)      ┐
   (diske açılmaz)         /dev/..., .ko, ioctl/bus dizgileri    │
                                                                 ├─► scratch/IID/hw_profile.json
 qemu.initial.serial.log ┐                                       │
 qemu.final.serial.log   ┴► [2] seri log kanıtı                  │
   (makeNetwork sonrası)      (hwprofile --update --serial-log)  ┘
                                                  özet: "[hw] gpio=failing ..." (tek satır)
```

`firmae/pipeline.py` iki adım ekler; ikisi de **yalnızca bilgi amaçlıdır**:

1. **`hwprofile`** (`_hwprofile_static`): mimari tespitinden sonra, `tar2db`/`makeImage`'den
   önce: `python3 -m firmae.hwprofile --tar images/<IID>.tar.gz --out scratch/<IID>/hw_profile.json
   --timeout <iç süre>`. Tarball taranır (üye adları yol olarak kullanılmaz, dosya diske açılmaz).
   Adımdan **önce** önceki koşudan kalan `hw_profile.json` silinir (yalnızca düzenli dosya ya da
   symlink'in kendisi; hedefine dokunulmaz). Adım 0 dönmezse (hata/zaman aşımı) dinamik adım ve
   özet bu koşuda atlanır: bayat bir profil güncellenmez ya da özetlenmez.
2. **`hwprofile-dynamic`** (`_hwprofile_dynamic`): `makeNetwork.py` bittikten sonra:
   `... --update --out ... --serial-log qemu.initial.serial.log --serial-log qemu.final.serial.log`.
   Yalnızca var olan loglar verilir; hiçbiri yoksa ya da statik adım başarılı değilse adım atlanır.
   `--update` statik bölümü korur, yalnızca seri log (dinamik) bölümünü yeniler.
   **Ağ çıkarımı başarısız ya da zaman aşımına uğradıysa da çalışır** (tanı değeri en yüksek
   olan `qemu.initial.serial.log` o durumda da vardır): `run_firmware`'ın `finally` bloğunda,
   `release_emulation`'dan **sonra** (QEMU durmuştur, log nihaidir; `release_emulation` seri
   logları silmez, yalnızca `run/*.sock` ve `/tmp/qemu.*` dosyalarını), ama imaj kilidi hâlâ
   tutulurken. Asıl çıkış kodu/hata mesajı aynen korunur. Yalnızca `FirmAEError` yolunda
   çalışır: Ctrl-C/SIGTERM'de ek iş yapılmaz.

Ortak kurallar:

- **Profil emülasyon sonucunu etkilemez.** CLI'nin başarısızlığı, zaman aşımı ya da
  `firmae.hwprofile` modülünün bulunmaması koşuyu durdurmaz, çıkış kodunu değiştirmez; yalnızca
  bir `[*]` uyarı satırı ve `scratch/<IID>/hwprofile.log` kalır. Yalnızca `Exception` yakalanır;
  `KeyboardInterrupt` ve SIGTERM'den gelen `SystemExit` yutulmaz (süreç grubunu
  `scripts.procgroup.run_with_timeout` durdurur).
- `FIRMAE_HWPROFILE=0` iki adımı kapatır (varsayılan açık). `FIRMAE_TIMEOUT_HWPROFILE`
  (varsayılan 300 sn, 0 = sınırsız) dış zaman aşımıdır; CLI'ye `--timeout` olarak dış sınırın
  %80'i (en az 1 sn) verilir, böylece süreç öldürülmeden kısmi sonucu yazabilir. Dış sınır 0
  (sınırsız) ise `--timeout 240` geçirilir: profil adımı hiçbir zaman süresiz kalmaz. Tüm
  `FIRMAE_TIMEOUT_*` değerleri için üst sınır 7 gündür; geçersiz (ya da 12'den çok anlamlı
  haneli) değer "ayarlanmamış" sayılır, işlenmemiş istisna oluşmaz. CLI'nin kendi bellek
  sınırı `--mem-limit-mb` (varsayılanı CLI içindedir; boru hattı geçirmez).
- Check modunda önceki başarılı sonuç yüzünden emülasyon atlanıyorsa mevcut profil dosyasına
  dokunulmaz; `web` zaten başarılıysa (emülasyon yeniden yapılmıyorsa) adımlar çalışmaz.
- Koşu sonunda profil okunabiliyorsa **tek satır** özet basılır (`[hw] gpio=failing
  watchdog=failing nvram=covered i2c=not-referenced ... (scratch/<IID>/hw_profile.json)`);
  `unsupported`/`failing` önce yazılır. Dosya güvenilmez sayılır (`O_NOFOLLOW`, en çok 8 MiB;
  CLI profili ≤ 2 MiB ile sınırlar): yalnızca bilinen anahtarlar ve bilinen `status` değerleri
  basılır. Sınır aşılırsa ya da JSON/yapı bozuksa satır sessizce kaybolmaz; sabit metinli
  `[hw] profil okunamadı (scratch/<IID>/hw_profile.json)` uyarısı basılır (dosyadan gelen hiçbir
  dize basılmaz).

**Şema özeti** (`hw_profile.json`, CLI sözleşmesi): üst anahtarlar `schema`, `static`, `dynamic`,
`peripherals`, `notes`; `dynamic.modules` (seri logda görülen modül bilgisi) eklendi. `peripherals` altında `i2c`, `spi`, `gpio`, `watchdog`, `led`, `mtd`,
`nvram`, `uart`, `wlan`, `other` anahtarlarının her biri `{status, evidence}` taşır.

**Yorum notları** (gerçek koşulardan; TEST_REPORT.md "Faz 6.1" D):

- Dinamik sayaçlar, ilk ve son emülasyonun seri loglarının **toplamıdır**; tek koşudaki olay
  sayısı değildir (log başına ayrı raporlama henüz yok).
- `nvram` ve `mtd` FirmAE'nin kendi mekanizması olan sınıflardır; yine de çalışma zamanında
  hata görüldüğü için `failing` olabilirler. Bu emülasyonun başarısız olduğu anlamına gelmez:
  iki firmware'de de `result`/`ping`/`web` = true idi.

**`status` sözlüğü**

| status | Anlamı |
|---|---|
| `not-referenced` | Firmware içinde bu sınıfa ait iz bulunmadı |
| `referenced` | İz var (dizge, `.ko`, düğüm); çalışma zamanında sorun görülmedi ya da hiç gözlenmedi |
| `failing` | Seri logda açma/ioctl/kayıt hatası görüldü (ör. `No such device`, `Cannot register character device`) |
| `covered` | Mevcut katmanlardan biri (kernel stub, nandsim, libnvram, dosya düğümü, QEMU) karşılıyor |
| `unsupported` | Kullanılıyor ama bu mimaride karşılayan katman yok |

**Kural: `unsupported` hiçbir zaman başarılı gösterilmez.** Emülasyon "başarılı" (web
erişilebilir) olsa bile profil bu durumu açıkça listeler; özet satırı da `unsupported`
ve `failing` değerlerini öne alır. Profil bir uyarıdır, emülasyonun başarı ölçütü değildir ve
tersi de geçerlidir: `covered` olması cihazın doğru davrandığı anlamına gelmez (kernel
stub'ları her `open/write/ioctl`'i başarılı sayar).

#### 9.2.1b Komut satırı izi: `dynamic.exec` (6.2, uygulandı)

Ölçüm (2026-11-17, iki gerçek analyze logu): analyze modu (`firmadyne.syscall=32`) `open`/`openat`/`ioctl`
**kaydetmez**; yalnızca `execve` (`[ANALYZE] [PID: n (comm)]: argv`) ve `sys_reboot` izi bırakır.
`firmae/hwserial.py` bu satırları (bağlantılı, doğrusal zamanlı ifadeyle) `dynamic.exec` altına ayrıştırır:
`commands` (en çok 200 ayrı komut adı), `device_args` (en çok 200 yol, yol başına en çok 3 komut adı),
`hw_tools` (i2c/spi/flash araçları) ve `truncated` (kernel satırı kesmiş olabilir). Satır başına en çok 64 belirteç.

`firmae/hwprofile.py` bunları şu kurallarla kanıt sayar: yalnızca exec kanıtı olan çevre birimi `referenced`;
i2c/spi için yalnızca exec kanıtı varsa `unsupported`; exec kanıtı hiçbir zaman `covered` yapmaz; `failing` ve statik
sonuçları değiştirmez. Boru hattı değişmedi; analyze logu elle eklenir (`python3 -m firmae.hwprofile --update --out
scratch/<IID>/hw_profile.json --serial-log scratch/<IID>/qemu.initial.serial.log --serial-log
scratch/<IID>/qemu.final.serial.log`). Guest yalnızca sahte `[ANALYZE]` satırlarıyla kanıt **ekleyebilir**.

**Uyarı: komut satırı ≠ başarılı donanım erişimi.** Bir komutun argümanında `/dev/mtd5` geçmesi cihazın açıldığını
ya da çalıştığını göstermez. Exec satırlarının içindeki hata metni bilerek genel olay olarak sayılmaz (bir komut
satırındaki "error" kelimesi yanlış pozitif üretiyordu).

#### 9.2.1c Toplu rapor (hwreport, 6.3, asgari; gerçek sette çalıştırılmadı)

`python3 -m firmae.hwreport [--scratch DIR] [--format md|csv|json] [--out FILE] [--force]`, `scratch/<IID>/` altında
önceki koşuların bıraktığını salt okunur tarar: `brand`, `name`, mimari, `ping`, `web`, `result` ve `hw_profile.json`.
Firmware başına ve toplamda her çevre biriminin durumunu ve emülasyon sonucuyla ilişkisini verir; `unsupported` ve
`failing` adlarıyla listelenir, hiçbir zaman başarı sayılmaz (`referenced` = "görüldü", "çalışıyor" değil).

*Güven modeli:* `scratch/<IID>/` altındaki her girdi güvenilmezdir. Yalnızca kanonik pozitif tamsayı adlı dizinler
gezilir; dosyalar dizin tanıtıcısına göre `dir_fd` + `O_NOFOLLOW` ile açılır, `S_ISREG` olmalı ve boyut sınırıyla
okunur (tek satırlık dosyalar 4 KiB, profil 2 MiB); mantıksal değerler tam `true` olmalı; mimari ve durumlar sabit
beyaz listelerden gelir; serbest metin yalnızca `brand`/`name`'dir, temizlenir (yazdırılabilir ASCII, uzunluk sınırı)
ve biçime göre kaçışlanır (CSV formül önekleri, Markdown üst karakterleri, satır sonu yok). Sınırlar: en çok 100000
IID, tarama başına 1M girdi. `--out` `O_EXCL|O_NOFOLLOW` ile oluşturulur; var olan yol `--force` olmadan reddedilir;
symlink, hardlink'li dosya, FIFO ve dizine hiçbir koşulda yazılmaz. Çıkış kodu 0 (bozuk/eksik profiller dahil),
kullanım hatası veya okunamayan scratch kökünde 2.

#### 9.2.2 Keşif bulguları (ölçüm; yalnızca iki firmware)

Örneklem dardır: **D-Link DIR-868L (ARM)** ve **Netgear WNAP320 (MIPS)**. WNAP320'nin rootfs'i
taranamadı; yalnızca dosya listesi ve seri log incelendi. Gözlemler:

- İki firmware'de de `/dev/i2c*`, `/dev/spidev*`, `I2C_RDWR`/`SPI_IOC` izi ve I2C/SPI `.ko`
  dosyası **yok**; yani bu iki örnek için I2C/SPI mock'u bir ihtiyaç göstermedi (genelleme yapılamaz).
- DIR-868L seri logunda ~147 kez `/dev/nvram: No such device` (libnvram libc `open`'ı
  yakalamadığı için; bkz. 9.1).
- WNAP320: watchdog açma hatası 3 kez (`sys-watchdog.ko` var, aygıt düğümü yok), `/dev/led` ve
  `/dev/sys-reset`, `panel-led-driver.ko`.
- Her iki mimaride firmadyne kernel kancaları `Cannot register character device` basıyor
  (ARM: `watchdog`, `wdt`; MIPS: `gpio`, `watchdog`, `wdt`). Nedeni **araştırılmadı**.
- WLAN ioctl `No such device` en gürültülü kaynak (kapsam dışı).
- WSL'de çapraz derleyici yok (`libhwmock` için engel, bkz. 9.2.3).

#### 9.2.3 Yapılmayanlar / öneri (uygulanmadı)

- *Guest içi dinamik izleme:* `/firmadyne/strace -f -e open,ioctl` ile web servisini izlemek (6.2 seçenek B)
  **yapılmadı**. İkili imajda var ama hiçbir yerde çağrılmıyor (bkz. 9.1). Yalnızca komut satırı izi
  uygulandı (9.2.1b); o `open`/`ioctl` görmez.
- Statik analiz firmware kodunu **çalıştırmaz** (yalnızca bayt okuma).

**Taklit (mock) katmanları — veri gerektirirse, bu sırayla:**

1. *Dosya tabanlı düğüm* (mevcut desen, en ucuz): yalnızca `read` bekleyen basit
   kullanımlar.
2. *`libhwmock`:* `/dev/i2c-*` için `I2C_SLAVE`, `I2C_RDWR`, `I2C_SMBUS`; `/dev/spidev*` için
   `SPI_IOC_MESSAGE(n)`, `SPI_IOC_RD/WR_*`; tablo dosyasından (`/firmadyne/hwmock/*.conf`) yanıt.
   **Seviye: işlem (transaction) seviyesi**, register seviyesi değil.
   *Önemli:* `libnvram`'dan farklı olarak bu kütüphane firmware'in kendi sembollerinin yerine
   geçmez; libc'nin `open`/`ioctl`/`read`/`write` çağrılarını **gerçekten araya girerek (libc
   interposer)** yakalamak zorundadır. **Statik bağlı ikililer ve doğrudan syscall yapanlar
   kapsanmaz.** Yüklenmesi de açık bir sorudur: `LD_PRELOAD`'ı hazır kernel ayarlıyor (bkz. 9.1),
   ikinci bir kütüphane kernel değişikliği ya da başka bir yükleme yolu gerektirebilir.
   *Risk:* firmware'ler eski uClibc/glibc sürümleriyle derlenmiş; `libnvram`'ı üreten
   çapraz derleme zinciri repoda yok, WSL'de de yok. Bu katmana ancak profil verisi gerekliliği
   gösterirse ve toolchain ile yükleme yolu kararı alındıktan sonra (ayrı onayla) geçilir.
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

---

## 12. Docker modu, daraltılmış loop yönetimi ve ayrıcalık ayrımı (grup 4, uygulandı; 2026-11-18)

Ölçümler: `TEST_REPORT.md` "Grup 4". **Python ≥ 3.10** gerekir (requirements; 3.8 desteği kaldırıldı).

### 12.1 Docker modu

- İmaj `core/Dockerfile` ile `ubuntu:24.04` tabanından üretilir (`fcore:24.04`, 5,12 GB). İmaj tek kullanımlıktır: `PIP_BREAK_SYSTEM_PACKAGES=1`, sabit sürümlü kurulumlar (`--ignore-installed`), apt `binwalk` 2.3.4+dfsg1, sabit commit'ten (`bd864a1b…`) derlenen `sasquatch` (`-Werror` kaldırıldı, `-fcommon`, squashfs4.3 tarball'ı SHA-256 ile doğrulanır), sabit `python-lzo` 1.15 / `cstruct` 6.2 / `ubi_reader` 0.8.16 / `jefferson` 0.4.8, `fdisk`; derleme sırasında import ve duman testleri çalışır.
- Windows/WSL: Docker Desktop'ın ilgili WSL dağıtımı için entegrasyonu açık olmalıdır (Ubuntu için açıldı; ayar dosyasının yedeği tutuldu).
- `docker-helper.py` varsayılan olarak **daraltılmış** bayraklarla çalıştırır: `--cap-add SYS_ADMIN --cap-add NET_ADMIN --device /dev/loop-control --device /dev/net/tun --device-cgroup-rule 'b 7:* rmw'`. `--privileged` ve `-v /dev:/dev` yok; `FIRMAE_DOCKER_PRIVILEGED=1` eski bayrakları geri getirir. AppArmor etkin daemon daraltılmış modu, `FIRMAE_DOCKER_APPARMOR=unconfined` verilmedikçe reddeder (doğrulanmadı: AppArmor'lu yerel Ubuntu).
- Veritabanı portu `FIRMAE_DB_PORT` ile verilir (varsayılan libpq varsayılanı/`PGPORT`).
- Başarısız boru hattı `docker exec pgrep` ile algılanır (eskiden 2400 sn beklenirdi). `stop_core`, `docker stop` öncesinde kayıtlı loop aygıtlarını serbest bırakır (yalnızca daraltılmış modda; ayrıcalıklı modda yok).

### 12.2 Daraltılmış modda loop yönetimi

`b 259:*` cihaz kuralı denetimde NVMe disklerini (259:0) konteynere açtığı için **kaldırıldı**. `--partscan` bölüm düğümleri (`/dev/loopNpM`, major 259) gerektirdiğinden daraltılmış modda kullanılmaz: imaj, `sfdisk` dökümü **katı doğrulandıktan** sonra her bölüm için `losetup --offset --sizelimit` ile bağlanır (yalnızca `b 7:*`). Bu, host'un tüm loop aygıtlarını konteynere açık bırakır (kalan risk). Ayrıcalıklı modda eski `--partscan` yolu geçerlidir.

### 12.3 Çıkarım kullanıcısı akışı (opt-in: `FIRMAE_EXTRACT_USER`)

1. Pipeline (root) çalışma alanını root tarafında oluşturur (`FIRMAE_EXTRACT_TMP`), genel `flock` alır ve çıkarım kullanıcısının süreçlerini uid-kill ile temizler.
2. Çıkarıcı `setpriv --no-new-privs` ve `unshare --pid --fork --kill-child` içinde ayrıcalıksız kullanıcı olarak çalışır.
3. Çıktı adlarını root belirler; yayın `os.link` ile yapılır (varolanın üzerine yazılmaz); tar, root sahipliğine normalleştirilir.
4. Sonrasında tekrar uid-kill ve çalışma alanı temizliği.

Varsayılan kapalıdır: ayrıcalıksız çıkarım aygıt düğümlerini, setgid bitlerini ve symlink mtime'larını kaybeder (rakamlar: SECURITY.md S9). `FIRMAE_CREATE_USERS=1` ile `install.sh` kullanıcıları oluşturur. Kalan risk: DB kimlik bilgisi taşıyan ele geçirilmiş çıkarıcı root'un henüz yayımlanmamış bir id altında yayımlamasını sağlayabilir.

### 12.4 Tarayıcı kullanıcısı akışı (opt-in: `FIRMAE_BROWSER_USER`)

`analyses/analyses_all.sh`, tarayıcı adımını `analyses/browser_user.sh` ile çalıştırır: `setsid --wait`, stdin `/dev/null`, kendi kilidi ve uid-kill; `FIRMAE_BROWSER_TMP` çalışma alanıdır. `analyses/initializer.py` yalnızca root iken ya da `FIRMAE_CHROME_NO_SANDBOX=1` ile `--no-sandbox` ekler. **Chrome'un kendisi doğrulanmadı** (kurulu değildi).
