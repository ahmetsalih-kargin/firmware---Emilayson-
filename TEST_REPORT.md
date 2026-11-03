# FirmAE Test Raporu

## Faz 0 — Değişiklik öncesi temel çizgi (2026-11-04)

> Bu bölüm **hiçbir kod değişikliği yapılmadan**, `master` `653565b` üzerinde ölçülmüştür.
> Sonraki fazlardaki iyileştirmeler bu sayılarla karşılaştırılacaktır.

### Ortam

| | |
|---|---|
| Host | Windows 11 + WSL2, Ubuntu 24.04.4, kernel 6.6.87.2, 16 CPU, 7,5 GB RAM |
| QEMU | 8.2.2 (Ubuntu paketi) |
| PostgreSQL | 16 — `127.0.0.1` + parola; `install.sh`'deki `trust` satırı (SECURITY.md S4) **bilinçli olarak eklenmedi** |
| Python | 3.12.3 |
| Kurulum | `install.sh` yerine Ubuntu deposu paketleri (sistem geneli `pip install` Ubuntu 24.04'te PEP 668 nedeniyle reddedilir). `sasquatch` sonradan kaynaktan derlendi (binwalk `deps.sh` yöntemi + PR #51 yaması; GCC 13 için ayrıca `-Werror` kaldırıldı). `jefferson`, `ubi_reader` **kurulu değil** |
| Proje kopyası | `~/FirmAE` (WSL dosya sistemi), binary'ler `download.sh` ile |
| Ölçüm düzeneği | `~/firmae-phase0/{baseline.sh,snapshot.sh}` — repoya eklenmedi; FirmAE dosyalarına dokunmaz |

Firmware örnekleri:

| Ad | Mimari | SHA-256 |
|---|---|---|
| `DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip` (README örneği) | armel | `43fa0196…2675263` |
| `WNAP320_V2.0.3.zip` (Netgear) | mipseb | `4c169735…2b9e06a` |

Her senaryodan önce ve sonra şunlar sayıldı: FirmAE'ye ait loop device'lar, mount noktaları,
`tapN_M` arayüzleri, `qemu-system-*` süreçleri, sistemdeki zombie süreçler, `/tmp/qemu.*`
soketleri ve `/tmp` geçici dizinleri. Bellek ve fd kullanımı 5 sn aralıkla örneklendi.

### Sonuçlar

| Senaryo | Sonuç | Süre | exit | Sonrasında kalan kaynak |
|---|---|---|---|---|
| **A** Normal, ARM | ✅ ağ + web erişilebilir (`192.168.0.1`) | 452 sn | 0 | **yok** |
| **B** Normal, MIPS | ✅ ağ + web erişilebilir (`192.168.0.100`) | 434 sn | 0 | **yok** |
| B (ilk deneme, `sasquatch` yokken) | ❌ `extraction fail` | 8 sn | **0** | yok |
| **C** Ön emülasyon sırasında Ctrl-C (süreç grubuna SIGINT) | `run.sh` 60 sn sonra **hâlâ çalışıyor** | — | — | **QEMU=1, /tmp soket=2** (90 sn sonra) |
| **G** C'den sonra sıfırlamadan tekrar | ❌ `qemu-img: Failed to get "write" lock` | 1 sn | 1 | QEMU=1 (C'den) |
| **D** Ön emülasyon sırasında yalnızca `run.sh`'a SIGTERM | `run.sh` hemen öldü | — | — | **QEMU=1, /tmp soket=2** (30 sn sonra) |
| **E** ARM + MIPS paralel | ARM ✅ / MIPS ✅ | 475 / 457 sn | 0 / 0 | yok |
| **F** Rastgele 4 MB dosya | ❌ `extraction fail` | 2 sn | **0** | yok |
| **F** Kesilmiş zip (6 MB) | ❌ `extraction fail` | 163 sn | **0** | yok |

Zombie süreç hiçbir senaryoda gözlenmedi (sistem genelinde sayıldı).

**Aşama süreleri:**

| Aşama | A (ARM) | B (MIPS) |
|---|---|---|
| Çıkarım | 17,1 sn | 12,7 sn |
| Mimari | 0,5 sn | 0,3 sn |
| tar2db | 1,4 sn | 0,8 sn |
| İmaj | 9,1 sn | 16,2 sn |
| **Ağ çıkarımı + kontrol** | **423,1 sn (%94)** | **403,8 sn (%93)** |

**Kaynak kullanımı (5 sn örnekleme, en yüksek değer):**

| Senaryo | Eşzamanlı QEMU | Toplam QEMU RSS | QEMU fd | 1 dk yük ort. |
|---|---|---|---|---|
| A (ARM) | 1 | ~520 MB | 20 | — |
| B (MIPS) | 1 | ~468 MB | 15 | 0,64 |
| E (paralel) | 2 | ~988 MB | 33 | 1,10 |

Paralel çalıştırma süreyi yalnızca %3–5 uzattı (ARM 452 → 475 sn); 16 çekirdekli bu ortamda
darboğaz CPU değil, ağ çıkarımındaki sabit bekleme süreleri (`TIMEOUT=360`, `sleep` çağrıları).

**Yanlış süreç öldürme (ölçüldü, iki biçimde):**
- A sırasında adı `qemu-system-arm-SENTINEL` olan zararsız, ilgisiz bir süreç FirmAE
  tarafından **öldürüldü**.
- B (mipseb) sırasında adı `qemu-system-mipsel-SENTINEL` olan süreç de **öldürüldü**:
  `grep qemu-system-mips` kalıbı `qemu-system-mipsel` ile de eşleşiyor. Yani bir mipseb
  analizi, paralel çalışan mipsel analizlerini de sonlandırır.
- Kaynak: `scripts/check_emulation.sh:56` (`kill $(ps aux | grep $(get_qemu …) …)`).
- E'de ARM ve MIPS farklı kalıplarla eşleştiği için birbirini etkilemedi; iki **aynı
  mimari** firmware'in paralel çalıştırılması bu nedenle güvenli değildir.

### Statik analizle karşılaştırma

| Statik bulgu | Ölçüm |
|---|---|
| `ps \| grep \| kill` ilgisiz süreçleri öldürür | **Doğrulandı**, kapsamı beklenenden geniş: mipseb, mipsel süreçlerini de öldürüyor |
| Hata durumunda exit 0 | **Doğrulandı** (ilk B denemesi ve F: hepsi başarısız, hepsi exit 0) |
| Ctrl-C / sinyalde temizlik yok | **Doğrulandı**. Ayrıca beklenenden ağır: Ctrl-C QEMU'yu hiç durdurmuyor; `run.sh` dahil süreç grubu SIGKILL ile öldürülse de QEMU yaşamaya devam ediyor (QEMU, `timeout`'un kendi açtığı süreç grubunda) |
| Sızıntı sonraki çalıştırmayı bozar | **Doğrulandı**, fakat mekanizma farklı: tahmin TAP sızıntısıydı; ölçülen, sızan QEMU'nun `image.raw` yazma kilidini tutması |
| `/tmp/qemu.*` soketleri hiç silinmez | **Düzeltme:** normal çıkışta QEMU soketleri kendisi siliyor (A, E: 0). Sızıntı yalnızca anormal sonlanmada (C, D: 2) |
| Normal yolda loop/mount/TAP temizliği | Normal yolda **sızıntı yok** (A, E) |

### Yeni bulgular (statik analizde yoktu)

1. **Python 3.12 uyarıları:** `scripts/makeNetwork.py:136,153,178,207,228,229,250` →
   `SyntaxWarning: invalid escape sequence '\['`. Desenler raw string (`rb"..."`) değil;
   ileriki Python sürümlerinde hataya dönüşecek.
2. **Ubuntu 24.04 uyumsuzluğu:** `install.sh` sistem geneline `pip install` yapıyor; Ubuntu
   24.04 bunu PEP 668 ile reddediyor (README Ubuntu 20.04'ü hedefliyor).
3. Bozuk girdi (kesilmiş zip) çıkarımda 163 sn harcıyor; çıkarım `timeout 300` ile sınırlı.
4. `sasquatch` olmadan MIPS (WNAP320) çıkarımı sessizce başarısız oluyor; binwalk yalnızca
   `WARNING` basıyor, kullanıcıya eksik aracın adı söylenmiyor (yalnızca "Extracting root
   filesystem failed!"). Ayrıca `sasquatch` GCC 13 ile `-Werror` yüzünden derlenmiyor —
   `install.sh` → binwalk `deps.sh` yolu Ubuntu 24.04'te bu adımda da kırık.

### Ölçülemeyenler / sınırlamalar

- mipsel firmware örneği yok; mipsel yolu yalnızca dolaylı (sentinel) olarak test edildi.
- İki **aynı mimari** firmware'in paralel çalıştırılması (beklenen: biri diğerinin QEMU'sunu
  öldürür) ayrıca çalıştırılmadı; mekanizma sentinel testleriyle gösterildi.
- Analiz modu (`-a`) ölçülmedi: `routersploit` submodule'ü başlatılmamış, Chrome/Selenium kurulu değil.
- TAP/loop sızıntısı yalnızca ön emülasyon sırasında kesilerek test edildi. Final emülasyon
  (TAP oluşturulduktan sonra) sırasında kesme senaryosu henüz yok.
- Yetim süreç sayacı yalnızca PPID=1'e bakıyor. WSL'de sahipsiz süreçler WSL `/init`'ine
  bağlandığı için bu sayaç **eksik sayabilir**. QEMU sayacı bu açığı kapatıyor.
- Senaryolar birer kez çalıştırıldı; süreler tek ölçümdür.
- ARM `virt`'te ikinci UART (`/tmp/qemu.IID.S1`) çalışıyor mu sorusu bu senaryolarla
  yanıtlanmadı (debug modu gerekiyor).

---

## Faz 1 — Güvenlik ağı: karakterizasyon testleri (2026-11-04)

> FirmAE'nin hiçbir mevcut dosyası değiştirilmedi. Yalnızca yeni dosyalar eklendi:
> `pytest.ini`, `requirements-dev.txt`, `tests/` (conftest, 3 test modülü, fixture'lar).

### Çalıştırma

```bash
sudo apt install python3-pytest      # Ubuntu 24.04: pytest 7.4.4
python3 -m pytest                    # Linux/WSL, LF satır sonlu bir checkout'ta
```

`linux` işaretli testler bash script'lerini çalıştırır. Bu yüzden Windows'ta veya CRLF ile
checkout edilmiş bir kopyada nedeni yazılarak SKIP edilir.

### Kapsam

| Modül | Test | Kilitlenen davranış |
|---|---|---|
| `tests/unit/test_network_parse.py` | 36 | `makeNetwork.py` log ayrıştırıcıları (gerçek ARM/MIPS log'ları + sentetik satırlar), `checkNetwork`'ün 8 dalının hepsi, `FIRMAE_NET=false` yolu, yardımcı fonksiyonlar |
| `tests/unit/test_qemu_cmd.py` | 9 | **Uçtan uca:** gerçek seri log → ayrıştırıcılar → `qemuCmd()` çıktısı, Faz 0'da gerçekten üretilen `run.sh` ile **bayt bayt aynı** (ARM ve MIPS). NIC/hostfwd/TAP/VLAN parçaları, desteklenmeyen mimariler |
| `tests/unit/test_config_and_initial_qemu.py` | 9 | `firmae.config` mimari tabloları; 3 `run.<arch>.sh` için QEMU'nun tam argv'si (QEMU başlatılmaz, PATH'teki bir stub argv'yi kaydeder) |

Bilinen hatalar testlerde `KNOWN BUG` / `KNOWN ISSUE` olarak işaretlendi. Böylece hata
düzeltildiğinde test bilinçli olarak, aynı commit içinde güncellenecek.

### Sonuçlar

| Ortam | Sonuç |
|---|---|
| WSL2 Ubuntu 24.04, Python 3.12.3, pytest 7.4.4, kullanıcı (root değil) | **54 geçti, 0 başarısız, 0 atlandı** (0,22 sn) |
| Windows | **Çalıştırılmadı** (Windows'ta pytest kurulu değil) |

**Testlerin hata yakalayabildiğinin kontrolü (mutasyon):** WSL kopyasında koda bilinçli
bozulmalar eklenip test takımı çalıştırıldı. Her denemeden sonra kopya `git checkout` ile
geri alındı.

| Bozulma | Sonuç |
|---|---|
| Final QEMU belleği `-m 1024` → `-m 512` (`makeNetwork.py`) | 2 test başarısız ✅ |
| armel makinesi `virt` → `versatilepb` (`firmae.config`) | 2 test başarısız ✅ |
| `convertToHostIp` `-= 1` → `+= 1` | 2 test başarısız ✅ |
| `run.mipsel.sh` `-m 256` → `-m 128` | 1 test başarısız ✅ |

### Faz 1'de ortaya çıkan yeni bulgular

1. **Port keşfi gerçek kernel'lerle hiç çalışmıyor (ölçüldü).** FirmAE 4.1 kernel'leri
   `inet_bind[...]: proto:SOCK_STREAM, port:80` yazıyor. `findPorts()` ise eski
   `ip:port: 0x<ip>:<port>` biçimini bekliyor. İki firmware de onlarca port açmasına
   (80, 443, 22, 161, 8181, 49152, …) rağmen sonuç her seferinde boş liste. Etkisi: DHCP
   modunda yalnızca sabit kodlanmış 80/443 yönlendiriliyor; diğer servislere hostfwd
   oluşmuyor. (`scripts/makeNetwork.py:167-191`)
2. `run.mipseb.sh` NIC kimliklerini `net1…net4`, `run.mipsel.sh` `net0…net3` kullanıyor.
   Kopyalanmış script'ler birbirinden ayrışmış (zararsız).
3. Windows checkout'u (`core.autocrlf=true`, `.gitattributes` yok) tüm script'leri CRLF ile
   yazıyor. Bu dizin Docker'a veya bir Linux makinesine bağlanırsa bash script'leri çalışmaz.

### ShellCheck raporu (yalnızca rapor, düzeltme yapılmadı)

ShellCheck 0.9.0. Host script'leri `-s bash -x` ile, guest script'leri `-s sh` ile
(busybox ash) tarandı.

| Grup | Toplam | Öne çıkanlar |
|---|---|---|
| Host (17 dosya) | 379 | SC2086 tırnaksız değişken ×249 · SC2006 eski `` `…` `` ×60 · SC2034 kullanılmayan değişken ×14 · SC2046 tırnaksız `$(…)` ×12 (`kill $(ps … )` dahil) · **SC2069 `2>&1 > file` yönlendirme sırası ×6** (stderr'in log'a yazılmaması bulgusunu bağımsız olarak doğruluyor) · SC2164 `cd` hatası kontrol edilmiyor ×2 · **1 error:** SC2145 `scripts/check_emulation.sh:42` |
| Guest (6 dosya) | 103 | Çoğu POSIX dışı ama busybox ash'in desteklediği yapılar (SC3037 `echo -n/-e` ×21, SC3030 dizi ×5) — guest'te sorun değil; SC2086 ×40 |

Dosya başına (host, `-x` ile kaynak edilen `firmae.config` sayıları `run.sh`'a da yansır):
`run.sh` 147 · `check_emulation.sh` 32 · `firmae.config` 32 · `analyses_all.sh` 32 ·
`makeImage.sh` 27 · `delete.sh` 23 · `run.<arch>.sh` 16'şar.

### Sınırlamalar

- Testler yalnızca **saf mantığı ve üretilen komutları** kilitliyor. Root gerektiren
  yollar (`makeImage.sh`, loop/mount/TAP, gerçek QEMU) Faz 1'de test edilmedi; bunlar
  Faz 3'teki entegrasyon testlerinin konusu. O zamana kadar referans Faz 0 ölçümleri.
- Analiz modülleri (`analyses/`), `extractor.py`, `tar2db.py`, `getArch.py` için henüz test yok.
- Fixture'lar tek bir ARM ve tek bir mipseb firmware'den geliyor; mipsel örneği yok.

---

## Faz 2 — Güvenlik ve işlevsel düzeltmeler (2026-11-04)

> Değişikliklerin listesi ve davranış değişiklikleri: `CHANGELOG.md`. Kod `653565b`
> üzerine **commit edilmemiş** Faz 2 değişiklikleriyle test edildi.

### Birim testleri

WSL2 Ubuntu 24.04, Python 3.12.3, pytest 7.4.4, root değil, `-W error::SyntaxWarning`:
**106 geçti, 0 başarısız, 0 atlandı.** Faz 1'in 54 karakterizasyon testi değişmeden
geçiyor. Faz 2 için 52 yeni test eklendi:

| Modül | Test | Doğrulanan |
|---|---|---|
| `test_fwscan.py` | 14 | `a;touch PWNED;cgi` adlı dosya taranınca komut çalışmıyor. Ağaç dışına giden symlink okunmuyor. FIFO takılmaya yol açmıyor. Zararsız bir ağaçta sonuçlar eski `strings\|grep -P\|sort\|uniq`, `find`, `egrep -ril` pipeline'larıyla **aynı** (eşdeğerlik testleri) |
| `test_getarch.py` | 11 | Gerçek `file` ile mipseb/mipsel/armel tespiti. Symlink ve dizin atlanıyor, hard link okunuyor. `../` ve mutlak yollu üyeler diske hiçbir şey yazmıyor, geçici dizin her durumda siliniyor. Sayısal olmayan IID reddediliyor |
| `test_imagepath.py` | 9 | `bin -> <host dizini>` imajın içine çözülüyor. `..` kökte duruyor. Symlink döngüsü hata veriyor. Komut satırı arayüzü |
| `test_workdir_perms.py` | 2 | `777` izinli eski dizin ve dosyalar `755`/`644` oluyor, sahiplik `scratch/`'a göre. `a+rwx` tekrar eklenemiyor |
| `test_docker_helper.py` | 4 | Hiçbir docker çağrısı shell kullanmıyor. Gerçek bash'te `$(touch PWNED)` içeren firmware adı çalıştırılmıyor |
| `test_nmap_sh.py` | 3 | Hedef IP argümandan veya `scratch/<IID>/ip`'den alınıyor, XML `analysis_log/nmap_log.txt`'ye yazılıyor (sahte `nmap` ile) |
| `test_cleanup_scripts.py` | 2 | `delete.sh` yalnızca `/scratch/1/` süreçlerine dokunuyor ve tüm `tap1_*` arayüzlerini (önce VLAN'ları) siliyor. `cleanup.sh` yalnızca `fcore` konteynerlerine ve `scratch/<IID>` imajlarına dokunuyor (sistem komutları sahte) |
| `test_firmae_dir.py` | 3 | `analyses/` dizininden kaynak edildiğinde de `SCRATCH_DIR` doğru; Docker modu değişmedi |
| `test_run_logged.py` | 4 | stdout ve stderr log'a gidiyor. Hatada log'un sonu basılıyor ve aynı çıkış koduyla duruluyor. Ters yönlendirme tekrar eklenemiyor |

Ek kontroller: tüm Python dosyaları (`scraper/` hariç) uyarılar hata sayılarak
derlendi, uyarı yok. Değişen bash script'leri `bash -n` kontrolünden geçti.

### Gerçek emülasyon (regresyon)

Faz 0'ın A ve B senaryoları, Faz 2 koduyla root olarak tekrar çalıştırıldı:

| | Faz 0 | Faz 2 |
|---|---|---|
| A — DIR-868L (armel) | ✅ web, 452 sn | ✅ web, 459 sn |
| B — WNAP320 (mipseb) | ✅ web, 434 sn | ✅ web, 416 sn |
| Üretilen `scratch/1/run.sh` | — | A ve B'de **Faz 0 ile birebir aynı** |
| ip / web / ping / mimari / init | — | A ve B'de Faz 0 ile aynı |
| Sonrasında kalan kaynak | 0 | 0 |
| `scratch/` altında başkalarının yazabildiği dosya | tümü (`777`) | **0**, dizin modu `755` |
| `makeImage.log` / `emulation.log` boyutu (A) | 2033 / 262 bayt | 2087 / 321 bayt (stderr artık log'da) |

### Test edilmeyenler / kalan riskler

- **Analiz modu (`-a`) çalıştırılmadı:** `routersploit`, Chrome/Selenium ve `bs4` kurulu
  değil. `fuzzer.py`'nin yeni tarama kodu yalnızca `fwscan` birim testleriyle ve
  eşdeğerlik testleriyle doğrulandı. Fuzzer'ın kendisi ve gerçek `nmap` taraması uçtan
  uca çalıştırılmadı.
- **`docker-helper.py`** gerçek Docker ile çalıştırılmadı (`fcore` imajı oluşturulmadı);
  yalnızca üretilen argv'ler test edildi.
- **`install.sh`** çalıştırılmadı. Yeni `pg_hba.conf` satırı gerçek bir konteynerden
  bağlanılarak doğrulanmadı.
- **`delete.sh` / `cleanup.sh`** gerçek süreç, mount ve loop'lara karşı değil, sahte
  komutlarla test edildi.
- Symlink saldırısı (S5) çözücü düzeyinde test edildi. Kötü niyetli bir **firmware
  imajıyla** uçtan uca (`makeImage.sh` + `makeNetwork.py`) denenmedi.
- Faz 2 süreç yaşam döngüsüne dokunmadı. "Aynı mimarideki tüm QEMU'ları öldür"
  (sentinel A ve B'de yine öldürüldü), Ctrl-C/SIGTERM sızıntısı ve sızıntı zinciri
  Faz 3'e kadar **aynen duruyor**.
- 2.10 (`findPorts` biçimi) bilinçli olarak uygulanmadı: Faz 5.1'de hostfwd `127.0.0.1`'e
  bağlanmadan, keşfedilen portları da tüm arayüzlerde açmış olurdu.
