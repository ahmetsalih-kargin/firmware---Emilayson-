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
> üzerine **commit edilmemiş** Faz 2 değişiklikleriyle test edildi. Aynı içerik daha sonra
> değiştirilmeden `refactor/hardening` dalına adım başına bir commit olarak alındı. Test
> takımı 13 commit'in her birinde ayrı ayrı çalıştırıldı ve hepsinde geçti (54 → 106 test).

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

---

## Faz 3 — Süreç ve kaynak yaşam döngüsü (2026-11-04)

> Ayrıntılar: `CHANGELOG.md`. `067f99e` üzerine **commit edilmemiş** Faz 3 değişiklikleriyle
> test edildi. Soket temizliği (`rm -f /tmp/qemu.<IID>*`) ölçümden **sonra** eklendi;
> ölçüm bu satır olmadan yapıldı, satır birim testiyle doğrulandı.

### Birim testleri
WSL2, Python 3.12, root değil, `-W error::SyntaxWarning`: **122 geçti, 0 başarısız**
(Faz 2: 106). Yeni testler: `test_procgroup.py` (zaman aşımı, SIGINT→SIGKILL, torunların
ölmesi, kesilme), `test_lifecycle_functions.py` (`stop_qemu` yalnızca kendi imajına
dokunuyor, sentinel/mipsel/IID 11 hayatta; `add_partition` zaman aşımı;
`release_emulation` idempotent), `test_generated_run_sh.py` (üretilen `run.sh` sahte
komutlarla çalıştırıldı: normal bitiş, SIGTERM, Ctrl-C, `START_NET` hatası, imaj hazırlama
hatası — hepsinde temizlik).

### Gerçek emülasyon: Faz 0 ile karşılaştırma

| Senaryo | Faz 0 | Faz 3 |
|---|---|---|
| **C** Ctrl-C (süreç grubuna SIGINT) | `run.sh` 60 sn sonra hâlâ çalışıyor; **QEMU=1**, soket=2 | `run.sh` **5 sn** içinde bitti; **QEMU=0**, loop/mount/TAP=0, soket=2 (bkz. not) |
| **G** C'den sonra sıfırlamadan tekrar | ❌ `Failed to get "write" lock`, 1 sn, exit 1 | ✅ web erişilebilir, 432 sn, kaynak=0 |
| **D** yalnızca `run.sh`'a SIGTERM | **QEMU=1**, soket=2 | `run.sh` 5 sn'de bitti; **QEMU=0**, soket=2 (bkz. not) |
| **A** normal ARM + `qemu-system-arm-SENTINEL` | ✅ 452 sn; sentinel **öldürüldü** | ✅ 444 sn; sentinel **hayatta** |
| **B** normal MIPS (mipseb) + `qemu-system-mipsel-SENTINEL` | ✅ 434 sn; sentinel **öldürüldü** | ✅ 406 sn; sentinel **hayatta** |

**Not (soketler):** C ve D'de QEMU sinyalle durdurulunca `/tmp/qemu.1` ve `/tmp/qemu.1.S1`
kaldı (QEMU bunları yalnızca temiz çıkışta siliyor). G'nin normal bitişi bunları
temizledi. `release_emulation`'a silme satırı eklendi; bu satırın C/D'de gerçek QEMU ile
tekrar ölçümü **yapılmadı**.

### Ölçüm ortamı notu
WSL'deki test PostgreSQL'i 5432'de açılamadı: o port Docker'daki başka bir PostgreSQL
konteynerinde (kullanıcıya ait, dokunulmadı) ve FirmAE yanlış veritabanına bağlanıp
reddedildi (ilk çalıştırma geçersiz sayıldı). Test kümesi 5433'e taşındı, ölçüm betiği
`PGPORT=5433` ile çalıştırıldı. **Kod bu portu desteklemek için değişmedi**; psycopg2
`PGPORT` ortam değişkenini kendisi okuyor.

### Test edilmeyenler / kalan riskler
- Final emülasyon (TAP oluşturulduktan sonra) sırasında Ctrl-C/SIGTERM gerçek QEMU ve
  gerçek TAP ile denenmedi; yalnızca sahte komutlarla (`test_generated_run_sh.py`).
- Debug/analiz/run/boot modlarının yeni trap ve `stop_qemu` yolları gerçek çalıştırmada
  denenmedi (analiz modu için ayrıca `routersploit`/Chrome yok).
- `extractor.py`'nin kendi geçici dizinleri (`/tmp/tmpXXXX`) bu fazda ele alınmadı.
- Aynı mimariden iki firmware'in paralel çalıştırılması yeniden ölçülmedi (sabit
  `listen=:2001-2003` portları ve `hostfwd` Faz 5'te).
- Kaynak sınırları (cgroup), eşzamanlılık kilidi ve metrikler (planın 4.7'si) uygulanmadı.


---

## Faz 4 — Python orkestrasyonu, kısmi (2026-11-05)

> Ayrıntılar ve davranış değişiklikleri: `CHANGELOG.md`. `ec2370b` üzerine **commit
> edilmemiş** Faz 4 değişiklikleriyle test edildi.

**Kapsam:** yalnızca `run.sh`'ın aşama orkestrasyonu Python'a taşındı. `makeImage.sh`,
`makeNetwork.py`, `run.<arch>.sh`, `check_emulation.sh` (planın 4.2-4.5'i) **taşınmadı**;
çünkü Faz 0-3'te ölçüp doğruladığım kodu yeni bir yetenek katmadan yeniden yazmak regresyon
riski getiriyordu. Eşzamanlılık kilitleri ve metrikler (4.7) de yok.

### Birim testleri
WSL2, Python 3.12, root değil: **139 geçti, 0 başarısız** (Faz 3: 122). 17 yeni test
(`test_pipeline.py`), gerçek `firmae.config` ile, sahte aşama script'leriyle: başarı;
web yok → 50; kök dosya sistemi yok / extractor hatası → 10; imaj kimliği yok → 11 (scratch
oluşmuyor); mimari boş / geçersiz → 20; imaj → 30 (log'un sonu gösteriliyor, ağ aşaması
çalışmıyor); ağ → 40; Docker'da veritabanı → 12; sonucu zaten `true` olan firmware atlanıyor;
`-b auto` yapışmıyor; dizin: üç dosyanın üçü de işleniyor, ortadaki başarısız, çıkış kodu 10;
kullanım ve root denetimi; `VALID_ARCHS` ile `check_arch` tutarlılığı.

### Gerçek emülasyon (Faz 3 ile karşılaştırma)

| Senaryo | Sonuç |
|---|---|
| A normal ARM | ✅ web, 422 sn, exit 0, kaynak 0, sentinel hayatta |
| B normal MIPS | ✅ web, 384 sn, exit 0, kaynak 0, mipsel sentinel hayatta |
| F rastgele bayt | `result=extraction fail`, **exit 10** (Faz 0: exit 0), 3 sn |
| F kesilmiş zip | `result=extraction fail`, **exit 10** (Faz 0: exit 0), 153 sn |
| C Ctrl-C | `run.sh` 5 sn'de bitti; QEMU/loop/mount/TAP **ve /tmp soketi 0** |

A ve B'de `run.sh` (IID/tap adı normalize edilmiş), IP, web, ping, mimari, init, ad, marka ve
sonuç Faz 3 çıktısıyla **birebir aynı**; tek yeni dosya `firmae.log`. C'de Faz 3'te kalan
2 `/tmp/qemu.*` soketi artık gerçek QEMU ile de kalmıyor (Faz 3 notu doğrulandı).

### Ölçüm notları
- Bu çalıştırmada C sıfırlamasız bırakıldığı için B firmware'i IID 2 aldı; karşılaştırmalar
  buna göre yapıldı. İlk karşılaştırma betiğim yanlış IID'ye bakmıştı, düzeltilip tekrarlandı.
- Test PostgreSQL'i 5433 portunda (Faz 3 notuna bakınız).

### Test edilmeyenler
- `-a` (analyze), `-d` (debug), `-r` (run), `-b` (boot) modları **çalıştırılmadı**:
  `scripts/run_mode.sh` yalnızca `bash -n` düzeyinde kontrol edildi; analiz modu için
  routersploit/Chrome/Selenium yok, debug/boot interaktif. Bu modların terminal ve sinyal
  davranışı doğrulanmadı.
- Docker modu (`FIRMAE_DOCKER`) yalnızca veritabanı denetimi için birim testlendi;
  `docker-helper.py` ile uçtan uca denenmedi.
- SIGTERM'in yalnızca `python3 -m firmae` sürecine gönderilmesi gerçek emülasyonla bu
  fazda yeniden ölçülmedi (Faz 3'te `run.sh` için ölçülmüştü).


---

## Faz 5 — Ağ izolasyonu, kısmi (2026-11-08)

> Ayrıntılar ve davranış değişiklikleri: `CHANGELOG.md`. `a6dcfe4` üzerine **commit edilmemiş**
> Faz 5 değişiklikleriyle test edildi. Önceki oturum ölçüm sırasında kesildi (yarım kalan
> çalıştırma kaynak bırakmamıştı); ölçüm baştan tekrarlandı.

### Birim testleri
WSL2, Python 3.12, root değil: **148 geçti, 0 başarısız** (Faz 4: 139). Yeni/değişen testler:
ilk emülasyonun üç mimarisinde de her `-netdev user` için `restrict=on`; soketlerin
`scratch/<IID>/run/` (mod 0700) içinde olması, `/tmp/qemu` kalmaması; eski kalıntı soketlerin
başlamadan önce silinmesi; `FIRMAE_NET=false` yer tutucu NIC'lerinin `127.0.0.1` ve imaja özel
portlarda dinlemesi; farklı imajların port aralıklarının çakışmaması; DHCP modunda `hostfwd`'nin
`127.0.0.1`'e bağlı olması; `debug.py`/temizlik yollarının yeni dizini kullanması. Başlangıç
emülasyonu testleri artık depoyu kirletmemek için geçici proje kopyasında çalışıyor.

### Gerçek emülasyon (Faz 4 ile karşılaştırma)

| Senaryo | Sonuç |
|---|---|
| A normal ARM (ilk emülasyon `restrict=on`) | ✅ web, 442 sn, exit 0, kaynak ve soket 0, sentinel hayatta |
| B normal MIPS | ✅ web, 405 sn, exit 0, kaynak ve soket 0, mipsel sentinel hayatta |
| C Ctrl-C | `run.sh` 5 sn'de bitti; QEMU/loop/mount/TAP ve `scratch/*/run/*.sock` **0** |

A ve B'de ağ çıkarımı değişmedi: IP, web, ping, mimari, init, ad, marka ve sonuç Faz 4 ile
aynı. Üretilen `run.sh`'ta yalnızca soket yolları, `mkdir` satırı ve MIPS'te yer tutucu NIC
adresleri farklı (`listen=:2001` → `listen=127.0.0.1:20005`).

### Faz 5 kalanı: TAP modunda misafir yalıtımı (2026-11-08)

> Adım 5.4 için ağ namespace'i yerine güvenlik duvarı kuralları kullanıldı (gerekçe: `CHANGELOG.md`).
> `b598d5c` üzerine **commit edilmemiş** değişiklikle test edildi. WSL'de `iptables` kurulu
> değildi, kuruldu; WSL'de `ip_forward=1` (Docker Desktop): misafir paketleri host üzerinden
> yönlendirilebiliyordu.

**Birim testleri:** WSL2, Python 3.12, root değil: **158 geçti, 0 başarısız** (önce 148). Yeni 10 test
(`test_guest_isolation.py`, kuralları dosyada tutan sahte iptables/ip6tables ile): iki kural
× iki aile, idempotent uygulama, başka imajın kurallarına dokunulmaması, düşürülen paket
sayısının kaydı, yarım uygulanan kümenin geri alınması, iptables yoksa uyarı ama devam,
`release_emulation`'ın kuralları kaldırması, üretilen `run.sh`'ta sıra (TAP → kurallar → QEMU;
temizlikte kaldırma). Üretilen `run.sh`'ı çalıştıran testler de kuralların QEMU çalışırken
var olduğunu, normal bitişte ve SIGTERM'de kaldırıldığını doğruladı.

**Gerçek emülasyon:**

| Senaryo | Sonuç |
|---|---|
| A normal ARM | ✅ web, 445 sn; kurallar çalışma sırasında 4 (12 örnekte), öncesinde/sonrasında 0; `isolation`: `applied: iptables ip6tables`, **misafirin host'a 6 yeni bağlantı denemesi düşürüldü** (IPv6: 0) |
| B normal MIPS | ✅ web, 399 sn, kaynak ve kural 0, mipsel sentinel hayatta |
| C Ctrl-C (ilk emülasyon) | `run.sh` 4 sn; QEMU/loop/mount/TAP/soket/kural 0 |
| **H Ctrl-C, son emülasyon** (TAP=2, QEMU=1, kural=4, soket=2) | `run.sh` 5 sn'de bitti; 30 sn sonra **TAP, QEMU, loop, mount, soket ve kural 0** |

H, Faz 3'ten beri açık kalan "son emülasyon sırasında kesme" boşluğunu da gerçek TAP ile kapatıyor.

**Kalan riskler:** Yalıtım yalnızca misafirden host'a/yönlendirmeye gelen **yeni** bağlantıları kesiyor;
L2 düzeyi (ARP, aynı TAP üzerinde yayın) kapsam dışı. Kuralların bir misafir saldırısıyla
(host servisine bağlanma girişimi) sınanması yapılmadı; yalnızca düşürülen paket sayacı ve
kural varlığı ölçüldü. Kendi güvenlik duvarı kuralları olan veya nftables-yalın (iptables
olmayan) sistemlerde ve rootless Docker'da denenmedi.

### Test edilmeyenler / kalan riskler
- **DHCP modu (`-netdev user` ile final emülasyon) hiç çalıştırılmadı:** elimde bu modu
  tetikleyen (10.0.2.x / `.190` adresli) bir örnek firmware yok. `restrict=on` ve
  `127.0.0.1` `hostfwd` yalnızca birim testi ve QEMU belgeleri düzeyinde doğrulandı;
  `hostfwd`'nin `restrict=on` ile çalışmaya devam ettiği gerçek QEMU ile denenmedi.
- **TAP modunda (A, B'nin final emülasyonu) misafir hâlâ host ağına bağlı:** TAP arayüzü
  host'ta bir IP taşıyor; misafirin host'un o arayüzdeki servislerine erişimi engellenmedi.
  Analiz başına ağ namespace'i (5.4) yapılmadı.
- Ağ yalıtımı gerçek bir saldırıya karşı sınanmadı (ör. misafirin dışarı çıkmaya çalışması);
  `restrict=on` etkisi bu fazda doğrudan ölçülmedi, yalnızca komut satırında doğrulandı.
- `findPorts` hatası (2.10) ve dinamik `hostfwd` portları bilerek yapılmadı (bkz. CHANGELOG).
- Soketler `/mnt/c` gibi Windows sürücülerinde oluşturulamaz.


---

## Denetim: Faz 0-5 gözden geçirmesi (2026-11-08)

> İstek: "eski fazlar tamamen bitti mi, güvenlik, bellek sızıntısı, bug, optimizasyon sorunu var mı".
> Yöntem: ShellCheck, AST/derleme, `-X dev -W error::ResourceWarning` ile test, ölçüm
> sondaları (büyük dosya, 40 firmware döngüsü), yeni kodun elle incelenmesi, gerçek emülasyon.
> Her bulgunun düzeltmesi `CHANGELOG.md`'de; testler: **181 geçti, 0 başarısız, 0 uyarı**.

**Kaynak sızıntısı ölçümleri**

| Kontrol | Sonuç |
|---|---|
| 40 firmware boyunca orkestratör (fd, RSS) | fd 4 → 4, RSS 15.768 KB → 15.768 KB: **sızıntı yok** |
| ResourceWarning (kapatılmayan dosya/soket) | Ürün kodunda **yok**; 2 tane test yardımcımdaydı, kapatıldı |
| Sistem artıkları (loop, mount, TAP, QEMU, zombie, güvenlik duvarı kuralı, soket, `/tmp`) | Her senaryo sonrasında **0** (A, B, C, F, H) |
| Fuzzer tarayıcısı, 300 MB dosya | **Bulundu: +300 MB / +413 MB RSS** → düzeltildi (1 MiB bloklar, tepe < 16 MB) |
| getArch, 200 MB üye | **Bulundu:** 200 MB geçici dosya → 1 MB |
| getArch ölçekleme | 500 / 3000 / 6000 aday üye: 1,9 / 13,7 / 30,9 sn (doğrusala yakın, üye başına ~4-5 ms = `file` süreci) |

**Gerçek emülasyon (düzeltmelerden sonra):** A 451 ve 429 sn, B 399 ve 395 sn (hepsi `result=true`,
kaynak 0, sentinel hayatta); F: iki bozuk girdi `exit=10`; H (son emülasyonda Ctrl-C): TAP/QEMU/kural/soket 0.
**Bir B çalıştırması `exit=40` verdi** (`mount` ENOENT, yukarıdaki yarış); düzeltildi ama
**yeniden üretilemedi**: 150 döngülük stres testinde eski ve yeni sürüm 0 hata verdi. Düzeltme hata
mesajına ve udev davranışına dayanıyor, ölçülmüş bir kanıtı yok; B, A, B sonrası temiz çıktı.

**Bu denetimde de test edilemeyenler:** analiz/debug/run/boot modları, Docker modu, DHCP (`-netdev user`) final
emülasyonu, iki aynı mimari firmware'in paralel çalıştırılması, uzun süreli (saatlerce) çalışma.


---

## İkinci sağlamlaştırma turu ve bağımsız denetim (2026-11-16)

> Bu bölüm önceki bölümlerin sayılarına dokunmaz (onlar tarihsel kayıttır). Değişiklikler:
> `CHANGELOG.md` "Second hardening pass"; bulgular: `SECURITY.md` S19-S25. Kod henüz
> commit edilmedi (`git status`).

**Yöntem.** İki tur: her turda paralel çalışan geliştirici ajanlar (toplam yedi) ayrı dosya
kümelerini düzeltti ve test yazdı; ayrıca sıfır bağlamlı bağımsız bir denetçi hem kodu hem
belgeleri inceledi. Denetçi mutasyon yöntemiyle (düzeltmeyi bozup testin kırılmasına
bakarak) düzeltmelerin testlerle korunduğunu doğruladı. Gerçek emülasyon son turda
(`results/20261116-181217`) yapıldı.

### Birim testleri

WSL Ubuntu 24.04, Python 3.12, root değil: **428 geçti, 0 başarısız** (önceki: 181). Bu
belgeyi yazarken tüm takım yeniden koşuldu: `python3 -m pytest -q -p no:cacheprovider` →
428 passed (uyarısız). `-X dev -W error::ResourceWarning` ile `test_debug_py.py` +
`test_locking.py` 16 test, uyarısız. Yeni test dosyaları: `test_compare_py.py`,
`test_debug_py.py`, `test_extractor.py`, `test_fuzzer_robustness.py`, `test_inferdefault.py`,
`test_locking.py`, `test_makenetwork_security.py`, `test_review_fixes_core.py`,
`test_review_fixes_scripts.py`, `test_tar2db.py`, `test_util_py.py`.

### Gerçek emülasyon (son tur)

| Senaryo | Sonuç |
|---|---|
| **A** ARM DIR-868L | exit 0, 406 sn, `result` = true; ilgisiz `qemu-system-arm` süreci hayatta kaldı |
| **B** MIPS WNAP320 | exit 0, 381 sn; ilgisiz `qemu-system-mipsel` hayatta kaldı |
| **F** iki bozuk girdi | exit 10 (ikisi de) |
| **H** son emülasyonda Ctrl-C | öncesinde TAP=2, QEMU=1, güvenlik duvarı kuralı=4, `/tmp` soketi=2; 30 sn sonra hepsi 0 |
| **C** ilk emülasyonda Ctrl-C | 30 sn sonra TAP/QEMU/kural/soket hepsi 0 |
| **G** C'den sonra sıfırlamadan tekrar | exit 0, 386 sn (Faz 3'te bu senaryo `Failed to get "write" lock` ile düşüyordu) |

**Karşılaştırma:** A ve B çıktıları ile üretilen `run.sh` bir önceki turla birebir aynı; tek
fark (önceki commit'e göre) şablondaki 16 satırlık denetim bloğu
(`tests/fixtures/generated/run_sh_*.expected`). `tar2db.py` gerçek PostgreSQL'de hatasız
çalıştı.

### Denetçinin belge-kod çelişkileri ve kapatılması

| Bulgu | Kapatılma |
|---|---|
| `SECURITY.md` S19 ve `CHANGELOG.md` `util/compare.py`'yi "açık" gösteriyor | Düzeltildi; S19 "giderildi" (kabuksuz yeniden yazım) |
| `ARCHITECTURE.md` kilidi `scratch/IID/run/lock` ve `scratch/.slots/` diye anlatıyor | Gerçek: `scratch/<IID>/.firmae.lock` ve `scratch/.locks/<md5>.lock`, slot yok; belge düzeltildi |
| `ARCHITECTURE.md` "-pidfile" diyor | Kodda yok; "uygulanmadı" diye işaretlendi |
| `ARCHITECTURE.md` "hiçbiri uygulanmadı" / "15 fonksiyon" | `firmae/` paketi var; `firmae.config` 29 fonksiyon içeriyor; düzeltildi |
| `REFACTORING_PLAN.md` ve bu raporun Faz 4 bölümü "kilitler yok" | Plan tablosu güncellendi; bu rapordaki eski cümle tarihsel kayıt olarak bırakıldı (bu bölüm düzeltir) |
| `ip6tables` yoksa IPv6 sessizce yalıtılmıyor | `SECURITY.md` kalan riskler bölümüne eklendi (kod değişmedi) |

### Test edilmeyenler / kalan riskler

- DHCP modu, analiz modu (`-a`), debug/run/boot modları, Docker modu ve `install.sh` gerçek
  çalıştırmayla doğrulanmadı.
- `makeImage.sh`'in FIFO/symlink (`/bin/a`) yolu yalnızca sahte ağaçta denendi.
- `findPorts` gerçek 4.1 çekirdek log biçimini tanımıyor (bilinen, bilerek bekletildi).
- TAP adları ve iptables etiketi host genelinde tek ad alanı: aynı IID'li iki kurulum çakışır.
- `scratch/.locks/*.lock` dosyaları birikir; `get_scratch` hâlâ global `IID` kullanıyor.
- Açık bulgular S7, S9, S10, S11, S15, S16; Faz 6 (peripheral) ve Faz 7 (bağımlılık/kurulum)
  hiç başlanmadı.
- Eşzamanlı çalıştırma kilidi birim testlerle (gerçek `flock` tutan ayrı süreç) denendi;
  iki gerçek emülasyonun aynı anda koşturulması doğrulanmadı.
