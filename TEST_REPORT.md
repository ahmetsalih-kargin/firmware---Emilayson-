# FirmAE Test Raporu

> **Not (2026-11-17):** Faz 2–5 ve ikinci tur bölümlerindeki "commit edilmemiş" ifadeleri **ölçüm anını** anlatan tarihsel
> kayıttır; kodun tamamı sonradan commit edilmiş ve `origin/refactor/hardening`'e push edilmiştir (HEAD `d9aaee7`, dalda 136 commit).
> Güncel birim test sayısı 1076 (çalışma ağacı, bkz. "Faz 2.10 / 5.1 / 4.2").

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
> üzerine (ölçüm anında) **commit edilmemiş** Faz 2 değişiklikleriyle test edildi (sonradan hepsi commit edildi ve push edildi). Aynı içerik daha sonra
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

> Ayrıntılar: `CHANGELOG.md`. `067f99e` üzerine (ölçüm anında) **commit edilmemiş** Faz 3 değişiklikleriyle
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

> Ayrıntılar ve davranış değişiklikleri: `CHANGELOG.md`. `ec2370b` üzerine (ölçüm anında) **commit
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

> Ayrıntılar ve davranış değişiklikleri: `CHANGELOG.md`. `a6dcfe4` üzerine (ölçüm anında) **commit edilmemiş**
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
> `b598d5c` üzerine (ölçüm anında) **commit edilmemiş** değişiklikle test edildi. WSL'de `iptables` kurulu
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
> ölçüm anında commit edilmemişti; sonradan commit edildi ve `origin/refactor/hardening`'e push edildi (HEAD `d9aaee7`).

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
- Açık bulgular S7, S9, S10, S11, S15, S16; Faz 7 (bağımlılık/kurulum) hiç başlanmadı; Faz 6
  (peripheral) yalnızca 6.1 (bkz. aşağıdaki "Faz 6.1"), 6.2–6.5 açık (bu bölüm 2026-11-16 durumunu anlatır).
- Eşzamanlı çalıştırma kilidi birim testlerle (gerçek `flock` tutan ayrı süreç) denendi;
  iki gerçek emülasyonun aynı anda koşturulması doğrulanmadı.

## Faz 6.1 — donanım profili (2026-11-17)

> Değişiklikler: `CHANGELOG.md` "Phase 6.1"; yüzey ve bulgular: `SECURITY.md` S26; tasarım:
> `ARCHITECTURE.md` 9.2. Aşağıdaki sayıların hepsi ölçülmüştür; ölçülmeyen her şey sonda
> "Doğrulanmayanlar" altında listelidir.

### A) Birim testleri

WSL2 Ubuntu, Python 3.12.3: **428 → 769 test, hepsi geçiyor** (F altındaki düzeltmeden sonra 772; 769 ilk ölçümdür). Python 3.8 ile **koşulmadı**.
Yeni dosyalar: `test_hwprofile.py` (204 test), `test_hwserial.py` (62),
`test_pipeline_hwprofile.py` ve `test_hwprofile_integration.py` (gerçek
`python3 -m firmae.hwprofile` ile bütünleşme).

**Bilinen kararsız test:** `tests/unit/test_audit_fixes.py::test_normal_exit_leaves_no_background_process_behind`
tam takımda ara sıra kalıyor (`/proc/<pid>/stat` okunurken `ProcessLookupError`; test içi
yarış, satır ~116). Bu değişiklikle ilgisiz; **düzeltilmedi.**

### B) Bağımsız denetim ve düzeltme sonrası ölçümler

Sıfır bağlamlı ayrı bir denetçi profilleyiciyi inceledi. Bulgular ve düzeltme öncesi/sonrası ölçümler:

| Bulgu | Önce | Sonra |
|---|---|---|
| Sparse başlıklı tarball (2 MB girdi) | 3,93 GB RSS, `MemoryError`, profil yok | 27 MB, 0,2 s, çıkış 0, profil yazıldı |
| Aynı girdi, yapısal önlem kapalı, yalnız `RLIMIT_AS` (1536 MB) | — | 1,53 GB'ta durdu, 21 s, çıkış 0, `limits_hit` "memory" |
| xz sözlük bombası (610 KB girdi) | 2,1 GB (denetçi ölçümü 3,1 GB) | 17 MB, 0,04 s |
| İç içe pax zinciri (14 KB) | `RecursionError`/traceback, çıkış 1 | kısmi profil, çıkış 0 |
| Global pax başlıkları (3×600k anahtar) | — | 17 MB |
| İlk 5 örnek yüzünden kaçan modül hataları | watchdog/i2c "not-referenced" | "failing" (`dynamic.modules` sayaçları) |
| Profil boyutu | 6,27 MiB | 1,08 MiB |

Seri log: yalnız satırsonlu 64 MiB log 0,2 s (denetçinin eski ölçümü: 2×64 MiB için 120,8 s);
`\r\n` ile 1,4 s; tipik log 2,9 s; 8 MiB düşmanca satır 0,03 s. Yanlış pozitif satırlar
("gpio-keys: no error", "0 errors", "error_count=0") artık sayılmıyor; tek çökmenin çift
sayımı giderildi.

**Denetimde sorun bulunmayanlar:** diske yazma/yol geçişi yok; çıktı `O_EXCL|O_NOFOLLOW` +
`os.replace`; terminal çıktısı beyaz listeli; düzenli ifadeler 6-10 MiB düşmanca girdide
≤ 0,30 s; gzip/bz2 bombası akış sınırında duruyor.

**AÇIK:** düzeltmeler ikinci bir bağımsız denetimden **geçmedi.** Belgelenmiş kısıt: gerçek
firmadyne iz satırı biçimini birebir taklit eden bir guest genel hata türlerini (aygıt açma,
no such device, mtd, watchdog, gpio) gizleyebilir; panic/segfault/modül hataları
gizlenemez. Eski GNU 'S' sparse için bellek ölçümü yalnızca birim testiyle yapıldı.

### C) Gerçek emülasyon (iki tur)

**Tur 1** (düzeltme öncesi kod, `results/20261117-002109`): A exit 0, 452 s; B exit 0, 406 s;
F exit 10/10 (3 s ve 175 s); G exit 0, 444 s. C kesildi: 30 s sonra tüm sayaçlar 0. H: Ctrl-C
öncesi TAP=2, QEMU=1, güvenlik duvarı kuralı=4, `/tmp` soketi=2; 30 s sonra hepsi 0.
`FIRMAE_HWPROFILE=0` (`results/20261117-010010`): B exit 0, 402 s, profil dosyası ve `[hw]`
satırı yok, sonuçlar aynı; F 10/10.

**Tur 2** (düzeltme SONRASI kod, `results/20261117-011518`): A exit 0, 450 s; B exit 0, 402 s;
C ve H aynı; tüm bitiş sayaçları (LOOP/MOUNT/TAP/QEMU/ZOMBIE/ORPHAN/TMPSOCK/TMPDIR/FWRULES)
0; sentinel QEMU'lar hayatta. A/B için `result`/`ping`/`web`/`ip`/`architecture` ve üretilen
`run.sh`, önceki güvenlik turuyla (`20261116-181217`; A 406 s, B 381 s, G 386 s) birebir aynı.

**Süre farkı profil adımına atfedilemez:** profil adımları toplam ≈ 1,7 s (A: statik 1,6 +
dinamik 0,1; B: 0,9 + 0,0); profil kapalıyken de B 402 s; profile hiç ulaşmayan F de uzadı.
Bu ortam gürültüsüdür (kanıtlanmış bir neden yok). F, G ve `FIRMAE_HWPROFILE=0` Tur 2'de
yeniden **koşulmadı**; `FIRMAE_HWPROFILE=0` ile A hiç koşulmadı.

**Ağ-hatası yolu** (`results/20261117-013912`, B, `FIRMAE_TIMEOUT_NETWORK=60`): çıkış 124, 76 s;
hata sonrası dinamik profil adımı çalıştı, `dynamic` dolu (tek log, 713 satır), `[hw]` satırı
basıldı, bitişte tüm sayaçlar 0.

**Ctrl-C (C, H):** kesmeden +5 s ve +30 s sonra `firmae.hwprofile` süreci yok; profil yalnız
statik kaldı (`hwprofile.log`: dynamic=no).

### D) Profil sonuçları (Tur 2)

| Firmware | failing | covered / referenced | not-referenced | Profil |
|---|---|---|---|---|
| DIR-868L (ARM) | gpio (sysfs "cannot create duplicate filename '/class/gpio'", gpio_error); nvram (`/dev/nvram: No such device`; iki log toplamı 293, ham loglarda 147+145: 1'lik fark **incelenmedi**); mtd (`/dev/mtdblock/4` mount hatası) | uart covered; wlan, other referenced | watchdog, led, i2c, spi | 28 499 bayt |
| WNAP320 (MIPS) | watchdog (açma hatası; iki logda 3+2); mtd ("Error Writing device /dev/mtd5") | uart covered; led, wlan, other referenced | gpio, nvram, i2c, spi | 18 672 bayt |

DIR-868L `dynamic.modules`: `nf_conntrack_proto_gre.ko` ve `nf_nat_proto_gre.ko` (2'şer
hata). WNAP320: modül listesi boş; segfault iki logda 1+1.

Basılan özet satırları:

```
A: [hw] gpio=failing nvram=failing mtd=failing watchdog=not-referenced i2c=not-referenced spi=not-referenced led=not-referenced uart=covered wlan=referenced other=referenced (scratch/1/hw_profile.json)
B: [hw] watchdog=failing mtd=failing gpio=not-referenced nvram=not-referenced i2c=not-referenced spi=not-referenced led=referenced uart=covered wlan=referenced other=referenced (scratch/1/hw_profile.json)
```

**Yorum notları:**

1. Sayaçlar ilk ve son emülasyonun seri loglarının **toplamıdır**; tek koşudaki olay sayısı değildir.
2. nvram ve mtd, FirmAE'nin kendi mekanizması olan sınıflar olmasına rağmen çalışma zamanı
   hatası görüldüğü için "failing"dir; bu, emülasyonun başarısız olduğu anlamına gelmez (iki
   firmware'de de `result`/`ping`/`web` = true).
3. Örneklem yalnız iki firmware: I2C/SPI için sonuç "bu iki firmware'de iz yok"tur, genelleme değildir.
4. Profil dosyası 0640, `hwprofile.log` 0644.

### E) Doğrulanmayanlar

- Python 3.8.
- Düzeltmeler için ikinci bağımsız denetim.
- analyze/debug/run/boot modlarında profil adımı.
- Docker modu.
- Daha geniş firmware seti.
- Kernel gpio/watchdog kanca kayıt hatalarının nedeni.

### F) Commit sonrası bulunan kararsızlık: bellek sınırında takılma

**Belirti.** Commit `715f226` içeriğinde tam takım 3 koşunun 1'inde `test_cli_rlimit_catches_what_the_bounds_miss`
yüzünden kaldı; test tek başına 5 koşunun 1'inde 116,57 s sürüp kaldı. `--timeout` da tutmadı.

**Kök neden (kısmen kanıtlı).** `RLIMIT_AS` sınırına çarpan süreç ara sıra %100 CPU'da dönüyordu;
faulthandler dökümü `tarfile.py … in next` içinde, `MemoryError`'ın yeniden fırlatıldığı yolu gösterdi.
Süreç sert sınırdayken Python düzeyindeki süre denetimi hiç çalışmıyordu. **CPython içinde tam olarak
neyin döndüğü kanıtlanmadı: C yığını alınmadı.**

**Düzeltme (yalnız CLI; kütüphane fonksiyonları, pipeline argümanları ve profil şeması aynı; `git diff HEAD` okunarak denetlendi).**
1. Yumuşak bekçi: `/proc/self/statm` ile adres alanı, `--mem-limit-mb` değerinin %75'ini (veya sınır - 64 MiB, hangisi küçükse) geçince akış okuyucusu taramayı `limits_hit: memory` ile temiz bitirir.
2. Sert son çare: faulthandler bekçi iş parçacığı `--timeout` + 30 s sonra süreci çıkış 1 ile bitirir; döküm `/dev/null`'a gider, terminale traceback basılmaz.
3. `MemoryError` için 8 MiB yedek: hata anında bırakılır, kısmi profil yazmaya yer kalır.

Yeni testler: `test_cli_hard_deadline_ends_a_stuck_process`, `test_memory_guard_stops_the_scan`,
`test_memory_error_drops_the_reserve`; kararsız test süre üst sınırı (25 s) ve ayrıntılı hata iletisi kazandı. Toplam 769 → 772.

**Düzeltmeyi yazanın ölçümü (bağımsız doğrulanmadı):** Python ebeveynli alt süreçte yeniden üretim önce 8/8 takılma;
düzeltmeden sonra 25/25 koşu 0,3-0,5 s.

**Bağımsız doğrulama (WSL2 Ubuntu, Python 3.12.3, çalışma ağacının kopyası):**

| Ölçüm | Sonuç |
|---|---|
| `-k rlimit` (4 test) 40 kez döngü | 0 hata; koşu başına en uzun süre 1,99 s (pytest başlangıcı dahil) |
| Tam takım, 2 koşu | 772 passed (104,96 s ve 100,47 s); eski kararsız `test_normal_exit_leaves_no_background_process_behind` bu koşularda kalmadı |
| DIR-868L `1.tar.gz`, `python3 -m firmae.hwprofile` | çıkış 0, 1,52 s, tepe RSS 31 MB (beklenen ~22 MB'tan yüksek, **nedeni incelenmedi**), `limits_hit` boş; gpio/wlan referenced, nvram/mtd/uart covered, i2c/spi/watchdog/led not-referenced |
| Denetçinin sparse PoC'si (`gen.py sparse10 … 2`, `ulimit -v 4000000`, varsayılan 1536 MB) | çıkış 0, 0,22 s, RSS 35,7 MB, `limits_hit` `header_size` |

PoC'yi yapısal başlık sınırı yakalıyor; yumuşak bekçiyi **bu girdi sınamıyor**. Bekçiyi sınayan,
başlık sınırını kapatan birim testidir (yukarıdaki 40 koşu).

**Kısıtlar.** Bekçi Linux'a özgü (`/proc`); başka yerde kapalı, yalnız sert son çare ve `RLIMIT_AS` kalır.
Sert sınırdaki dönme kendi başına duruyor; bekçi ondan önce durdurarak kaçınıyor, dönmeyi gidermiyor.
Sert son çare yalnız sahte `scan_tarball` ile sınandı. **Bu düzeltme için ikinci bağımsız denetim yapılmadı.**

### G) Kararsız test düzeltmesi: `test_normal_exit_leaves_no_background_process_behind` (2026-11-17)

**Belirti.** Testin `/proc/<pid>/stat` döngüsü yalnız `FileNotFoundError` yakalıyordu. Süreç dosya açıldıktan sonra,
`read()` sırasında reap edilirse çekirdek `ProcessLookupError` (ESRCH) fırlatır; test "süreç kaldı" demeden, yakalanmamış
istisnayla kalıyordu.

**Ölçüm (WSL2 Ubuntu, Python 3.12; testi tek başına, her seferinde yeni pytest süreci olarak döngüde koşarak).**

| | Koşu | Başarısız |
|---|---|---|
| Düzeltmeden önce | 100 | 12 (`ProcessLookupError`, `test_audit_fixes.py:116`) |
| Düzeltmeden önce (ikinci ölçüm) | 150 | 6 (aynı hata) |
| Düzeltmeden sonra | 200 | 0 |
| Tam takım, düzeltmeden sonra | 2 | 0 (772 passed, 127,7 s ve 108,9 s) |

**Düzeltme.** Yalnız yarış kapatıldı: `FileNotFoundError`, `ProcessLookupError` ile boş/yarım `stat` içeriğinin yol açtığı
`IndexError`/`ValueError` "süreç bitti" sayılır. Asıl iddia (normal çıkıştan sonra arka plan süreci kalmaz; kalırsa 5 sn
sonra `pytest.fail`) aynı.

**Aynı kalıp başka testlerde (sonradan, "grup 1" turunda aynı şekilde kapatıldı — yalnız yarış, asıl iddialar aynı; ayrı bir 100/200 koşulu ölçümü yapılmadı, yalnız tam takım koşuları aşağıda):** `tests/unit/test_procgroup.py:18-20`,
`tests/unit/test_lifecycle_functions.py:43-45`; `tests/unit/test_pipeline.py:368` ve `tests/unit/test_pipeline_hwprofile.py:595`
(`os.path.exists` sonra `open` — aynı yarış, hiç yakalama yok). Üretim kodunda (`scripts/procgroup.py`, `firmae/`, `firmae.config`)
`/proc/<pid>/stat` okuması yok; `firmae.config:420-470` (`qemu_pids`, `scratch_pids`) `/proc/*/cmdline`i `|| continue` ile okur, her hatayı "süreç gitti" sayar (güvenli).

## Faz 2.10 / 5.1 / 4.2 (2026-11-17)

> Kod: çalışma ağacında **commit edilmemiş** "grup 1" değişiklikleri (HEAD `d9aaee7` üzerine). Ayrıntı: `CHANGELOG.md`
> "Phase 2.10 / 5.1 / 4.2". Bu bölüm yalnız birim testle ölçülenleri anlatır; gerçek koşu **yoktur** (aşağıda "Doğrulanmayanlar").

### A) Birim testleri

WSL Ubuntu 24.04, Python 3.12, root değil; her koşuda çalışma ağacının temiz bir kopyası (`.git` ve `__pycache__` hariç), tam takım **sırayla** iki kez: **1076 passed** (131,2 s) ve **1076 passed** (133,4 s). Bundan önceki 772 test, bu turla 1076'ya çıktı. Aynı kopya üzerinde ölçüldü; ölçümden önceki koşular (ağaç o sırada başka ajanlarca değiştiriliyordu, kopya her koşuda yeniden alınmıştı) şunlardı: 1012 passed + 1 failed (`test_qemu_py.py::test_sigint_kill_fallback_kills_qemu_that_ignores_sigint`, QEMU taklidi SIGKILL yerine -15 ile bitti; bir daha görülmedi, nedeni belirlenmedi — WSL'de aynı sırada başka bir ajanın süreçleri çalışıyordu), 1013 passed, 1075 passed ve iki kez `test_review_fixes_scripts.py::test_process_clips_networks_and_ip_files` kırık (ağaç o sırada değişiyordu; sonraki kopyada geçti). Bu bölümdeki 1076 sayısı son, kararlı ağaçtandır.


### B) Altın argv (4.2) nasıl yakalandı

`tests/unit/golden_qemu_initial.json`: `scripts/run.{armel,mipseb,mipsel}.sh`in **eski Bash sürümleri** sahte bir `qemu-system-*`
ile (QEMU hiç başlatılmadan) çalıştırılıp komut satırı (argv) kaydedildi; 54 durum = 3 mimari x `FIRMAE_NET` x `FIRMAE_KERNEL` x
IID'ler, ayrıca boş/boşluklu `QEMU_INIT` ve diğer `FIRMAE_*` anahtarları kapalı durumlar. `tests/unit/test_qemu_py.py` (a)
`firmae.qemu.build_initial_argv`in bu argv'yi birebir ürettiğini, (b) yeni sarmalayıcı betiklerin (sahte QEMU ile, Linux'ta) aynı
argv'yi çalıştırdığını (Bash↔Python eşdeğerliği), (c) sahte QEMU'nun sarmalayıcıyı başlatan süreçle aynı PID'e sahip olduğunu
(`os.execvpe`, arada süreç yok), (d) SIGINT'in doğrudan QEMU'ya ulaştığını ve SIGINT'i yok sayan QEMU'nun SIGKILL ile sonlandığını,
(e) SIGPIPE/SIGXFSZ'in exec öncesi varsayılana döndüğünü, (f) sarmalayıcının `python3 -I` ile çalıştığını (cwd'deki sahte `firmae/` paketi yüklenmez, kurulum kökü `sys.path`'in sonundadır) denetler. Bilinçli farklar ayrı altın dosyada (`tests/unit/golden_old_quirks.json`, `git archive HEAD` eski betikleriyle sahte QEMU'da kaydedildi): baştaki sıfırlı IID (`08`/`09`) ve `true`/`false` dışı `FIRMAE_NET` eski betikte QEMU'yu başlatıyordu, yeni kod reddeder; eski betikte `FIRMAE_NET=yes` keyfi komut (`/usr/bin/yes`) çalıştırıyordu.

### C) `findPorts` — gerçek fixture sonuçları (2.10)

| Fixture | Sonuç (ilk bind sırasıyla) |
|---|---|
| DIR-868L (ARM, 4.1 çekirdek; 40 `inet_bind` satırı) | udp 19541, 5353, 67, 5355, 137, 53, 1900; tcp 4433, 443, 53, 8181, 80, 8182 |
| WNAP320 (MIPS eb; 20 satır, 11'i `ntpclient` port 0) | tcp 80, 443, 22; udp 161, 137, 138 |

Atılanlar: port 0 (mDNSResponder, arpmonitor, ntpclient), geçici aralık >= 32768 (fakedns:63481, httpd:49152) ve tekrarlar. Test:
`tests/unit/test_network_parse.py` (`REAL_PORTS`). `tests/unit/test_dhcp_ports.py`: iki `inet_bind` biçimi, sınırlar, `chooseHostPorts`/`hostfwdBlock`, `scratch/<IID>/hostfwd` biçimi (run.sh'nin `-netdev` satırlarından geri okunur), `check_emulation.sh` DHCP dalı ve `hostfwd_check.sh` (yabancı dinleyici, yaşamayan emülasyon, `ss` yok durumları); `tests/unit/test_run_mode_dhcp.py`: `run_mode.sh` DHCP dalları (analyze 60, debug 50, run).

### D) TAP modunda üretilen `run.sh` değişmedi

`sha256sum tests/fixtures/generated/*.expected` ile `git show HEAD:<yol> | sha256sum` bu turda karşılaştırıldı, **eşit**:

| Dosya | sha256 (çalışma ağacı = HEAD) |
|---|---|
| `run_sh_armel_dir868l.expected` | `ebd0f9443cd94c72d6535085529508ed0bc6a0429aef0f7be128e2e8dbfbd746` |
| `run_sh_mipseb_wnap320.expected` | `7d54bb4dd0e300e7b2e7187126fddcb598deb22c966a8556331c6946875e7d3c` |

### E) Test düzeltmeleri

- `test_qemu_cmd.py::test_user_network_is_isolated_and_forwards_on_loopback_only` eski sabit `127.0.0.1:80-:80` çıktısını kilitliyordu
  (kırıktı); artık açık `hostfwd=[("tcp",80,10000),("tcp",443,10001),("tcp",8080,10002)]` verir, iddia aynı (`restrict=on`, hepsi
  `127.0.0.1`, `0.0.0.0`/boş adresli kural yok). Yeni test `hostfwd=None` (`chooseHostPorts`: 80, 443 ve ek portlar, host portları
  10000-19999, benzersiz) ve `hostfwd=[]` (yalnız `restrict=on`) davranışını kilitler.
- `/proc/<pid>/stat` yarışı (G bölümündeki kalıp) `test_procgroup.py`, `test_lifecycle_functions.py`, `test_pipeline.py` ve
  `test_pipeline_hwprofile.py`de aynı şekilde kapatıldı.

### F) Doğrulanmayanlar

- **DHCP modu eldeki iki firmware ile tetiklenemiyor** (`isDhcpIp` yalnız `10.0.2.*` / `*.190`); gerçek DHCP koşusu için uygun firmware gerekir. `ss -p`'nin slirp dinleyicisini QEMU pid'iyle gösterdiği doğrulanmadı.
- **DHCP/user-net modu gerçek firmware ve gerçek QEMU ile hiç koşulmadı.** Port seçimi, `hostfwd` dosyası ve `check_emulation.sh`
  DHCP dalı yalnız birim testlidir; `-netdev user,...,hostfwd=...` argümanını gerçek QEMU'nun kabul ettiği görülmedi.
- **4.2 (`firmae.qemu`) gerçek QEMU ile denenmedi**; bu belge yazılırken gerçek koşu yapılmamıştı (ilk deneme WSL çökmesi yüzünden ölçüm üretmedi; sonuç sonradan eklenecek). Testler sahte QEMU kullanır.
- **Docker modu** hiç denenmedi.
- DHCP modunda analiz araçları (`nmap.sh`, `analyses_all.sh`, `initializer.py`, `debug.py`) hâlâ `127.0.0.1`'i (host) hedefler (açık,
  `REFACTORING_PLAN.md` "Takip gerekir").
- Port boşluk sınaması ile QEMU'nun bind'i arasındaki yarış (TOCTOU) kabul edildi; `run.sh` TCP portlarını QEMU'dan önce yeniden sınar.

### G) Olay notu: doğrulama sırasında WSL dört kez çöktü (2026-11-17)

Grup 1 doğrulaması sırasında WSL dört kez çöktü (`Wsl/Service/E_UNEXPECTED`; yarım kalan test koşuları sonuç üretmedi ve baştan alındı).
Kök neden grup 1 kodu **değil**: bir deneme betiği eski `run.<arch>.sh`'yi `FIRMAE_NET=yes` ile çalıştırdı (eski betik bu değeri komut olarak
çalıştırır: `/usr/bin/yes`) ve çıktısını zaman aşımsız belleğe topladı (~7 GB); çekirdek OOM'u systemd `init.scope`'unu durdurdu, WSL'deki
tüm işler SIGTERM aldı. Mekanizma `journalctl` ile doğrulandı; tetikleyen betik **güçlü şüphe**, sürecin komut satırı günlükte yok.
Önlemler: alt süreçlere zaman aşımı ve çıktı sınırı; gerçek emülasyon yalnız tek başına koşulur, tam takım aynı anda birden çok kez koşulmaz.
Bu olay yüzünden gerçek QEMU ile 4.2 ölçümü bu belge yazılırken yapılmamıştı.

### H) Grup 1 gerçek emülasyon doğrulaması (WSL2 Ubuntu, ölçüm: 2026-11-17)

Sonuç dizinleri: `/home/ahmet/firmae-phase0/results/20261117-062305` (A, B, C, G), `.../20261117-132638` (H); karşılaştırma tabanı: `.../20261117-011518`.
Bu bölümdeki her şey **ölçülmüştür**; ölçülmeyenler "Hâlâ doğrulanmayanlar" altında ayrıdır (F bölümünün 4.2 ve `ss -p` maddeleri bu bölümle kısmen güncellenmiştir).

**Ölçülenler**

- Tam birim takımı, eşitlenmiş ağaçta: **1076 geçti** (132 sn).
- **A (ARM, DIR-868L):** çıkış 0, 422 sn (taban 450 sn). **B (MIPS, WNAP320):** çıkış 0, 384 sn (taban 402 sn). Bitiş anlık görüntüsü sayaçları hep 0; sentinel hayatta kaldı.
  `result`/`ping`/`web`/`ip`/`architecture`/`ip.0`/`ip_num`/`isDhcp` dosyaları tabanla aynı; üretilen `run.sh` ikisinde de bayt bayt aynı. Tek fark `isolation` içindeki iptables paket sayacı (A 6→5, B 16→21; trafik gürültüsü).
- **C (başlangıç emülasyonunda Ctrl-C):** kesildi, 6 sn'de bitti; +5 sn ve +30 sn'de qemu/firmae/hwprofile süreci yok; sayaçlar 0.
  **G (C'den sonra yeniden koşu):** çıkış 0, 404 sn, sonuç `true`.
- **H (son emülasyonda Ctrl-C):** ilk deneme **geçersiz**: `makeImage.sh` içindeki `/sbin/fdisk` D (kesilemez) durumunda takıldı, öldürülemedi, ikinci denemeyi de engelledi; yalnız `wsl --shutdown` ile temizlendi.
  Neden bilinmiyor; aynı ağaç fdisk'i A/B/C/G'de ve H yeniden koşusunda geçti, bu yüzden ortamsal görünüyor (**kanıtlanmadı**).
  WSL yeniden başlatıldıktan sonraki H koşusu: `run.sh`'ye SIGINT'ten bitişe 3 sn (taban 5 sn), +5/+30 sn'de süreç yok, tüm sayaçlar 0, `[-] interrupted`; dinamik donanım profili adımı Ctrl-C'de çalışmaz (tasarım gereği).
- **Yeni kod yolu (4.2):** başlangıç QEMU'su `firmae/qemu.py` tarafından doğrudan `exec` edilir (ebeveyn pid = `makeNetwork.py`); araya giren `qemu.py` ya da `run.<arch>.sh` süreci yok.
  TAP modunda `hostfwd` dosyası yok (A, B, G). `findPorts` çıktısı `makeNetwork.log`'da var (A: örn. tcp 443, 4433, udp 19541; B: tcp 80, 443, 22; udp 161, 137, 138). `hw_profile.json` çevre birimi durumları tabana göre değişmedi.
- **Bellek:** tepe kullanım 1641 MB (en büyük `qemu-system-arm` ~515 MB); kullanılabilir bellek hep > 5900 MB.
- **DHCP port sahipliği varsayımı (root olmayan, durdurulmuş `-S` `qemu-system-arm`, `-netdev user,restrict=on,hostfwd=tcp:127.0.0.1:15999-:80`):**
  `ss -Htlnp "sport = :15999"` dinleyiciyi kendi pid'iyle `qemu-system-arm` olarak gösterir. Port zaten tutuluyorsa (127.0.0.1 ya da 0.0.0.0) QEMU 1 koduyla çıkar: "Could not set up host forwarding rule".

**Hâlâ doğrulanmayanlar**

- DHCP/user-net modu **gerçek firmware ile** (iki örnek de tetiklemiyor).
- `analyze` / `debug` / `run` / `boot` modları.
- H'nin çıkış kodu ayrıca yakalanmadı.
