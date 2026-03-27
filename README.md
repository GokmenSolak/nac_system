# NAC Sistemi — Network Access Control

Docker, FreeRADIUS, FastAPI, PostgreSQL ve Redis kullanılarak geliştirilmiş AAA tabanlı ağ erişim kontrol sistemi.

## Teknolojiler

| Bileşen | Teknoloji |
|---|---|
| RADIUS Sunucusu | FreeRADIUS 3.2 |
| Policy Engine | Python 3.13 / FastAPI |
| Veritabanı | PostgreSQL 18 |
| Önbellek / Rate-Limit | Redis 8 |
| Altyapı | Docker Compose |

## Mimari

```
Kullanıcı / Cihaz
      │
      ▼
 FreeRADIUS (1812/1813)
      │  rlm_rest
      ▼
 FastAPI Policy Engine (:8000)
      │
      ├──► PostgreSQL (kullanıcı, grup, accounting)
      └──► Redis (aktif oturum cache, rate-limit)
```

FreeRADIUS gelen RADIUS isteklerini `rlm_rest` modülü üzerinden FastAPI'ye iletir. FastAPI kimlik doğrulama, yetkilendirme ve accounting kararlarını verir; sonuçları FreeRADIUS'a döner.

## Kurulum

### Gereksinimler

- Docker Desktop
- Git

### Adımlar

```bash
# Repoyu klonla
git clone <repo-url>
cd nac-project

# Ortam değişkenlerini ayarla
cp .env.example .env
# .env dosyasını düzenle (şifreler ve API key)

# Sistemi başlat
docker compose up -d

# Servislerin ayağa kalktığını doğrula
docker compose ps
```

`docker compose ps` çıktısında tüm servisler `healthy` görünmeli.

## Ortam Değişkenleri

`.env.example` dosyasını kopyalayıp `.env` olarak kaydet:

```env
POSTGRES_USER=nacadmin
POSTGRES_PASSWORD=guclu_bir_sifre
POSTGRES_DB=nacdb
RADIUS_SECRET=radius_secret
API_KEY=guclu_bir_api_key
```

> `.env` dosyası git'e commit edilmez. Sadece `.env.example` repoda tutulur.

## Proje Yapısı

```
nac-project/
├── api/
│   ├── Dockerfile
│   ├── main.py          # FastAPI policy engine
│   └── requirements.txt
├── db/
│   └── init.sql         # Tablo şeması ve test verileri
├── freeradius/
│   ├── Dockerfile
│   ├── mods-available/
│   │   └── rest         # rlm_rest modül konfigürasyonu
│   └── sites-available/
│       └── default      # Sanal sunucu (AAA akışı)
├── .env.example
├── .gitignore
└── docker-compose.yml
```

## Test

### PAP Authentication (Şifre Tabanlı)

```bash
# admin kullanıcısı — VLAN 20
docker exec -it nac-project-freeradius-1 radtest admin1 test1234 localhost 0 testing123

# employee kullanıcısı — VLAN 10
docker exec -it nac-project-freeradius-1 radtest employee1 test1234 localhost 0 testing123

# guest kullanıcısı — VLAN 30
docker exec -it nac-project-freeradius-1 radtest guest1 test1234 localhost 0 testing123
```

### MAB (MAC Authentication Bypass)

```bash
# Kayıtlı cihaz — Access-Accept
echo "User-Name = \"AA:BB:CC:DD:EE:FF\", Calling-Station-Id = \"AA:BB:CC:DD:EE:FF\", NAS-IP-Address = \"127.0.0.1\"" \
  | docker exec -i nac-project-freeradius-1 radclient localhost auth testing123

# Kayıtsız cihaz — Access-Reject
echo "User-Name = \"11:22:33:44:55:66\", Calling-Station-Id = \"11:22:33:44:55:66\", NAS-IP-Address = \"127.0.0.1\"" \
  | docker exec -i nac-project-freeradius-1 radclient localhost auth testing123
```

### Accounting

```bash
# Oturum başlat
echo "User-Name = \"admin1\", Acct-Status-Type = Start, Acct-Session-Id = \"sess001\", NAS-IP-Address = \"127.0.0.1\", Acct-Input-Octets = 0, Acct-Output-Octets = 0" \
  | docker exec -i nac-project-freeradius-1 radclient localhost acct testing123

# Oturum bitir
echo "User-Name = \"admin1\", Acct-Status-Type = Stop, Acct-Session-Id = \"sess001\", NAS-IP-Address = \"127.0.0.1\", Acct-Input-Octets = 102400, Acct-Output-Octets = 204800, Acct-Terminate-Cause = User-Request" \
  | docker exec -i nac-project-freeradius-1 radclient localhost acct testing123
```

### Rate-Limiting Testi

```bash
# 5 kez yanlış şifre → hesap kilitlenir
for i in {1..6}; do
  curl -s -X POST http://localhost:8000/auth \
    -H "Content-Type: application/json" \
    -H "X-API-Key: <api_key>" \
    -d '{"username":"admin1","password":"yanlis"}'
  echo
done
```

## API Endpoint'leri

Tüm endpoint'ler `X-API-Key` header'ı gerektirir.

| Endpoint | Metot | Açıklama |
|---|---|---|
| `/auth` | POST | Kimlik doğrulama ve VLAN atama |
| `/authorize` | POST | Grup ve politika bilgisi döner |
| `/accounting` | POST | Oturum kaydı (Start/Stop/Interim) |
| `/register` | POST | Yeni kullanıcı kaydı (sadece iç ağ) |
| `/users` | GET | Kullanıcı listesi |
| `/sessions/active` | GET | Aktif oturumlar (Redis) |

### Örnek İstekler

```bash
# Kullanıcı listesi
curl http://localhost:8000/users -H "X-API-Key: <api_key>"

# Aktif oturumlar
curl http://localhost:8000/sessions/active -H "X-API-Key: <api_key>"

# Yeni kullanıcı (sadece Docker iç ağından)
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <api_key>" \
  -d '{"username":"yeni_kullanici","password":"sifre123"}'
```

## VLAN Politikaları

| Grup | VLAN ID | Açıklama |
|---|---|---|
| admin | 20 | Tam yetki |
| employee | 10 | Standart erişim |
| guest | 30 | Kısıtlı erişim |

## Güvenlik

- Şifreler bcrypt ile hashlenir, plaintext saklanmaz
- Başarısız girişler Redis'te sayılır; 5 başarısız denemede hesap 5 dakika kilitlenir
- `/register` endpoint'i sadece Docker iç ağından erişilebilir
- Veritabanı kimlik bilgileri `.env` dosyasında tutulur, koda gömülmez
- Tüm SQL sorguları parameterized query kullanır (SQL injection koruması)
