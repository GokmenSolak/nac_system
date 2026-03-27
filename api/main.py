from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Optional
import bcrypt
import redis
import psycopg
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_USER = os.environ.get("POSTGRES_USER")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD")
DB_NAME = os.environ.get("POSTGRES_DB")
DB_HOST = "postgres"
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
API_KEY = os.environ.get("API_KEY")

MAX_DENEME = 5
KILITLENME_SURESI = 300

if not all([DB_USER, DB_PASSWORD, DB_NAME, API_KEY]):
    raise RuntimeError("Zorunlu ortam değişkenleri eksik!")

app = FastAPI(title="NAC Policy Engine")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_db():
    return psycopg.connect(
        f"dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD} host={DB_HOST}"
    )

def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def sifre_dogrula(duz: str, hashli: str) -> bool:
    return bcrypt.checkpw(duz[:72].encode(), hashli.encode())

def sifre_hashle(duz: str) -> str:
    return bcrypt.hashpw(duz[:72].encode(), bcrypt.gensalt()).decode()

def api_key_kontrol(request: Request, key: str = Depends(api_key_header)):
    client_ip = request.client.host
    ic_ag = ("172.", "10.", "127.")
    if any(client_ip.startswith(ag) for ag in ic_ag):
        return key
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="Yetkisiz erişim")
    return key

def dahili_ag_kontrol(request: Request):
    client_ip = request.client.host
    izinli_aglar = ("172.", "10.", "127.")
    if not any(client_ip.startswith(ag) for ag in izinli_aglar):
        raise HTTPException(status_code=403, detail="Bu işlem sadece iç ağdan yapılabilir")
    return client_ip

def rol_vlan(rol: str) -> str:
    return {"admin": "20", "guest": "30"}.get(rol, "10")

def kullanici_rol(cur, username: str) -> str:
    cur.execute("SELECT groupname FROM radusergroup WHERE username = %s", (username,))
    sonuc = cur.fetchone()
    return sonuc[0] if sonuc else "employee"


class AuthIstegi(BaseModel):
    username: str
    password: Optional[str] = None
    mac_address: Optional[str] = None

class AuthzIstegi(BaseModel):
    username: str

class AcctIstegi(BaseModel):
    username: str
    session_id: str
    status_type: str
    nas_ip: str
    input_octets: Optional[int] = 0
    output_octets: Optional[int] = 0
    terminate_cause: Optional[str] = ""


@app.post("/auth", dependencies=[Depends(api_key_kontrol)])
async def kimlik_dogrula(req: AuthIstegi):
    r = get_redis()
    kilit_key = f"kilit:{req.username}"
    hata_key = f"hata:{req.username}"

    if r.exists(kilit_key):
        kalan = r.ttl(kilit_key)
        raise HTTPException(status_code=429, detail=f"Hesap kilitli. {kalan} saniye sonra tekrar deneyin.")

    try:
        with get_db() as conn:
            with conn.cursor() as cur:

                if req.mac_address and not req.password:
                    cur.execute(
                        "SELECT id FROM radcheck WHERE username = %s AND attribute = 'MAC-Address'",
                        (req.mac_address.upper(),)
                    )
                    if not cur.fetchone():
                        logger.warning(f"Bilinmeyen MAC: {req.mac_address}")
                        raise HTTPException(status_code=401, detail="Kayıtsız cihaz")

                    cur.execute(
                        "SELECT groupname FROM radusergroup WHERE username = %s",
                        (req.mac_address.upper(),)
                    )
                    grup = cur.fetchone()
                    vlan = rol_vlan(grup[0] if grup else "guest")
                    return {
                        "control:Auth-Type": "Accept",
                        "reply:Tunnel-Type": "VLAN",
                        "reply:Tunnel-Medium-Type": "IEEE-802",
                        "reply:Tunnel-Private-Group-Id": vlan
                    }

                cur.execute(
                    "SELECT value FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password'",
                    (req.username,)
                )
                kayit = cur.fetchone()

                if not kayit or not req.password or not sifre_dogrula(req.password, kayit[0]):
                    deneme = r.incr(hata_key)
                    r.expire(hata_key, KILITLENME_SURESI)
                    kalan_hak = MAX_DENEME - deneme
                    logger.warning(f"Başarısız giriş: {req.username} ({deneme}. deneme)")

                    if deneme >= MAX_DENEME:
                        r.set(kilit_key, "1", ex=KILITLENME_SURESI)
                        r.delete(hata_key)
                        raise HTTPException(status_code=429, detail="Hesap 5 dakika kilitlendi.")

                    raise HTTPException(status_code=401, detail=f"Kimlik doğrulama başarısız. {kalan_hak} hakkınız kaldı.")

                r.delete(hata_key)
                rol = kullanici_rol(cur, req.username)
                vlan = rol_vlan(rol)
                logger.info(f"Başarılı giriş: {req.username} → VLAN {vlan}")

                return {
                    "control:Auth-Type": "Accept",
                    "reply:Tunnel-Type": "VLAN",
                    "reply:Tunnel-Medium-Type": "IEEE-802",
                    "reply:Tunnel-Private-Group-Id": vlan
                }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Auth hatası: {e}")
        raise HTTPException(status_code=500, detail="Sunucu hatası")


@app.post("/register", dependencies=[Depends(api_key_kontrol)])
async def kullanici_kayit(req: AuthIstegi, request: Request):
    dahili_ag_kontrol(request)

    if not req.password:
        return {"status": "reject", "message": "Şifre zorunludur."}

    hashli = sifre_hashle(req.password)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM radcheck WHERE username = %s", (req.username,))
                if cur.fetchone():
                    return {"status": "reject", "message": "Bu kullanıcı zaten mevcut."}

                cur.execute(
                    "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                    (req.username, "Cleartext-Password", ":=", hashli)
                )
                conn.commit()
                logger.info(f"Yeni kullanıcı kaydedildi: {req.username}")
                return {"status": "success", "message": f"{req.username} kaydedildi."}
    except Exception as e:
        logger.error(f"Kayıt hatası: {e}")
        raise HTTPException(status_code=500, detail="Sunucu hatası")

@app.post("/authorize", dependencies=[Depends(api_key_kontrol)])
async def yetkilendir(req: AuthzIstegi):
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                import re
                mac_pattern = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$')
                is_mac = bool(mac_pattern.match(req.username.upper()))

                if is_mac:
                    cur.execute(
                        "SELECT id FROM radcheck WHERE username = %s AND attribute = 'MAC-Address'",
                        (req.username.upper(),)
                    )
                    if not cur.fetchone():
                        logger.warning(f"Kayıtsız MAC adresi reddedildi: {req.username}")
                        raise HTTPException(status_code=401, detail="Kayıtsız cihaz")

                cur.execute(
                    "SELECT groupname FROM radusergroup WHERE username = %s",
                    (req.username.upper() if is_mac else req.username,)
                )
                sonuc = cur.fetchone()
                grup = sonuc[0] if sonuc else "guest"

                cur.execute(
                    "SELECT attribute, value FROM radgroupreply WHERE groupname = %s",
                    (grup,)
                )
                nitelikler = [{"attribute": r[0], "value": r[1]} for r in cur.fetchall()]

                return {"status": "accept", "group": grup, "attributes": nitelikler}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Yetkilendirme hatası: {e}")
        raise HTTPException(status_code=500, detail="Sunucu hatası")

@app.post("/accounting", dependencies=[Depends(api_key_kontrol)])
async def muhasebe(req: AcctIstegi):
    r = get_redis()

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                if req.status_type == "Start":
                    cur.execute(
                        """INSERT INTO radacct (username, acctsessionid, nasipaddress, acctstarttime)
                           VALUES (%s, %s, %s, NOW())
                           ON CONFLICT (acctsessionid) DO NOTHING""",
                        (req.username, req.session_id, req.nas_ip)
                    )
                    r.hset("aktif_oturumlar", req.session_id, f"{req.username}|{req.nas_ip}")

                elif req.status_type == "Interim-Update":
                    cur.execute(
                        """UPDATE radacct SET acctinputoctets = %s, acctoutputoctets = %s
                           WHERE acctsessionid = %s AND acctstoptime IS NULL""",
                        (req.input_octets, req.output_octets, req.session_id)
                    )

                elif req.status_type == "Stop":
                    cur.execute(
                        """UPDATE radacct
                           SET acctstoptime = NOW(), acctinputoctets = %s,
                               acctoutputoctets = %s, acctterminatecause = %s
                           WHERE acctsessionid = %s AND username = %s AND acctstoptime IS NULL""",
                        (req.input_octets, req.output_octets, req.terminate_cause,
                         req.session_id, req.username)
                    )
                    r.hdel("aktif_oturumlar", req.session_id)

                conn.commit()
                return {"status": "success", "message": "Oturum kaydedildi"}
    except Exception as e:
        logger.error(f"Accounting hatası: {e}")
        raise HTTPException(status_code=500, detail="Sunucu hatası")


@app.get("/users", dependencies=[Depends(api_key_kontrol)])
async def kullanici_listesi():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT r.username, ug.groupname
                    FROM radcheck r
                    LEFT JOIN radusergroup ug ON r.username = ug.username
                    WHERE r.attribute = 'Cleartext-Password'
                    ORDER BY r.username
                """)
                kullanicilar = [
                    {"username": row[0], "group": row[1] or "employee"}
                    for row in cur.fetchall()
                ]
                return {"status": "success", "count": len(kullanicilar), "users": kullanicilar}
    except Exception as e:
        logger.error(f"Kullanıcı listesi hatası: {e}")
        raise HTTPException(status_code=500, detail="Sunucu hatası")


@app.get("/sessions/active", dependencies=[Depends(api_key_kontrol)])
async def aktif_oturumlar():
    try:
        r = get_redis()
        ham_veri = r.hgetall("aktif_oturumlar")
        oturumlar = []
        for session_id, veri in ham_veri.items():
            parca = veri.split("|")
            oturumlar.append({
                "session_id": session_id,
                "username": parca[0] if len(parca) > 0 else "",
                "nas_ip": parca[1] if len(parca) > 1 else ""
            })
        return {"status": "success", "count": len(oturumlar), "active_sessions": oturumlar}
    except Exception as e:
        logger.error(f"Oturum sorgulama hatası: {e}")
        raise HTTPException(status_code=500, detail="Sunucu hatası")