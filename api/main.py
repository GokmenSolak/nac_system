from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import bcrypt
import redis
import psycopg
import os

DB_USER = os.environ.get("POSTGRES_USER")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD")
DB_NAME = os.environ.get("POSTGRES_DB")
DB_HOST = "postgres"

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  

if not all([DB_USER, DB_PASSWORD, DB_NAME]):
    raise RuntimeError("KRITIK GUVENLIK HATASI: Veritabani kimlik bilgileri okunamadi!")

def get_db():
    return psycopg.connect(
        f"dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD} host={DB_HOST}"
    )

def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain[:72].encode(), hashed.encode())

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain[:72].encode(), bcrypt.gensalt()).decode()

app = FastAPI(title="NAC Policy Engine API")


class AuthRequest(BaseModel):
    username: str
    password: Optional[str] = None
    mac_address: Optional[str] = None

class AuthzRequest(BaseModel):
    username: str

class AcctRequest(BaseModel):
    username: str
    session_id: str
    status_type: str
    nas_ip: str
    input_octets: Optional[int] = 0
    output_octets: Optional[int] = 0
    terminate_cause: Optional[str] = ""


def get_vlan_for_role(role: str) -> str:
    return {"admin": "20", "guest": "30"}.get(role, "10")

def get_user_role(cur, username: str) -> str:
    cur.execute("SELECT groupname FROM radusergroup WHERE username = %s", (username,))
    res = cur.fetchone()
    return res[0] if res else "employee"



@app.post("/auth")
async def authenticate(req: AuthRequest):
    r = get_redis()
    lock_key = f"lockout:{req.username}"
    fail_key = f"failed:{req.username}"

    
    if r.exists(lock_key):
        ttl = r.ttl(lock_key)
        raise HTTPException(status_code=429, detail=f"Hesap kilitli. {ttl} saniye bekleyin.")

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                
                if req.mac_address and not req.password:
                    cur.execute(
                        "SELECT id FROM radcheck WHERE username = %s AND attribute = 'MAC-Address'",
                        (req.mac_address.upper(),)
                    )
                    if cur.fetchone():
                        cur.execute(
                            "SELECT groupname FROM radusergroup WHERE username = %s",
                            (req.mac_address.upper(),)
                        )
                        group_res = cur.fetchone()
                        vlan = get_vlan_for_role(group_res[0] if group_res else "guest")
                        return {
                            "control:Auth-Type": "Accept",
                            "reply:Tunnel-Type": "VLAN",
                            "reply:Tunnel-Medium-Type": "IEEE-802",
                            "reply:Tunnel-Private-Group-Id": vlan
                        }
                    else:
                        raise HTTPException(status_code=401, detail="Bilinmeyen MAC adresi")

                
                cur.execute(
                    "SELECT value FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password'",
                    (req.username,)
                )
                result = cur.fetchone()

                if not result:
                    raise HTTPException(status_code=401, detail="Kullanici bulunamadi")

                if not req.password or not verify_password(req.password, result[0]):
                    
                    attempts = r.incr(fail_key)
                    r.expire(fail_key, LOCKOUT_SECONDS)
                    remaining = MAX_FAILED_ATTEMPTS - attempts
                    if attempts >= MAX_FAILED_ATTEMPTS:
                        r.set(lock_key, "1", ex=LOCKOUT_SECONDS)
                        r.delete(fail_key)
                        raise HTTPException(status_code=429, detail="Cok fazla basarisiz deneme. Hesap 5 dakika kilitlendi.")
                    raise HTTPException(status_code=401, detail=f"Sifre hatali. {remaining} deneme hakki kaldi.")

                
                r.delete(fail_key)

                role = get_user_role(cur, req.username)
                vlan = get_vlan_for_role(role)

                return {
                    "control:Auth-Type": "Accept",
                    "reply:Tunnel-Type": "VLAN",
                    "reply:Tunnel-Medium-Type": "IEEE-802",
                    "reply:Tunnel-Private-Group-Id": vlan
                }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/register")
async def register(req: AuthRequest):
    if not req.password:
        return {"status": "reject", "message": "Sifre zorunludur!"}

    hashed = hash_password(req.password)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM radcheck WHERE username = %s", (req.username,))
                if cur.fetchone():
                    return {"status": "reject", "message": "Bu kullanici zaten mevcut!"}

                cur.execute(
                    "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                    (req.username, "Cleartext-Password", ":=", hashed)
                )
                conn.commit()

                return {"status": "success", "message": f"{req.username} basariyla kaydedildi!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/authorize")
async def authorize(req: AuthzRequest):
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT groupname FROM radusergroup WHERE username = %s",
                    (req.username,)
                )
                res = cur.fetchone()
                groupname = res[0] if res else "guest"

                cur.execute(
                    "SELECT attribute, value FROM radgroupreply WHERE groupname = %s",
                    (groupname,)
                )
                replies = cur.fetchall()
                attributes = [{"attribute": r[0], "value": r[1]} for r in replies]

                return {"status": "accept", "group": groupname, "attributes": attributes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/accounting")
async def accounting(req: AcctRequest):
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
                    
                    session_data = f"{req.username}|{req.nas_ip}"
                    r.hset("active_sessions", req.session_id, session_data)

                elif req.status_type == "Interim-Update":
                    cur.execute(
                        """UPDATE radacct
                           SET acctinputoctets = %s, acctoutputoctets = %s
                           WHERE acctsessionid = %s AND acctstoptime IS NULL""",
                        (req.input_octets, req.output_octets, req.session_id)
                    )

                elif req.status_type == "Stop":
                    cur.execute(
                        """UPDATE radacct
                           SET acctstoptime = NOW(),
                               acctinputoctets = %s,
                               acctoutputoctets = %s,
                               acctterminatecause = %s
                           WHERE acctsessionid = %s AND username = %s AND acctstoptime IS NULL""",
                        (req.input_octets, req.output_octets, req.terminate_cause,
                         req.session_id, req.username)
                    )
                    
                    r.hdel("active_sessions", req.session_id)

                conn.commit()
                return {"status": "success", "message": "Log basariyla kaydedildi"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/users")
async def get_users():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT r.username, r.attribute, ug.groupname
                    FROM radcheck r
                    LEFT JOIN radusergroup ug ON r.username = ug.username
                    WHERE r.attribute = 'Cleartext-Password'
                    ORDER BY r.username
                """)
                rows = cur.fetchall()
                users = [
                    {"username": row[0], "group": row[2] or "employee"}
                    for row in rows
                ]
                return {"status": "success", "count": len(users), "users": users}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sessions/active")
async def get_active_sessions():
    try:
        r = get_redis()
        sessions_raw = r.hgetall("active_sessions")
        sessions = []
        for session_id, data in sessions_raw.items():
            parts = data.split("|")
            sessions.append({
                "session_id": session_id,
                "username": parts[0] if len(parts) > 0 else "",
                "nas_ip": parts[1] if len(parts) > 1 else ""
            })
        return {"status": "success", "count": len(sessions), "active_sessions": sessions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))