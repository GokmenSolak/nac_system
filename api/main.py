from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
import bcrypt
import redis
import psycopg
import os

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password[:72].encode('utf-8'), 
        hashed_password.encode('utf-8')
    )

def get_password_hash(password: str) -> str:
    hashed_bytes = bcrypt.hashpw(password[:72].encode('utf-8'), bcrypt.gensalt())
    return hashed_bytes.decode('utf-8')

app = FastAPI(title="NAC Policy Engine API")

DB_USER = os.environ.get("POSTGRES_USER")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD")
DB_NAME = os.environ.get("POSTGRES_DB")
DB_HOST = "postgres"

if not all([DB_USER, DB_PASSWORD, DB_NAME]):
    raise RuntimeError("KRITIK GUVENLIK HATASI: Veritabani kimlik bilgileri .env dosyasindan okunamadi!")

def get_db_connection():
    return psycopg.connect(
        f"dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD} host={DB_HOST}"
    )

class AuthRequest(BaseModel):
    username: str
    password: Optional[str] = None
    mac_address: Optional[str] = None

@app.post("/auth")
async def authenticate_user(req: AuthRequest):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT value FROM radcheck WHERE username = %s",
                (req.username,)
            )
            result = cur.fetchone()
            
            if not result:
                return {"status": "reject", "message": "Kimlik dogrulama basarisiz"}
            
            stored_hash = result[0]
            
            if req.password and verify_password(req.password, stored_hash):
                return {"status": "success", "message": "Kimlik dogrulama basarili"}
            else:
                return {"status": "reject", "message": "Kimlik dogrulama basarisiz"}

@app.post("/register")
async def register_user(req: AuthRequest):
    if not req.password:
         return {"status": "reject", "message": "Sifre zorunludur!"}
         
    hashed_password = get_password_hash(req.password)
    
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM radcheck WHERE username = %s", (req.username,))
            if cur.fetchone():
                return {"status": "reject", "message": "Bu kullanici zaten mevcut!"}
                
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (req.username, "Cleartext-Password", ":=", hashed_password)
            )
            conn.commit()
            
            return {"status": "success", "message": f"{req.username} basariyla kaydedildi!"}

class AuthzRequest(BaseModel):
    username: str

@app.post("/authorize")
async def authorize_user(req: AuthzRequest):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT groupname FROM radusergroup WHERE username = %s",
                (req.username,)
            )
            group_res = cur.fetchone()
            groupname = group_res[0] if group_res else "guest"
            
            cur.execute(
                "SELECT attribute, value FROM radgroupreply WHERE groupname = %s",
                (groupname,)
            )
            replies = cur.fetchall()
            
            attributes = []
            for r in replies:
                attributes.append({"attribute": r[0], "value": r[1]})
            
            return {
                "status": "accept",
                "group": groupname,
                "attributes": attributes
            }

@app.post("/accounting")
async def accounting_record(request: Request):
    return {"status": "success", "message": "Accounting endpoint hazir"}

@app.get("/users")
async def get_users():
    return {"status": "success", "users": []}

@app.get("/sessions/active")
async def get_active_sessions():
    return {"status": "success", "active_sessions": []}