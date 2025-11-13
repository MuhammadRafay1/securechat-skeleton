from pydantic import BaseModel
from typing import Optional

class Hello(BaseModel):
    type: str = 'hello'
    cert: str
    nonce: str

class ServerHello(BaseModel):
    type: str = 'server hello'
    cert: str
    nonce: str

class Register(BaseModel):
    type: str = 'register'
    email: str
    username: str
    pwd: str
    salt: str

class Login(BaseModel):
    type: str = 'login'
    email: str
    pwd: str
    nonce: str

class DHClient(BaseModel):
    type: str = 'dh client'
    g: int
    p: int
    A: int

class DHServer(BaseModel):
    type: str = 'dh server'
    B: int

class Msg(BaseModel):
    type: str = 'msg'
    seqno: int
    ts: int
    ct: str
    sig: str

class Receipt(BaseModel):
    type: str = 'receipt'
    peer: str
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str
