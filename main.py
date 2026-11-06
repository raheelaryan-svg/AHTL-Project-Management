import os, json, uuid, pathlib, datetime, secrets
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import psycopg
import jwt
from passlib.context import CryptContext

DATABASE_URL=os.environ['DATABASE_URL']
JWT_SECRET=os.environ['JWT_SECRET']
ADMIN_PASSWORD=os.environ['ADMIN_PASSWORD']
ROLE_PASSWORD=os.environ.get('ROLE_PASSWORD',ADMIN_PASSWORD)
ROLES=['EP','Approver','Quality','Production','SCM','PPC']
STORAGE=pathlib.Path(os.environ.get('ATTACHMENT_DIR','/data/attachments')).resolve()
STORAGE.mkdir(parents=True,exist_ok=True)
ctx=CryptContext(schemes=['bcrypt'],deprecated='auto')
password_hashes={r:ctx.hash(ADMIN_PASSWORD if r in ('EP','Approver') else ROLE_PASSWORD) for r in ROLES}
app=FastAPI(title='AHTL Portal API',docs_url=None,redoc_url=None)
@contextmanager
def conn():
    with psycopg.connect(DATABASE_URL) as db: yield db

def actor(authorization: str|None=Header(default=None)):
    if not authorization or not authorization.startswith('Bearer '): raise HTTPException(401,'Authentication required')
    try:
        payload=jwt.decode(authorization[7:],JWT_SECRET,algorithms=['HS256'])
        if payload.get('role') not in ROLES: raise ValueError()
        return payload['role']
    except Exception: raise HTTPException(401,'Invalid or expired session')

class Login(BaseModel):
    role:str
    password:str
class StateUpdate(BaseModel):
    revision:int
    data:dict

@app.on_event('startup')
def init():
    with conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS portal_state (id INTEGER PRIMARY KEY CHECK (id=1), revision BIGINT NOT NULL DEFAULT 0, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        c.execute("CREATE TABLE IF NOT EXISTS portal_audit (id BIGSERIAL PRIMARY KEY, occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), actor TEXT NOT NULL, old_revision BIGINT, new_revision BIGINT, operation TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS attachments (id UUID PRIMARY KEY, name TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes BIGINT NOT NULL, storage_path TEXT NOT NULL, uploaded_by TEXT NOT NULL, uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        initial={'projects':[],'changes':[],'audit':[],'workflow':[],'version':1,'roles':ROLES,'directory':{r:{'email':'','passcode':''} for r in ROLES},'notifications':[]}
        c.execute('INSERT INTO portal_state(id,revision,data) VALUES(1,0,%s::jsonb) ON CONFLICT DO NOTHING',(json.dumps(initial),))

@app.post('/api/login')
def login(body:Login):
    if body.role not in password_hashes or not ctx.verify(body.password,password_hashes[body.role]): raise HTTPException(401,'Invalid credentials')
    now=datetime.datetime.now(datetime.timezone.utc)
    token=jwt.encode({'role':body.role,'iat':now,'exp':now+datetime.timedelta(hours=8)},JWT_SECRET,algorithm='HS256')
    return {'token':token,'role':body.role}

@app.get('/api/state')
def get_state(user:str=Depends(actor)):
    with conn() as c:
        row=c.execute('SELECT revision,data FROM portal_state WHERE id=1').fetchone()
        return {'revision':row[0],'data':row[1]}

@app.put('/api/state')
def put_state(body:StateUpdate,user:str=Depends(actor)):
    if len(json.dumps(body.data))>15_000_000: raise HTTPException(413,'State too large; use attachment upload')
    if not isinstance(body.data.get('projects'),list): raise HTTPException(422,'Invalid projects')
    # Role-based checks are coarse. Production deployment needs record-level authorization.
    with conn() as c:
        row=c.execute('SELECT revision,data FROM portal_state WHERE id=1 FOR UPDATE').fetchone()
        if row[0]!=body.revision: raise HTTPException(409,'Stale revision; reload')
        before=row[1]; after=body.data
        if user not in ('EP','Approver'):
            if before.get('roles')!=after.get('roles') or before.get('workflow')!=after.get('workflow') or before.get('directory')!=after.get('directory'):
                raise HTTPException(403,'Insufficient privileges')
            if {p.get('id') for p in before.get('projects',[])}!={p.get('id') for p in after.get('projects',[])}:
                raise HTTPException(403,'Cannot create or delete projects')
            for old,new in zip(before.get('projects',[]),after.get('projects',[])):
                if old.get('id')!=new.get('id') or old.get('approval')!=new.get('approval') or old.get('deleted')!=new.get('deleted'):
                    raise HTTPException(403,'Cannot change project approval')
        new_rev=row[0]+1
        c.execute('UPDATE portal_state SET revision=%s,data=%s::jsonb,updated_at=NOW() WHERE id=1',(new_rev,json.dumps(after)))
        c.execute('INSERT INTO portal_audit(actor,old_revision,new_revision,operation) VALUES(%s,%s,%s,%s)',(user,row[0],new_rev,'state update'))
        return {'revision':new_rev}

@app.post('/api/attachments')
async def upload_attachment(file:UploadFile=File(...),user:str=Depends(actor)):
    content=await file.read(10_000_001)
    if len(content)>10_000_000: raise HTTPException(413,'Maximum file size 10 MB')
    fid=uuid.uuid4(); path=STORAGE/str(fid)
    path.write_bytes(content)
    with conn() as c:
        c.execute('INSERT INTO attachments(id,name,mime_type,size_bytes,storage_path,uploaded_by) VALUES(%s,%s,%s,%s,%s,%s)',(fid,(file.filename or 'attachment')[:255],file.content_type or 'application/octet-stream',len(content),str(path),user))
    return {'id':str(fid),'name':file.filename,'size':len(content)}

@app.get('/api/attachments/{attachment_id}')
def download_attachment(attachment_id:uuid.UUID,user:str=Depends(actor)):
    with conn() as c:
        row=c.execute('SELECT name,mime_type,storage_path FROM attachments WHERE id=%s',(attachment_id,)).fetchone()
    if not row: raise HTTPException(404,'Not found')
    return FileResponse(row[2],filename=row[0],media_type=row[1])

@app.get('/api/health')
def health(): return {'status':'ok'}
app.mount('/',StaticFiles(directory='frontend',html=True),name='frontend')
