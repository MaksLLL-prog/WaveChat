import asyncio, json, base64, os, sys
from datetime import datetime
from pathlib import Path
from collections import deque
from aiohttp import web, WSMsgType

PORT          = int(os.environ.get("PORT", 8080))
MAX_FILE_MB   = int(os.environ.get("MAX_FILE_MB", 25))
HISTORY_LIMIT = int(os.environ.get("HISTORY_LIMIT", 200))

clients: dict = {}
global_history = deque(maxlen=HISTORY_LIMIT)
dm_history: dict = {}
counter = 0

def ts():    return datetime.now().strftime("%H:%M")
def iso():   return datetime.now().isoformat(timespec="seconds")
def log(m):  print(f"[{datetime.now().strftime('%H:%M:%S')}] {m}", flush=True)
def dm_key(a,b): return f"dm:{min(a,b)}-{max(a,b)}"
def get_dm(a,b):
    k=dm_key(a,b)
    if k not in dm_history: dm_history[k]=deque(maxlen=HISTORY_LIMIT)
    return dm_history[k]
def ws_by_id(uid):
    for w,v in clients.items():
        if v["id"]==uid: return w
def all_users(): return [{"id":v["id"],"name":v["name"]} for v in clients.values()]

async def snd(ws,p):
    try: await ws.send_str(json.dumps(p,ensure_ascii=False))
    except: pass

async def bcast(p,ex=None):
    d=json.dumps(p,ensure_ascii=False)
    for w in list(clients):
        if w!=ex:
            try: await w.send_str(d)
            except: pass

async def push_users():
    await bcast({"type":"users","users":all_users()})

async def index(req):
    p=Path(__file__).parent/"client.html"
    html=p.read_text("utf-8") if p.exists() else "<h1>client.html missing</h1>"
    return web.Response(text=html,content_type="text/html")

async def health(req):
    return web.Response(text="ok")

async def ws_handler(req):
    global counter
    ws=web.WebSocketResponse(heartbeat=30,max_msg_size=(MAX_FILE_MB+2)*1024*1024)
    await ws.prepare(req)
    counter+=1; cid=counter; name=f"User{cid}"

    try:
        try: first=await asyncio.wait_for(ws.__anext__(),timeout=15)
        except (asyncio.TimeoutError,StopAsyncIteration): return ws
        if first.type!=WSMsgType.TEXT: return ws
        msg=json.loads(first.data)
        if msg.get("type")!="join": return ws

        name=(msg.get("name") or "").strip()[:32] or f"User{cid}"
        clients[ws]={"id":cid,"name":name}
        log(f"+ [{cid}] {name} (total {len(clients)})")

        await snd(ws,{"type":"init","my_id":cid,"my_name":name,
                      "history":list(global_history),"users":all_users()})
        await bcast({"type":"system","text":f"{name} joined 👋","ts":ts()},ex=ws)
        await push_users()

        async for m in ws:
            if m.type==WSMsgType.ERROR: break
            if m.type!=WSMsgType.TEXT:  continue
            msg=json.loads(m.data); mtype=msg.get("type"); t=ts(); i=iso()

            if mtype=="text":
                text=msg.get("text","").strip()
                if not text or len(text)>4000: continue
                to_id=msg.get("to_id")
                if to_id:
                    to_id=int(to_id)
                    to_name=next((v["name"] for v in clients.values() if v["id"]==to_id),"?")
                    p={"type":"text","dm":True,"from_id":cid,"from_name":name,
                       "to_id":to_id,"to_name":to_name,"text":text,"ts":t,"iso":i}
                    get_dm(cid,to_id).append(p)
                    tw=ws_by_id(to_id)
                    if tw: await snd(tw,p)
                    await snd(ws,{**p,"self":True})
                else:
                    p={"type":"text","dm":False,"from_id":cid,"from_name":name,"text":text,"ts":t,"iso":i}
                    global_history.append(p)
                    await bcast(p,ex=ws); await snd(ws,{**p,"self":True})

            elif mtype=="file":
                fname=(msg.get("filename") or "file").strip()[:200]
                mime=msg.get("mime") or "application/octet-stream"
                data=msg.get("data",""); to_id=msg.get("to_id")
                try: size=len(base64.b64decode(data+"=="))
                except: continue
                if size>MAX_FILE_MB*1024*1024:
                    await snd(ws,{"type":"error","text":f"Max {MAX_FILE_MB}MB"}); continue
                if to_id:
                    to_id=int(to_id)
                    to_name=next((v["name"] for v in clients.values() if v["id"]==to_id),"?")
                    p={"type":"file","dm":True,"from_id":cid,"from_name":name,
                       "to_id":to_id,"to_name":to_name,"filename":fname,"mime":mime,"data":data,"size":size,"ts":t,"iso":i}
                    tw=ws_by_id(to_id)
                    if tw: await snd(tw,p)
                    await snd(ws,{**p,"self":True})
                else:
                    p={"type":"file","dm":False,"from_id":cid,"from_name":name,
                       "filename":fname,"mime":mime,"data":data,"size":size,"ts":t,"iso":i}
                    global_history.append({**p,"data":None})
                    await bcast(p,ex=ws); await snd(ws,{**p,"self":True})

            elif mtype=="voice":
                data=msg.get("data",""); to_id=msg.get("to_id"); dur=msg.get("duration",0)
                try: size=len(base64.b64decode(data+"=="))
                except: continue
                if size>10*1024*1024:
                    await snd(ws,{"type":"error","text":"Voice max 10MB"}); continue
                if to_id:
                    to_id=int(to_id)
                    to_name=next((v["name"] for v in clients.values() if v["id"]==to_id),"?")
                    p={"type":"voice","dm":True,"from_id":cid,"from_name":name,
                       "to_id":to_id,"to_name":to_name,"data":data,"duration":dur,"ts":t,"iso":i}
                    tw=ws_by_id(to_id)
                    if tw: await snd(tw,p)
                    await snd(ws,{**p,"self":True})
                else:
                    p={"type":"voice","dm":False,"from_id":cid,"from_name":name,"data":data,"duration":dur,"ts":t,"iso":i}
                    await bcast(p,ex=ws); await snd(ws,{**p,"self":True})

            elif mtype=="dm_history":
                peer_id=int(msg.get("peer_id",0))
                await snd(ws,{"type":"dm_history","messages":list(get_dm(cid,peer_id)),"peer_id":peer_id})

            elif mtype=="typing":
                to_id=msg.get("to_id")
                if to_id:
                    tw=ws_by_id(int(to_id))
                    if tw: await snd(tw,{"type":"typing","from_id":cid,"from_name":name,"dm":True})
                else:
                    await bcast({"type":"typing","from_id":cid,"from_name":name},ex=ws)

            # ── WebRTC signaling ──────────────────────────────
            elif mtype=="call-offer":
                to_id=int(msg.get("to_id",0))
                tw=ws_by_id(to_id)
                if tw:
                    await snd(tw,{"type":"call-offer","from_id":cid,"from_name":name,"sdp":msg.get("sdp")})
                    log(f"  call {cid}→{to_id}")
                else:
                    await snd(ws,{"type":"call-error","text":"User is offline"})

            elif mtype=="call-answer":
                to_id=int(msg.get("to_id",0))
                tw=ws_by_id(to_id)
                if tw: await snd(tw,{"type":"call-answer","from_id":cid,"sdp":msg.get("sdp")})

            elif mtype=="ice-candidate":
                to_id=int(msg.get("to_id",0))
                tw=ws_by_id(to_id)
                if tw: await snd(tw,{"type":"ice-candidate","from_id":cid,"candidate":msg.get("candidate")})

            elif mtype in ("call-reject","call-end"):
                to_id=int(msg.get("to_id",0))
                tw=ws_by_id(to_id)
                if tw: await snd(tw,{"type":mtype,"from_id":cid,"from_name":name})

    except Exception as e:
        log(f"! [{cid}] {e}")
    finally:
        clients.pop(ws,None)
        log(f"- [{cid}] {name} left (total {len(clients)})")
        await bcast({"type":"system","text":f"{name} left the chat","ts":ts()})
        await push_users()
    return ws

app=web.Application()
app.router.add_get("/",       index)
app.router.add_get("/health", health)
app.router.add_get("/ws",     ws_handler)

if __name__=="__main__":
    log(f"WaveChat | port={PORT} | max_file={MAX_FILE_MB}MB")
    web.run_app(app,host="0.0.0.0",port=PORT,access_log=None)