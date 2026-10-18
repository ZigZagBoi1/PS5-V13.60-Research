import hashlib,json,struct
from pathlib import Path
root=Path(__file__).resolve().parent
source=root/'kernel-13.60-live.bin'; meta=json.loads((root/'kernel-13.60-live.bin.json').read_text())
outdir=root/'rea_import'; outdir.mkdir(exist_ok=True)
out=outdir/'ps5_1360_attack_surface_analysis.exe'
TEXT=0xffffffff9e3f0000; DATA=0xffffffff9f0b0000; TSIZE=13369344; FILE_ALIGN=0x200; SECT_ALIGN=0x1000; HEAD=0x400; PE=0x80
regions=[
 (b'.tramp',0xffffffff9e655000,0x1000,'text'),
 (b'.common',0xffffffff9e952000,0x8000,'text'),
 (b'.nosys',0xffffffff9e79d000,0x4000,'text'),
 (b'.handler',0xffffffff9ecec000,0x8000,'text'),
 (b'.sysent',0xffffffff9f25e000,0x6000,'data'),
 (b'.ip6core',0xffffffff9ecba000,0x5000,'text'),
 (b'.icmp6',0xffffffff9ec41000,0x5000,'text'),
 (b'.icmpdt',0xffffffff9fb74000,0x4000,'data'),
 (b'.ip6call',0xffffffff9e841000,0x2000,'text'),
 (b'.ip6call2',0xffffffff9ef31000,0x2000,'text'),
 (b'.aio',0xffffffff9ef70000,0x10000,'text'),
 (b'.evf',0xffffffff9ec1c000,0x8000,'text'),
 (b'.roots',0xffffffff9e656000,0x100,'synthetic'),
]
ENTRY=0xffffffff9e656000
roots=[0xffffffff9e655a90,0xffffffff9e9520e0,0xffffffff9ecec820,0xffffffff9ecbaac0,0xffffffff9e841070,0xffffffff9ef31100,0xffffffff9ef70060,0xffffffff9ec1c800,0xffffffff9ec41850,0xffffffff9ec41da0]
rootcode=bytearray()
for target in roots:
 callva=ENTRY+len(rootcode); disp=target-(callva+5)
 if not -(1<<31)<=disp<(1<<31): raise SystemExit('call target out of range')
 rootcode+=b'\xe8'+struct.pack('<i',disp)
rootcode+=b'\xc3'
src_hash=hashlib.sha256(source.read_bytes()).hexdigest()
if src_hash!=meta['sha256']: raise SystemExit(f'hash mismatch {src_hash}')
def align(x,a): return (x+a-1)&~(a-1)
def sh(name,vsize,rva,rsize,roff,flags):return struct.pack('<8sIIIIIIHHI',name.ljust(8,b'\0'),vsize,rva,rsize,roff,0,0,0,0,flags)
base=min(x[1] for x in regions)-SECT_ALIGN; sections=[]; cursor=HEAD
for name,va,size,kind in regions:
 raw=align(size,FILE_ALIGN); rva=va-base
 off=va-TEXT if kind=='text' else TSIZE+va-DATA if kind=='data' else None
 flags=0x60000020 if kind in ('text','synthetic') else 0xC0000040
 sections.append((name,va,size,kind,raw,rva,cursor,off,flags));cursor+=raw
dos=bytearray(PE);dos[:2]=b'MZ';struct.pack_into('<I',dos,0x3c,PE)
cs=sum(s[4] for s in sections if s[3] in ('text','synthetic'));ds=sum(s[4] for s in sections if s[3]=='data')
opt=bytearray(0xf0);struct.pack_into('<H',opt,0,0x20b);struct.pack_into('<II',opt,4,cs,ds);struct.pack_into('<I',opt,16,ENTRY-base);struct.pack_into('<I',opt,20,min(s[5] for s in sections if s[3] in ('text','synthetic')));struct.pack_into('<Q',opt,24,base);struct.pack_into('<II',opt,32,SECT_ALIGN,FILE_ALIGN);struct.pack_into('<HHHHHH',opt,40,6,0,0,0,6,0);end=max(s[5]+s[2] for s in sections);struct.pack_into('<II',opt,56,align(end,SECT_ALIGN),HEAD);struct.pack_into('<HH',opt,68,1,0);struct.pack_into('<QQQQ',opt,72,0x100000,0x1000,0x100000,0x1000);struct.pack_into('<II',opt,104,0,16)
coff=struct.pack('<HHIIIHH',0x8664,len(sections),0,0,0,0xf0,0x22)
headers=bytes(dos)+b'PE\0\0'+coff+bytes(opt)+b''.join(sh(s[0],s[2],s[5],s[4],s[6],s[8]) for s in sections)
if len(headers)>HEAD: raise SystemExit('headers too large')
with source.open('rb') as f,out.open('wb') as g:
 g.write(headers);g.write(bytes(HEAD-len(headers)))
 for s in sections:
  if s[3]=='synthetic': payload=bytes(rootcode)
  else:
   f.seek(s[7]);payload=f.read(s[2])
   if len(payload)!=s[2]: raise SystemExit(f'short read {s[0]}')
  g.write(payload);g.write(bytes(s[4]-len(payload)))
print('carrier',out.resolve());print('source_sha256',src_hash);print('carrier_sha256',hashlib.sha256(out.read_bytes()).hexdigest());print('size',out.stat().st_size);print('synthetic_static_call_roots',','.join(hex(x) for x in roots))
