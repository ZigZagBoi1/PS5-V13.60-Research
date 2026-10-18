"""Build a non-runnable PE carrier for broad static review of PS5 13.60.
The root-call code is synthetic analysis scaffolding; mapped kernel bytes remain copied from the capture.
"""
import hashlib,json,struct,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/'kernel-13.60-live.bin'; META=ROOT/'kernel-13.60-live.bin.json'
OUT=ROOT/'rea_import'/'ps5_1360_prologue_roots_analysis.exe'
FILE_ALIGN=0x200; SECTION_ALIGN=0x1000; HEADERS=0x400; DOS_SIZE=0x80
meta=json.loads(META.read_text(encoding='utf-8'))
text_info,data_info=meta['sections']
text_base=int(text_info['virtual_address'],16); data_base=int(data_info['virtual_address'],16)
text_size=text_info['size']; data_size=data_info['size']
with SOURCE.open('rb') as f:
    whole_hash=hashlib.sha256(f.read()).hexdigest()
if whole_hash!=meta['sha256']: raise SystemExit(f'input SHA-256 mismatch {whole_hash}')
raw=SOURCE.read_bytes()
text=raw[:text_size]
prologue=b'\x55\x48\x89\xe5'
candidates=[m.start() for m in re.finditer(re.escape(prologue),text) if m.start()==0 or text[m.start()-1] in (0xc3,0xcc,0x90)]
# Direct calls force Ghidra to consider each heuristic start; this is not execution code.
root_code=bytearray()
roots_va=((data_base+data_size+SECTION_ALIGN-1)//SECTION_ALIGN)*SECTION_ALIGN
for off in candidates:
    callva=roots_va+len(root_code)
    target=text_base+off
    disp=target-(callva+5)
    if not -(1<<31)<=disp<(1<<31): raise SystemExit(f'out-of-range root target 0x{target:x}')
    root_code+=b'\xe8'+struct.pack('<i',disp)
root_code+=b'\xc3'
image_base=text_base-SECTION_ALIGN
text_rva=text_base-image_base; data_rva=data_base-image_base; root_rva=roots_va-image_base
text_raw=(text_size+FILE_ALIGN-1)&~(FILE_ALIGN-1); data_raw=(data_size+FILE_ALIGN-1)&~(FILE_ALIGN-1); root_raw=(len(root_code)+FILE_ALIGN-1)&~(FILE_ALIGN-1)
text_off=HEADERS; data_off=text_off+text_raw; root_off=data_off+data_raw
size_image=(root_rva+len(root_code)+SECTION_ALIGN-1)&~(SECTION_ALIGN-1)
def section(name,vsize,rva,rsize,off,flags): return struct.pack('<8sIIIIIIHHI',name.ljust(8,b'\0'),vsize,rva,rsize,off,0,0,0,0,flags)
dos=bytearray(DOS_SIZE);dos[:2]=b'MZ';struct.pack_into('<I',dos,0x3c,DOS_SIZE)
coff=struct.pack('<HHIIIHH',0x8664,3,0,0,0,0xf0,0x22)
opt=bytearray(0xf0);struct.pack_into('<H',opt,0,0x20b);struct.pack_into('<II',opt,4,text_raw,data_raw+root_raw);struct.pack_into('<I',opt,16,root_rva);struct.pack_into('<I',opt,20,text_rva);struct.pack_into('<Q',opt,24,image_base);struct.pack_into('<II',opt,32,SECTION_ALIGN,FILE_ALIGN);struct.pack_into('<HHHHHH',opt,40,6,0,0,0,6,0);struct.pack_into('<II',opt,56,size_image,HEADERS);struct.pack_into('<HH',opt,68,1,0);struct.pack_into('<QQQQ',opt,72,0x100000,0x1000,0x100000,0x1000);struct.pack_into('<II',opt,104,0,16)
shdrs=section(b'.text',text_size,text_rva,text_raw,text_off,0x60000020)+section(b'.data',data_size,data_rva,data_raw,data_off,0xC0000040)+section(b'.roots',len(root_code),root_rva,root_raw,root_off,0x60000020)
headers=bytes(dos)+b'PE\0\0'+coff+bytes(opt)+shdrs
if len(headers)>HEADERS: raise SystemExit('header overflow')
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('wb') as f:
    f.write(headers); f.write(bytes(HEADERS-len(headers))); f.write(text); f.write(bytes(text_raw-text_size)); f.write(raw[text_size:text_size+data_size]); f.write(bytes(data_raw-data_size)); f.write(root_code); f.write(bytes(root_raw-len(root_code)))
print(f'carrier={OUT.resolve()}')
print(f'source_sha256={whole_hash}')
print(f'carrier_sha256={hashlib.sha256(OUT.read_bytes()).hexdigest()}')
print(f'candidate_roots={len(candidates)} root_section_va=0x{roots_va:x} root_code_bytes={len(root_code)}')
print(f'text_bytes={text_size} data_bytes={data_size} zero_filled_unmapped_pages={meta["unmapped_data_pages"]}')
