#!/usr/bin/env python3
"""Compares two `native/sleigh_diff.cc ... pcode ELF` dumps of the same R5900 image.

usage: pcode_diff.py OLD.pcode NEW.pcode

Reports (a) words whose disassembly line differs, (b) per word class whether the p-code is
identical once `unique` offsets and LOAD/STORE space ids (run-dependent) are renumbered, and
(c) non-COP2 words whose p-code changed although the next word is not a COP2 word: a branch
delays into its slot, so a COP2 delay-slot instruction legitimately changes the branch's
p-code and anything else is a regression. Used for P4.3 (VU0 macro-mode lane semantics).
"""
import re,sys,collections
def load(path):
    d={}; cur=None
    for line in open(path):
        if line.startswith('    '):
            if cur is not None: d[cur][1].append(line.rstrip('\n'))
        else:
            p=line.split(' ',2); cur=p[0]; d[cur]=(line.rstrip('\n'),[])
    return d
def norm(ops):
    m={}
    def sub(mo):
        k=mo.group(1)
        if k not in m: m[k]=len(m)
        return f'(unique,u{m[k]},'
    out=[]
    for o in ops:
        o=re.sub(r'(LOAD|STORE) \(const,0x[0-9a-f]+,\d+\)',r'\1 (space)',o)
        out.append(re.sub(r'\(unique,(0x[0-9a-f]+),',sub,o))
    return out
old=load(sys.argv[1]); new=load(sys.argv[2])
assert old.keys()==new.keys()
VU=lambda w: (w>>26) in (18,54,62)
chg=collections.Counter(); same=collections.Counter(); badnon=[]; asmbad=0
for a,(hl,ops) in old.items():
    hl2,ops2=new[a]
    if hl!=hl2: asmbad+=1
    w=int(hl.split(' ')[1],16) if ' ' in hl and not hl.split(' ')[1].startswith('ERR') else None
    if w is None: continue
    if norm(ops)==norm(ops2):
        same[VU(w)]+=1
    else:
        chg[VU(w)]+=1
        if not VU(w):
            nxt=new.get('%x'%(int(a,16)+4))
            nw=int(nxt[0].split(' ')[1],16) if nxt and not nxt[0].split(' ')[1].startswith('ERR') else None
            if nw is None or not VU(nw): badnon.append(a)
print('asm header differences',asmbad,'| pcode identical: non-vu',same[False],'vu',same[True],'| changed: non-vu',chg[False],'vu',chg[True])
print('non-VU words whose pcode changed without a VU delay-slot instruction:',len(badnon),badnon[:10])
