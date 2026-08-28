import struct,random
CODE=open('/tmp/fh.bin','rb').read()
def ror(v,r):
    r&=31
    return v if r==0 else (((v>>r)|(v<<((32-r)&31)))&0xffffffff)

def emu_trace(k):
    R={i:0 for i in range(32)}; T=[]
    def rd(r): return R[r&31]
    def wr(r,v): R[r&31]=v&0xffffffff
    base=0x7000000; mem={base+i*4:k[i] for i in range(5)}
    R[0]=base; pc=0
    while pc+4<=len(CODE):
        ins=struct.unpack_from('<I',CODE,pc)[0]
        if hi:=ins>>24:
            pass
        if pc==0x7c: pass
        hi=ins>>24
        if hi==0x29:
            imm7=(ins>>15)&0x7f
            if imm7>=64: imm7-=128
            wt=ins&31; wn=(ins>>10)&31
            a=rd(0)+imm7*4
            wr(wt,mem.get(a,0)); wr(wn,mem.get(a+4,0))
        elif hi==0xb9:
            imm12=(ins>>10)&0xfff; rn=(ins>>5)&31; rt=ins&31; L=(ins>>22)&1
            a=rd(rn)+imm12*4
            if L: wr(rt,mem.get(a,mem.get(a,0)))
            else: mem[a]=rd(rt)
        elif hi==0x52: wr(ins&31,((ins>>5)&0xffff)<<(16*((ins>>21)&3)))
        elif hi==0x72:
            r=ins&31; imm16=(ins>>5)&0xffff; hw=(ins>>21)&3
            v=rd(r); v=(v&~(0xffff<<(16*hw)))|(imm16<<(16*hw)); wr(r,v)
        elif hi in (0x0b,0x4b):
            o=(ins>>29)&3; rm=(ins>>16)&31; imm6=(ins>>10)&63; rn=(ins>>5)&31; rd_=ins&31
            t=(ins>>22)&3; v=rd(rm)
            if t==3 and imm6: v=ror(v,imm6)
            elif t==1 and imm6: v=(v<<imm6)&0xffffffff
            elif t==2 and imm6: v=v>>imm6
            res=(rd(rn)+v) if o==0 else (rd(rn)-v)
            wr(rd_,res); T.append((hex(pc),rd_))
        elif hi==0x4a:
            rm=(ins>>16)&31; imm6=(ins>>10)&63; rn=(ins>>5)&31; rd_=ins&31
            t=(ins>>22)&3; v=rd(rm)
            if t==3 and imm6: v=ror(v,imm6)
            elif t==1 and imm6: v=(v<<imm6)&0xffffffff
            elif t==2 and imm6: v=v>>imm6
            wr(rd_,rd(rn)^v); T.append((hex(pc),rd_))
        elif hi==0x13:
            rm=(ins>>16)&31; r=((ins>>10)&63); rd_=ins&31
            wr(rd_,ror(rd(rm),r)); T.append((hex(pc),rd_))
        elif hi==0x51:
            imm12=(ins>>10)&0xfff; rn=(ins>>5)&31; rd_=ins&31
            wr(rd_,rd(rn)-imm12); T.append((hex(pc),rd_))
        elif hi in (0x90,): pass
        elif ins==0xb940314a: wr(10,2048); T.append((hex(pc),10))
        elif ins==0xf9401189: pass
        elif hi==0x8a or hi==0x8b:
            rm=(ins>>16)&31; imm6=(ins>>10)&63; rn=(ins>>5)&31; rd_=ins&31
            t=(ins>>22)&3; sh=imm6; v=rd(rm)
            if t==3 and sh: v=ror(v,sh)
            elif t==1 and sh: v=(v<<sh)
            o='+' if hi==0x8b else '&'
            res=(rd(rn)+v)&0xffffffffffffffff if o=='+' else (rd(rn)&v)
            if o=='&': res&=0xffffffff
            R[rd_&31]=res; T.append((hex(pc),rd_))
        elif hi==0xd6: return R[8],T
        else: raise Exception(f'{hex(pc)} {hex(ins)}')
        pc+=4
    return R[8],T

def model(k):
    M32=lambda x:x&0xffffffff
    tr=[]
    w13,w9,w12,w10,w11=k[3],k[4],k[1],k[2],k[0]
    K=0xdeadbeff
    w8=M32(w9+K);  tr.append(('0x14',w8))
    w9=M32(w11+w8);tr.append(('0x18',w9))
    w10=M32(w10+w8);tr.append(('0x1c',w10))
    w9=M32(w9-w10);tr.append(('0x20',w9))
    w8=M32(w12+w8);tr.append(('0x24',w8))
    w9=w9^ror(w10,28); tr.append(('0x28',w9))
    w11=M32(w8-w9); tr.append(('0x2c',w11))
    w8=M32(w10+w8); tr.append(('0x30',w8))
    w10=w11^ror(w9,26); tr.append(('0x34',w10))
    w11=M32(w8-w10); tr.append(('0x38',w11))
    w8=M32(w9+w8);  tr.append(('0x3c',w8))
    w9=w11^ror(w10,24); tr.append(('0x40',w9))
    w11=M32(w8-w9); tr.append(('0x44',w11))
    w8=M32(w10+w8); tr.append(('0x48',w8))
    w10=w11^ror(w9,16); tr.append(('0x4c',w10))
    w9=M32(w9+w8);  tr.append(('0x50',w9))
    w8=M32(w8-w10); tr.append(('0x54',w8))
    w11=M32(w10+w9);tr.append(('0x58',w11))
    w8=w8^ror(w10,13); tr.append(('0x5c',w8))
    w10=M32(w8+w11); tr.append(('0x60',w10))
    w9=M32(w9-w8);  tr.append(('0x64',w9))
    w8=w9^ror(w8,28); tr.append(('0x68',w8))
    w11=M32(w11+k[3]); tr.append(('0x6c',w11))
    w8=w8^w10;      tr.append(('0x70',w8))
    w12=ror(w10,18); tr.append(('0x74',w12))
    w8=M32(w8-w12); tr.append(('0x78',w8))
    w11=w11^w8;      tr.append(('0x80',w11))
    w9=ror(w8,21);  tr.append(('0x84',w9))
    w9=M32(w11-w9); tr.append(('0x88',w9))
    w10=w9^w10;     tr.append(('0x8c',w10))
    w11=ror(w9,7);  tr.append(('0x90',w11))
    w10=M32(w10-w11);tr.append(('0x94',w10))
    w8=w10^w8;      tr.append(('0x98',w8))
    w11=ror(w10,16);tr.append(('0x9c',w11))
    w8=M32(w8-w11); tr.append(('0xa0',w8))
    w9=w8^w9;       tr.append(('0xa4',w9))
    w11=ror(w8,28); tr.append(('0xa8',w11))
    w9=M32(w9-w11); tr.append(('0xac',w9))
    w11=ror(w9,18); tr.append(('0xb0',w11))
    w9=w9^w10;      tr.append(('0xb4',w9))
    w9=M32(w9-w11); tr.append(('0xbc',w9))
    w8=w8^w9;       tr.append(('0xc4',w8))
    w11=ror(w9,8);  tr.append(('0xc8',w11))
    w8=M32(w8-w11); tr.append(('0xd4',w8))
    return w8,tr

random.seed(99)
k=[random.getrandbits(32) for _ in range(5)]
res,etr=emu_trace(k)
mres,mtr=model(k)
print('final emu=',hex(res),'model=',hex(mres))
emap=dict(etr)
div=None
for pc,v in mtr:
    ev=emap.get(pc)
    if ev is None: continue
    if ev!=v:
        div=(pc,v,ev); break
print('first divergence:',div)
