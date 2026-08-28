import struct, random
CODE=open('/tmp/fh.bin','rb').read()
def ror(v,r):
    r&=31
    return v if r==0 else (((v>>r)|(v<<((32-r)&31)))&0xffffffff)
def emu(k):
    R={i:0 for i in range(32)}
    def rd(r): return R[r&31]
    def wr(r,v): R[r&31]=v&0xffffffff
    base=0x7000000; mem={base+i*4:k[i] for i in range(5)}
    R[0]=base; pc=0
    while pc+4<=len(CODE):
        ins=struct.unpack_from('<I',CODE,pc)[0]
        if pc==0x7c: return R[8]
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
            if L: wr(rt,mem.get(a,0))
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
            wr(rd_,res)
        elif hi==0x4a:
            rm=(ins>>16)&31; imm6=(ins>>10)&63; rn=(ins>>5)&31; rd_=ins&31
            t=(ins>>22)&3; v=rd(rm)
            if t==3 and imm6: v=ror(v,imm6)
            elif t==1 and imm6: v=(v<<imm6)&0xffffffff
            elif t==2 and imm6: v=v>>imm6
            wr(rd_,rd(rn)^v)
        elif hi==0x13:
            rm=(ins>>16)&31; r=((ins>>10)&63); rd_=ins&31; v=rd(rm); r&=31
            wr(rd_,ror(v,r))
        elif hi==0x51:
            imm12=(ins>>10)&0xfff; rn=(ins>>5)&31; rd_=ins&31
            wr(rd_,rd(rn)-imm12)
        elif hi==0xd6: return R[8]
        else: raise Exception(hex(ins))
        pc+=4
def M(k):
    M32=lambda x:x&0xffffffff
    w13,w9,w12,w10,w11=k[3],k[4],k[1],k[2],k[0]
    K=0xdeadbeff
    w8=M32(w9+K)
    w9=M32(w11+w8); w10=M32(w10+w8); w9=M32(w9-w10); w8=M32(w12+w8)
    w9^=ror(w10,28); w11=M32(w8-w9); w8=M32(w10+w8); w10=w11^ror(w9,26)
    w11=M32(w8-w10); w8=M32(w9+w8);  w9=w11^ror(w10,24); w11=M32(w8-w9)
    w8=M32(w10+w8);  w10=w11^ror(w9,16); w9=M32(w9+w8); w8=M32(w8-w10)
    w11=M32(w10+w9); w8^=ror(w10,13);   w10=M32(w8+w11); w9=M32(w9-w8)
    w8=w9^ror(w8,28); w11=M32(w11+w13); w8^=w10;       w12=ror(w10,18)
    w8=M32(w8-w12);  w11^=w8;           w9=ror(w8,21);   w9=M32(w11-w9)
    w10^=w9;         w11=ror(w9,7);     w10=M32(w10-w11);w8^=w10
    w11=ror(w10,16); w8=M32(w8-w11);    w9^=w8;          w11=ror(w8,28)
    w9=M32(w9-w11);  w8^=w9;            w11=ror(w9,8);   w8=M32(w8-w11)
    return w8
random.seed(1337); bad=0
for _ in range(20000):
    k=[random.getrandbits(32) for _ in range(5)]
    if emu(k)!=M(k): bad+=1
print('mismatches:',bad,'/20000')
