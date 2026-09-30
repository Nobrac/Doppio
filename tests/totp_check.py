import hmac, hashlib, struct

BASE32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# --- faithful port of my C++ Base32Encode ---
def b32enc(data):
    out=""; buf=0; bits=0
    for b in data:
        buf=(buf<<8)|b; bits+=8
        while bits>=5:
            bits-=5; out+=BASE32[(buf>>bits)&0x1F]
        buf &= (1<<bits)-1
    if bits>0: out+=BASE32[(buf<<(5-bits))&0x1F]
    return out

# --- faithful port of my C++ Base32Decode ---
def b32dec(s):
    def val(c):
        if 'A'<=c<='Z': return ord(c)-65
        if 'a'<=c<='z': return ord(c)-97
        if '2'<=c<='7': return ord(c)-ord('2')+26
        return -1
    buf=0; bits=0; out=bytearray()
    for c in s:
        if c in '= ': continue
        v=val(c)
        if v<0: return None
        buf=(buf<<5)|v; bits+=5
        if bits>=8:
            bits-=8; out.append((buf>>bits)&0xFF); buf&=(1<<bits)-1
    return bytes(out)

# --- faithful port of my C++ TotpAt ---
def totp_at(key, unixtime, step=30, digits=6):
    counter = unixtime//step
    msg = struct.pack(">Q", counter)          # big-endian 8 bytes == my loop
    h = hmac.new(key, msg, hashlib.sha1).digest()
    off = h[19] & 0x0F
    binv = ((h[off]&0x7F)<<24)|((h[off+1]&0xFF)<<16)|((h[off+2]&0xFF)<<8)|(h[off+3]&0xFF)
    mod = 10**digits
    return binv % mod

seed = b"12345678901234567890"  # RFC 6238 appendix B (SHA1)
vectors = {59:94287082, 1111111109:7081804, 1111111111:14050471,
           1234567890:89005924, 2000000000:69279037, 20000000000:65353130}

print("== RFC 6238 (8-digit) ==")
ok_all=True
for t,exp in vectors.items():
    got8 = totp_at(seed, t, digits=8)
    got6 = totp_at(seed, t, digits=6)
    ok = (got8==exp)
    ok_all &= ok
    print(f"T={t:<12} got8={got8:08d} exp={exp:08d} {'OK' if ok else 'FAIL'}   (6-digit={got6:06d})")

print("\n== Base32 round-trip ==")
enc=b32enc(seed)
dec=b32dec(enc)
print("encode(seed)=",enc)
print("decode==seed:", dec==seed)

# Known: base32 of ASCII "12345678901234567890" is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
print("matches known GEZD... :", enc=="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")

# --- faithful port of my C++ ValidateTotp (with replay protection) ---
def validate(key, code, now, last_step, step=30, digits=6, window=1):
    if len(code)!=digits or not all('0'<=c<='9' for c in code): return None
    current = now//step
    for w in range(-window, window+1):
        if w<0 and current < -w: continue
        counter = current + w
        if counter <= last_step: continue          # "<=", not "=="
        if totp_at(key, counter*step, step, digits) == int(code): return counter
    return None

print("\n== Replay protection ==")
T=1800000000
c=f"{totp_at(seed,T):06d}"
s1=validate(seed,c,T,0)
checks = {
    "fresh code accepted":             s1==T//30,
    "same code rejected":              validate(seed,c,T+5,s1) is None,
    "previous step rejected":          validate(seed,f"{totp_at(seed,T-30):06d}",T,s1) is None,
    "next step accepted":              validate(seed,f"{totp_at(seed,T+30):06d}",T,s1)==T//30+1,
    "old code after clock turned back":validate(seed,f"{totp_at(seed,T-3600):06d}",T-3600,s1) is None,
    "'12abc' rejected":                validate(seed,"12abc",T,0) is None,
}
for k,v in checks.items(): print(f"{k:<34} {'OK' if v else 'FAIL'}")
ok_all &= all(checks.values())

print("\nALL CHECKS PASS:", ok_all)
