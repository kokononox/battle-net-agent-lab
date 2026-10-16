"""32-bit lookup3, after Bob Jenkins' public-domain May 2006 algorithm.
Reference: CascLib commit 38a34665624b8775bb875274b36191b21c38d97b,
src/jenkins/lookup3.c. No native dependency. pc/pb ordering follows C.
"""
M=0xffffffff

def rot(x,n):return ((x<<n)|(x>>(32-n)))&M

def hashlittle2(data,pc=0,pb=0):
    a=b=c=(0xdeadbeef+len(data)+pc)&M;c=(c+pb)&M
    pos=0;left=len(data)
    while left>12:
        a=(a+int.from_bytes(data[pos:pos+4],'little'))&M
        b=(b+int.from_bytes(data[pos+4:pos+8],'little'))&M
        c=(c+int.from_bytes(data[pos+8:pos+12],'little'))&M
        a=((a-c)&M)^rot(c,4);c=(c+b)&M
        b=((b-a)&M)^rot(a,6);a=(a+c)&M
        c=((c-b)&M)^rot(b,8);b=(b+a)&M
        a=((a-c)&M)^rot(c,16);c=(c+b)&M
        b=((b-a)&M)^rot(a,19);a=(a+c)&M
        c=((c-b)&M)^rot(b,4);b=(b+a)&M
        pos+=12;left-=12
    if not left:return c,b
    a=(a+int.from_bytes(data[pos:pos+min(left,4)],'little'))&M
    if left>4:b=(b+int.from_bytes(data[pos+4:pos+min(left,8)],'little'))&M
    if left>8:c=(c+int.from_bytes(data[pos+8:pos+left],'little'))&M
    c=((c^b)-rot(b,14))&M
    a=((a^c)-rot(c,11))&M
    b=((b^a)-rot(a,25))&M
    c=((c^b)-rot(b,16))&M
    a=((a^c)-rot(c,4))&M
    b=((b^a)-rot(a,14))&M
    c=((c^b)-rot(b,24))&M
    return c,b

def hashlittle(data,seed=0):return hashlittle2(data,seed,0)[0]
