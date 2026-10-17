
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0086516f <.text+0x46416f>:
  86516f:	55                   	push   ebp
  865170:	8b ec                	mov    ebp,esp
  865172:	83 ec 14             	sub    esp,0x14
  865175:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  865178:	0f 57 c0             	xorps  xmm0,xmm0
  86517b:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  86517f:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
  865182:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  865185:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  865188:	8d 45 ec             	lea    eax,[ebp-0x14]
  86518b:	50                   	push   eax
  86518c:	8d 45 18             	lea    eax,[ebp+0x18]
  86518f:	66 0f 13 45 ec       	movlpd QWORD PTR [ebp-0x14],xmm0
  865194:	50                   	push   eax
  865195:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  865198:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  86519b:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  86519e:	ff 30                	push   DWORD PTR [eax]
  8651a0:	ff 15 c8 b2 8f 00    	call   DWORD PTR ds:0x8fb2c8
  8651a6:	85 c0                	test   eax,eax
  8651a8:	75 18                	jne    0x8651c2
  8651aa:	ff 15 48 b2 8f 00    	call   DWORD PTR ds:0x8fb248
  8651b0:	83 f8 26             	cmp    eax,0x26
  8651b3:	74 0d                	je     0x8651c2
  8651b5:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  8651b8:	83 20 00             	and    DWORD PTR [eax],0x0
  8651bb:	e8 f1 8c 00 00       	call   0x86deb1
  8651c0:	c9                   	leave
  8651c1:	c3                   	ret
  8651c2:	8b 4d 1c             	mov    ecx,DWORD PTR [ebp+0x1c]
  8651c5:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  8651c8:	89 01                	mov    DWORD PTR [ecx],eax
  8651ca:	a1 60 d2 9a 00       	mov    eax,ds:0x9ad260
  8651cf:	c9                   	leave
  8651d0:	c3                   	ret
