
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00865253 <.text+0x464253>:
  865253:	55                   	push   ebp
  865254:	8b ec                	mov    ebp,esp
  865256:	51                   	push   ecx
  865257:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  86525c:	33 c5                	xor    eax,ebp
  86525e:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  865261:	53                   	push   ebx
  865262:	56                   	push   esi
  865263:	57                   	push   edi
  865264:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  865267:	e8 dd 41 00 00       	call   0x869449
  86526c:	59                   	pop    ecx
  86526d:	8d 04 45 02 00 00 00 	lea    eax,[eax*2+0x2]
  865274:	e8 d7 1e 01 00       	call   0x877150
  865279:	8b fc                	mov    edi,esp
  86527b:	bb ff ff ff 3f       	mov    ebx,0x3fffffff
  865280:	6a ff                	push   0xffffffff
  865282:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  865285:	53                   	push   ebx
  865286:	57                   	push   edi
  865287:	e8 59 40 00 00       	call   0x8692e5
  86528c:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  86528f:	e8 b5 41 00 00       	call   0x869449
  865294:	83 c4 14             	add    esp,0x14
  865297:	8d 04 45 02 00 00 00 	lea    eax,[eax*2+0x2]
  86529e:	e8 ad 1e 01 00       	call   0x877150
  8652a3:	8b f4                	mov    esi,esp
  8652a5:	6a ff                	push   0xffffffff
  8652a7:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  8652aa:	53                   	push   ebx
  8652ab:	56                   	push   esi
  8652ac:	e8 34 40 00 00       	call   0x8692e5
  8652b1:	83 c4 10             	add    esp,0x10
  8652b4:	6a 00                	push   0x0
  8652b6:	57                   	push   edi
  8652b7:	56                   	push   esi
  8652b8:	ff 15 dc b2 8f 00    	call   DWORD PTR ds:0x8fb2dc
  8652be:	85 c0                	test   eax,eax
  8652c0:	75 07                	jne    0x8652c9
  8652c2:	e8 ea 8b 00 00       	call   0x86deb1
  8652c7:	eb 05                	jmp    0x8652ce
  8652c9:	a1 60 d2 9a 00       	mov    eax,ds:0x9ad260
  8652ce:	8d 65 f0             	lea    esp,[ebp-0x10]
  8652d1:	5f                   	pop    edi
  8652d2:	5e                   	pop    esi
  8652d3:	5b                   	pop    ebx
  8652d4:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  8652d7:	33 cd                	xor    ecx,ebp
  8652d9:	e8 1a 0d 01 00       	call   0x875ff8
  8652de:	c9                   	leave
  8652df:	c3                   	ret
