
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072219d <.text+0x32119d>:
  72219d:	6a ff                	push   0xffffffff
  72219f:	ff 71 04             	push   DWORD PTR [ecx+0x4]
  7221a2:	ff 15 54 b2 8f 00    	call   DWORD PTR ds:0x8fb254
  7221a8:	85 c0                	test   eax,eax
  7221aa:	74 70                	je     0x72221c
  7221ac:	3d 80 00 00 00       	cmp    eax,0x80
  7221b1:	74 4e                	je     0x722201
  7221b3:	3d 02 01 00 00       	cmp    eax,0x102
  7221b8:	74 29                	je     0x7221e3
  7221ba:	83 f8 ff             	cmp    eax,0xffffffff
  7221bd:	75 3f                	jne    0x7221fe
  7221bf:	ff 15 48 b2 8f 00    	call   DWORD PTR ds:0x8fb248
  7221c5:	50                   	push   eax
  7221c6:	68 60 ee 9b 00       	push   0x9bee60
  7221cb:	6a 00                	push   0x0
  7221cd:	68 08 bc 8f 00       	push   0x8fbc08
  7221d2:	6a 04                	push   0x4
  7221d4:	68 38 ba 9b 00       	push   0x9bba38
  7221d9:	e8 65 16 1a 00       	call   0x8c3843
  7221de:	83 c4 18             	add    esp,0x18
  7221e1:	eb 1b                	jmp    0x7221fe
  7221e3:	68 2c ee 9b 00       	push   0x9bee2c
  7221e8:	6a 00                	push   0x0
  7221ea:	68 08 bc 8f 00       	push   0x8fbc08
  7221ef:	6a 04                	push   0x4
  7221f1:	68 38 ba 9b 00       	push   0x9bba38
  7221f6:	e8 48 16 1a 00       	call   0x8c3843
  7221fb:	83 c4 14             	add    esp,0x14
  7221fe:	32 c0                	xor    al,al
  722200:	c3                   	ret
  722201:	68 f8 ed 9b 00       	push   0x9bedf8
  722206:	6a 00                	push   0x0
  722208:	68 08 bc 8f 00       	push   0x8fbc08
  72220d:	6a 02                	push   0x2
  72220f:	68 38 ba 9b 00       	push   0x9bba38
  722214:	e8 2a 16 1a 00       	call   0x8c3843
  722219:	83 c4 14             	add    esp,0x14
  72221c:	b0 01                	mov    al,0x1
  72221e:	c3                   	ret
