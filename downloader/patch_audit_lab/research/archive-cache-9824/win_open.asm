
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00864f87 <.text+0x463f87>:
  864f87:	55                   	push   ebp
  864f88:	8b ec                	mov    ebp,esp
  864f8a:	83 ec 0c             	sub    esp,0xc
  864f8d:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  864f92:	33 c5                	xor    eax,ebp
  864f94:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  864f97:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  864f9a:	53                   	push   ebx
  864f9b:	56                   	push   esi
  864f9c:	57                   	push   edi
  864f9d:	83 f8 0d             	cmp    eax,0xd
  864fa0:	0f 87 30 01 00 00    	ja     0x8650d6
  864fa6:	ff 24 85 f3 50 86 00 	jmp    DWORD PTR [eax*4+0x8650f3]
  864fad:	bf 00 00 00 40       	mov    edi,0x40000000
  864fb2:	eb 62                	jmp    0x865016
  864fb4:	bf 00 00 00 c0       	mov    edi,0xc0000000
  864fb9:	eb 5b                	jmp    0x865016
  864fbb:	bf 00 00 00 40       	mov    edi,0x40000000
  864fc0:	33 db                	xor    ebx,ebx
  864fc2:	43                   	inc    ebx
  864fc3:	eb 54                	jmp    0x865019
  864fc5:	bf 00 00 00 c0       	mov    edi,0xc0000000
  864fca:	eb f4                	jmp    0x864fc0
  864fcc:	bf 00 00 00 80       	mov    edi,0x80000000
  864fd1:	6a 03                	push   0x3
  864fd3:	eb 43                	jmp    0x865018
  864fd5:	bf 00 00 00 40       	mov    edi,0x40000000
  864fda:	eb f5                	jmp    0x864fd1
  864fdc:	bf 00 00 00 c0       	mov    edi,0xc0000000
  864fe1:	eb ee                	jmp    0x864fd1
  864fe3:	bf 00 00 00 40       	mov    edi,0x40000000
  864fe8:	6a 02                	push   0x2
  864fea:	eb 2c                	jmp    0x865018
  864fec:	bf 00 00 00 c0       	mov    edi,0xc0000000
  864ff1:	eb f5                	jmp    0x864fe8
  864ff3:	bf 00 00 00 40       	mov    edi,0x40000000
  864ff8:	6a 05                	push   0x5
  864ffa:	eb 1c                	jmp    0x865018
  864ffc:	bf 00 00 00 c0       	mov    edi,0xc0000000
  865001:	eb f5                	jmp    0x864ff8
  865003:	bf 14 01 12 00       	mov    edi,0x120114
  865008:	eb 0c                	jmp    0x865016
  86500a:	6a 04                	push   0x4
  86500c:	5f                   	pop    edi
  86500d:	8b df                	mov    ebx,edi
  86500f:	eb 08                	jmp    0x865019
  865011:	bf 14 01 12 80       	mov    edi,0x80120114
  865016:	6a 04                	push   0x4
  865018:	5b                   	pop    ebx
  865019:	8b 4d 14             	mov    ecx,DWORD PTR [ebp+0x14]
  86501c:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  86501f:	83 e1 02             	and    ecx,0x2
  865022:	c1 e1 1c             	shl    ecx,0x1c
  865025:	c1 e8 04             	shr    eax,0x4
  865028:	81 c9 80 00 00 00    	or     ecx,0x80
  86502e:	f7 d0                	not    eax
  865030:	8b d1                	mov    edx,ecx
  865032:	83 e0 07             	and    eax,0x7
  865035:	81 ca 00 01 00 00    	or     edx,0x100
  86503b:	f6 45 14 01          	test   BYTE PTR [ebp+0x14],0x1
  86503f:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
  865042:	0f 44 d1             	cmove  edx,ecx
  865045:	f6 45 14 04          	test   BYTE PTR [ebp+0x14],0x4
  865049:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  86504c:	74 08                	je     0x865056
  86504e:	81 ca 00 00 00 10    	or     edx,0x10000000
  865054:	eb 0c                	jmp    0x865062
  865056:	f6 45 14 08          	test   BYTE PTR [ebp+0x14],0x8
  86505a:	74 09                	je     0x865065
  86505c:	81 ca 00 00 00 08    	or     edx,0x8000000
  865062:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  865065:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  865068:	e8 dc 43 00 00       	call   0x869449
  86506d:	59                   	pop    ecx
  86506e:	8d 04 45 02 00 00 00 	lea    eax,[eax*2+0x2]
  865075:	e8 d6 20 01 00       	call   0x877150
  86507a:	8b f4                	mov    esi,esp
  86507c:	6a ff                	push   0xffffffff
  86507e:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  865081:	68 ff ff ff 3f       	push   0x3fffffff
  865086:	56                   	push   esi
  865087:	e8 59 42 00 00       	call   0x8692e5
  86508c:	83 c4 10             	add    esp,0x10
  86508f:	6a 00                	push   0x0
  865091:	ff 75 f8             	push   DWORD PTR [ebp-0x8]
  865094:	53                   	push   ebx
  865095:	6a 00                	push   0x0
  865097:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
  86509a:	57                   	push   edi
  86509b:	56                   	push   esi
  86509c:	ff 15 b4 b2 8f 00    	call   DWORD PTR ds:0x8fb2b4
  8650a2:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  8650a5:	8b d0                	mov    edx,eax
  8650a7:	89 11                	mov    DWORD PTR [ecx],edx
  8650a9:	83 fa ff             	cmp    edx,0xffffffff
  8650ac:	75 07                	jne    0x8650b5
  8650ae:	e8 fe 8d 00 00       	call   0x86deb1
  8650b3:	eb 29                	jmp    0x8650de
  8650b5:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  8650b8:	83 f8 0b             	cmp    eax,0xb
  8650bb:	74 05                	je     0x8650c2
  8650bd:	83 f8 0c             	cmp    eax,0xc
  8650c0:	75 0d                	jne    0x8650cf
  8650c2:	6a 02                	push   0x2
  8650c4:	6a 00                	push   0x0
  8650c6:	6a 00                	push   0x0
  8650c8:	52                   	push   edx
  8650c9:	ff 15 d0 b2 8f 00    	call   DWORD PTR ds:0x8fb2d0
  8650cf:	a1 60 d2 9a 00       	mov    eax,ds:0x9ad260
  8650d4:	eb 08                	jmp    0x8650de
  8650d6:	6a 02                	push   0x2
  8650d8:	e8 06 8d 00 00       	call   0x86dde3
  8650dd:	59                   	pop    ecx
  8650de:	8d 65 e8             	lea    esp,[ebp-0x18]
  8650e1:	5f                   	pop    edi
  8650e2:	5e                   	pop    esi
  8650e3:	5b                   	pop    ebx
  8650e4:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  8650e7:	33 cd                	xor    ecx,ebp
  8650e9:	e8 0a 0f 01 00       	call   0x875ff8
  8650ee:	c9                   	leave
  8650ef:	c3                   	ret
  8650f0:	0f 1f 00             	nop    DWORD PTR [eax]
