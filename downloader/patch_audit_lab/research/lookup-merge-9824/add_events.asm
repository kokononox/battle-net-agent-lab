
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072f280 <.text+0x32e280>:
  72f280:	55                   	push   ebp
  72f281:	8b ec                	mov    ebp,esp
  72f283:	51                   	push   ecx
  72f284:	53                   	push   ebx
  72f285:	56                   	push   esi
  72f286:	8b f1                	mov    esi,ecx
  72f288:	57                   	push   edi
  72f289:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  72f28c:	8b 86 24 01 00 00    	mov    eax,DWORD PTR [esi+0x124]
  72f292:	40                   	inc    eax
  72f293:	3b 86 28 01 00 00    	cmp    eax,DWORD PTR [esi+0x128]
  72f299:	72 05                	jb     0x72f2a0
  72f29b:	e8 70 ff ff ff       	call   0x72f210
  72f2a0:	8a 5d 0c             	mov    bl,BYTE PTR [ebp+0xc]
  72f2a3:	33 c0                	xor    eax,eax
  72f2a5:	40                   	inc    eax
  72f2a6:	bf 00 00 00 c0       	mov    edi,0xc0000000
  72f2ab:	84 db                	test   bl,bl
  72f2ad:	0f 45 f8             	cmovne edi,eax
  72f2b0:	8b 86 24 01 00 00    	mov    eax,DWORD PTR [esi+0x124]
  72f2b6:	8b d0                	mov    edx,eax
  72f2b8:	c1 e2 04             	shl    edx,0x4
  72f2bb:	03 96 20 01 00 00    	add    edx,DWORD PTR [esi+0x120]
  72f2c1:	40                   	inc    eax
  72f2c2:	89 86 24 01 00 00    	mov    DWORD PTR [esi+0x124],eax
  72f2c8:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  72f2cb:	8b 06                	mov    eax,DWORD PTR [esi]
  72f2cd:	8b 4e 04             	mov    ecx,DWORD PTR [esi+0x4]
  72f2d0:	89 4a 04             	mov    DWORD PTR [edx+0x4],ecx
  72f2d3:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  72f2d6:	89 7a 08             	mov    DWORD PTR [edx+0x8],edi
  72f2d9:	89 02                	mov    DWORD PTR [edx],eax
  72f2db:	8b 81 24 01 00 00    	mov    eax,DWORD PTR [ecx+0x124]
  72f2e1:	8b d0                	mov    edx,eax
  72f2e3:	c1 e2 04             	shl    edx,0x4
  72f2e6:	03 91 20 01 00 00    	add    edx,DWORD PTR [ecx+0x120]
  72f2ec:	40                   	inc    eax
  72f2ed:	89 81 24 01 00 00    	mov    DWORD PTR [ecx+0x124],eax
  72f2f3:	8b 4e 08             	mov    ecx,DWORD PTR [esi+0x8]
  72f2f6:	03 0e                	add    ecx,DWORD PTR [esi]
  72f2f8:	8b 46 0c             	mov    eax,DWORD PTR [esi+0xc]
  72f2fb:	13 46 04             	adc    eax,DWORD PTR [esi+0x4]
  72f2fe:	f7 df                	neg    edi
  72f300:	89 7a 08             	mov    DWORD PTR [edx+0x8],edi
  72f303:	84 db                	test   bl,bl
  72f305:	5f                   	pop    edi
  72f306:	5e                   	pop    esi
  72f307:	89 0a                	mov    DWORD PTR [edx],ecx
  72f309:	89 42 04             	mov    DWORD PTR [edx+0x4],eax
  72f30c:	5b                   	pop    ebx
  72f30d:	75 08                	jne    0x72f317
  72f30f:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  72f312:	e8 c7 f4 ff ff       	call   0x72e7de
  72f317:	c9                   	leave
  72f318:	c2 08 00             	ret    0x8
