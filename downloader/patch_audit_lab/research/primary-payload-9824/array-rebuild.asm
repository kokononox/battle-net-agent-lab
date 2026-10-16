
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00722bd6 <.text+0x321bd6>:
  722bd6:	55                   	push   ebp
  722bd7:	8b ec                	mov    ebp,esp
  722bd9:	81 ec d8 00 00 00    	sub    esp,0xd8
  722bdf:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  722be4:	33 c5                	xor    eax,ebp
  722be6:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  722be9:	53                   	push   ebx
  722bea:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  722bed:	8b d3                	mov    edx,ebx
  722bef:	56                   	push   esi
  722bf0:	57                   	push   edi
  722bf1:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  722bf4:	8b f1                	mov    esi,ecx
  722bf6:	c1 e2 02             	shl    edx,0x2
  722bf9:	8b c2                	mov    eax,edx
  722bfb:	89 bd 28 ff ff ff    	mov    DWORD PTR [ebp-0xd8],edi
  722c01:	68 80 2f 72 00       	push   0x722f80
  722c06:	c1 f8 02             	sar    eax,0x2
  722c09:	50                   	push   eax
  722c0a:	8d 04 3a             	lea    eax,[edx+edi*1]
  722c0d:	50                   	push   eax
  722c0e:	57                   	push   edi
  722c0f:	e8 3b f9 ff ff       	call   0x72254f
  722c14:	68 d0 00 00 00       	push   0xd0
  722c19:	8d 85 2c ff ff ff    	lea    eax,[ebp-0xd4]
  722c1f:	6a 00                	push   0x0
  722c21:	50                   	push   eax
  722c22:	e8 e9 70 15 00       	call   0x879d10
  722c27:	83 c4 1c             	add    esp,0x1c
  722c2a:	8d 85 2c ff ff ff    	lea    eax,[ebp-0xd4]
  722c30:	8b ce                	mov    ecx,esi
  722c32:	50                   	push   eax
  722c33:	6a 00                	push   0x0
  722c35:	53                   	push   ebx
  722c36:	57                   	push   edi
  722c37:	e8 67 00 00 00       	call   0x722ca3
  722c3c:	b8 42 04 00 00       	mov    eax,0x442
  722c41:	6a 33                	push   0x33
  722c43:	5a                   	pop    edx
  722c44:	8b c8                	mov    ecx,eax
  722c46:	8b f8                	mov    edi,eax
  722c48:	39 84 95 2c ff ff ff 	cmp    DWORD PTR [ebp+edx*4-0xd4],eax
  722c4f:	8b c7                	mov    eax,edi
  722c51:	0f 42 8c 95 2c ff ff 	cmovb  ecx,DWORD PTR [ebp+edx*4-0xd4]
  722c58:	ff 
  722c59:	2b c1                	sub    eax,ecx
  722c5b:	89 8c 95 2c ff ff ff 	mov    DWORD PTR [ebp+edx*4-0xd4],ecx
  722c62:	83 ea 01             	sub    edx,0x1
  722c65:	8b c8                	mov    ecx,eax
  722c67:	8b f8                	mov    edi,eax
  722c69:	79 dd                	jns    0x722c48
  722c6b:	83 26 00             	and    DWORD PTR [esi],0x0
  722c6e:	8d 85 2c ff ff ff    	lea    eax,[ebp-0xd4]
  722c74:	8b bd 28 ff ff ff    	mov    edi,DWORD PTR [ebp-0xd8]
  722c7a:	8b ce                	mov    ecx,esi
  722c7c:	50                   	push   eax
  722c7d:	6a 01                	push   0x1
  722c7f:	53                   	push   ebx
  722c80:	57                   	push   edi
  722c81:	0f ae f0             	mfence
  722c84:	e8 1a 00 00 00       	call   0x722ca3
  722c89:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  722c8c:	5f                   	pop    edi
  722c8d:	0f ae f0             	mfence
  722c90:	c7 06 01 00 00 00    	mov    DWORD PTR [esi],0x1
  722c96:	33 cd                	xor    ecx,ebp
  722c98:	5e                   	pop    esi
  722c99:	5b                   	pop    ebx
  722c9a:	e8 59 33 15 00       	call   0x875ff8
  722c9f:	c9                   	leave
  722ca0:	c2 08 00             	ret    0x8
