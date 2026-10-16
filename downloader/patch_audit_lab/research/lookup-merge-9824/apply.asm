
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072f0be <.text+0x32e0be>:
  72f0be:	55                   	push   ebp
  72f0bf:	8b ec                	mov    ebp,esp
  72f0c1:	0f b6 45 08          	movzx  eax,BYTE PTR [ebp+0x8]
  72f0c5:	53                   	push   ebx
  72f0c6:	8b d9                	mov    ebx,ecx
  72f0c8:	56                   	push   esi
  72f0c9:	57                   	push   edi
  72f0ca:	83 f8 07             	cmp    eax,0x7
  72f0cd:	0f 87 b3 00 00 00    	ja     0x72f186
  72f0d3:	ff 24 85 aa f1 72 00 	jmp    DWORD PTR [eax*4+0x72f1aa]
  72f0da:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  72f0dd:	8d 7b 10             	lea    edi,[ebx+0x10]
  72f0e0:	c6 43 08 01          	mov    BYTE PTR [ebx+0x8],0x1
  72f0e4:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f0e5:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f0e6:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f0e7:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f0e8:	83 a3 24 01 00 00 00 	and    DWORD PTR [ebx+0x124],0x0
  72f0ef:	6a 01                	push   0x1
  72f0f1:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  72f0f4:	e8 87 01 00 00       	call   0x72f280
  72f0f9:	e9 a4 00 00 00       	jmp    0x72f1a2
  72f0fe:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  72f101:	8d 7b 10             	lea    edi,[ebx+0x10]
  72f104:	c6 43 08 01          	mov    BYTE PTR [ebx+0x8],0x1
  72f108:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f109:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f10a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f10b:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f10c:	83 a3 24 01 00 00 00 	and    DWORD PTR [ebx+0x124],0x0
  72f113:	e9 8a 00 00 00       	jmp    0x72f1a2
  72f118:	33 c0                	xor    eax,eax
  72f11a:	88 43 08             	mov    BYTE PTR [ebx+0x8],al
  72f11d:	89 43 10             	mov    DWORD PTR [ebx+0x10],eax
  72f120:	89 43 14             	mov    DWORD PTR [ebx+0x14],eax
  72f123:	89 43 18             	mov    DWORD PTR [ebx+0x18],eax
  72f126:	89 43 1c             	mov    DWORD PTR [ebx+0x1c],eax
  72f129:	89 83 24 01 00 00    	mov    DWORD PTR [ebx+0x124],eax
  72f12f:	eb 71                	jmp    0x72f1a2
  72f131:	51                   	push   ecx
  72f132:	8b 4b 04             	mov    ecx,DWORD PTR [ebx+0x4]
  72f135:	33 f6                	xor    esi,esi
  72f137:	c7 04 24 00 00 80 3f 	mov    DWORD PTR [esp],0x3f800000
  72f13e:	56                   	push   esi
  72f13f:	6a 01                	push   0x1
  72f141:	68 9c 01 9c 00       	push   0x9c019c
  72f146:	56                   	push   esi
  72f147:	e8 2a b3 fd ff       	call   0x70a476
  72f14c:	6a 01                	push   0x1
  72f14e:	8d 43 10             	lea    eax,[ebx+0x10]
  72f151:	89 b3 24 01 00 00    	mov    DWORD PTR [ebx+0x124],esi
  72f157:	50                   	push   eax
  72f158:	8b cb                	mov    ecx,ebx
  72f15a:	eb 98                	jmp    0x72f0f4
  72f15c:	51                   	push   ecx
  72f15d:	8b 4b 04             	mov    ecx,DWORD PTR [ebx+0x4]
  72f160:	33 f6                	xor    esi,esi
  72f162:	c7 04 24 00 00 80 3f 	mov    DWORD PTR [esp],0x3f800000
  72f169:	56                   	push   esi
  72f16a:	6a 01                	push   0x1
  72f16c:	68 cc 01 9c 00       	push   0x9c01cc
  72f171:	56                   	push   esi
  72f172:	e8 ff b2 fd ff       	call   0x70a476
  72f177:	89 b3 24 01 00 00    	mov    DWORD PTR [ebx+0x124],esi
  72f17d:	eb 23                	jmp    0x72f1a2
  72f17f:	6a 00                	push   0x0
  72f181:	e9 6b ff ff ff       	jmp    0x72f0f1
  72f186:	50                   	push   eax
  72f187:	68 8c ff 9b 00       	push   0x9bff8c
  72f18c:	6a 00                	push   0x0
  72f18e:	68 08 bc 8f 00       	push   0x8fbc08
  72f193:	6a 04                	push   0x4
  72f195:	68 38 ba 9b 00       	push   0x9bba38
  72f19a:	e8 a4 46 19 00       	call   0x8c3843
  72f19f:	83 c4 18             	add    esp,0x18
  72f1a2:	5f                   	pop    edi
  72f1a3:	5e                   	pop    esi
  72f1a4:	5b                   	pop    ebx
  72f1a5:	5d                   	pop    ebp
  72f1a6:	c2 08 00             	ret    0x8
