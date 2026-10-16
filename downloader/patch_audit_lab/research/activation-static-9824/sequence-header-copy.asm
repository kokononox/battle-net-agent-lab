
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071e9d4 <.text+0x31d9d4>:
  71e9d4:	55                   	push   ebp
  71e9d5:	8b ec                	mov    ebp,esp
  71e9d7:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  71e9da:	56                   	push   esi
  71e9db:	8b f1                	mov    esi,ecx
  71e9dd:	57                   	push   edi
  71e9de:	8b 7d 10             	mov    edi,DWORD PTR [ebp+0x10]
  71e9e1:	57                   	push   edi
  71e9e2:	89 46 04             	mov    DWORD PTR [esi+0x4],eax
  71e9e5:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71e9e8:	89 46 08             	mov    DWORD PTR [esi+0x8],eax
  71e9eb:	e8 1a 06 00 00       	call   0x71f00a
  71e9f0:	83 f8 06             	cmp    eax,0x6
  71e9f3:	75 4c                	jne    0x71ea41
  71e9f5:	68 50 e7 9b 00       	push   0x9be750
  71e9fa:	6a 00                	push   0x0
  71e9fc:	68 08 bc 8f 00       	push   0x8fbc08
  71ea01:	6a 02                	push   0x2
  71ea03:	68 38 ba 9b 00       	push   0x9bba38
  71ea08:	e8 36 4e 1a 00       	call   0x8c3843
  71ea0d:	83 c4 14             	add    esp,0x14
  71ea10:	8b ce                	mov    ecx,esi
  71ea12:	e8 c0 03 00 00       	call   0x71edd7
  71ea17:	8b ce                	mov    ecx,esi
  71ea19:	e8 12 fa ff ff       	call   0x71e430
  71ea1e:	85 c0                	test   eax,eax
  71ea20:	75 1f                	jne    0x71ea41
  71ea22:	8b 0f                	mov    ecx,DWORD PTR [edi]
  71ea24:	6a 10                	push   0x10
  71ea26:	81 c1 10 01 00 00    	add    ecx,0x110
  71ea2c:	83 c6 0c             	add    esi,0xc
  71ea2f:	5a                   	pop    edx
  71ea30:	8b 06                	mov    eax,DWORD PTR [esi]
  71ea32:	8d 76 08             	lea    esi,[esi+0x8]
  71ea35:	89 01                	mov    DWORD PTR [ecx],eax
  71ea37:	8d 49 04             	lea    ecx,[ecx+0x4]
  71ea3a:	83 ea 01             	sub    edx,0x1
  71ea3d:	75 f1                	jne    0x71ea30
  71ea3f:	33 c0                	xor    eax,eax
  71ea41:	5f                   	pop    edi
  71ea42:	5e                   	pop    esi
  71ea43:	5d                   	pop    ebp
  71ea44:	c2 0c 00             	ret    0xc
