
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072dd0a <.text+0x32cd0a>:
  72dd0a:	55                   	push   ebp
  72dd0b:	8b ec                	mov    ebp,esp
  72dd0d:	51                   	push   ecx
  72dd0e:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  72dd13:	33 c5                	xor    eax,ebp
  72dd15:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  72dd18:	53                   	push   ebx
  72dd19:	8a 5d 14             	mov    bl,BYTE PTR [ebp+0x14]
  72dd1c:	33 c9                	xor    ecx,ecx
  72dd1e:	56                   	push   esi
  72dd1f:	6a 02                	push   0x2
  72dd21:	80 fb 01             	cmp    bl,0x1
  72dd24:	58                   	pop    eax
  72dd25:	0f 45 c1             	cmovne eax,ecx
  72dd28:	83 7d 10 04          	cmp    DWORD PTR [ebp+0x10],0x4
  72dd2c:	75 6d                	jne    0x72dd9b
  72dd2e:	38 4d 18             	cmp    BYTE PTR [ebp+0x18],cl
  72dd31:	74 68                	je     0x72dd9b
  72dd33:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  72dd36:	e8 0e b7 13 00       	call   0x869449
  72dd3b:	59                   	pop    ecx
  72dd3c:	8d 04 45 02 00 00 00 	lea    eax,[eax*2+0x2]
  72dd43:	e8 08 94 14 00       	call   0x877150
  72dd48:	8b f4                	mov    esi,esp
  72dd4a:	6a ff                	push   0xffffffff
  72dd4c:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  72dd4f:	68 ff ff ff 3f       	push   0x3fffffff
  72dd54:	56                   	push   esi
  72dd55:	e8 8b b5 13 00       	call   0x8692e5
  72dd5a:	83 c4 10             	add    esp,0x10
  72dd5d:	b9 80 00 00 00       	mov    ecx,0x80
  72dd62:	80 fb 01             	cmp    bl,0x1
  72dd65:	b8 80 00 00 20       	mov    eax,0x20000080
  72dd6a:	0f 45 c1             	cmovne eax,ecx
  72dd6d:	6a 00                	push   0x0
  72dd6f:	50                   	push   eax
  72dd70:	6a 03                	push   0x3
  72dd72:	6a 00                	push   0x0
  72dd74:	6a 01                	push   0x1
  72dd76:	68 00 00 00 80       	push   0x80000000
  72dd7b:	56                   	push   esi
  72dd7c:	ff 15 b4 b2 8f 00    	call   DWORD PTR ds:0x8fb2b4
  72dd82:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  72dd85:	89 01                	mov    DWORD PTR [ecx],eax
  72dd87:	83 f8 ff             	cmp    eax,0xffffffff
  72dd8a:	75 08                	jne    0x72dd94
  72dd8c:	ff 15 48 b2 8f 00    	call   DWORD PTR ds:0x8fb248
  72dd92:	eb 19                	jmp    0x72ddad
  72dd94:	a1 60 d2 9a 00       	mov    eax,ds:0x9ad260
  72dd99:	eb 12                	jmp    0x72ddad
  72dd9b:	50                   	push   eax
  72dd9c:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  72dd9f:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  72dda2:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72dda5:	e8 dd 71 13 00       	call   0x864f87
  72ddaa:	83 c4 10             	add    esp,0x10
  72ddad:	8d 65 f4             	lea    esp,[ebp-0xc]
  72ddb0:	5e                   	pop    esi
  72ddb1:	5b                   	pop    ebx
  72ddb2:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  72ddb5:	33 cd                	xor    ecx,ebp
  72ddb7:	e8 3c 82 14 00       	call   0x875ff8
  72ddbc:	c9                   	leave
  72ddbd:	c3                   	ret
