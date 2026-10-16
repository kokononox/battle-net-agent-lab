
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00722d9b <.text+0x321d9b>:
  722d9b:	55                   	push   ebp
  722d9c:	8b ec                	mov    ebp,esp
  722d9e:	8b 55 10             	mov    edx,DWORD PTR [ebp+0x10]
  722da1:	2b 55 08             	sub    edx,DWORD PTR [ebp+0x8]
  722da4:	53                   	push   ebx
  722da5:	56                   	push   esi
  722da6:	8b 75 14             	mov    esi,DWORD PTR [ebp+0x14]
  722da9:	8b d9                	mov    ebx,ecx
  722dab:	1b 75 0c             	sbb    esi,DWORD PTR [ebp+0xc]
  722dae:	75 05                	jne    0x722db5
  722db0:	83 fa 40             	cmp    edx,0x40
  722db3:	72 6d                	jb     0x722e22
  722db5:	33 c9                	xor    ecx,ecx
  722db7:	39 34 cd fc ee 9b 00 	cmp    DWORD PTR [ecx*8+0x9beefc],esi
  722dbe:	77 11                	ja     0x722dd1
  722dc0:	72 09                	jb     0x722dcb
  722dc2:	39 14 cd f8 ee 9b 00 	cmp    DWORD PTR [ecx*8+0x9beef8],edx
  722dc9:	77 06                	ja     0x722dd1
  722dcb:	41                   	inc    ecx
  722dcc:	83 f9 34             	cmp    ecx,0x34
  722dcf:	72 e6                	jb     0x722db7
  722dd1:	80 7d 18 00          	cmp    BYTE PTR [ebp+0x18],0x0
  722dd5:	57                   	push   edi
  722dd6:	8b 7d 1c             	mov    edi,DWORD PTR [ebp+0x1c]
  722dd9:	8b 44 8f fc          	mov    eax,DWORD PTR [edi+ecx*4-0x4]
  722ddd:	75 07                	jne    0x722de6
  722ddf:	40                   	inc    eax
  722de0:	89 44 8f fc          	mov    DWORD PTR [edi+ecx*4-0x4],eax
  722de4:	eb 3b                	jmp    0x722e21
  722de6:	85 c0                	test   eax,eax
  722de8:	74 37                	je     0x722e21
  722dea:	48                   	dec    eax
  722deb:	89 44 8f fc          	mov    DWORD PTR [edi+ecx*4-0x4],eax
  722def:	6b 43 04 05          	imul   eax,DWORD PTR [ebx+0x4],0x5
  722df3:	56                   	push   esi
  722df4:	52                   	push   edx
  722df5:	6a 05                	push   0x5
  722df7:	83 c0 20             	add    eax,0x20
  722dfa:	03 c3                	add    eax,ebx
  722dfc:	50                   	push   eax
  722dfd:	e8 ce d2 fe ff       	call   0x7100d0
  722e02:	6b 43 04 05          	imul   eax,DWORD PTR [ebx+0x4],0x5
  722e06:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  722e09:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  722e0c:	05 6a 15 00 00       	add    eax,0x156a
  722e11:	03 c3                	add    eax,ebx
  722e13:	6a 05                	push   0x5
  722e15:	50                   	push   eax
  722e16:	e8 b5 d2 fe ff       	call   0x7100d0
  722e1b:	83 c4 20             	add    esp,0x20
  722e1e:	ff 43 04             	inc    DWORD PTR [ebx+0x4]
  722e21:	5f                   	pop    edi
  722e22:	5e                   	pop    esi
  722e23:	5b                   	pop    ebx
  722e24:	5d                   	pop    ebp
  722e25:	c2 18 00             	ret    0x18
