
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00713b90 <.text+0x312b90>:
  713b90:	55                   	push   ebp
  713b91:	8b ec                	mov    ebp,esp
  713b93:	51                   	push   ecx
  713b94:	53                   	push   ebx
  713b95:	56                   	push   esi
  713b96:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  713b99:	57                   	push   edi
  713b9a:	68 71 e9 6b 3d       	push   0x3d6be971
  713b9f:	6a 16                	push   0x16
  713ba1:	56                   	push   esi
  713ba2:	e8 b5 f8 00 00       	call   0x72345c
  713ba7:	83 c4 0c             	add    esp,0xc
  713baa:	33 c9                	xor    ecx,ecx
  713bac:	6a 04                	push   0x4
  713bae:	5f                   	pop    edi
  713baf:	88 44 0e 16          	mov    BYTE PTR [esi+ecx*1+0x16],al
  713bb3:	c1 e8 08             	shr    eax,0x8
  713bb6:	41                   	inc    ecx
  713bb7:	3b cf                	cmp    ecx,edi
  713bb9:	72 f4                	jb     0x713baf
  713bbb:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  713bbe:	6a 1a                	push   0x1a
  713bc0:	8d 4b 1e             	lea    ecx,[ebx+0x1e]
  713bc3:	8b c1                	mov    eax,ecx
  713bc5:	83 e0 0f             	and    eax,0xf
  713bc8:	8b 14 85 50 d6 9b 00 	mov    edx,DWORD PTR [eax*4+0x9bd650]
  713bcf:	33 d1                	xor    edx,ecx
  713bd1:	8b c2                	mov    eax,edx
  713bd3:	88 55 fc             	mov    BYTE PTR [ebp-0x4],dl
  713bd6:	c1 e8 08             	shr    eax,0x8
  713bd9:	88 45 fd             	mov    BYTE PTR [ebp-0x3],al
  713bdc:	8b c2                	mov    eax,edx
  713bde:	c1 e8 10             	shr    eax,0x10
  713be1:	c1 ea 18             	shr    edx,0x18
  713be4:	88 45 fe             	mov    BYTE PTR [ebp-0x2],al
  713be7:	33 c0                	xor    eax,eax
  713be9:	88 55 ff             	mov    BYTE PTR [ebp-0x1],dl
  713bec:	2b de                	sub    ebx,esi
  713bee:	8b d6                	mov    edx,esi
  713bf0:	89 45 10             	mov    DWORD PTR [ebp+0x10],eax
  713bf3:	5e                   	pop    esi
  713bf4:	8a 02                	mov    al,BYTE PTR [edx]
  713bf6:	8d 0c 13             	lea    ecx,[ebx+edx*1]
  713bf9:	83 e1 03             	and    ecx,0x3
  713bfc:	30 44 0d 10          	xor    BYTE PTR [ebp+ecx*1+0x10],al
  713c00:	42                   	inc    edx
  713c01:	83 ee 01             	sub    esi,0x1
  713c04:	75 ee                	jne    0x713bf4
  713c06:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  713c09:	83 c2 1a             	add    edx,0x1a
  713c0c:	8d 0c 13             	lea    ecx,[ebx+edx*1]
  713c0f:	83 e1 03             	and    ecx,0x3
  713c12:	8a 44 0d 10          	mov    al,BYTE PTR [ebp+ecx*1+0x10]
  713c16:	32 44 0d fc          	xor    al,BYTE PTR [ebp+ecx*1-0x4]
  713c1a:	88 02                	mov    BYTE PTR [edx],al
  713c1c:	42                   	inc    edx
  713c1d:	83 ef 01             	sub    edi,0x1
  713c20:	75 ea                	jne    0x713c0c
  713c22:	5f                   	pop    edi
  713c23:	5e                   	pop    esi
  713c24:	5b                   	pop    ebx
  713c25:	c9                   	leave
  713c26:	c3                   	ret
