
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00722b05 <.text+0x321b05>:
  722b05:	55                   	push   ebp
  722b06:	8b ec                	mov    ebp,esp
  722b08:	83 ec 18             	sub    esp,0x18
  722b0b:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  722b0e:	53                   	push   ebx
  722b0f:	56                   	push   esi
  722b10:	57                   	push   edi
  722b11:	8b f9                	mov    edi,ecx
  722b13:	b9 00 00 00 40       	mov    ecx,0x40000000
  722b18:	f7 e1                	mul    ecx
  722b1a:	83 3f 02             	cmp    DWORD PTR [edi],0x2
  722b1d:	8b ca                	mov    ecx,edx
  722b1f:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  722b22:	89 4d fc             	mov    DWORD PTR [ebp-0x4],ecx
  722b25:	75 0d                	jne    0x722b34
  722b27:	8b cf                	mov    ecx,edi
  722b29:	e8 11 03 00 00       	call   0x722e3f
  722b2e:	8b 45 f8             	mov    eax,DWORD PTR [ebp-0x8]
  722b31:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  722b34:	83 3f 01             	cmp    DWORD PTR [edi],0x1
  722b37:	75 79                	jne    0x722bb2
  722b39:	05 e0 01 00 00       	add    eax,0x1e0
  722b3e:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
  722b41:	8b c1                	mov    eax,ecx
  722b43:	6a 00                	push   0x0
  722b45:	5b                   	pop    ebx
  722b46:	13 c3                	adc    eax,ebx
  722b48:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
  722b4b:	39 5f 04             	cmp    DWORD PTR [edi+0x4],ebx
  722b4e:	76 62                	jbe    0x722bb2
  722b50:	8d 47 20             	lea    eax,[edi+0x20]
  722b53:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  722b56:	05 4a 15 00 00       	add    eax,0x154a
  722b5b:	6a 05                	push   0x5
  722b5d:	50                   	push   eax
  722b5e:	e8 9d 03 00 00       	call   0x722f00
  722b63:	6a 05                	push   0x5
  722b65:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  722b68:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
  722b6b:	8b f2                	mov    esi,edx
  722b6d:	e8 8e 03 00 00       	call   0x722f00
  722b72:	8b 4d ec             	mov    ecx,DWORD PTR [ebp-0x14]
  722b75:	83 c4 10             	add    esp,0x10
  722b78:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  722b7b:	8b c2                	mov    eax,edx
  722b7d:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
  722b80:	03 d1                	add    edx,ecx
  722b82:	13 c6                	adc    eax,esi
  722b84:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
  722b87:	3b 75 fc             	cmp    esi,DWORD PTR [ebp-0x4]
  722b8a:	77 17                	ja     0x722ba3
  722b8c:	72 05                	jb     0x722b93
  722b8e:	3b 4d f8             	cmp    ecx,DWORD PTR [ebp-0x8]
  722b91:	77 10                	ja     0x722ba3
  722b93:	8b 4d e8             	mov    ecx,DWORD PTR [ebp-0x18]
  722b96:	3b c1                	cmp    eax,ecx
  722b98:	77 22                	ja     0x722bbc
  722b9a:	72 07                	jb     0x722ba3
  722b9c:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
  722b9f:	3b d0                	cmp    edx,eax
  722ba1:	73 1c                	jae    0x722bbf
  722ba3:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  722ba6:	43                   	inc    ebx
  722ba7:	83 c0 05             	add    eax,0x5
  722baa:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  722bad:	3b 5f 04             	cmp    ebx,DWORD PTR [edi+0x4]
  722bb0:	72 a4                	jb     0x722b56
  722bb2:	6a 0e                	push   0xe
  722bb4:	58                   	pop    eax
  722bb5:	5f                   	pop    edi
  722bb6:	5e                   	pop    esi
  722bb7:	5b                   	pop    ebx
  722bb8:	c9                   	leave
  722bb9:	c2 04 00             	ret    0x4
  722bbc:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
  722bbf:	8b 75 ec             	mov    esi,DWORD PTR [ebp-0x14]
  722bc2:	2b d0                	sub    edx,eax
  722bc4:	1b f1                	sbb    esi,ecx
  722bc6:	56                   	push   esi
  722bc7:	52                   	push   edx
  722bc8:	51                   	push   ecx
  722bc9:	50                   	push   eax
  722bca:	53                   	push   ebx
  722bcb:	8b cf                	mov    ecx,edi
  722bcd:	e8 b6 02 00 00       	call   0x722e88
  722bd2:	33 c0                	xor    eax,eax
  722bd4:	eb df                	jmp    0x722bb5
