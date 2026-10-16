
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072cf38 <.text+0x32bf38>:
  72cf38:	55                   	push   ebp
  72cf39:	8b ec                	mov    ebp,esp
  72cf3b:	83 ec 14             	sub    esp,0x14
  72cf3e:	53                   	push   ebx
  72cf3f:	8b d9                	mov    ebx,ecx
  72cf41:	33 c9                	xor    ecx,ecx
  72cf43:	56                   	push   esi
  72cf44:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  72cf47:	57                   	push   edi
  72cf48:	8b 43 3c             	mov    eax,DWORD PTR [ebx+0x3c]
  72cf4b:	2b c6                	sub    eax,esi
  72cf4d:	1b 4d 0c             	sbb    ecx,DWORD PTR [ebp+0xc]
  72cf50:	75 09                	jne    0x72cf5b
  72cf52:	83 f8 08             	cmp    eax,0x8
  72cf55:	0f 82 84 00 00 00    	jb     0x72cfdf
  72cf5b:	8b 7b 38             	mov    edi,DWORD PTR [ebx+0x38]
  72cf5e:	89 7d ec             	mov    DWORD PTR [ebp-0x14],edi
  72cf61:	8b 14 37             	mov    edx,DWORD PTR [edi+esi*1]
  72cf64:	83 c2 08             	add    edx,0x8
  72cf67:	85 c9                	test   ecx,ecx
  72cf69:	72 74                	jb     0x72cfdf
  72cf6b:	77 04                	ja     0x72cf71
  72cf6d:	3b c2                	cmp    eax,edx
  72cf6f:	72 6e                	jb     0x72cfdf
  72cf71:	8d 46 08             	lea    eax,[esi+0x8]
  72cf74:	33 c9                	xor    ecx,ecx
  72cf76:	21 4d f4             	and    DWORD PTR [ebp-0xc],ecx
  72cf79:	03 c7                	add    eax,edi
  72cf7b:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  72cf7e:	89 43 40             	mov    DWORD PTR [ebx+0x40],eax
  72cf81:	8b 04 37             	mov    eax,DWORD PTR [edi+esi*1]
  72cf84:	21 4d f0             	and    DWORD PTR [ebp-0x10],ecx
  72cf87:	c1 e8 05             	shr    eax,0x5
  72cf8a:	89 43 44             	mov    DWORD PTR [ebx+0x44],eax
  72cf8d:	89 4d fc             	mov    DWORD PTR [ebp-0x4],ecx
  72cf90:	85 c0                	test   eax,eax
  72cf92:	74 2b                	je     0x72cfbf
  72cf94:	8b 75 f8             	mov    esi,DWORD PTR [ebp-0x8]
  72cf97:	8b 7d f4             	mov    edi,DWORD PTR [ebp-0xc]
  72cf9a:	8d 45 f0             	lea    eax,[ebp-0x10]
  72cf9d:	50                   	push   eax
  72cf9e:	8d 45 fc             	lea    eax,[ebp-0x4]
  72cfa1:	50                   	push   eax
  72cfa2:	6a 20                	push   0x20
  72cfa4:	56                   	push   esi
  72cfa5:	e8 16 60 ff ff       	call   0x722fc0
  72cfaa:	83 c4 10             	add    esp,0x10
  72cfad:	83 c6 20             	add    esi,0x20
  72cfb0:	47                   	inc    edi
  72cfb1:	3b 7b 44             	cmp    edi,DWORD PTR [ebx+0x44]
  72cfb4:	72 e4                	jb     0x72cf9a
  72cfb6:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  72cfb9:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  72cfbc:	8b 7d ec             	mov    edi,DWORD PTR [ebp-0x14]
  72cfbf:	3b 4c 37 04          	cmp    ecx,DWORD PTR [edi+esi*1+0x4]
  72cfc3:	74 07                	je     0x72cfcc
  72cfc5:	68 e0 eb 9b 00       	push   0x9bebe0
  72cfca:	eb 18                	jmp    0x72cfe4
  72cfcc:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  72cfcf:	8b 0c 37             	mov    ecx,DWORD PTR [edi+esi*1]
  72cfd2:	83 c1 08             	add    ecx,0x8
  72cfd5:	83 60 04 00          	and    DWORD PTR [eax+0x4],0x0
  72cfd9:	89 08                	mov    DWORD PTR [eax],ecx
  72cfdb:	33 c0                	xor    eax,eax
  72cfdd:	eb 1e                	jmp    0x72cffd
  72cfdf:	68 b8 eb 9b 00       	push   0x9bebb8
  72cfe4:	6a 00                	push   0x0
  72cfe6:	68 08 bc 8f 00       	push   0x8fbc08
  72cfeb:	6a 04                	push   0x4
  72cfed:	68 38 ba 9b 00       	push   0x9bba38
  72cff2:	e8 4c 68 19 00       	call   0x8c3843
  72cff7:	83 c4 14             	add    esp,0x14
  72cffa:	6a 09                	push   0x9
  72cffc:	58                   	pop    eax
  72cffd:	5f                   	pop    edi
  72cffe:	5e                   	pop    esi
  72cfff:	5b                   	pop    ebx
  72d000:	c9                   	leave
  72d001:	c2 0c 00             	ret    0xc
