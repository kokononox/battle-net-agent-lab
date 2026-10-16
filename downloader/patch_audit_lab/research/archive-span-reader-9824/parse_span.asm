
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00713c8c <.text+0x312c8c>:
  713c8c:	55                   	push   ebp
  713c8d:	8b ec                	mov    ebp,esp
  713c8f:	83 7d 0c 1e          	cmp    DWORD PTR [ebp+0xc],0x1e
  713c93:	56                   	push   esi
  713c94:	0f 82 8b 00 00 00    	jb     0x713d25
  713c9a:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  713c9d:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  713ca0:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  713ca3:	56                   	push   esi
  713ca4:	e8 7e ff ff ff       	call   0x713c27
  713ca9:	83 c4 0c             	add    esp,0xc
  713cac:	84 c0                	test   al,al
  713cae:	74 75                	je     0x713d25
  713cb0:	68 71 e9 6b 3d       	push   0x3d6be971
  713cb5:	6a 16                	push   0x16
  713cb7:	56                   	push   esi
  713cb8:	e8 9f f7 00 00       	call   0x72345c
  713cbd:	83 c4 0c             	add    esp,0xc
  713cc0:	33 d2                	xor    edx,edx
  713cc2:	8b ca                	mov    ecx,edx
  713cc4:	38 44 31 16          	cmp    BYTE PTR [ecx+esi*1+0x16],al
  713cc8:	75 5b                	jne    0x713d25
  713cca:	41                   	inc    ecx
  713ccb:	c1 e8 08             	shr    eax,0x8
  713cce:	83 f9 04             	cmp    ecx,0x4
  713cd1:	72 f1                	jb     0x713cc4
  713cd3:	8a 46 14             	mov    al,BYTE PTR [esi+0x14]
  713cd6:	84 c0                	test   al,al
  713cd8:	74 04                	je     0x713cde
  713cda:	3c 01                	cmp    al,0x1
  713cdc:	75 47                	jne    0x713d25
  713cde:	53                   	push   ebx
  713cdf:	57                   	push   edi
  713ce0:	8b 7d 18             	mov    edi,DWORD PTR [ebp+0x18]
  713ce3:	8d 5e 0f             	lea    ebx,[esi+0xf]
  713ce6:	8b ca                	mov    ecx,edx
  713ce8:	8a 03                	mov    al,BYTE PTR [ebx]
  713cea:	88 04 39             	mov    BYTE PTR [ecx+edi*1],al
  713ced:	41                   	inc    ecx
  713cee:	4b                   	dec    ebx
  713cef:	83 f9 10             	cmp    ecx,0x10
  713cf2:	72 f4                	jb     0x713ce8
  713cf4:	8b da                	mov    ebx,edx
  713cf6:	8b ca                	mov    ecx,edx
  713cf8:	0f b6 44 1e 10       	movzx  eax,BYTE PTR [esi+ebx*1+0x10]
  713cfd:	d3 e0                	shl    eax,cl
  713cff:	83 c1 08             	add    ecx,0x8
  713d02:	0b d0                	or     edx,eax
  713d04:	43                   	inc    ebx
  713d05:	83 f9 20             	cmp    ecx,0x20
  713d08:	72 ee                	jb     0x713cf8
  713d0a:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  713d0d:	89 47 10             	mov    DWORD PTR [edi+0x10],eax
  713d10:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  713d13:	89 47 14             	mov    DWORD PTR [edi+0x14],eax
  713d16:	89 57 18             	mov    DWORD PTR [edi+0x18],edx
  713d19:	8a 46 14             	mov    al,BYTE PTR [esi+0x14]
  713d1c:	88 47 20             	mov    BYTE PTR [edi+0x20],al
  713d1f:	b0 01                	mov    al,0x1
  713d21:	5f                   	pop    edi
  713d22:	5b                   	pop    ebx
  713d23:	eb 02                	jmp    0x713d27
  713d25:	32 c0                	xor    al,al
  713d27:	5e                   	pop    esi
  713d28:	5d                   	pop    ebp
  713d29:	c3                   	ret
