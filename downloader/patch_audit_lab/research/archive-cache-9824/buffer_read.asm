
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0070bcad <.text+0x30acad>:
  70bcad:	6a 04                	push   0x4
  70bcaf:	b8 d9 17 8f 00       	mov    eax,0x8f17d9
  70bcb4:	e8 7f a3 16 00       	call   0x876038
  70bcb9:	89 4d f0             	mov    DWORD PTR [ebp-0x10],ecx
  70bcbc:	8b 41 18             	mov    eax,DWORD PTR [ecx+0x18]
  70bcbf:	33 db                	xor    ebx,ebx
  70bcc1:	8b 75 14             	mov    esi,DWORD PTR [ebp+0x14]
  70bcc4:	8b 7d 10             	mov    edi,DWORD PTR [ebp+0x10]
  70bcc7:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  70bcca:	85 c0                	test   eax,eax
  70bccc:	74 5f                	je     0x70bd2d
  70bcce:	8a 40 24             	mov    al,BYTE PTR [eax+0x24]
  70bcd1:	84 c0                	test   al,al
  70bcd3:	75 58                	jne    0x70bd2d
  70bcd5:	8b 41 18             	mov    eax,DWORD PTR [ecx+0x18]
  70bcd8:	33 d2                	xor    edx,edx
  70bcda:	8b 48 08             	mov    ecx,DWORD PTR [eax+0x8]
  70bcdd:	8b c1                	mov    eax,ecx
  70bcdf:	83 c0 ff             	add    eax,0xffffffff
  70bce2:	f7 d0                	not    eax
  70bce4:	83 d2 ff             	adc    edx,0xffffffff
  70bce7:	23 45 0c             	and    eax,DWORD PTR [ebp+0xc]
  70bcea:	f7 d2                	not    edx
  70bcec:	23 d7                	and    edx,edi
  70bcee:	3b 45 0c             	cmp    eax,DWORD PTR [ebp+0xc]
  70bcf1:	75 0c                	jne    0x70bcff
  70bcf3:	3b d7                	cmp    edx,edi
  70bcf5:	75 08                	jne    0x70bcff
  70bcf7:	f7 d9                	neg    ecx
  70bcf9:	23 ce                	and    ecx,esi
  70bcfb:	3b ce                	cmp    ecx,esi
  70bcfd:	74 2e                	je     0x70bd2d
  70bcff:	ff 75 1c             	push   DWORD PTR [ebp+0x1c]
  70bd02:	8b 4d f0             	mov    ecx,DWORD PTR [ebp-0x10]
  70bd05:	8d 45 17             	lea    eax,[ebp+0x17]
  70bd08:	50                   	push   eax
  70bd09:	56                   	push   esi
  70bd0a:	57                   	push   edi
  70bd0b:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  70bd0e:	88 5d 17             	mov    BYTE PTR [ebp+0x17],bl
  70bd11:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  70bd14:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  70bd17:	e8 1d 0b 00 00       	call   0x70c839
  70bd1c:	38 5d 17             	cmp    BYTE PTR [ebp+0x17],bl
  70bd1f:	75 0c                	jne    0x70bd2d
  70bd21:	33 db                	xor    ebx,ebx
  70bd23:	84 c0                	test   al,al
  70bd25:	6a 08                	push   0x8
  70bd27:	59                   	pop    ecx
  70bd28:	0f 44 d9             	cmove  ebx,ecx
  70bd2b:	eb 2f                	jmp    0x70bd5c
  70bd2d:	ff 75 1c             	push   DWORD PTR [ebp+0x1c]
  70bd30:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  70bd33:	57                   	push   edi
  70bd34:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  70bd37:	83 c0 24             	add    eax,0x24
  70bd3a:	56                   	push   esi
  70bd3b:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  70bd3e:	50                   	push   eax
  70bd3f:	e8 2b 94 15 00       	call   0x86516f
  70bd44:	83 c4 18             	add    esp,0x18
  70bd47:	85 c0                	test   eax,eax
  70bd49:	74 11                	je     0x70bd5c
  70bd4b:	50                   	push   eax
  70bd4c:	57                   	push   edi
  70bd4d:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  70bd50:	56                   	push   esi
  70bd51:	e8 21 13 00 00       	call   0x70d077
  70bd56:	83 c4 10             	add    esp,0x10
  70bd59:	6a 08                	push   0x8
  70bd5b:	5b                   	pop    ebx
  70bd5c:	83 7d 08 00          	cmp    DWORD PTR [ebp+0x8],0x0
  70bd60:	c7 45 fc 04 00 00 00 	mov    DWORD PTR [ebp-0x4],0x4
  70bd67:	74 09                	je     0x70bd72
  70bd69:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  70bd6c:	e8 24 f7 f6 ff       	call   0x67b495
  70bd71:	59                   	pop    ecx
  70bd72:	8b c3                	mov    eax,ebx
  70bd74:	e8 8d a2 16 00       	call   0x876006
  70bd79:	c2 18 00             	ret    0x18
