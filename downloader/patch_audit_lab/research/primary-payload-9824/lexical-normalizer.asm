
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0086398b <.text+0x46298b>:
  86398b:	55                   	push   ebp
  86398c:	8b ec                	mov    ebp,esp
  86398e:	83 ec 18             	sub    esp,0x18
  863991:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  863994:	83 65 f8 00          	and    DWORD PTR [ebp-0x8],0x0
  863998:	48                   	dec    eax
  863999:	56                   	push   esi
  86399a:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  86399d:	03 c6                	add    eax,esi
  86399f:	83 65 ec 00          	and    DWORD PTR [ebp-0x14],0x0
  8639a3:	8b ce                	mov    ecx,esi
  8639a5:	57                   	push   edi
  8639a6:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
  8639a9:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  8639ac:	53                   	push   ebx
  8639ad:	8b f8                	mov    edi,eax
  8639af:	8a 10                	mov    dl,BYTE PTR [eax]
  8639b1:	8b d8                	mov    ebx,eax
  8639b3:	40                   	inc    eax
  8639b4:	89 5d e8             	mov    DWORD PTR [ebp-0x18],ebx
  8639b7:	88 55 0f             	mov    BYTE PTR [ebp+0xf],dl
  8639ba:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  8639bd:	80 fa 2f             	cmp    dl,0x2f
  8639c0:	74 09                	je     0x8639cb
  8639c2:	80 fa 5c             	cmp    dl,0x5c
  8639c5:	74 04                	je     0x8639cb
  8639c7:	84 d2                	test   dl,dl
  8639c9:	75 e4                	jne    0x8639af
  8639cb:	2b df                	sub    ebx,edi
  8639cd:	c6 45 ff 00          	mov    BYTE PTR [ebp-0x1],0x0
  8639d1:	83 fb 01             	cmp    ebx,0x1
  8639d4:	75 09                	jne    0x8639df
  8639d6:	80 3f 2e             	cmp    BYTE PTR [edi],0x2e
  8639d9:	75 4e                	jne    0x863a29
  8639db:	33 db                	xor    ebx,ebx
  8639dd:	eb 2f                	jmp    0x863a0e
  8639df:	83 fb 02             	cmp    ebx,0x2
  8639e2:	75 26                	jne    0x863a0a
  8639e4:	80 3f 2e             	cmp    BYTE PTR [edi],0x2e
  8639e7:	75 40                	jne    0x863a29
  8639e9:	80 7f 01 2e          	cmp    BYTE PTR [edi+0x1],0x2e
  8639ed:	75 3a                	jne    0x863a29
  8639ef:	83 7d f8 00          	cmp    DWORD PTR [ebp-0x8],0x0
  8639f3:	76 11                	jbe    0x863a06
  8639f5:	33 db                	xor    ebx,ebx
  8639f7:	eb 06                	jmp    0x8639ff
  8639f9:	49                   	dec    ecx
  8639fa:	80 39 2f             	cmp    BYTE PTR [ecx],0x2f
  8639fd:	74 04                	je     0x863a03
  8639ff:	3b ce                	cmp    ecx,esi
  863a01:	77 f6                	ja     0x8639f9
  863a03:	ff 4d f8             	dec    DWORD PTR [ebp-0x8]
  863a06:	c6 45 ff 01          	mov    BYTE PTR [ebp-0x1],0x1
  863a0a:	85 db                	test   ebx,ebx
  863a0c:	75 1b                	jne    0x863a29
  863a0e:	3b ce                	cmp    ecx,esi
  863a10:	74 17                	je     0x863a29
  863a12:	8d 46 01             	lea    eax,[esi+0x1]
  863a15:	3b c8                	cmp    ecx,eax
  863a17:	75 05                	jne    0x863a1e
  863a19:	80 3e 2f             	cmp    BYTE PTR [esi],0x2f
  863a1c:	74 08                	je     0x863a26
  863a1e:	84 d2                	test   dl,dl
  863a20:	0f 85 a4 00 00 00    	jne    0x863aca
  863a26:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
  863a29:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  863a2c:	3b 7d 10             	cmp    edi,DWORD PTR [ebp+0x10]
  863a2f:	75 21                	jne    0x863a52
  863a31:	8b 75 10             	mov    esi,DWORD PTR [ebp+0x10]
  863a34:	39 75 e8             	cmp    DWORD PTR [ebp-0x18],esi
  863a37:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  863a3a:	75 16                	jne    0x863a52
  863a3c:	84 d2                	test   dl,dl
  863a3e:	74 12                	je     0x863a52
  863a40:	3b 4d f4             	cmp    ecx,DWORD PTR [ebp-0xc]
  863a43:	0f 83 64 ff ff ff    	jae    0x8639ad
  863a49:	c6 01 2f             	mov    BYTE PTR [ecx],0x2f
  863a4c:	41                   	inc    ecx
  863a4d:	e9 5b ff ff ff       	jmp    0x8639ad
  863a52:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  863a55:	40                   	inc    eax
  863a56:	3b f8                	cmp    edi,eax
  863a58:	75 26                	jne    0x863a80
  863a5a:	39 45 e8             	cmp    DWORD PTR [ebp-0x18],eax
  863a5d:	75 21                	jne    0x863a80
  863a5f:	8d 46 01             	lea    eax,[esi+0x1]
  863a62:	3b c8                	cmp    ecx,eax
  863a64:	75 1a                	jne    0x863a80
  863a66:	80 3e 2f             	cmp    BYTE PTR [esi],0x2f
  863a69:	75 15                	jne    0x863a80
  863a6b:	84 d2                	test   dl,dl
  863a6d:	74 11                	je     0x863a80
  863a6f:	3b 4d f4             	cmp    ecx,DWORD PTR [ebp-0xc]
  863a72:	73 04                	jae    0x863a78
  863a74:	c6 01 2f             	mov    BYTE PTR [ecx],0x2f
  863a77:	41                   	inc    ecx
  863a78:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
  863a7b:	e9 2d ff ff ff       	jmp    0x8639ad
  863a80:	8b 45 f8             	mov    eax,DWORD PTR [ebp-0x8]
  863a83:	85 c0                	test   eax,eax
  863a85:	75 05                	jne    0x863a8c
  863a87:	39 45 ec             	cmp    DWORD PTR [ebp-0x14],eax
  863a8a:	76 09                	jbe    0x863a95
  863a8c:	3b 4d f4             	cmp    ecx,DWORD PTR [ebp-0xc]
  863a8f:	73 04                	jae    0x863a95
  863a91:	c6 01 2f             	mov    BYTE PTR [ecx],0x2f
  863a94:	41                   	inc    ecx
  863a95:	33 d2                	xor    edx,edx
  863a97:	85 db                	test   ebx,ebx
  863a99:	74 2c                	je     0x863ac7
  863a9b:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
  863a9e:	3b c8                	cmp    ecx,eax
  863aa0:	73 09                	jae    0x863aab
  863aa2:	8a 04 3a             	mov    al,BYTE PTR [edx+edi*1]
  863aa5:	88 01                	mov    BYTE PTR [ecx],al
  863aa7:	41                   	inc    ecx
  863aa8:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
  863aab:	42                   	inc    edx
  863aac:	3b d3                	cmp    edx,ebx
  863aae:	72 ee                	jb     0x863a9e
  863ab0:	80 7d ff 00          	cmp    BYTE PTR [ebp-0x1],0x0
  863ab4:	8b 45 f8             	mov    eax,DWORD PTR [ebp-0x8]
  863ab7:	8a 55 0f             	mov    dl,BYTE PTR [ebp+0xf]
  863aba:	74 05                	je     0x863ac1
  863abc:	ff 45 ec             	inc    DWORD PTR [ebp-0x14]
  863abf:	eb 09                	jmp    0x863aca
  863ac1:	40                   	inc    eax
  863ac2:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  863ac5:	eb 03                	jmp    0x863aca
  863ac7:	8a 55 0f             	mov    dl,BYTE PTR [ebp+0xf]
  863aca:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
  863acd:	8b f8                	mov    edi,eax
  863acf:	84 d2                	test   dl,dl
  863ad1:	0f 85 d8 fe ff ff    	jne    0x8639af
  863ad7:	88 11                	mov    BYTE PTR [ecx],dl
  863ad9:	8a 0e                	mov    cl,BYTE PTR [esi]
  863adb:	5b                   	pop    ebx
  863adc:	84 c9                	test   cl,cl
  863ade:	74 20                	je     0x863b00
  863ae0:	80 7e 01 3a          	cmp    BYTE PTR [esi+0x1],0x3a
  863ae4:	75 1a                	jne    0x863b00
  863ae6:	80 7e 02 2f          	cmp    BYTE PTR [esi+0x2],0x2f
  863aea:	75 14                	jne    0x863b00
  863aec:	8d 51 bf             	lea    edx,[ecx-0x41]
  863aef:	8d 41 20             	lea    eax,[ecx+0x20]
  863af2:	80 fa 19             	cmp    dl,0x19
  863af5:	0f b6 c9             	movzx  ecx,cl
  863af8:	0f b6 c0             	movzx  eax,al
  863afb:	0f 46 c8             	cmovbe ecx,eax
  863afe:	88 0e                	mov    BYTE PTR [esi],cl
  863b00:	5f                   	pop    edi
  863b01:	5e                   	pop    esi
  863b02:	c9                   	leave
  863b03:	c3                   	ret
