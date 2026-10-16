
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

007229e3 <.text+0x3219e3>:
  7229e3:	55                   	push   ebp
  7229e4:	8b ec                	mov    ebp,esp
  7229e6:	83 ec 10             	sub    esp,0x10
  7229e9:	53                   	push   ebx
  7229ea:	8b d9                	mov    ebx,ecx
  7229ec:	56                   	push   esi
  7229ed:	57                   	push   edi
  7229ee:	89 5d f0             	mov    DWORD PTR [ebp-0x10],ebx
  7229f1:	83 3b 02             	cmp    DWORD PTR [ebx],0x2
  7229f4:	75 05                	jne    0x7229fb
  7229f6:	e8 44 04 00 00       	call   0x722e3f
  7229fb:	83 3b 01             	cmp    DWORD PTR [ebx],0x1
  7229fe:	0f 85 f7 00 00 00    	jne    0x722afb
  722a04:	33 ff                	xor    edi,edi
  722a06:	39 7d 08             	cmp    DWORD PTR [ebp+0x8],edi
  722a09:	75 12                	jne    0x722a1d
  722a0b:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  722a0e:	89 38                	mov    DWORD PTR [eax],edi
  722a10:	89 78 04             	mov    DWORD PTR [eax+0x4],edi
  722a13:	89 78 08             	mov    DWORD PTR [eax+0x8],edi
  722a16:	33 c0                	xor    eax,eax
  722a18:	e9 e1 00 00 00       	jmp    0x722afe
  722a1d:	8b 43 04             	mov    eax,DWORD PTR [ebx+0x4]
  722a20:	8b f7                	mov    esi,edi
  722a22:	89 7d f4             	mov    DWORD PTR [ebp-0xc],edi
  722a25:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  722a28:	85 c0                	test   eax,eax
  722a2a:	74 39                	je     0x722a65
  722a2c:	8d 4b 20             	lea    ecx,[ebx+0x20]
  722a2f:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
  722a32:	89 4d f8             	mov    DWORD PTR [ebp-0x8],ecx
  722a35:	6a 05                	push   0x5
  722a37:	51                   	push   ecx
  722a38:	e8 c3 04 00 00       	call   0x722f00
  722a3d:	59                   	pop    ecx
  722a3e:	59                   	pop    ecx
  722a3f:	3b d7                	cmp    edx,edi
  722a41:	77 19                	ja     0x722a5c
  722a43:	72 04                	jb     0x722a49
  722a45:	3b c3                	cmp    eax,ebx
  722a47:	73 13                	jae    0x722a5c
  722a49:	8b 4d f8             	mov    ecx,DWORD PTR [ebp-0x8]
  722a4c:	46                   	inc    esi
  722a4d:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  722a50:	83 c1 05             	add    ecx,0x5
  722a53:	89 4d f8             	mov    DWORD PTR [ebp-0x8],ecx
  722a56:	3b f0                	cmp    esi,eax
  722a58:	72 db                	jb     0x722a35
  722a5a:	eb 03                	jmp    0x722a5f
  722a5c:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  722a5f:	8b 5d f0             	mov    ebx,DWORD PTR [ebp-0x10]
  722a62:	89 75 f4             	mov    DWORD PTR [ebp-0xc],esi
  722a65:	3b f0                	cmp    esi,eax
  722a67:	0f 84 8e 00 00 00    	je     0x722afb
  722a6d:	6b f6 05             	imul   esi,esi,0x5
  722a70:	6a 05                	push   0x5
  722a72:	8d 86 6a 15 00 00    	lea    eax,[esi+0x156a]
  722a78:	03 c3                	add    eax,ebx
  722a7a:	50                   	push   eax
  722a7b:	e8 80 04 00 00       	call   0x722f00
  722a80:	8d 4e 20             	lea    ecx,[esi+0x20]
  722a83:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  722a86:	03 cb                	add    ecx,ebx
  722a88:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  722a8b:	6a 05                	push   0x5
  722a8d:	51                   	push   ecx
  722a8e:	e8 6d 04 00 00       	call   0x722f00
  722a93:	8b 75 fc             	mov    esi,DWORD PTR [ebp-0x4]
  722a96:	83 c4 10             	add    esp,0x10
  722a99:	8b ce                	mov    ecx,esi
  722a9b:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  722a9e:	81 e1 ff ff ff 3f    	and    ecx,0x3fffffff
  722aa4:	0b cf                	or     ecx,edi
  722aa6:	75 20                	jne    0x722ac8
  722aa8:	3b d7                	cmp    edx,edi
  722aaa:	77 07                	ja     0x722ab3
  722aac:	3d e0 01 00 00       	cmp    eax,0x1e0
  722ab1:	72 15                	jb     0x722ac8
  722ab3:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  722ab6:	8b 4d f8             	mov    ecx,DWORD PTR [ebp-0x8]
  722ab9:	6a 10                	push   0x10
  722abb:	89 48 04             	mov    DWORD PTR [eax+0x4],ecx
  722abe:	8b 4d f0             	mov    ecx,DWORD PTR [ebp-0x10]
  722ac1:	89 30                	mov    DWORD PTR [eax],esi
  722ac3:	89 48 08             	mov    DWORD PTR [eax+0x8],ecx
  722ac6:	eb 35                	jmp    0x722afd
  722ac8:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  722acb:	8b cb                	mov    ecx,ebx
  722acd:	2b c6                	sub    eax,esi
  722acf:	1b d7                	sbb    edx,edi
  722ad1:	52                   	push   edx
  722ad2:	50                   	push   eax
  722ad3:	8b c6                	mov    eax,esi
  722ad5:	03 45 fc             	add    eax,DWORD PTR [ebp-0x4]
  722ad8:	13 7d f8             	adc    edi,DWORD PTR [ebp-0x8]
  722adb:	57                   	push   edi
  722adc:	50                   	push   eax
  722add:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
  722ae0:	e8 a3 03 00 00       	call   0x722e88
  722ae5:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  722ae8:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  722aeb:	89 08                	mov    DWORD PTR [eax],ecx
  722aed:	8b 4d f8             	mov    ecx,DWORD PTR [ebp-0x8]
  722af0:	89 48 04             	mov    DWORD PTR [eax+0x4],ecx
  722af3:	89 70 08             	mov    DWORD PTR [eax+0x8],esi
  722af6:	e9 1b ff ff ff       	jmp    0x722a16
  722afb:	6a 0e                	push   0xe
  722afd:	58                   	pop    eax
  722afe:	5f                   	pop    edi
  722aff:	5e                   	pop    esi
  722b00:	5b                   	pop    ebx
  722b01:	c9                   	leave
  722b02:	c2 08 00             	ret    0x8
