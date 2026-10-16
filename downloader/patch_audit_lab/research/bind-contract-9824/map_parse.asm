
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072b8f9 <.text+0x32a8f9>:
  72b8f9:	55                   	push   ebp
  72b8fa:	8b ec                	mov    ebp,esp
  72b8fc:	83 ec 14             	sub    esp,0x14
  72b8ff:	53                   	push   ebx
  72b900:	56                   	push   esi
  72b901:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  72b904:	57                   	push   edi
  72b905:	56                   	push   esi
  72b906:	8b f9                	mov    edi,ecx
  72b908:	e8 27 22 f7 ff       	call   0x69db34
  72b90d:	59                   	pop    ecx
  72b90e:	8b c8                	mov    ecx,eax
  72b910:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  72b913:	0b ca                	or     ecx,edx
  72b915:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  72b918:	6a 00                	push   0x0
  72b91a:	59                   	pop    ecx
  72b91b:	74 7c                	je     0x72b999
  72b91d:	3b d1                	cmp    edx,ecx
  72b91f:	77 78                	ja     0x72b999
  72b921:	72 05                	jb     0x72b928
  72b923:	83 f8 ff             	cmp    eax,0xffffffff
  72b926:	77 71                	ja     0x72b999
  72b928:	83 7f 08 02          	cmp    DWORD PTR [edi+0x8],0x2
  72b92c:	8d 45 f8             	lea    eax,[ebp-0x8]
  72b92f:	89 7d ec             	mov    DWORD PTR [ebp-0x14],edi
  72b932:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  72b935:	89 75 f4             	mov    DWORD PTR [ebp-0xc],esi
  72b938:	75 0e                	jne    0x72b948
  72b93a:	8d 4d ec             	lea    ecx,[ebp-0x14]
  72b93d:	e8 ba f9 ff ff       	call   0x72b2fc
  72b942:	85 c0                	test   eax,eax
  72b944:	74 4a                	je     0x72b990
  72b946:	eb 70                	jmp    0x72b9b8
  72b948:	51                   	push   ecx
  72b949:	51                   	push   ecx
  72b94a:	51                   	push   ecx
  72b94b:	51                   	push   ecx
  72b94c:	6a 01                	push   0x1
  72b94e:	8d 5f 10             	lea    ebx,[edi+0x10]
  72b951:	56                   	push   esi
  72b952:	53                   	push   ebx
  72b953:	e8 8d 0f 14 00       	call   0x86c8e5
  72b958:	8b f0                	mov    esi,eax
  72b95a:	83 c4 1c             	add    esp,0x1c
  72b95d:	85 f6                	test   esi,esi
  72b95f:	74 24                	je     0x72b985
  72b961:	56                   	push   esi
  72b962:	68 88 fc 9b 00       	push   0x9bfc88
  72b967:	6a 00                	push   0x0
  72b969:	68 08 bc 8f 00       	push   0x8fbc08
  72b96e:	6a 04                	push   0x4
  72b970:	68 38 ba 9b 00       	push   0x9bba38
  72b975:	e8 c9 7e 19 00       	call   0x8c3843
  72b97a:	56                   	push   esi
  72b97b:	e8 a1 b8 fe ff       	call   0x717221
  72b980:	83 c4 1c             	add    esp,0x1c
  72b983:	eb 33                	jmp    0x72b9b8
  72b985:	8b 03                	mov    eax,DWORD PTR [ebx]
  72b987:	89 47 38             	mov    DWORD PTR [edi+0x38],eax
  72b98a:	8b 47 18             	mov    eax,DWORD PTR [edi+0x18]
  72b98d:	89 47 3c             	mov    DWORD PTR [edi+0x3c],eax
  72b990:	8b cf                	mov    ecx,edi
  72b992:	e8 f6 13 00 00       	call   0x72cd8d
  72b997:	eb 1f                	jmp    0x72b9b8
  72b999:	52                   	push   edx
  72b99a:	50                   	push   eax
  72b99b:	68 18 ea 9b 00       	push   0x9bea18
  72b9a0:	51                   	push   ecx
  72b9a1:	68 08 bc 8f 00       	push   0x8fbc08
  72b9a6:	6a 04                	push   0x4
  72b9a8:	68 38 ba 9b 00       	push   0x9bba38
  72b9ad:	e8 91 7e 19 00       	call   0x8c3843
  72b9b2:	83 c4 1c             	add    esp,0x1c
  72b9b5:	6a 09                	push   0x9
  72b9b7:	58                   	pop    eax
  72b9b8:	5f                   	pop    edi
  72b9b9:	5e                   	pop    esi
  72b9ba:	5b                   	pop    ebx
  72b9bb:	c9                   	leave
  72b9bc:	c2 04 00             	ret    0x4
