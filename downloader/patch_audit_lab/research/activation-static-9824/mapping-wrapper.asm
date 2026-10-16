
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0086c8e5 <.text+0x46b8e5>:
  86c8e5:	55                   	push   ebp
  86c8e6:	8b ec                	mov    ebp,esp
  86c8e8:	83 ec 10             	sub    esp,0x10
  86c8eb:	53                   	push   ebx
  86c8ec:	56                   	push   esi
  86c8ed:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  86c8f0:	57                   	push   edi
  86c8f1:	83 3e 00             	cmp    DWORD PTR [esi],0x0
  86c8f4:	0f 85 81 01 00 00    	jne    0x86ca7b
  86c8fa:	8b 46 08             	mov    eax,DWORD PTR [esi+0x8]
  86c8fd:	0b 46 0c             	or     eax,DWORD PTR [esi+0xc]
  86c900:	0f 85 75 01 00 00    	jne    0x86ca7b
  86c906:	39 46 18             	cmp    DWORD PTR [esi+0x18],eax
  86c909:	0f 85 6c 01 00 00    	jne    0x86ca7b
  86c90f:	8d 46 1c             	lea    eax,[esi+0x1c]
  86c912:	83 38 ff             	cmp    DWORD PTR [eax],0xffffffff
  86c915:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  86c918:	0f 85 5d 01 00 00    	jne    0x86ca7b
  86c91e:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  86c921:	83 38 ff             	cmp    DWORD PTR [eax],0xffffffff
  86c924:	0f 84 51 01 00 00    	je     0x86ca7b
  86c92a:	8d 4d f0             	lea    ecx,[ebp-0x10]
  86c92d:	51                   	push   ecx
  86c92e:	50                   	push   eax
  86c92f:	e8 11 86 ff ff       	call   0x864f45
  86c934:	59                   	pop    ecx
  86c935:	59                   	pop    ecx
  86c936:	85 c0                	test   eax,eax
  86c938:	0f 85 45 01 00 00    	jne    0x86ca83
  86c93e:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
  86c941:	8b c2                	mov    eax,edx
  86c943:	8b 4d f4             	mov    ecx,DWORD PTR [ebp-0xc]
  86c946:	0b c1                	or     eax,ecx
  86c948:	0f 84 2d 01 00 00    	je     0x86ca7b
  86c94e:	8b 5d 20             	mov    ebx,DWORD PTR [ebp+0x20]
  86c951:	3b d9                	cmp    ebx,ecx
  86c953:	0f 87 22 01 00 00    	ja     0x86ca7b
  86c959:	8b 7d 1c             	mov    edi,DWORD PTR [ebp+0x1c]
  86c95c:	72 08                	jb     0x86c966
  86c95e:	3b fa                	cmp    edi,edx
  86c960:	0f 87 15 01 00 00    	ja     0x86ca7b
  86c966:	8b c2                	mov    eax,edx
  86c968:	2b c7                	sub    eax,edi
  86c96a:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  86c96d:	8b c1                	mov    eax,ecx
  86c96f:	1b c3                	sbb    eax,ebx
  86c971:	39 45 18             	cmp    DWORD PTR [ebp+0x18],eax
  86c974:	0f 87 01 01 00 00    	ja     0x86ca7b
  86c97a:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  86c97d:	72 09                	jb     0x86c988
  86c97f:	3b 45 fc             	cmp    eax,DWORD PTR [ebp-0x4]
  86c982:	0f 87 f3 00 00 00    	ja     0x86ca7b
  86c988:	3b c2                	cmp    eax,edx
  86c98a:	75 09                	jne    0x86c995
  86c98c:	39 4d 18             	cmp    DWORD PTR [ebp+0x18],ecx
  86c98f:	0f 84 e6 00 00 00    	je     0x86ca7b
  86c995:	8b c7                	mov    eax,edi
  86c997:	0b c3                	or     eax,ebx
  86c999:	75 0a                	jne    0x86c9a5
  86c99b:	8b fa                	mov    edi,edx
  86c99d:	8b d9                	mov    ebx,ecx
  86c99f:	2b 7d 14             	sub    edi,DWORD PTR [ebp+0x14]
  86c9a2:	1b 5d 18             	sbb    ebx,DWORD PTR [ebp+0x18]
  86c9a5:	e8 20 06 00 00       	call   0x86cfca
  86c9aa:	8b 4d 18             	mov    ecx,DWORD PTR [ebp+0x18]
  86c9ad:	8b d0                	mov    edx,eax
  86c9af:	33 c0                	xor    eax,eax
  86c9b1:	89 7e 08             	mov    DWORD PTR [esi+0x8],edi
  86c9b4:	83 c2 ff             	add    edx,0xffffffff
  86c9b7:	89 5e 0c             	mov    DWORD PTR [esi+0xc],ebx
  86c9ba:	f7 d2                	not    edx
  86c9bc:	83 d0 ff             	adc    eax,0xffffffff
  86c9bf:	f7 d0                	not    eax
  86c9c1:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  86c9c4:	21 4d 08             	and    DWORD PTR [ebp+0x8],ecx
  86c9c7:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  86c9ca:	23 d0                	and    edx,eax
  86c9cc:	2b c2                	sub    eax,edx
  86c9ce:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  86c9d1:	6a 00                	push   0x0
  86c9d3:	1b 4d 08             	sbb    ecx,DWORD PTR [ebp+0x8]
  86c9d6:	03 f8                	add    edi,eax
  86c9d8:	57                   	push   edi
  86c9d9:	13 d9                	adc    ebx,ecx
  86c9db:	89 46 10             	mov    DWORD PTR [esi+0x10],eax
  86c9de:	83 7d 10 00          	cmp    DWORD PTR [ebp+0x10],0x0
  86c9e2:	53                   	push   ebx
  86c9e3:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  86c9e6:	6a 04                	push   0x4
  86c9e8:	58                   	pop    eax
  86c9e9:	6a 02                	push   0x2
  86c9eb:	89 4e 14             	mov    DWORD PTR [esi+0x14],ecx
  86c9ee:	59                   	pop    ecx
  86c9ef:	0f 44 c1             	cmove  eax,ecx
  86c9f2:	50                   	push   eax
  86c9f3:	6a 00                	push   0x0
  86c9f5:	ff 33                	push   DWORD PTR [ebx]
  86c9f7:	ff 15 e4 b2 8f 00    	call   DWORD PTR ds:0x8fb2e4
  86c9fd:	8b c8                	mov    ecx,eax
  86c9ff:	89 4e 18             	mov    DWORD PTR [esi+0x18],ecx
  86ca02:	85 c9                	test   ecx,ecx
  86ca04:	75 07                	jne    0x86ca0d
  86ca06:	e8 a6 14 00 00       	call   0x86deb1
  86ca0b:	eb 76                	jmp    0x86ca83
  86ca0d:	83 7d 10 00          	cmp    DWORD PTR [ebp+0x10],0x0
  86ca11:	57                   	push   edi
  86ca12:	ff 75 fc             	push   DWORD PTR [ebp-0x4]
  86ca15:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  86ca18:	6a 02                	push   0x2
  86ca1a:	58                   	pop    eax
  86ca1b:	6a 04                	push   0x4
  86ca1d:	5a                   	pop    edx
  86ca1e:	0f 44 c2             	cmove  eax,edx
  86ca21:	50                   	push   eax
  86ca22:	51                   	push   ecx
  86ca23:	ff 15 ec b2 8f 00    	call   DWORD PTR ds:0x8fb2ec
  86ca29:	8b c8                	mov    ecx,eax
  86ca2b:	89 0e                	mov    DWORD PTR [esi],ecx
  86ca2d:	85 c9                	test   ecx,ecx
  86ca2f:	75 1c                	jne    0x86ca4d
  86ca31:	ff 76 18             	push   DWORD PTR [esi+0x18]
  86ca34:	ff 15 44 b2 8f 00    	call   DWORD PTR ds:0x8fb244
  86ca3a:	33 c0                	xor    eax,eax
  86ca3c:	89 46 18             	mov    DWORD PTR [esi+0x18],eax
  86ca3f:	89 46 08             	mov    DWORD PTR [esi+0x8],eax
  86ca42:	89 46 0c             	mov    DWORD PTR [esi+0xc],eax
  86ca45:	89 46 10             	mov    DWORD PTR [esi+0x10],eax
  86ca48:	89 46 14             	mov    DWORD PTR [esi+0x14],eax
  86ca4b:	eb b9                	jmp    0x86ca06
  86ca4d:	8b 46 10             	mov    eax,DWORD PTR [esi+0x10]
  86ca50:	03 c1                	add    eax,ecx
  86ca52:	89 06                	mov    DWORD PTR [esi],eax
  86ca54:	8b 35 38 b2 8f 00    	mov    esi,DWORD PTR ds:0x8fb238
  86ca5a:	ff d6                	call   esi
  86ca5c:	8b 1b                	mov    ebx,DWORD PTR [ebx]
  86ca5e:	8b f8                	mov    edi,eax
  86ca60:	ff d6                	call   esi
  86ca62:	6a 02                	push   0x2
  86ca64:	6a 00                	push   0x0
  86ca66:	6a 00                	push   0x0
  86ca68:	ff 75 f8             	push   DWORD PTR [ebp-0x8]
  86ca6b:	57                   	push   edi
  86ca6c:	53                   	push   ebx
  86ca6d:	50                   	push   eax
  86ca6e:	ff 15 4c b5 8f 00    	call   DWORD PTR ds:0x8fb54c
  86ca74:	a1 60 d2 9a 00       	mov    eax,ds:0x9ad260
  86ca79:	eb 08                	jmp    0x86ca83
  86ca7b:	6a 02                	push   0x2
  86ca7d:	e8 61 13 00 00       	call   0x86dde3
  86ca82:	59                   	pop    ecx
  86ca83:	5f                   	pop    edi
  86ca84:	5e                   	pop    esi
  86ca85:	5b                   	pop    ebx
  86ca86:	c9                   	leave
  86ca87:	c3                   	ret
  86ca88:	55                   	push   ebp
  86ca89:	8b                   	.byte 0x8b
