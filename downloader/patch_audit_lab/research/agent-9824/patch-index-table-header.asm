
agent-research/Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0068d02c <.text+0x28c02c>:
  68d02c:	55                   	push   ebp
  68d02d:	8b ec                	mov    ebp,esp
  68d02f:	83 ec 1c             	sub    esp,0x1c
  68d032:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  68d037:	33 c5                	xor    eax,ebp
  68d039:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  68d03c:	57                   	push   edi
  68d03d:	8b f9                	mov    edi,ecx
  68d03f:	89 7d e8             	mov    DWORD PTR [ebp-0x18],edi
  68d042:	e8 3b af 02 00       	call   0x6b7f82
  68d047:	89 47 14             	mov    DWORD PTR [edi+0x14],eax
  68d04a:	39 45 08             	cmp    DWORD PTR [ebp+0x8],eax
  68d04d:	73 26                	jae    0x68d075
  68d04f:	50                   	push   eax
  68d050:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  68d053:	68 00 a8 9a 00       	push   0x9aa800
  68d058:	6a 00                	push   0x0
  68d05a:	68 08 bc 8f 00       	push   0x8fbc08
  68d05f:	6a 04                	push   0x4
  68d061:	68 a4 82 9a 00       	push   0x9a82a4
  68d066:	e8 d8 67 23 00       	call   0x8c3843
  68d06b:	83 c4 1c             	add    esp,0x1c
  68d06e:	b0 08                	mov    al,0x8
  68d070:	e9 fa 00 00 00       	jmp    0x68d16f
  68d075:	53                   	push   ebx
  68d076:	56                   	push   esi
  68d077:	8b cf                	mov    ecx,edi
  68d079:	e8 04 af 02 00       	call   0x6b7f82
  68d07e:	8b cf                	mov    ecx,edi
  68d080:	89 47 18             	mov    DWORD PTR [edi+0x18],eax
  68d083:	e8 fa ae 02 00       	call   0x6b7f82
  68d088:	8b cf                	mov    ecx,edi
  68d08a:	89 47 1c             	mov    DWORD PTR [edi+0x1c],eax
  68d08d:	e8 e3 ae 02 00       	call   0x6b7f75
  68d092:	0f b7 c0             	movzx  eax,ax
  68d095:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
  68d098:	66 85 c0             	test   ax,ax
  68d09b:	76 60                	jbe    0x68d0fd
  68d09d:	8b cf                	mov    ecx,edi
  68d09f:	e8 ea ae 02 00       	call   0x6b7f8e
  68d0a4:	8a d8                	mov    bl,al
  68d0a6:	8d 45 ec             	lea    eax,[ebp-0x14]
  68d0a9:	0f b6 cb             	movzx  ecx,bl
  68d0ac:	51                   	push   ecx
  68d0ad:	50                   	push   eax
  68d0ae:	8b cf                	mov    ecx,edi
  68d0b0:	e8 8c ae 02 00       	call   0x6b7f41
  68d0b5:	83 c7 20             	add    edi,0x20
  68d0b8:	8b f0                	mov    esi,eax
  68d0ba:	0f b6 c3             	movzx  eax,bl
  68d0bd:	b9 ff ff 00 00       	mov    ecx,0xffff
  68d0c2:	66 2b c8             	sub    cx,ax
  68d0c5:	66 8b 45 e4          	mov    ax,WORD PTR [ebp-0x1c]
  68d0c9:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68d0ca:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68d0cb:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68d0cc:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68d0cd:	8b 7d e8             	mov    edi,DWORD PTR [ebp-0x18]
  68d0d0:	66 03 c1             	add    ax,cx
  68d0d3:	74 28                	je     0x68d0fd
  68d0d5:	0f b7 d8             	movzx  ebx,ax
  68d0d8:	8d 4f 30             	lea    ecx,[edi+0x30]
  68d0db:	0f b6 05 7a a7 9a 00 	movzx  eax,BYTE PTR ds:0x9aa77a
  68d0e2:	50                   	push   eax
  68d0e3:	53                   	push   ebx
  68d0e4:	e8 54 d4 1d 00       	call   0x86a53d
  68d0e9:	f6 47 30 01          	test   BYTE PTR [edi+0x30],0x1
  68d0ed:	8d 47 34             	lea    eax,[edi+0x34]
  68d0f0:	75 02                	jne    0x68d0f4
  68d0f2:	8b 00                	mov    eax,DWORD PTR [eax]
  68d0f4:	50                   	push   eax
  68d0f5:	53                   	push   ebx
  68d0f6:	8b cf                	mov    ecx,edi
  68d0f8:	e8 22 ae 02 00       	call   0x6b7f1f
  68d0fd:	8b cf                	mov    ecx,edi
  68d0ff:	e8 7e ae 02 00       	call   0x6b7f82
  68d104:	8b f0                	mov    esi,eax
  68d106:	8d 4f 70             	lea    ecx,[edi+0x70]
  68d109:	56                   	push   esi
  68d10a:	89 75 e4             	mov    DWORD PTR [ebp-0x1c],esi
  68d10d:	e8 bf 02 00 00       	call   0x68d3d1
  68d112:	33 c9                	xor    ecx,ecx
  68d114:	33 db                	xor    ebx,ebx
  68d116:	89 4d e8             	mov    DWORD PTR [ebp-0x18],ecx
  68d119:	85 f6                	test   esi,esi
  68d11b:	74 36                	je     0x68d153
  68d11d:	8b 47 74             	mov    eax,DWORD PTR [edi+0x74]
  68d120:	8d 34 c8             	lea    esi,[eax+ecx*8]
  68d123:	8b cf                	mov    ecx,edi
  68d125:	e8 58 ae 02 00       	call   0x6b7f82
  68d12a:	8b cf                	mov    ecx,edi
  68d12c:	89 06                	mov    DWORD PTR [esi],eax
  68d12e:	e8 4f ae 02 00       	call   0x6b7f82
  68d133:	56                   	push   esi
  68d134:	8d 8f 80 00 00 00    	lea    ecx,[edi+0x80]
  68d13a:	89 46 04             	mov    DWORD PTR [esi+0x4],eax
  68d13d:	e8 e6 dc ff ff       	call   0x68ae28
  68d142:	8b 4d e8             	mov    ecx,DWORD PTR [ebp-0x18]
  68d145:	89 18                	mov    DWORD PTR [eax],ebx
  68d147:	03 5e 04             	add    ebx,DWORD PTR [esi+0x4]
  68d14a:	41                   	inc    ecx
  68d14b:	89 4d e8             	mov    DWORD PTR [ebp-0x18],ecx
  68d14e:	3b 4d e4             	cmp    ecx,DWORD PTR [ebp-0x1c]
  68d151:	72 ca                	jb     0x68d11d
  68d153:	8b 47 14             	mov    eax,DWORD PTR [edi+0x14]
  68d156:	03 c3                	add    eax,ebx
  68d158:	5e                   	pop    esi
  68d159:	5b                   	pop    ebx
  68d15a:	39 45 08             	cmp    DWORD PTR [ebp+0x8],eax
  68d15d:	73 0e                	jae    0x68d16d
  68d15f:	50                   	push   eax
  68d160:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  68d163:	68 60 a8 9a 00       	push   0x9aa860
  68d168:	e9 eb fe ff ff       	jmp    0x68d058
  68d16d:	32 c0                	xor    al,al
  68d16f:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  68d172:	33 cd                	xor    ecx,ebp
  68d174:	5f                   	pop    edi
  68d175:	e8 7e 8e 1e 00       	call   0x875ff8
  68d17a:	c9                   	leave
  68d17b:	c2 04 00             	ret    0x4
