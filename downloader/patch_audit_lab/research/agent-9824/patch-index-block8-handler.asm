
agent-research/Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0068ce1e <.text+0x28be1e>:
  68ce1e:	55                   	push   ebp
  68ce1f:	8b ec                	mov    ebp,esp
  68ce21:	81 ec 88 00 00 00    	sub    esp,0x88
  68ce27:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  68ce2c:	33 c5                	xor    eax,ebp
  68ce2e:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  68ce31:	53                   	push   ebx
  68ce32:	56                   	push   esi
  68ce33:	57                   	push   edi
  68ce34:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  68ce37:	8b d9                	mov    ebx,ecx
  68ce39:	e8 5a b1 02 00       	call   0x6b7f98
  68ce3e:	8b cb                	mov    ecx,ebx
  68ce40:	e8 49 b1 02 00       	call   0x6b7f8e
  68ce45:	8b cb                	mov    ecx,ebx
  68ce47:	e8 42 b1 02 00       	call   0x6b7f8e
  68ce4c:	8b cb                	mov    ecx,ebx
  68ce4e:	88 45 8e             	mov    BYTE PTR [ebp-0x72],al
  68ce51:	e8 1f b1 02 00       	call   0x6b7f75
  68ce56:	8b cb                	mov    ecx,ebx
  68ce58:	0f b7 f0             	movzx  esi,ax
  68ce5b:	e8 22 b1 02 00       	call   0x6b7f82
  68ce60:	6a 04                	push   0x4
  68ce62:	8b cb                	mov    ecx,ebx
  68ce64:	89 45 88             	mov    DWORD PTR [ebp-0x78],eax
  68ce67:	e8 5c b1 02 00       	call   0x6b7fc8
  68ce6c:	8b cb                	mov    ecx,ebx
  68ce6e:	e8 1b b1 02 00       	call   0x6b7f8e
  68ce73:	8d 4d 8f             	lea    ecx,[ebp-0x71]
  68ce76:	0f b6 c0             	movzx  eax,al
  68ce79:	51                   	push   ecx
  68ce7a:	50                   	push   eax
  68ce7b:	8b cb                	mov    ecx,ebx
  68ce7d:	c6 45 8f 00          	mov    BYTE PTR [ebp-0x71],0x0
  68ce81:	e8 99 b0 02 00       	call   0x6b7f1f
  68ce86:	03 75 08             	add    esi,DWORD PTR [ebp+0x8]
  68ce89:	8b cb                	mov    ecx,ebx
  68ce8b:	56                   	push   esi
  68ce8c:	e8 07 b1 02 00       	call   0x6b7f98
  68ce91:	8d 4b 50             	lea    ecx,[ebx+0x50]
  68ce94:	e8 ff da ff ff       	call   0x68a998
  68ce99:	50                   	push   eax
  68ce9a:	e8 3d 06 00 00       	call   0x68d4dc
  68ce9f:	83 a5 7c ff ff ff 00 	and    DWORD PTR [ebp-0x84],0x0
  68cea6:	83 a5 78 ff ff ff 00 	and    DWORD PTR [ebp-0x88],0x0
  68cead:	83 7d 88 00          	cmp    DWORD PTR [ebp-0x78],0x0
  68ceb1:	59                   	pop    ecx
  68ceb2:	89 45 84             	mov    DWORD PTR [ebp-0x7c],eax
  68ceb5:	0f 86 12 01 00 00    	jbe    0x68cfcd
  68cebb:	0f b6 75 8e          	movzx  esi,BYTE PTR [ebp-0x72]
  68cebf:	89 75 80             	mov    DWORD PTR [ebp-0x80],esi
  68cec2:	6a 3c                	push   0x3c
  68cec4:	8d 45 90             	lea    eax,[ebp-0x70]
  68cec7:	6a 00                	push   0x0
  68cec9:	50                   	push   eax
  68ceca:	e8 41 ce 1e 00       	call   0x879d10
  68cecf:	83 c4 0c             	add    esp,0xc
  68ced2:	8d 45 dc             	lea    eax,[ebp-0x24]
  68ced5:	8b cb                	mov    ecx,ebx
  68ced7:	56                   	push   esi
  68ced8:	50                   	push   eax
  68ced9:	e8 63 b0 02 00       	call   0x6b7f41
  68cede:	8b f0                	mov    esi,eax
  68cee0:	8d 7d 90             	lea    edi,[ebp-0x70]
  68cee3:	8b cb                	mov    ecx,ebx
  68cee5:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68cee6:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68cee7:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68cee8:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68cee9:	e8 94 b0 02 00       	call   0x6b7f82
  68ceee:	89 45 a0             	mov    DWORD PTR [ebp-0x60],eax
  68cef1:	8a 45 8f             	mov    al,BYTE PTR [ebp-0x71]
  68cef4:	a8 01                	test   al,0x1
  68cef6:	74 14                	je     0x68cf0c
  68cef8:	8d 85 7c ff ff ff    	lea    eax,[ebp-0x84]
  68cefe:	8b cb                	mov    ecx,ebx
  68cf00:	50                   	push   eax
  68cf01:	ff 75 84             	push   DWORD PTR [ebp-0x7c]
  68cf04:	e8 16 b0 02 00       	call   0x6b7f1f
  68cf09:	8a 45 8f             	mov    al,BYTE PTR [ebp-0x71]
  68cf0c:	a8 04                	test   al,0x4
  68cf0e:	74 0a                	je     0x68cf1a
  68cf10:	8b cb                	mov    ecx,ebx
  68cf12:	e8 6b b0 02 00       	call   0x6b7f82
  68cf17:	89 45 a8             	mov    DWORD PTR [ebp-0x58],eax
  68cf1a:	ff 75 80             	push   DWORD PTR [ebp-0x80]
  68cf1d:	8d 45 cc             	lea    eax,[ebp-0x34]
  68cf20:	8b cb                	mov    ecx,ebx
  68cf22:	50                   	push   eax
  68cf23:	e8 19 b0 02 00       	call   0x6b7f41
  68cf28:	8b f0                	mov    esi,eax
  68cf2a:	8d 7d ac             	lea    edi,[ebp-0x54]
  68cf2d:	8b cb                	mov    ecx,ebx
  68cf2f:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68cf30:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68cf31:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68cf32:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  68cf33:	e8 4a b0 02 00       	call   0x6b7f82
  68cf38:	8b cb                	mov    ecx,ebx
  68cf3a:	89 45 bc             	mov    DWORD PTR [ebp-0x44],eax
  68cf3d:	e8 40 b0 02 00       	call   0x6b7f82
  68cf42:	f6 45 8f 02          	test   BYTE PTR [ebp-0x71],0x2
  68cf46:	89 45 c0             	mov    DWORD PTR [ebp-0x40],eax
  68cf49:	74 11                	je     0x68cf5c
  68cf4b:	8d 85 78 ff ff ff    	lea    eax,[ebp-0x88]
  68cf51:	8b cb                	mov    ecx,ebx
  68cf53:	50                   	push   eax
  68cf54:	ff 75 84             	push   DWORD PTR [ebp-0x7c]
  68cf57:	e8 c3 af 02 00       	call   0x6b7f1f
  68cf5c:	8b 75 80             	mov    esi,DWORD PTR [ebp-0x80]
  68cf5f:	8d 45 ec             	lea    eax,[ebp-0x14]
  68cf62:	56                   	push   esi
  68cf63:	50                   	push   eax
  68cf64:	8b cb                	mov    ecx,ebx
  68cf66:	e8 d6 af 02 00       	call   0x6b7f41
  68cf6b:	8d 53 50             	lea    edx,[ebx+0x50]
  68cf6e:	8a 0a                	mov    cl,BYTE PTR [edx]
  68cf70:	80 e1 01             	and    cl,0x1
  68cf73:	74 05                	je     0x68cf7a
  68cf75:	83 c2 04             	add    edx,0x4
  68cf78:	eb 03                	jmp    0x68cf7d
  68cf7a:	8b 52 04             	mov    edx,DWORD PTR [edx+0x4]
  68cf7d:	8b 85 7c ff ff ff    	mov    eax,DWORD PTR [ebp-0x84]
  68cf83:	03 c2                	add    eax,edx
  68cf85:	84 c9                	test   cl,cl
  68cf87:	89 45 a4             	mov    DWORD PTR [ebp-0x5c],eax
  68cf8a:	8d 4b 54             	lea    ecx,[ebx+0x54]
  68cf8d:	75 03                	jne    0x68cf92
  68cf8f:	8b 4b 54             	mov    ecx,DWORD PTR [ebx+0x54]
  68cf92:	8b 85 78 ff ff ff    	mov    eax,DWORD PTR [ebp-0x88]
  68cf98:	03 c1                	add    eax,ecx
  68cf9a:	8b cb                	mov    ecx,ebx
  68cf9c:	89 45 c4             	mov    DWORD PTR [ebp-0x3c],eax
  68cf9f:	8a 45 8e             	mov    al,BYTE PTR [ebp-0x72]
  68cfa2:	88 45 c8             	mov    BYTE PTR [ebp-0x38],al
  68cfa5:	88 45 c9             	mov    BYTE PTR [ebp-0x37],al
  68cfa8:	8d 83 38 01 00 00    	lea    eax,[ebx+0x138]
  68cfae:	50                   	push   eax
  68cfaf:	8d 83 1c 01 00 00    	lea    eax,[ebx+0x11c]
  68cfb5:	50                   	push   eax
  68cfb6:	8d 45 90             	lea    eax,[ebp-0x70]
  68cfb9:	50                   	push   eax
  68cfba:	8d 45 ec             	lea    eax,[ebp-0x14]
  68cfbd:	50                   	push   eax
  68cfbe:	e8 bc de ff ff       	call   0x68ae7f
  68cfc3:	83 6d 88 01          	sub    DWORD PTR [ebp-0x78],0x1
  68cfc7:	0f 85 f5 fe ff ff    	jne    0x68cec2
  68cfcd:	8a 45 8e             	mov    al,BYTE PTR [ebp-0x72]
  68cfd0:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  68cfd3:	5f                   	pop    edi
  68cfd4:	5e                   	pop    esi
  68cfd5:	88 83 18 01 00 00    	mov    BYTE PTR [ebx+0x118],al
  68cfdb:	33 cd                	xor    ecx,ebp
  68cfdd:	5b                   	pop    ebx
  68cfde:	e8 15 90 1e 00       	call   0x875ff8
  68cfe3:	c9                   	leave
  68cfe4:	c2 04 00             	ret    0x4
