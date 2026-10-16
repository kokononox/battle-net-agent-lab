
agent-research/Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

006e3cb0 <.text+0x2e2cb0>:
  6e3cb0:	41                   	inc    ecx
  6e3cb1:	01 0f                	add    DWORD PTR [edi],ecx
  6e3cb3:	a4                   	movs   BYTE PTR es:[edi],BYTE PTR ds:[esi]
  6e3cb4:	fe 08                	dec    BYTE PTR [eax]
  6e3cb6:	99                   	cdq
  6e3cb7:	c1 e7 08             	shl    edi,0x8
  6e3cba:	0b f2                	or     esi,edx
  6e3cbc:	0b f8                	or     edi,eax
  6e3cbe:	0f b6 01             	movzx  eax,BYTE PTR [ecx]
  6e3cc1:	0f a4 fe 08          	shld   esi,edi,0x8
  6e3cc5:	99                   	cdq
  6e3cc6:	c1 e7 08             	shl    edi,0x8
  6e3cc9:	0b f2                	or     esi,edx
  6e3ccb:	0b f8                	or     edi,eax
  6e3ccd:	84 db                	test   bl,bl
  6e3ccf:	79 07                	jns    0x6e3cd8
  6e3cd1:	f7 df                	neg    edi
  6e3cd3:	83 d6 00             	adc    esi,0x0
  6e3cd6:	f7 de                	neg    esi
  6e3cd8:	8b c7                	mov    eax,edi
  6e3cda:	8b d6                	mov    edx,esi
  6e3cdc:	5f                   	pop    edi
  6e3cdd:	5e                   	pop    esi
  6e3cde:	5b                   	pop    ebx
  6e3cdf:	5d                   	pop    ebp
  6e3ce0:	c3                   	ret
  6e3ce1:	55                   	push   ebp
  6e3ce2:	8b ec                	mov    ebp,esp
  6e3ce4:	53                   	push   ebx
  6e3ce5:	33 d2                	xor    edx,edx
  6e3ce7:	6a 20                	push   0x20
  6e3ce9:	5b                   	pop    ebx
  6e3cea:	39 55 10             	cmp    DWORD PTR [ebp+0x10],edx
  6e3ced:	77 2f                	ja     0x6e3d1e
  6e3cef:	72 05                	jb     0x6e3cf6
  6e3cf1:	39 5d 0c             	cmp    DWORD PTR [ebp+0xc],ebx
  6e3cf4:	73 28                	jae    0x6e3d1e
  6e3cf6:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  6e3cf9:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  6e3cfc:	53                   	push   ebx
  6e3cfd:	68 40 75 9b 00       	push   0x9b7540
  6e3d02:	52                   	push   edx
  6e3d03:	68 08 bc 8f 00       	push   0x8fbc08
  6e3d08:	6a 04                	push   0x4
  6e3d0a:	68 a4 82 9a 00       	push   0x9a82a4
  6e3d0f:	e8 2f fb 1d 00       	call   0x8c3843
  6e3d14:	83 c4 20             	add    esp,0x20
  6e3d17:	b0 08                	mov    al,0x8
  6e3d19:	e9 b5 00 00 00       	jmp    0x6e3dd3
  6e3d1e:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  6e3d21:	56                   	push   esi
  6e3d22:	be 30 75 9b 00       	mov    esi,0x9b7530
  6e3d27:	8b 01                	mov    eax,DWORD PTR [ecx]
  6e3d29:	3b 06                	cmp    eax,DWORD PTR [esi]
  6e3d2b:	0f 85 85 00 00 00    	jne    0x6e3db6
  6e3d31:	8b 41 04             	mov    eax,DWORD PTR [ecx+0x4]
  6e3d34:	3b 46 04             	cmp    eax,DWORD PTR [esi+0x4]
  6e3d37:	75 7d                	jne    0x6e3db6
  6e3d39:	8b 75 1c             	mov    esi,DWORD PTR [ebp+0x1c]
  6e3d3c:	8d 41 08             	lea    eax,[ecx+0x8]
  6e3d3f:	57                   	push   edi
  6e3d40:	50                   	push   eax
  6e3d41:	89 1e                	mov    DWORD PTR [esi],ebx
  6e3d43:	89 56 04             	mov    DWORD PTR [esi+0x4],edx
  6e3d46:	e8 fb fe ff ff       	call   0x6e3c46
  6e3d4b:	8b f8                	mov    edi,eax
  6e3d4d:	8b da                	mov    ebx,edx
  6e3d4f:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  6e3d52:	8b cb                	mov    ecx,ebx
  6e3d54:	89 7e 08             	mov    DWORD PTR [esi+0x8],edi
  6e3d57:	89 5e 0c             	mov    DWORD PTR [esi+0xc],ebx
  6e3d5a:	8b f7                	mov    esi,edi
  6e3d5c:	83 c6 20             	add    esi,0x20
  6e3d5f:	89 70 10             	mov    DWORD PTR [eax+0x10],esi
  6e3d62:	8b f0                	mov    esi,eax
  6e3d64:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  6e3d67:	83 d1 00             	adc    ecx,0x0
  6e3d6a:	83 c0 10             	add    eax,0x10
  6e3d6d:	50                   	push   eax
  6e3d6e:	89 4e 14             	mov    DWORD PTR [esi+0x14],ecx
  6e3d71:	e8 d0 fe ff ff       	call   0x6e3c46
  6e3d76:	8b 4d 14             	mov    ecx,DWORD PTR [ebp+0x14]
  6e3d79:	89 46 18             	mov    DWORD PTR [esi+0x18],eax
  6e3d7c:	03 c7                	add    eax,edi
  6e3d7e:	89 56 1c             	mov    DWORD PTR [esi+0x1c],edx
  6e3d81:	13 d3                	adc    edx,ebx
  6e3d83:	83 c0 20             	add    eax,0x20
  6e3d86:	89 46 20             	mov    DWORD PTR [esi+0x20],eax
  6e3d89:	83 d2 00             	adc    edx,0x0
  6e3d8c:	2b c8                	sub    ecx,eax
  6e3d8e:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  6e3d91:	1b c2                	sbb    eax,edx
  6e3d93:	89 56 24             	mov    DWORD PTR [esi+0x24],edx
  6e3d96:	89 46 2c             	mov    DWORD PTR [esi+0x2c],eax
  6e3d99:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  6e3d9c:	83 c0 18             	add    eax,0x18
  6e3d9f:	89 4e 28             	mov    DWORD PTR [esi+0x28],ecx
  6e3da2:	50                   	push   eax
  6e3da3:	e8 9e fe ff ff       	call   0x6e3c46
  6e3da8:	83 c4 0c             	add    esp,0xc
  6e3dab:	89 46 30             	mov    DWORD PTR [esi+0x30],eax
  6e3dae:	89 56 34             	mov    DWORD PTR [esi+0x34],edx
  6e3db1:	32 c0                	xor    al,al
  6e3db3:	5f                   	pop    edi
  6e3db4:	eb 1c                	jmp    0x6e3dd2
  6e3db6:	68 88 75 9b 00       	push   0x9b7588
  6e3dbb:	52                   	push   edx
  6e3dbc:	68 08 bc 8f 00       	push   0x8fbc08
  6e3dc1:	6a 04                	push   0x4
  6e3dc3:	68 a4 82 9a 00       	push   0x9a82a4
  6e3dc8:	e8 76 fa 1d 00       	call   0x8c3843
  6e3dcd:	83 c4 14             	add    esp,0x14
  6e3dd0:	b0 08                	mov    al,0x8
  6e3dd2:	5e                   	pop    esi
  6e3dd3:	5b                   	pop    ebx
  6e3dd4:	5d                   	pop    ebp
  6e3dd5:	c3                   	ret
  6e3dd6:	68 90 00 00 00       	push   0x90
  6e3ddb:	b8 7d 00 8f 00       	mov    eax,0x8f007d
  6e3de0:	e8 53 22 19 00       	call   0x876038
  6e3de5:	8d 8d 78 ff ff ff    	lea    ecx,[ebp-0x88]
  6e3deb:	e8 68 fa ff ff       	call   0x6e3858
  6e3df0:	8d 85 78 ff ff ff    	lea    eax,[ebp-0x88]
  6e3df6:	33 db                	xor    ebx,ebx
  6e3df8:	50                   	push   eax
  6e3df9:	53                   	push   ebx
  6e3dfa:	ff 75 1c             	push   DWORD PTR [ebp+0x1c]
  6e3dfd:	53                   	push   ebx
  6e3dfe:	ff 75 1c             	push   DWORD PTR [ebp+0x1c]
  6e3e01:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  6e3e04:	e8 d8 fe ff ff       	call   0x6e3ce1
  6e3e09:	83 c4 18             	add    esp,0x18
  6e3e0c:	84 c0                	test   al,al
  6e3e0e:	0f 85 7a 03 00 00    	jne    0x6e418e
  6e3e14:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  6e3e17:	3b 5d ac             	cmp    ebx,DWORD PTR [ebp-0x54]
  6e3e1a:	7f 0e                	jg     0x6e3e2a
  6e3e1c:	7c 05                	jl     0x6e3e23
  6e3e1e:	3b 45 a8             	cmp    eax,DWORD PTR [ebp-0x58]
  6e3e21:	73 07                	jae    0x6e3e2a
  6e3e23:	b0 04                	mov    al,0x4
  6e3e25:	e9 64 03 00 00       	jmp    0x6e418e
  6e3e2a:	6b 4d 80 06          	imul   ecx,DWORD PTR [ebp-0x80],0x6
  6e3e2e:	6b 7d 90 0c          	imul   edi,DWORD PTR [ebp-0x70],0xc
  6e3e32:	6b 75 a0 03          	imul   esi,DWORD PTR [ebp-0x60],0x3
  6e3e36:	a1 a0 8c a5 00       	mov    eax,ds:0xa58ca0
  6e3e3b:	53                   	push   ebx
  6e3e3c:	68 08 bc 8f 00       	push   0x8fbc08
  6e3e41:	53                   	push   ebx
  6e3e42:	6a 08                	push   0x8
  6e3e44:	5b                   	pop    ebx
  6e3e45:	53                   	push   ebx
  6e3e46:	51                   	push   ecx
  6e3e47:	6a 00                	push   0x0
  6e3e49:	ff 35 a4 8c a5 00    	push   DWORD PTR ds:0xa58ca4
  6e3e4f:	89 4d 1c             	mov    DWORD PTR [ebp+0x1c],ecx
  6e3e52:	89 7d e0             	mov    DWORD PTR [ebp-0x20],edi
  6e3e55:	89 75 f0             	mov    DWORD PTR [ebp-0x10],esi
  6e3e58:	ff d0                	call   eax
  6e3e5a:	33 c9                	xor    ecx,ecx
  6e3e5c:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
  6e3e5f:	a1 a0 8c a5 00       	mov    eax,ds:0xa58ca0
  6e3e64:	51                   	push   ecx
  6e3e65:	68 08 bc 8f 00       	push   0x8fbc08
  6e3e6a:	51                   	push   ecx
  6e3e6b:	53                   	push   ebx
  6e3e6c:	57                   	push   edi
  6e3e6d:	51                   	push   ecx
  6e3e6e:	ff 35 a4 8c a5 00    	push   DWORD PTR ds:0xa58ca4
  6e3e74:	ff d0                	call   eax
  6e3e76:	33 c9                	xor    ecx,ecx
  6e3e78:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
  6e3e7b:	a1 a0 8c a5 00       	mov    eax,ds:0xa58ca0
  6e3e80:	51                   	push   ecx
  6e3e81:	68 08 bc 8f 00       	push   0x8fbc08
  6e3e86:	51                   	push   ecx
  6e3e87:	53                   	push   ebx
  6e3e88:	56                   	push   esi
  6e3e89:	51                   	push   ecx
  6e3e8a:	ff 35 a4 8c a5 00    	push   DWORD PTR ds:0xa58ca4
  6e3e90:	ff d0                	call   eax
  6e3e92:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
  6e3e95:	83 c4 54             	add    esp,0x54
  6e3e98:	8d 45 e4             	lea    eax,[ebp-0x1c]
  6e3e9b:	89 85 64 ff ff ff    	mov    DWORD PTR [ebp-0x9c],eax
  6e3ea1:	8d 45 ec             	lea    eax,[ebp-0x14]
  6e3ea4:	89 85 68 ff ff ff    	mov    DWORD PTR [ebp-0x98],eax
  6e3eaa:	8d 45 e8             	lea    eax,[ebp-0x18]
  6e3ead:	89 85 6c ff ff ff    	mov    DWORD PTR [ebp-0x94],eax
  6e3eb3:	8b 85 78 ff ff ff    	mov    eax,DWORD PTR [ebp-0x88]
  6e3eb9:	33 d2                	xor    edx,edx
  6e3ebb:	03 45 18             	add    eax,DWORD PTR [ebp+0x18]
  6e3ebe:	52                   	push   edx
  6e3ebf:	52                   	push   edx
  6e3ec0:	52                   	push   edx
  6e3ec1:	ff 75 80             	push   DWORD PTR [ebp-0x80]
  6e3ec4:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  6e3ec7:	50                   	push   eax
  6e3ec8:	ff 75 1c             	push   DWORD PTR [ebp+0x1c]
  6e3ecb:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
  6e3ece:	ff 75 e4             	push   DWORD PTR [ebp-0x1c]
  6e3ed1:	e8 db a6 ff ff       	call   0x6de5b1
  6e3ed6:	83 c4 1c             	add    esp,0x1c
  6e3ed9:	3c 04                	cmp    al,0x4
  6e3edb:	75 43                	jne    0x6e3f20
  6e3edd:	8b 7d 1c             	mov    edi,DWORD PTR [ebp+0x1c]
  6e3ee0:	8b 75 80             	mov    esi,DWORD PTR [ebp-0x80]
  6e3ee3:	a1 a0 8c a5 00       	mov    eax,ds:0xa58ca0
  6e3ee8:	03 ff                	add    edi,edi
  6e3eea:	6a 00                	push   0x0
  6e3eec:	68 08 bc 8f 00       	push   0x8fbc08
  6e3ef1:	6a 00                	push   0x0
  6e3ef3:	53                   	push   ebx
  6e3ef4:	57                   	push   edi
  6e3ef5:	ff 75 e4             	push   DWORD PTR [ebp-0x1c]
  6e3ef8:	ff 35 a4 8c a5 00    	push   DWORD PTR ds:0xa58ca4
  6e3efe:	ff d0                	call   eax
  6e3f00:	33 c9                	xor    ecx,ecx
  6e3f02:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
  6e3f05:	51                   	push   ecx
  6e3f06:	51                   	push   ecx
  6e3f07:	51                   	push   ecx
  6e3f08:	56                   	push   esi
  6e3f09:	ff 75 d8             	push   DWORD PTR [ebp-0x28]
  6e3f0c:	57                   	push   edi
  6e3f0d:	50                   	push   eax
  6e3f0e:	e8 9e a6 ff ff       	call   0x6de5b1
  6e3f13:	83 c4 38             	add    esp,0x38
  6e3f16:	3c 04                	cmp    al,0x4
  6e3f18:	74 c9                	je     0x6e3ee3
  6e3f1a:	8b 75 f0             	mov    esi,DWORD PTR [ebp-0x10]
  6e3f1d:	8b 7d e0             	mov    edi,DWORD PTR [ebp-0x20]
  6e3f20:	84 c0                	test   al,al
  6e3f22:	74 0a                	je     0x6e3f2e
  6e3f24:	b9 c0 75 9b 00       	mov    ecx,0x9b75c0
  6e3f29:	e9 74 02 00 00       	jmp    0x6e41a2
  6e3f2e:	8b 45 88             	mov    eax,DWORD PTR [ebp-0x78]
  6e3f31:	33 c9                	xor    ecx,ecx
  6e3f33:	03 45 18             	add    eax,DWORD PTR [ebp+0x18]
  6e3f36:	51                   	push   ecx
  6e3f37:	51                   	push   ecx
  6e3f38:	51                   	push   ecx
  6e3f39:	ff 75 90             	push   DWORD PTR [ebp-0x70]
  6e3f3c:	89 45 1c             	mov    DWORD PTR [ebp+0x1c],eax
  6e3f3f:	50                   	push   eax
  6e3f40:	57                   	push   edi
  6e3f41:	ff 75 ec             	push   DWORD PTR [ebp-0x14]
  6e3f44:	e8 68 a6 ff ff       	call   0x6de5b1
  6e3f49:	83 c4 1c             	add    esp,0x1c
  6e3f4c:	3c 04                	cmp    al,0x4
  6e3f4e:	75 3e                	jne    0x6e3f8e
  6e3f50:	8b 75 1c             	mov    esi,DWORD PTR [ebp+0x1c]
  6e3f53:	a1 a0 8c a5 00       	mov    eax,ds:0xa58ca0
  6e3f58:	6a 00                	push   0x0
  6e3f5a:	68 08 bc 8f 00       	push   0x8fbc08
  6e3f5f:	6a 00                	push   0x0
  6e3f61:	6b ff 06             	imul   edi,edi,0x6
  6e3f64:	53                   	push   ebx
  6e3f65:	57                   	push   edi
  6e3f66:	ff 75 ec             	push   DWORD PTR [ebp-0x14]
  6e3f69:	ff 35 a4 8c a5 00    	push   DWORD PTR ds:0xa58ca4
  6e3f6f:	ff d0                	call   eax
  6e3f71:	33 c9                	xor    ecx,ecx
  6e3f73:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
  6e3f76:	51                   	push   ecx
  6e3f77:	51                   	push   ecx
  6e3f78:	51                   	push   ecx
  6e3f79:	ff 75 90             	push   DWORD PTR [ebp-0x70]
  6e3f7c:	56                   	push   esi
  6e3f7d:	57                   	push   edi
  6e3f7e:	50                   	push   eax
  6e3f7f:	e8                   	.byte 0xe8
