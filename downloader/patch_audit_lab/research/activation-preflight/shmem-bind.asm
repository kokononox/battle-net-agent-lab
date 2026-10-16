
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071dc00 <.text+0x31cc00>:
  71dc00:	8c 00                	mov    WORD PTR [eax],es
  71dc02:	64 a1 00 00 00 00    	mov    eax,fs:0x0
  71dc08:	50                   	push   eax
  71dc09:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71dc0e:	33 c5                	xor    eax,ebp
  71dc10:	50                   	push   eax
  71dc11:	8d 45 f4             	lea    eax,[ebp-0xc]
  71dc14:	64 a3 00 00 00 00    	mov    fs:0x0,eax
  71dc1a:	80 79 04 00          	cmp    BYTE PTR [ecx+0x4],0x0
  71dc1e:	74 08                	je     0x71dc28
  71dc20:	ff 31                	push   DWORD PTR [ecx]
  71dc22:	e8 6e 06 00 00       	call   0x71e295
  71dc27:	59                   	pop    ecx
  71dc28:	8b 4d f4             	mov    ecx,DWORD PTR [ebp-0xc]
  71dc2b:	64 89 0d 00 00 00 00 	mov    DWORD PTR fs:0x0,ecx
  71dc32:	59                   	pop    ecx
  71dc33:	c9                   	leave
  71dc34:	c3                   	ret
  71dc35:	cc                   	int3
  71dc36:	cc                   	int3
  71dc37:	cc                   	int3
  71dc38:	cc                   	int3
  71dc39:	cc                   	int3
  71dc3a:	55                   	push   ebp
  71dc3b:	8b ec                	mov    ebp,esp
  71dc3d:	b8 04 10 00 00       	mov    eax,0x1004
  71dc42:	e8 09 91 15 00       	call   0x876d50
  71dc47:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71dc4c:	33 c5                	xor    eax,ebp
  71dc4e:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71dc51:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  71dc54:	53                   	push   ebx
  71dc55:	56                   	push   esi
  71dc56:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  71dc59:	8b 98 50 01 00 00    	mov    ebx,DWORD PTR [eax+0x150]
  71dc5f:	57                   	push   edi
  71dc60:	f6 c3 02             	test   bl,0x2
  71dc63:	74 70                	je     0x71dcd5
  71dc65:	f6 80 54 01 00 00 01 	test   BYTE PTR [eax+0x154],0x1
  71dc6c:	74 67                	je     0x71dcd5
  71dc6e:	8b 16                	mov    edx,DWORD PTR [esi]
  71dc70:	33 ff                	xor    edi,edi
  71dc72:	47                   	inc    edi
  71dc73:	0f bc c7             	bsf    eax,edi
  71dc76:	8b 8c 82 d8 01 00 00 	mov    ecx,DWORD PTR [edx+eax*4+0x1d8]
  71dc7d:	03 ca                	add    ecx,edx
  71dc7f:	e8 81 fe ff ff       	call   0x71db05
  71dc84:	84 c0                	test   al,al
  71dc86:	74 4d                	je     0x71dcd5
  71dc88:	8b 16                	mov    edx,DWORD PTR [esi]
  71dc8a:	0f bc c7             	bsf    eax,edi
  71dc8d:	68 00 10 00 00       	push   0x1000
  71dc92:	8b 8c 82 d8 01 00 00 	mov    ecx,DWORD PTR [edx+eax*4+0x1d8]
  71dc99:	8d 85 fc ef ff ff    	lea    eax,[ebp-0x1004]
  71dc9f:	03 ca                	add    ecx,edx
  71dca1:	50                   	push   eax
  71dca2:	e8 65 fd ff ff       	call   0x71da0c
  71dca7:	80 bd fc ef ff ff 00 	cmp    BYTE PTR [ebp-0x1004],0x0
  71dcae:	74 25                	je     0x71dcd5
  71dcb0:	8d 85 fc ef ff ff    	lea    eax,[ebp-0x1004]
  71dcb6:	50                   	push   eax
  71dcb7:	53                   	push   ebx
  71dcb8:	68 a8 e4 9b 00       	push   0x9be4a8
  71dcbd:	6a 00                	push   0x0
  71dcbf:	68 08 bc 8f 00       	push   0x8fbc08
  71dcc4:	6a 04                	push   0x4
  71dcc6:	68 38 ba 9b 00       	push   0x9bba38
  71dccb:	e8 73 5b 1a 00       	call   0x8c3843
  71dcd0:	83 c4 1c             	add    esp,0x1c
  71dcd3:	eb 1c                	jmp    0x71dcf1
  71dcd5:	53                   	push   ebx
  71dcd6:	68 f8 e4 9b 00       	push   0x9be4f8
  71dcdb:	6a 00                	push   0x0
  71dcdd:	68 08 bc 8f 00       	push   0x8fbc08
  71dce2:	6a 04                	push   0x4
  71dce4:	68 38 ba 9b 00       	push   0x9bba38
  71dce9:	e8 55 5b 1a 00       	call   0x8c3843
  71dcee:	83 c4 18             	add    esp,0x18
  71dcf1:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  71dcf4:	5f                   	pop    edi
  71dcf5:	5e                   	pop    esi
  71dcf6:	33 cd                	xor    ecx,ebp
  71dcf8:	5b                   	pop    ebx
  71dcf9:	e8 fa 82 15 00       	call   0x875ff8
  71dcfe:	c9                   	leave
  71dcff:	c3                   	ret
  71dd00:	55                   	push   ebp
  71dd01:	8b ec                	mov    ebp,esp
  71dd03:	83 7d 0c 04          	cmp    DWORD PTR [ebp+0xc],0x4
  71dd07:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  71dd0a:	75 08                	jne    0x71dd14
  71dd0c:	83 c0 0f             	add    eax,0xf
  71dd0f:	83 e0 f0             	and    eax,0xfffffff0
  71dd12:	5d                   	pop    ebp
  71dd13:	c3                   	ret
  71dd14:	05 ff 0f 00 00       	add    eax,0xfff
  71dd19:	25 00 f0 ff ff       	and    eax,0xfffff000
  71dd1e:	5d                   	pop    ebp
  71dd1f:	c3                   	ret
  71dd20:	55                   	push   ebp
  71dd21:	8b ec                	mov    ebp,esp
  71dd23:	81 ec 18 03 00 00    	sub    esp,0x318
  71dd29:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71dd2e:	33 c5                	xor    eax,ebp
  71dd30:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71dd33:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  71dd36:	53                   	push   ebx
  71dd37:	8b 5d 14             	mov    ebx,DWORD PTR [ebp+0x14]
  71dd3a:	56                   	push   esi
  71dd3b:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  71dd3e:	57                   	push   edi
  71dd3f:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  71dd42:	89 85 ec fc ff ff    	mov    DWORD PTR [ebp-0x314],eax
  71dd48:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  71dd4b:	68 b8 ba 9b 00       	push   0x9bbab8
  71dd50:	89 85 e8 fc ff ff    	mov    DWORD PTR [ebp-0x318],eax
  71dd56:	8d 85 f0 fc ff ff    	lea    eax,[ebp-0x310]
  71dd5c:	56                   	push   esi
  71dd5d:	50                   	push   eax
  71dd5e:	e8 fb 26 de ff       	call   0x50045e
  71dd63:	8b 85 e8 fc ff ff    	mov    eax,DWORD PTR [ebp-0x318]
  71dd69:	83 c4 0c             	add    esp,0xc
  71dd6c:	83 38 04             	cmp    DWORD PTR [eax],0x4
  71dd6f:	75 1d                	jne    0x71dd8e
  71dd71:	8d 85 f0 fc ff ff    	lea    eax,[ebp-0x310]
  71dd77:	50                   	push   eax
  71dd78:	ff b5 ec fc ff ff    	push   DWORD PTR [ebp-0x314]
  71dd7e:	53                   	push   ebx
  71dd7f:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71dd82:	56                   	push   esi
  71dd83:	57                   	push   edi
  71dd84:	e8 3a 00 00 00       	call   0x71ddc3
  71dd89:	83 c4 18             	add    esp,0x18
  71dd8c:	eb 26                	jmp    0x71ddb4
  71dd8e:	83 38 05             	cmp    DWORD PTR [eax],0x5
  71dd91:	75 1e                	jne    0x71ddb1
  71dd93:	8d 8d f0 fc ff ff    	lea    ecx,[ebp-0x310]
  71dd99:	51                   	push   ecx
  71dd9a:	50                   	push   eax
  71dd9b:	ff b5 ec fc ff ff    	push   DWORD PTR [ebp-0x314]
  71dda1:	53                   	push   ebx
  71dda2:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71dda5:	56                   	push   esi
  71dda6:	57                   	push   edi
  71dda7:	e8 e7 00 00 00       	call   0x71de93
  71ddac:	83 c4 1c             	add    esp,0x1c
  71ddaf:	eb 03                	jmp    0x71ddb4
  71ddb1:	6a 0a                	push   0xa
  71ddb3:	58                   	pop    eax
  71ddb4:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  71ddb7:	5f                   	pop    edi
  71ddb8:	5e                   	pop    esi
  71ddb9:	33 cd                	xor    ecx,ebp
  71ddbb:	5b                   	pop    ebx
  71ddbc:	e8 37 82 15 00       	call   0x875ff8
  71ddc1:	c9                   	leave
  71ddc2:	c3                   	ret
  71ddc3:	55                   	push   ebp
  71ddc4:	8b ec                	mov    ebp,esp
  71ddc6:	81 ec 5c 01 00 00    	sub    esp,0x15c
  71ddcc:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71ddd1:	33 c5                	xor    eax,ebp
  71ddd3:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71ddd6:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  71ddd9:	53                   	push   ebx
  71ddda:	8b 5d 14             	mov    ebx,DWORD PTR [ebp+0x14]
  71dddd:	56                   	push   esi
  71ddde:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  71dde1:	57                   	push   edi
  71dde2:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  71dde5:	89 85 a8 fe ff ff    	mov    DWORD PTR [ebp-0x158],eax
  71ddeb:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  71ddee:	68 48 01 00 00       	push   0x148
  71ddf3:	89 85 a4 fe ff ff    	mov    DWORD PTR [ebp-0x15c],eax
  71ddf9:	8d 85 b4 fe ff ff    	lea    eax,[ebp-0x14c]
  71ddff:	6a 00                	push   0x0
  71de01:	50                   	push   eax
  71de02:	e8 09 bf 15 00       	call   0x879d10
  71de07:	56                   	push   esi
  71de08:	8d 85 b4 fe ff ff    	lea    eax,[ebp-0x14c]
  71de0e:	c7 85 ac fe ff ff 04 	mov    DWORD PTR [ebp-0x154],0x4
  71de15:	00 00 00 
  71de18:	68 00 01 00 00       	push   0x100
  71de1d:	50                   	push   eax
  71de1e:	c7 85 b0 fe ff ff 50 	mov    DWORD PTR [ebp-0x150],0x150
  71de25:	01 00 00 
  71de28:	e8 f2 01 00 00       	call   0x71e01f
  71de2d:	83 c4 18             	add    esp,0x18
  71de30:	85 c0                	test   eax,eax
  71de32:	75 50                	jne    0x71de84
  71de34:	83 bd ac fe ff ff 04 	cmp    DWORD PTR [ebp-0x154],0x4
  71de3b:	c7 45 b4 b8 2a 00 00 	mov    DWORD PTR [ebp-0x4c],0x2ab8
  71de42:	75 0e                	jne    0x71de52
  71de44:	c7 45 b8 50 01 00 00 	mov    DWORD PTR [ebp-0x48],0x150
  71de4b:	b8 10 2c 00 00       	mov    eax,0x2c10
  71de50:	eb 0c                	jmp    0x71de5e
  71de52:	c7 45 b8 00 10 00 00 	mov    DWORD PTR [ebp-0x48],0x1000
  71de59:	b8 00 40 00 00       	mov    eax,0x4000
  71de5e:	ff b5 a8 fe ff ff    	push   DWORD PTR [ebp-0x158]
  71de64:	8d 8d ac fe ff ff    	lea    ecx,[ebp-0x154]
  71de6a:	53                   	push   ebx
  71de6b:	68 50 01 00 00       	push   0x150
  71de70:	51                   	push   ecx
  71de71:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71de74:	50                   	push   eax
  71de75:	ff b5 a4 fe ff ff    	push   DWORD PTR [ebp-0x15c]
  71de7b:	57                   	push   edi
  71de7c:	e8 e4 03 01 00       	call   0x72e265
  71de81:	83 c4 20             	add    esp,0x20
  71de84:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  71de87:	5f                   	pop    edi
  71de88:	5e                   	pop    esi
  71de89:	33 cd                	xor    ecx,ebp
  71de8b:	5b                   	pop    ebx
  71de8c:	e8 67 81 15 00       	call   0x875ff8
  71de91:	c9                   	leave
  71de92:	c3                   	ret
  71de93:	55                   	push   ebp
  71de94:	8b ec                	mov    ebp,esp
  71de96:	81 ec 6c 02 00 00    	sub    esp,0x26c
  71de9c:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71dea1:	33 c5                	xor    eax,ebp
  71dea3:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71dea6:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  71dea9:	89 85 94 fd ff ff    	mov    DWORD PTR [ebp-0x26c],eax
  71deaf:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  71deb2:	53                   	push   ebx
  71deb3:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  71deb6:	89 85 9c fd ff ff    	mov    DWORD PTR [ebp-0x264],eax
  71debc:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  71debf:	89 85 a0 fd ff ff    	mov    DWORD PTR [ebp-0x260],eax
  71dec5:	8b 45 20             	mov    eax,DWORD PTR [ebp+0x20]
  71dec8:	56                   	push   esi
  71dec9:	57                   	push   edi
  71deca:	8b 7d 1c             	mov    edi,DWORD PTR [ebp+0x1c]
  71decd:	89 85 98 fd ff ff    	mov    DWORD PTR [ebp-0x268],eax
  71ded3:	b8 58 02 00 00       	mov    eax,0x258
  71ded8:	50                   	push   eax
  71ded9:	8d 85 a4 fd ff ff    	lea    eax,[ebp-0x25c]
  71dedf:	6a 00                	push   0x0
  71dee1:	50                   	push   eax
  71dee2:	e8 29 be 15 00       	call   0x879d10
  71dee7:	8b 47 04             	mov    eax,DWORD PTR [edi+0x4]
  71deea:	83 c4 0c             	add    esp,0xc
  71deed:	83 e0 fe             	and    eax,0xfffffffe
  71def0:	be 54 01 00 00       	mov    esi,0x154
  71def5:	b9 58 02 00 00       	mov    ecx,0x258
  71defa:	89 b5 a8 fd ff ff    	mov    DWORD PTR [ebp-0x258],esi
  71df00:	0f 45 f1             	cmovne esi,ecx
  71df03:	89 47 04             	mov    DWORD PTR [edi+0x4],eax
  71df06:	83 7d 10 04          	cmp    DWORD PTR [ebp+0x10],0x4
  71df0a:	6a 05                	push   0x5
  71df0c:	5a                   	pop    edx
  71df0d:	89 95 a4 fd ff ff    	mov    DWORD PTR [ebp-0x25c],edx
  71df13:	89 85 f4 fe ff ff    	mov    DWORD PTR [ebp-0x10c],eax
  71df19:	74 05                	je     0x71df20
  71df1b:	39 55 10             	cmp    DWORD PTR [ebp+0x10],edx
  71df1e:	75 09                	jne    0x71df29
  71df20:	83 c8 01             	or     eax,0x1
  71df23:	89 85 f4 fe ff ff    	mov    DWORD PTR [ebp-0x10c],eax
  71df29:	53                   	push   ebx
  71df2a:	8d 85 ac fd ff ff    	lea    eax,[ebp-0x254]
  71df30:	68 00 01 00 00       	push   0x100
  71df35:	50                   	push   eax
  71df36:	e8 e4 00 00 00       	call   0x71e01f
  71df3b:	83 c4 0c             	add    esp,0xc
  71df3e:	85 c0                	test   eax,eax
  71df40:	75 65                	jne    0x71dfa7
  71df42:	83 bd a4 fd ff ff 04 	cmp    DWORD PTR [ebp-0x25c],0x4
  71df49:	c7 85 ac fe ff ff b8 	mov    DWORD PTR [ebp-0x154],0x2ab8
  71df50:	2a 00 00 
  71df53:	75 08                	jne    0x71df5d
  71df55:	8d 46 0f             	lea    eax,[esi+0xf]
  71df58:	83 e0 f0             	and    eax,0xfffffff0
  71df5b:	eb 0b                	jmp    0x71df68
  71df5d:	8d 86 ff 0f 00 00    	lea    eax,[esi+0xfff]
  71df63:	25 00 f0 ff ff       	and    eax,0xfffff000
  71df68:	89 85 b0 fe ff ff    	mov    DWORD PTR [ebp-0x150],eax
  71df6e:	8d 85 a4 fd ff ff    	lea    eax,[ebp-0x25c]
  71df74:	57                   	push   edi
  71df75:	50                   	push   eax
  71df76:	e8 3b 00 00 00       	call   0x71dfb6
  71df7b:	ff b5 a0 fd ff ff    	push   DWORD PTR [ebp-0x260]
  71df81:	8d 8d a4 fd ff ff    	lea    ecx,[ebp-0x25c]
  71df87:	ff b5 9c fd ff ff    	push   DWORD PTR [ebp-0x264]
  71df8d:	56                   	push   esi
  71df8e:	51                   	push   ecx
  71df8f:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71df92:	50                   	push   eax
  71df93:	ff b5 98 fd ff ff    	push   DWORD PTR [ebp-0x268]
  71df99:	ff b5 94 fd ff ff    	push   DWORD PTR [ebp-0x26c]
  71df9f:	e8 c1 02 01 00       	call   0x72e265
  71dfa4:	83 c4 28             	add    esp,0x28
  71dfa7:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  71dfaa:	5f                   	pop    edi
  71dfab:	5e                   	pop    esi
  71dfac:	33 cd                	xor    ecx,ebp
  71dfae:	5b                   	pop    ebx
  71dfaf:	e8 44 80 15 00       	call   0x875ff8
  71dfb4:	c9                   	leave
  71dfb5:	c3                   	ret
  71dfb6:	55                   	push   ebp
  71dfb7:	8b ec                	mov    ebp,esp
  71dfb9:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  71dfbc:	56                   	push   esi
  71dfbd:	8b 82 0c 01 00 00    	mov    eax,DWORD PTR [edx+0x10c]
  71dfc3:	ff 32                	push   DWORD PTR [edx]
  71dfc5:	03 82 08 01 00 00    	add    eax,DWORD PTR [edx+0x108]
  71dfcb:	50                   	push   eax
  71dfcc:	e8 2f fd ff ff       	call   0x71dd00
  71dfd1:	8b f0                	mov    esi,eax
  71dfd3:	83 c4 08             	add    esp,0x8
  71dfd6:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71dfd9:	8b 48 04             	mov    ecx,DWORD PTR [eax+0x4]
  71dfdc:	d1 e9                	shr    ecx,1
  71dfde:	f6 c1 01             	test   cl,0x1
  71dfe1:	74 37                	je     0x71e01a
  71dfe3:	f6 40 08 01          	test   BYTE PTR [eax+0x8],0x1
  71dfe7:	74 31                	je     0x71e01a
  71dfe9:	33 c9                	xor    ecx,ecx
  71dfeb:	41                   	inc    ecx
  71dfec:	0f bc c1             	bsf    eax,ecx
  71dfef:	c7 84 82 58 01 00 00 	mov    DWORD PTR [edx+eax*4+0x158],0x228
  71dff6:	28 02 00 00 
  71dffa:	89 b4 82 d8 01 00 00 	mov    DWORD PTR [edx+eax*4+0x1d8],esi
  71e001:	8d 86 28 02 00 00    	lea    eax,[esi+0x228]
  71e007:	09 8a 54 01 00 00    	or     DWORD PTR [edx+0x154],ecx
  71e00d:	ff 32                	push   DWORD PTR [edx]
  71e00f:	50                   	push   eax
  71e010:	e8 eb fc ff ff       	call   0x71dd00
  71e015:	83 c4 08             	add    esp,0x8
  71e018:	8b f0                	mov    esi,eax
  71e01a:	8b c6                	mov    eax,esi
  71e01c:	5e                   	pop    esi
  71e01d:	5d                   	pop    ebp
  71e01e:	c3                   	ret
  71e01f:	55                   	push   ebp
  71e020:	8b ec                	mov    ebp,esp
  71e022:	8b 4d 10             	mov    ecx,DWORD PTR [ebp+0x10]
  71e025:	83 ec 0c             	sub    esp,0xc
  71e028:	8d 51 01             	lea    edx,[ecx+0x1]
  71e02b:	8a 01                	mov    al,BYTE PTR [ecx]
  71e02d:	41                   	inc    ecx
  71e02e:	84 c0                	test   al,al
  71e030:	75 f9                	jne    0x71e02b
  71e032:	2b ca                	sub    ecx,edx
  71e034:	c7 45 f4 47 6c 6f 62 	mov    DWORD PTR [ebp-0xc],0x626f6c47
  71e03b:	66 c7 45 f8 61 6c    	mov    WORD PTR [ebp-0x8],0x6c61
  71e041:	c6 45 fa 5c          	mov    BYTE PTR [ebp-0x6],0x5c
  71e045:	8d 41 07             	lea    eax,[ecx+0x7]
  71e048:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71e04b:	3d ff 00 00 00       	cmp    eax,0xff
  71e050:	76 23                	jbe    0x71e075
  71e052:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71e055:	68 78 e4 9b 00       	push   0x9be478
  71e05a:	6a 00                	push   0x0
  71e05c:	68 08 bc 8f 00       	push   0x8fbc08
  71e061:	6a 04                	push   0x4
  71e063:	68 38 ba 9b 00       	push   0x9bba38
  71e068:	e8 d6 57 1a 00       	call   0x8c3843
  71e06d:	83 c4 18             	add    esp,0x18
  71e070:	6a 13                	push   0x13
  71e072:	58                   	pop    eax
  71e073:	c9                   	leave
  71e074:	c3                   	ret
  71e075:	53                   	push   ebx
  71e076:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
  71e079:	56                   	push   esi
  71e07a:	57                   	push   edi
  71e07b:	8b fb                	mov    edi,ebx
  71e07d:	8d 75 f4             	lea    esi,[ebp-0xc]
  71e080:	51                   	push   ecx
  71e081:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71e084:	8d 43 07             	lea    eax,[ebx+0x7]
  71e087:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71e088:	50                   	push   eax
  71e089:	66 a5                	movs   WORD PTR es:[edi],WORD PTR ds:[esi]
  71e08b:	a4                   	movs   BYTE PTR es:[edi],BYTE PTR ds:[esi]
  71e08c:	e8 ff b6 15 00       	call   0x879790
  71e091:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  71e094:	83 c4 0c             	add    esp,0xc
  71e097:	5f                   	pop    edi
  71e098:	c6 04 18 00          	mov    BYTE PTR [eax+ebx*1],0x0
  71e09c:	33 c0                	xor    eax,eax
  71e09e:	5e                   	pop    esi
  71e09f:	5b                   	pop    ebx
  71e0a0:	c9                   	leave
  71e0a1:	c3                   	ret
  71e0a2:	55                   	push   ebp
  71e0a3:	8b ec                	mov    ebp,esp
  71e0a5:	83 ec 0c             	sub    esp,0xc
  71e0a8:	8d 45 f4             	lea    eax,[ebp-0xc]
  71e0ab:	c7 45 f4 05 00 00 00 	mov    DWORD PTR [ebp-0xc],0x5
  71e0b2:	50                   	push   eax
  71e0b3:	ff 75 1c             	push   DWORD PTR [ebp+0x1c]
  71e0b6:	c7 45 f8 02 00 00 00 	mov    DWORD PTR [ebp-0x8],0x2
  71e0bd:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  71e0c0:	c7 45 fc 01 00 00 00 	mov    DWORD PTR [ebp-0x4],0x1
  71e0c7:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  71e0ca:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71e0cd:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  71e0d0:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  71e0d3:	e8 05 00 00 00       	call   0x71e0dd
  71e0d8:	83 c4 1c             	add    esp,0x1c
  71e0db:	c9                   	leave
  71e0dc:	c3                   	ret
  71e0dd:	6a 08                	push   0x8
  71e0df:	b8 24 2d 8f 00       	mov    eax,0x8f2d24
  71e0e4:	e8 4f 7f 15 00       	call   0x876038
  71e0e9:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  71e0ec:	33 db                	xor    ebx,ebx
  71e0ee:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  71e0f1:	56                   	push   esi
  71e0f2:	88 18                	mov    BYTE PTR [eax],bl
  71e0f4:	e8 18 43 00 00       	call   0x722411
  71e0f9:	59                   	pop    ecx
  71e0fa:	83 f8 01             	cmp    eax,0x1
  71e0fd:	75 23                	jne    0x71e122
  71e0ff:	56                   	push   esi
  71e100:	68 44 e5 9b 00       	push   0x9be544
  71e105:	53                   	push   ebx
  71e106:	68 08 bc 8f 00       	push   0x8fbc08
  71e10b:	6a 04                	push   0x4
  71e10d:	68 38 ba 9b 00       	push   0x9bba38
  71e112:	e8 2c 57 1a 00       	call   0x8c3843
  71e117:	83 c4 18             	add    esp,0x18
  71e11a:	6a 0d                	push   0xd
  71e11c:	58                   	pop    eax
  71e11d:	e9 6d 01 00 00       	jmp    0x71e28f
  71e122:	85 c0                	test   eax,eax
  71e124:	75 1b                	jne    0x71e141
  71e126:	56                   	push   esi
  71e127:	68 e4 cf 9b 00       	push   0x9bcfe4
  71e12c:	53                   	push   ebx
  71e12d:	68 08 bc 8f 00       	push   0x8fbc08
  71e132:	6a 03                	push   0x3
  71e134:	68 38 ba 9b 00       	push   0x9bba38
  71e139:	e8 05 57 1a 00       	call   0x8c3843
  71e13e:	83 c4 18             	add    esp,0x18
  71e141:	ff 75 20             	push   DWORD PTR [ebp+0x20]
  71e144:	8b 7d 18             	mov    edi,DWORD PTR [ebp+0x18]
  71e147:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  71e14a:	57                   	push   edi
  71e14b:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  71e14e:	50                   	push   eax
  71e14f:	56                   	push   esi
  71e150:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  71e153:	e8 c8 fb ff ff       	call   0x71dd20
  71e158:	83 c4 18             	add    esp,0x18
  71e15b:	85 c0                	test   eax,eax
  71e15d:	0f 85 2c 01 00 00    	jne    0x71e28f
  71e163:	8b 4d 10             	mov    ecx,DWORD PTR [ebp+0x10]
  71e166:	6a 04                	push   0x4
  71e168:	5a                   	pop    edx
  71e169:	0f ae f0             	mfence
  71e16c:	8b 77 18             	mov    esi,DWORD PTR [edi+0x18]
  71e16f:	3b ca                	cmp    ecx,edx
  71e171:	0f 84 09 01 00 00    	je     0x71e280
  71e177:	6a 05                	push   0x5
  71e179:	58                   	pop    eax
  71e17a:	3b c8                	cmp    ecx,eax
  71e17c:	0f 84 fe 00 00 00    	je     0x71e280
  71e182:	89 7d ec             	mov    DWORD PTR [ebp-0x14],edi
  71e185:	c6 45 f0 01          	mov    BYTE PTR [ebp-0x10],0x1
  71e189:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  71e18c:	39 16                	cmp    DWORD PTR [esi],edx
  71e18e:	0f 82 b5 00 00 00    	jb     0x71e249
  71e194:	39 06                	cmp    DWORD PTR [esi],eax
  71e196:	0f 87 ad 00 00 00    	ja     0x71e249
  71e19c:	81 be 08 01 00 00 b8 	cmp    DWORD PTR [esi+0x108],0x2ab8
  71e1a3:	2a 00 00 
  71e1a6:	74 1e                	je     0x71e1c6
  71e1a8:	68 a0 e5 9b 00       	push   0x9be5a0
  71e1ad:	53                   	push   ebx
  71e1ae:	68 08 bc 8f 00       	push   0x8fbc08
  71e1b3:	52                   	push   edx
  71e1b4:	68 38 ba 9b 00       	push   0x9bba38
  71e1b9:	e8 85 56 1a 00       	call   0x8c3843
  71e1be:	83 c4 14             	add    esp,0x14
  71e1c1:	e9 9e 00 00 00       	jmp    0x71e264
  71e1c6:	39 06                	cmp    DWORD PTR [esi],eax
  71e1c8:	75 3a                	jne    0x71e204
  71e1ca:	8b 86 50 01 00 00    	mov    eax,DWORD PTR [esi+0x150]
  71e1d0:	a8 01                	test   al,0x1
  71e1d2:	74 30                	je     0x71e204
  71e1d4:	50                   	push   eax
  71e1d5:	68 f8 e4 9b 00       	push   0x9be4f8
  71e1da:	53                   	push   ebx
  71e1db:	68 08 bc 8f 00       	push   0x8fbc08
  71e1e0:	52                   	push   edx
  71e1e1:	68 38 ba 9b 00       	push   0x9bba38
  71e1e6:	e8 58 56 1a 00       	call   0x8c3843
  71e1eb:	8b 4d 1c             	mov    ecx,DWORD PTR [ebp+0x1c]
  71e1ee:	57                   	push   edi
  71e1ef:	56                   	push   esi
  71e1f0:	c6 01 01             	mov    BYTE PTR [ecx],0x1
  71e1f3:	8b 47 18             	mov    eax,DWORD PTR [edi+0x18]
  71e1f6:	89 07                	mov    DWORD PTR [edi],eax
  71e1f8:	e8 3d fa ff ff       	call   0x71dc3a
  71e1fd:	83 c4 20             	add    esp,0x20
  71e200:	6a 0b                	push   0xb
  71e202:	eb 62                	jmp    0x71e266
  71e204:	39 9e 0c 01 00 00    	cmp    DWORD PTR [esi+0x10c],ebx
  71e20a:	74 17                	je     0x71e223
  71e20c:	80 7e 08 00          	cmp    BYTE PTR [esi+0x8],0x0
  71e210:	74 11                	je     0x71e223
  71e212:	89 37                	mov    DWORD PTR [edi],esi
  71e214:	8b 86 0c 01 00 00    	mov    eax,DWORD PTR [esi+0x10c]
  71e21a:	03 c6                	add    eax,esi
  71e21c:	89 47 04             	mov    DWORD PTR [edi+0x4],eax
  71e21f:	8a c3                	mov    al,bl
  71e221:	eb 47                	jmp    0x71e26a
  71e223:	68 d0 e5 9b 00       	push   0x9be5d0
  71e228:	53                   	push   ebx
  71e229:	68 08 bc 8f 00       	push   0x8fbc08
  71e22e:	6a 03                	push   0x3
  71e230:	68 38 ba 9b 00       	push   0x9bba38
  71e235:	e8 09 56 1a 00       	call   0x8c3843
  71e23a:	8b 4d 1c             	mov    ecx,DWORD PTR [ebp+0x1c]
  71e23d:	83 c4 14             	add    esp,0x14
  71e240:	33 c0                	xor    eax,eax
  71e242:	40                   	inc    eax
  71e243:	88 01                	mov    BYTE PTR [ecx],al
  71e245:	6a 0b                	push   0xb
  71e247:	eb 20                	jmp    0x71e269
  71e249:	ff 36                	push   DWORD PTR [esi]
  71e24b:	68 74 e5 9b 00       	push   0x9be574
  71e250:	53                   	push   ebx
  71e251:	68 08 bc 8f 00       	push   0x8fbc08
  71e256:	52                   	push   edx
  71e257:	68 38 ba 9b 00       	push   0x9bba38
  71e25c:	e8 e2 55 1a 00       	call   0x8c3843
  71e261:	83 c4 18             	add    esp,0x18
  71e264:	6a 05                	push   0x5
  71e266:	33 c0                	xor    eax,eax
  71e268:	40                   	inc    eax
  71e269:	5b                   	pop    ebx
  71e26a:	c7 45 fc 06 00 00 00 	mov    DWORD PTR [ebp-0x4],0x6
  71e271:	84 c0                	test   al,al
  71e273:	74 07                	je     0x71e27c
  71e275:	57                   	push   edi
  71e276:	e8 1a 00 00 00       	call   0x71e295
  71e27b:	59                   	pop    ecx
  71e27c:	8b c3                	mov    eax,ebx
  71e27e:	eb 0f                	jmp    0x71e28f
  71e280:	89 37                	mov    DWORD PTR [edi],esi
  71e282:	8b 86 0c 01 00 00    	mov    eax,DWORD PTR [esi+0x10c]
  71e288:	03 c6                	add    eax,esi
  71e28a:	89 47 04             	mov    DWORD PTR [edi+0x4],eax
  71e28d:	33 c0                	xor    eax,eax
  71e28f:	e8 72 7d 15 00       	call   0x876006
  71e294:	c3                   	ret
  71e295:	55                   	push   ebp
  71e296:	8b ec                	mov    ebp,esp
  71e298:	56                   	push   esi
  71e299:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  71e29c:	8d 46 18             	lea    eax,[esi+0x18]
  71e29f:	50                   	push   eax
  71e2a0:	e8 3b e5 14 00       	call   0x86c7e0
  71e2a5:	83 26 00             	and    DWORD PTR [esi],0x0
  71e2a8:	83 66 04 00          	and    DWORD PTR [esi+0x4],0x0
  71e2ac:	59                   	pop    ecx
  71e2ad:	5e                   	pop    esi
  71e2ae:	5d                   	pop    ebp
  71e2af:	c3                   	ret
  71e2b0:	55                   	push   ebp
  71e2b1:	8b ec                	mov    ebp,esp
  71e2b3:	56                   	push   esi
  71e2b4:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71e2b7:	8d 45 0c             	lea    eax,[ebp+0xc]
  71e2ba:	50                   	push   eax
  71e2bb:	8d 45 08             	lea    eax,[ebp+0x8]
  71e2be:	50                   	push   eax
  71e2bf:	e8 65 25 f8 ff       	call   0x6a0829
  71e2c4:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  71e2c7:	8b f0                	mov    esi,eax
  71e2c9:	8d 45 0c             	lea    eax,[ebp+0xc]
  71e2cc:	50                   	push   eax
  71e2cd:	8d 45 08             	lea    eax,[ebp+0x8]
  71e2d0:	50                   	push   eax
  71e2d1:	e8 53 25 f8 ff       	call   0x6a0829
  71e2d6:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  71e2d9:	03 f0                	add    esi,eax
  71e2db:	8d 45 0c             	lea    eax,[ebp+0xc]
  71e2de:	50                   	push   eax
  71e2df:	8d 45 08             	lea    eax,[ebp+0x8]
  71e2e2:	50                   	push   eax
  71e2e3:	e8 c1 20 de ff       	call   0x5003a9
  71e2e8:	ff 75 1c             	push   DWORD PTR [ebp+0x1c]
  71e2eb:	03 f0                	add    esi,eax
  71e2ed:	8d 45 0c             	lea    eax,[ebp+0xc]
  71e2f0:	50                   	push   eax
  71e2f1:	8d 45 08             	lea    eax,[ebp+0x8]
  71e2f4:	50                   	push   eax
  71e2f5:	e8 af 20 de ff       	call   0x5003a9
  71e2fa:	83 c4 30             	add    esp,0x30
  71e2fd:	03 c6                	add    eax,esi
  71e2ff:	5e                   	pop    esi
  71e300:	5d                   	pop    ebp
  71e301:	c3                   	ret
  71e302:	55                   	push   ebp
  71e303:	8b ec                	mov    ebp,esp
  71e305:	51                   	push   ecx
  71e306:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  71e309:	56                   	push   esi
  71e30a:	8b f1                	mov    esi,ecx
  71e30c:	68 9a e3 71 00       	push   0x71e39a
  71e311:	68 3a e3 71 00       	push   0x71e33a
  71e316:	6a 10                	push   0x10
  71e318:	83 66 04 00          	and    DWORD PTR [esi+0x4],0x0
  71e31c:	89 06                	mov    DWORD PTR [esi],eax
  71e31e:	8d 46 0c             	lea    eax,[esi+0xc]
  71e321:	6a 08                	push   0x8
  71e323:	50                   	push   eax
  71e324:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  71e327:	c7 46 08 02 00 00 00 	mov    DWORD PTR [esi+0x8],0x2
  71e32e:	e8 a4 8d 15 00       	call   0x8770d7
  71e333:	8b c6                	mov    eax,esi
  71e335:	5e                   	pop    esi
  71e336:	c9                   	leave
  71e337:	c2 04 00             	ret    0x4
  71e33a:	55                   	push   ebp
  71e33b:	8b ec                	mov    ebp,esp
  71e33d:	51                   	push   ecx
  71e33e:	56                   	push   esi
  71e33f:	8b f1                	mov    esi,ecx
  71e341:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  71e344:	83 26 00             	and    DWORD PTR [esi],0x0
  71e347:	8d 4e 04             	lea    ecx,[esi+0x4]
  71e34a:	e8 75 12 01 00       	call   0x72f5c4
  71e34f:	8b c6                	mov    eax,esi
  71e351:	5e                   	pop    esi
  71e352:	c9                   	leave
  71e353:	c3                   	ret
  71e354:	55                   	push   ebp
  71e355:	8b ec                	mov    ebp,esp
  71e357:	6a ff                	push   0xffffffff
  71e359:	68 6c 95 8c 00       	push   0x8c956c
  71e35e:	64 a1 00 00 00 00    	mov    eax,fs:0x0
  71e364:	50                   	push   eax
  71e365:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71e36a:	33 c5                	xor    eax,ebp
  71e36c:	50                   	push   eax
  71e36d:	8d 45 f4             	lea    eax,[ebp-0xc]
  71e370:	64 a3 00 00 00 00    	mov    fs:0x0,eax
  71e376:	68 9a e3 71 00       	push   0x71e39a
  71e37b:	6a 10                	push   0x10
  71e37d:	6a 08                	push   0x8
  71e37f:	8d 41 0c             	lea    eax,[ecx+0xc]
  71e382:	50                   	push   eax
  71e383:	e8 5c 84 15 00       	call   0x8767e4
  71e388:	8b 4d f4             	mov    ecx,DWORD PTR [ebp-0xc]
  71e38b:	64 89 0d 00 00 00 00 	mov    DWORD PTR fs:0x0,ecx
  71e392:	59                   	pop    ecx
  71e393:	c9                   	leave
  71e394:	c3                   	ret
  71e395:	cc                   	int3
  71e396:	cc                   	int3
  71e397:	cc                   	int3
  71e398:	cc                   	int3
  71e399:	cc                   	int3
  71e39a:	83 c1 04             	add    ecx,0x4
  71e39d:	e9 a8 68 14 00       	jmp    0x864c4a
  71e3a2:	55                   	push   ebp
  71e3a3:	8b ec                	mov    ebp,esp
  71e3a5:	81 ec 04 01 00 00    	sub    esp,0x104
  71e3ab:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71e3b0:	33 c5                	xor    eax,ebp
  71e3b2:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71e3b5:	56                   	push   esi
  71e3b6:	8b f1                	mov    esi,ecx
  71e3b8:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  71e3bb:	8b 06                	mov    eax,DWORD PTR [esi]
  71e3bd:	83 78 08 02          	cmp    DWORD PTR [eax+0x8],0x2
  71e3c1:	74 5e                	je     0x71e421
  71e3c3:	51                   	push   ecx
  71e3c4:	ff 70 04             	push   DWORD PTR [eax+0x4]
  71e3c7:	ff 76 04             	push   DWORD PTR [esi+0x4]
  71e3ca:	e8 8f 20 de ff       	call   0x50045e
  71e3cf:	ff 76 04             	push   DWORD PTR [esi+0x4]
  71e3d2:	e8 fa 6d 14 00       	call   0x8651d1
  71e3d7:	8b 4e 08             	mov    ecx,DWORD PTR [esi+0x8]
  71e3da:	83 c4 10             	add    esp,0x10
  71e3dd:	89 01                	mov    DWORD PTR [ecx],eax
  71e3df:	8b 46 08             	mov    eax,DWORD PTR [esi+0x8]
  71e3e2:	83 38 00             	cmp    DWORD PTR [eax],0x0
  71e3e5:	74 3a                	je     0x71e421
  71e3e7:	ff 30                	push   DWORD PTR [eax]
  71e3e9:	8d 85 fc fe ff ff    	lea    eax,[ebp-0x104]
  71e3ef:	50                   	push   eax
  71e3f0:	e8 2c e6 f5 ff       	call   0x67ca21
  71e3f5:	8d 85 fc fe ff ff    	lea    eax,[ebp-0x104]
  71e3fb:	50                   	push   eax
  71e3fc:	8b 46 08             	mov    eax,DWORD PTR [esi+0x8]
  71e3ff:	ff 30                	push   DWORD PTR [eax]
  71e401:	8b 06                	mov    eax,DWORD PTR [esi]
  71e403:	ff 70 04             	push   DWORD PTR [eax+0x4]
  71e406:	68 58 e8 9b 00       	push   0x9be858
  71e40b:	6a 00                	push   0x0
  71e40d:	68 08 bc 8f 00       	push   0x8fbc08
  71e412:	6a 03                	push   0x3
  71e414:	68 38 ba 9b 00       	push   0x9bba38
  71e419:	e8 25 54 1a 00       	call   0x8c3843
  71e41e:	83 c4 28             	add    esp,0x28
  71e421:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  71e424:	33 cd                	xor    ecx,ebp
  71e426:	5e                   	pop    esi
  71e427:	e8 cc 7b 15 00       	call   0x875ff8
  71e42c:	c9                   	leave
  71e42d:	c2 04 00             	ret    0x4
  71e430:	55                   	push   ebp
  71e431:	8b ec                	mov    ebp,esp
  71e433:	83 ec 0c             	sub    esp,0xc
  71e436:	53                   	push   ebx
  71e437:	56                   	push   esi
  71e438:	8b c1                	mov    eax,ecx
  71e43a:	33 db                	xor    ebx,ebx
  71e43c:	57                   	push   edi
  71e43d:	6a 10                	push   0x10
  71e43f:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  71e442:	8d 50 0c             	lea    edx,[eax+0xc]
  71e445:	5e                   	pop    esi
  71e446:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  71e449:	83 3a 00             	cmp    DWORD PTR [edx],0x0
  71e44c:	74 06                	je     0x71e454
  71e44e:	4e                   	dec    esi
  71e44f:	8d 48 08             	lea    ecx,[eax+0x8]
  71e452:	eb 2a                	jmp    0x71e47e
  71e454:	8d 78 08             	lea    edi,[eax+0x8]
  71e457:	83 3f 02             	cmp    DWORD PTR [edi],0x2
  71e45a:	8b cf                	mov    ecx,edi
  71e45c:	74 20                	je     0x71e47e
  71e45e:	83 3f 03             	cmp    DWORD PTR [edi],0x3
  71e461:	74 1b                	je     0x71e47e
  71e463:	6a 00                	push   0x0
  71e465:	6a 01                	push   0x1
  71e467:	53                   	push   ebx
  71e468:	8b c8                	mov    ecx,eax
  71e46a:	e8 d8 05 00 00       	call   0x71ea47
  71e46f:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
  71e472:	8b cf                	mov    ecx,edi
  71e474:	85 c0                	test   eax,eax
  71e476:	75 1a                	jne    0x71e492
  71e478:	8b 45 f8             	mov    eax,DWORD PTR [ebp-0x8]
  71e47b:	8b 55 fc             	mov    edx,DWORD PTR [ebp-0x4]
  71e47e:	43                   	inc    ebx
  71e47f:	83 c2 08             	add    edx,0x8
  71e482:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  71e485:	83 fb 10             	cmp    ebx,0x10
  71e488:	72 bf                	jb     0x71e449
  71e48a:	85 f6                	test   esi,esi
  71e48c:	75 24                	jne    0x71e4b2
  71e48e:	33 c0                	xor    eax,eax
  71e490:	eb 42                	jmp    0x71e4d4
  71e492:	68 2c e9 9b 00       	push   0x9be92c
  71e497:	6a 00                	push   0x0
  71e499:	68 08 bc 8f 00       	push   0x8fbc08
  71e49e:	6a 04                	push   0x4
  71e4a0:	68 38 ba 9b 00       	push   0x9bba38
  71e4a5:	e8 99 53 1a 00       	call   0x8c3843
  71e4aa:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
  71e4ad:	83 c4 14             	add    esp,0x14
  71e4b0:	eb 22                	jmp    0x71e4d4
  71e4b2:	83 fe 10             	cmp    esi,0x10
  71e4b5:	74 0d                	je     0x71e4c4
  71e4b7:	33 d2                	xor    edx,edx
  71e4b9:	83 39 04             	cmp    DWORD PTR [ecx],0x4
  71e4bc:	6a 09                	push   0x9
  71e4be:	58                   	pop    eax
  71e4bf:	0f 44 c2             	cmove  eax,edx
  71e4c2:	eb 10                	jmp    0x71e4d4
  71e4c4:	83 39 02             	cmp    DWORD PTR [ecx],0x2
  71e4c7:	6a 12                	push   0x12
  71e4c9:	58                   	pop    eax
  71e4ca:	74 08                	je     0x71e4d4
  71e4cc:	33 d2                	xor    edx,edx
  71e4ce:	83 39 03             	cmp    DWORD PTR [ecx],0x3
  71e4d1:	0f 45 c2             	cmovne eax,edx
  71e4d4:	5f                   	pop    edi
  71e4d5:	5e                   	pop    esi
  71e4d6:	5b                   	pop    ebx
  71e4d7:	c9                   	leave
  71e4d8:	c3                   	ret
  71e4d9:	68 20 03 00 00       	push   0x320
  71e4de:	b8 51 2d 8f 00       	mov    eax,0x8f2d51
  71e4e3:	e8 83 7b 15 00       	call   0x87606b
  71e4e8:	8b d9                	mov    ebx,ecx
  71e4ea:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71e4ed:	8d 8d e0 fc ff ff    	lea    ecx,[ebp-0x320]
  71e4f3:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  71e4f6:	89 85 dc fc ff ff    	mov    DWORD PTR [ebp-0x324],eax
  71e4fc:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  71e4ff:	89                   	.byte 0x89
