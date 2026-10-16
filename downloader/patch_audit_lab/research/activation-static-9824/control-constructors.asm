
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071dd00 <.text+0x31cd00>:
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
