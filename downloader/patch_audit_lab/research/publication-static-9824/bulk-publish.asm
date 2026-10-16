
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071bb82 <.text+0x31ab82>:
  71bb82:	68 18 01 00 00       	push   0x118
  71bb87:	b8 da 2a 8f 00       	mov    eax,0x8f2ada
  71bb8c:	e8 da a4 15 00       	call   0x87606b
  71bb91:	8b d9                	mov    ebx,ecx
  71bb93:	89 9d ec fe ff ff    	mov    DWORD PTR [ebp-0x114],ebx
  71bb99:	83 7b 2c 02          	cmp    DWORD PTR [ebx+0x2c],0x2
  71bb9d:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  71bba0:	89 85 e8 fe ff ff    	mov    DWORD PTR [ebp-0x118],eax
  71bba6:	0f 84 b6 02 00 00    	je     0x71be62
  71bbac:	83 7b 2c 04          	cmp    DWORD PTR [ebx+0x2c],0x4
  71bbb0:	0f 84 ac 02 00 00    	je     0x71be62
  71bbb6:	8d 43 70             	lea    eax,[ebx+0x70]
  71bbb9:	8b c8                	mov    ecx,eax
  71bbbb:	89 85 e0 fe ff ff    	mov    DWORD PTR [ebp-0x120],eax
  71bbc1:	e8 9c 67 00 00       	call   0x722362
  71bbc6:	84 c0                	test   al,al
  71bbc8:	75 07                	jne    0x71bbd1
  71bbca:	6a 0b                	push   0xb
  71bbcc:	e9 93 02 00 00       	jmp    0x71be64
  71bbd1:	89 9d dc fe ff ff    	mov    DWORD PTR [ebp-0x124],ebx
  71bbd7:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  71bbdb:	33 f6                	xor    esi,esi
  71bbdd:	8d 83 20 06 00 00    	lea    eax,[ebx+0x620]
  71bbe3:	8d 04 b0             	lea    eax,[eax+esi*4]
  71bbe6:	50                   	push   eax
  71bbe7:	e8 00 a5 14 00       	call   0x8660ec
  71bbec:	59                   	pop    ecx
  71bbed:	56                   	push   esi
  71bbee:	8b cb                	mov    ecx,ebx
  71bbf0:	e8 60 09 00 00       	call   0x71c555
  71bbf5:	8b f8                	mov    edi,eax
  71bbf7:	85 ff                	test   edi,edi
  71bbf9:	0f 85 4d 02 00 00    	jne    0x71be4c
  71bbff:	46                   	inc    esi
  71bc00:	83 fe 10             	cmp    esi,0x10
  71bc03:	72 d8                	jb     0x71bbdd
  71bc05:	89 9d e4 fe ff ff    	mov    DWORD PTR [ebp-0x11c],ebx
  71bc0b:	33 c9                	xor    ecx,ecx
  71bc0d:	8b 03                	mov    eax,DWORD PTR [ebx]
  71bc0f:	89 85 f0 fe ff ff    	mov    DWORD PTR [ebp-0x110],eax
  71bc15:	89 8d f4 fe ff ff    	mov    DWORD PTR [ebp-0x10c],ecx
  71bc1b:	89 8d f8 fe ff ff    	mov    DWORD PTR [ebp-0x108],ecx
  71bc21:	89 8d fc fe ff ff    	mov    DWORD PTR [ebp-0x104],ecx
  71bc27:	89 85 00 ff ff ff    	mov    DWORD PTR [ebp-0x100],eax
  71bc2d:	89 8d 04 ff ff ff    	mov    DWORD PTR [ebp-0xfc],ecx
  71bc33:	89 8d 08 ff ff ff    	mov    DWORD PTR [ebp-0xf8],ecx
  71bc39:	89 8d 0c ff ff ff    	mov    DWORD PTR [ebp-0xf4],ecx
  71bc3f:	89 85 10 ff ff ff    	mov    DWORD PTR [ebp-0xf0],eax
  71bc45:	89 8d 14 ff ff ff    	mov    DWORD PTR [ebp-0xec],ecx
  71bc4b:	89 8d 18 ff ff ff    	mov    DWORD PTR [ebp-0xe8],ecx
  71bc51:	89 8d 1c ff ff ff    	mov    DWORD PTR [ebp-0xe4],ecx
  71bc57:	89 85 20 ff ff ff    	mov    DWORD PTR [ebp-0xe0],eax
  71bc5d:	89 8d 24 ff ff ff    	mov    DWORD PTR [ebp-0xdc],ecx
  71bc63:	89 8d 28 ff ff ff    	mov    DWORD PTR [ebp-0xd8],ecx
  71bc69:	89 8d 2c ff ff ff    	mov    DWORD PTR [ebp-0xd4],ecx
  71bc6f:	89 85 30 ff ff ff    	mov    DWORD PTR [ebp-0xd0],eax
  71bc75:	89 8d 34 ff ff ff    	mov    DWORD PTR [ebp-0xcc],ecx
  71bc7b:	89 8d 38 ff ff ff    	mov    DWORD PTR [ebp-0xc8],ecx
  71bc81:	89 8d 3c ff ff ff    	mov    DWORD PTR [ebp-0xc4],ecx
  71bc87:	89 85 40 ff ff ff    	mov    DWORD PTR [ebp-0xc0],eax
  71bc8d:	89 8d 44 ff ff ff    	mov    DWORD PTR [ebp-0xbc],ecx
  71bc93:	89 8d 48 ff ff ff    	mov    DWORD PTR [ebp-0xb8],ecx
  71bc99:	89 8d 4c ff ff ff    	mov    DWORD PTR [ebp-0xb4],ecx
  71bc9f:	89 85 50 ff ff ff    	mov    DWORD PTR [ebp-0xb0],eax
  71bca5:	89 8d 54 ff ff ff    	mov    DWORD PTR [ebp-0xac],ecx
  71bcab:	89 8d 58 ff ff ff    	mov    DWORD PTR [ebp-0xa8],ecx
  71bcb1:	89 8d 5c ff ff ff    	mov    DWORD PTR [ebp-0xa4],ecx
  71bcb7:	89 85 60 ff ff ff    	mov    DWORD PTR [ebp-0xa0],eax
  71bcbd:	89 8d 64 ff ff ff    	mov    DWORD PTR [ebp-0x9c],ecx
  71bcc3:	89 8d 68 ff ff ff    	mov    DWORD PTR [ebp-0x98],ecx
  71bcc9:	89 8d 6c ff ff ff    	mov    DWORD PTR [ebp-0x94],ecx
  71bccf:	89 85 70 ff ff ff    	mov    DWORD PTR [ebp-0x90],eax
  71bcd5:	89 8d 74 ff ff ff    	mov    DWORD PTR [ebp-0x8c],ecx
  71bcdb:	89 8d 78 ff ff ff    	mov    DWORD PTR [ebp-0x88],ecx
  71bce1:	89 8d 7c ff ff ff    	mov    DWORD PTR [ebp-0x84],ecx
  71bce7:	89 45 80             	mov    DWORD PTR [ebp-0x80],eax
  71bcea:	89 4d 84             	mov    DWORD PTR [ebp-0x7c],ecx
  71bced:	89 4d 88             	mov    DWORD PTR [ebp-0x78],ecx
  71bcf0:	89 4d 8c             	mov    DWORD PTR [ebp-0x74],ecx
  71bcf3:	89 45 90             	mov    DWORD PTR [ebp-0x70],eax
  71bcf6:	89 4d 94             	mov    DWORD PTR [ebp-0x6c],ecx
  71bcf9:	89 4d 98             	mov    DWORD PTR [ebp-0x68],ecx
  71bcfc:	89 4d 9c             	mov    DWORD PTR [ebp-0x64],ecx
  71bcff:	89 45 a0             	mov    DWORD PTR [ebp-0x60],eax
  71bd02:	89 4d a4             	mov    DWORD PTR [ebp-0x5c],ecx
  71bd05:	89 4d a8             	mov    DWORD PTR [ebp-0x58],ecx
  71bd08:	89 4d ac             	mov    DWORD PTR [ebp-0x54],ecx
  71bd0b:	89 45 b0             	mov    DWORD PTR [ebp-0x50],eax
  71bd0e:	89 4d b4             	mov    DWORD PTR [ebp-0x4c],ecx
  71bd11:	89 4d b8             	mov    DWORD PTR [ebp-0x48],ecx
  71bd14:	89 4d bc             	mov    DWORD PTR [ebp-0x44],ecx
  71bd17:	89 45 c0             	mov    DWORD PTR [ebp-0x40],eax
  71bd1a:	89 4d c4             	mov    DWORD PTR [ebp-0x3c],ecx
  71bd1d:	89 4d c8             	mov    DWORD PTR [ebp-0x38],ecx
  71bd20:	89 4d cc             	mov    DWORD PTR [ebp-0x34],ecx
  71bd23:	89 45 d0             	mov    DWORD PTR [ebp-0x30],eax
  71bd26:	89 4d d4             	mov    DWORD PTR [ebp-0x2c],ecx
  71bd29:	89 4d d8             	mov    DWORD PTR [ebp-0x28],ecx
  71bd2c:	89 4d dc             	mov    DWORD PTR [ebp-0x24],ecx
  71bd2f:	89 45 e0             	mov    DWORD PTR [ebp-0x20],eax
  71bd32:	89 4d e4             	mov    DWORD PTR [ebp-0x1c],ecx
  71bd35:	89 4d e8             	mov    DWORD PTR [ebp-0x18],ecx
  71bd38:	89 4d ec             	mov    DWORD PTR [ebp-0x14],ecx
  71bd3b:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  71bd3e:	8b c6                	mov    eax,esi
  71bd40:	c1 e8 1f             	shr    eax,0x1f
  71bd43:	c6 45 fc 03          	mov    BYTE PTR [ebp-0x4],0x3
  71bd47:	66 0f 6e c6          	movd   xmm0,esi
  71bd4b:	f3 0f e6 c0          	cvtdq2pd xmm0,xmm0
  71bd4f:	f2 0f 58 04 c5 30 c2 	addsd  xmm0,QWORD PTR [eax*8+0x8fc230]
  71bd56:	8f 00 
  71bd58:	f2 0f 59 05 c0 02 91 	mulsd  xmm0,QWORD PTR ds:0x9102c0
  71bd5f:	00 
  71bd60:	e8 0b a8 15 00       	call   0x876570
  71bd65:	8b de                	mov    ebx,esi
  71bd67:	c1 eb 04             	shr    ebx,0x4
  71bd6a:	03 d8                	add    ebx,eax
  71bd6c:	6a 10                	push   0x10
  71bd6e:	8d bd f0 fe ff ff    	lea    edi,[ebp-0x110]
  71bd74:	5e                   	pop    esi
  71bd75:	53                   	push   ebx
  71bd76:	8b cf                	mov    ecx,edi
  71bd78:	e8 01 20 f6 ff       	call   0x67dd7e
  71bd7d:	83 c7 10             	add    edi,0x10
  71bd80:	83 ee 01             	sub    esi,0x1
  71bd83:	75 f0                	jne    0x71bd75
  71bd85:	8b 9d ec fe ff ff    	mov    ebx,DWORD PTR [ebp-0x114]
  71bd8b:	39 75 0c             	cmp    DWORD PTR [ebp+0xc],esi
  71bd8e:	74 4a                	je     0x71bdda
  71bd90:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  71bd93:	8b 8d e8 fe ff ff    	mov    ecx,DWORD PTR [ebp-0x118]
  71bd99:	51                   	push   ecx
  71bd9a:	e8 91 0c 00 00       	call   0x71ca30
  71bd9f:	59                   	pop    ecx
  71bda0:	c1 e0 04             	shl    eax,0x4
  71bda3:	8d 8d f0 fe ff ff    	lea    ecx,[ebp-0x110]
  71bda9:	03 c8                	add    ecx,eax
  71bdab:	0f b6 05 cc e2 9b 00 	movzx  eax,BYTE PTR ds:0x9be2cc
  71bdb2:	50                   	push   eax
  71bdb3:	e8 34 06 00 00       	call   0x71c3ec
  71bdb8:	8b 8d e8 fe ff ff    	mov    ecx,DWORD PTR [ebp-0x118]
  71bdbe:	8b f8                	mov    edi,eax
  71bdc0:	8b f1                	mov    esi,ecx
  71bdc2:	83 c1 10             	add    ecx,0x10
  71bdc5:	89 8d e8 fe ff ff    	mov    DWORD PTR [ebp-0x118],ecx
  71bdcb:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71bdcc:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71bdcd:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71bdce:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71bdcf:	83 eb 01             	sub    ebx,0x1
  71bdd2:	75 c5                	jne    0x71bd99
  71bdd4:	8b 9d ec fe ff ff    	mov    ebx,DWORD PTR [ebp-0x114]
  71bdda:	33 ff                	xor    edi,edi
  71bddc:	8d b5 f4 fe ff ff    	lea    esi,[ebp-0x10c]
  71bde2:	89 bd ec fe ff ff    	mov    DWORD PTR [ebp-0x114],edi
  71bde8:	8b 46 04             	mov    eax,DWORD PTR [esi+0x4]
  71bdeb:	85 c0                	test   eax,eax
  71bded:	74 28                	je     0x71be17
  71bdef:	c1 e0 04             	shl    eax,0x4
  71bdf2:	03 06                	add    eax,DWORD PTR [esi]
  71bdf4:	50                   	push   eax
  71bdf5:	ff 36                	push   DWORD PTR [esi]
  71bdf7:	e8 bd d2 f6 ff       	call   0x6890b9
  71bdfc:	59                   	pop    ecx
  71bdfd:	59                   	pop    ecx
  71bdfe:	ff 76 04             	push   DWORD PTR [esi+0x4]
  71be01:	8b cb                	mov    ecx,ebx
  71be03:	ff 36                	push   DWORD PTR [esi]
  71be05:	57                   	push   edi
  71be06:	e8 0e 03 00 00       	call   0x71c119
  71be0b:	8b f8                	mov    edi,eax
  71be0d:	85 ff                	test   edi,edi
  71be0f:	75 17                	jne    0x71be28
  71be11:	8b bd ec fe ff ff    	mov    edi,DWORD PTR [ebp-0x114]
  71be17:	47                   	inc    edi
  71be18:	83 c6 10             	add    esi,0x10
  71be1b:	89 bd ec fe ff ff    	mov    DWORD PTR [ebp-0x114],edi
  71be21:	83 ff 10             	cmp    edi,0x10
  71be24:	72 c2                	jb     0x71bde8
  71be26:	33 ff                	xor    edi,edi
  71be28:	68 25 ee 4f 00       	push   0x4fee25
  71be2d:	6a 10                	push   0x10
  71be2f:	6a 10                	push   0x10
  71be31:	8d 85 f0 fe ff ff    	lea    eax,[ebp-0x110]
  71be37:	c6 45 fc 02          	mov    BYTE PTR [ebp-0x4],0x2
  71be3b:	50                   	push   eax
  71be3c:	e8 a3 a9 15 00       	call   0x8767e4
  71be41:	8d 8d e4 fe ff ff    	lea    ecx,[ebp-0x11c]
  71be47:	e8 2e fa ff ff       	call   0x71b87a
  71be4c:	8b 8d e0 fe ff ff    	mov    ecx,DWORD PTR [ebp-0x120]
  71be52:	c7 45 fc 05 00 00 00 	mov    DWORD PTR [ebp-0x4],0x5
  71be59:	e8 98 65 00 00       	call   0x7223f6
  71be5e:	8b c7                	mov    eax,edi
  71be60:	eb 03                	jmp    0x71be65
  71be62:	6a 05                	push   0x5
  71be64:	58                   	pop    eax
  71be65:	e8 b0 a1 15 00       	call   0x87601a
  71be6a:	c2 08 00             	ret    0x8
