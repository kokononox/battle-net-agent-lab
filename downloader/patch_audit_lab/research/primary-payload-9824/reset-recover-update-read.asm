
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00722e28 <.text+0x321e28>:
  722e28:	33 c0                	xor    eax,eax
  722e2a:	89 01                	mov    DWORD PTR [ecx],eax
  722e2c:	89 41 04             	mov    DWORD PTR [ecx+0x4],eax
  722e2f:	89 41 08             	mov    DWORD PTR [ecx+0x8],eax
  722e32:	89 41 10             	mov    DWORD PTR [ecx+0x10],eax
  722e35:	89 41 14             	mov    DWORD PTR [ecx+0x14],eax
  722e38:	89 41 18             	mov    DWORD PTR [ecx+0x18],eax
  722e3b:	89 41 1c             	mov    DWORD PTR [ecx+0x1c],eax
  722e3e:	c3                   	ret
  722e3f:	56                   	push   esi
  722e40:	8b f1                	mov    esi,ecx
  722e42:	83 3e 02             	cmp    DWORD PTR [esi],0x2
  722e45:	75 3f                	jne    0x722e86
  722e47:	ff 76 14             	push   DWORD PTR [esi+0x14]
  722e4a:	6b 46 08 05          	imul   eax,DWORD PTR [esi+0x8],0x5
  722e4e:	ff 76 10             	push   DWORD PTR [esi+0x10]
  722e51:	6a 05                	push   0x5
  722e53:	05 6a 15 00 00       	add    eax,0x156a
  722e58:	03 c6                	add    eax,esi
  722e5a:	50                   	push   eax
  722e5b:	e8 70 d2 fe ff       	call   0x7100d0
  722e60:	ff 76 1c             	push   DWORD PTR [esi+0x1c]
  722e63:	6b 46 08 05          	imul   eax,DWORD PTR [esi+0x8],0x5
  722e67:	ff 76 18             	push   DWORD PTR [esi+0x18]
  722e6a:	6a 05                	push   0x5
  722e6c:	83 c0 20             	add    eax,0x20
  722e6f:	03 c6                	add    eax,esi
  722e71:	50                   	push   eax
  722e72:	e8 59 d2 fe ff       	call   0x7100d0
  722e77:	0f ae f0             	mfence
  722e7a:	c7 06 01 00 00 00    	mov    DWORD PTR [esi],0x1
  722e80:	83 c4 20             	add    esp,0x20
  722e83:	0f ae f0             	mfence
  722e86:	5e                   	pop    esi
  722e87:	c3                   	ret
  722e88:	55                   	push   ebp
  722e89:	8b ec                	mov    ebp,esp
  722e8b:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  722e8e:	53                   	push   ebx
  722e8f:	56                   	push   esi
  722e90:	8b d9                	mov    ebx,ecx
  722e92:	6b f0 05             	imul   esi,eax,0x5
  722e95:	57                   	push   edi
  722e96:	6a 05                	push   0x5
  722e98:	8d bb 6a 15 00 00    	lea    edi,[ebx+0x156a]
  722e9e:	89 43 08             	mov    DWORD PTR [ebx+0x8],eax
  722ea1:	03 fe                	add    edi,esi
  722ea3:	57                   	push   edi
  722ea4:	e8 57 00 00 00       	call   0x722f00
  722ea9:	83 c6 20             	add    esi,0x20
  722eac:	89 43 10             	mov    DWORD PTR [ebx+0x10],eax
  722eaf:	03 f3                	add    esi,ebx
  722eb1:	89 53 14             	mov    DWORD PTR [ebx+0x14],edx
  722eb4:	6a 05                	push   0x5
  722eb6:	56                   	push   esi
  722eb7:	e8 44 00 00 00       	call   0x722f00
  722ebc:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  722ebf:	89 43 18             	mov    DWORD PTR [ebx+0x18],eax
  722ec2:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  722ec5:	89 53 1c             	mov    DWORD PTR [ebx+0x1c],edx
  722ec8:	0f ae f0             	mfence
  722ecb:	6a 05                	push   0x5
  722ecd:	c7 03 02 00 00 00    	mov    DWORD PTR [ebx],0x2
  722ed3:	56                   	push   esi
  722ed4:	0f ae f0             	mfence
  722ed7:	e8 f4 d1 fe ff       	call   0x7100d0
  722edc:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  722edf:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  722ee2:	6a 05                	push   0x5
  722ee4:	57                   	push   edi
  722ee5:	e8 e6 d1 fe ff       	call   0x7100d0
  722eea:	83 c4 30             	add    esp,0x30
  722eed:	0f ae f0             	mfence
  722ef0:	c7 03 01 00 00 00    	mov    DWORD PTR [ebx],0x1
  722ef6:	0f ae f0             	mfence
  722ef9:	5f                   	pop    edi
  722efa:	5e                   	pop    esi
  722efb:	5b                   	pop    ebx
  722efc:	5d                   	pop    ebp
  722efd:	c2 14 00             	ret    0x14
  722f00:	55                   	push   ebp
  722f01:	8b ec                	mov    ebp,esp
  722f03:	51                   	push   ecx
  722f04:	51                   	push   ecx
  722f05:	56                   	push   esi
  722f06:	57                   	push   edi
  722f07:	0f 57 c0             	xorps  xmm0,xmm0
  722f0a:	33 ff                	xor    edi,edi
  722f0c:	66 0f 13 45 f8       	movlpd QWORD PTR [ebp-0x8],xmm0
  722f11:	8b 75 fc             	mov    esi,DWORD PTR [ebp-0x4]
  722f14:	8b 4d f8             	mov    ecx,DWORD PTR [ebp-0x8]
  722f17:	39 7d 0c             	cmp    DWORD PTR [ebp+0xc],edi
  722f1a:	76 1b                	jbe    0x722f37
  722f1c:	53                   	push   ebx
  722f1d:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
  722f20:	0f b6 04 1f          	movzx  eax,BYTE PTR [edi+ebx*1]
  722f24:	0f a4 ce 08          	shld   esi,ecx,0x8
  722f28:	99                   	cdq
  722f29:	c1 e1 08             	shl    ecx,0x8
  722f2c:	0b f2                	or     esi,edx
  722f2e:	0b c8                	or     ecx,eax
  722f30:	47                   	inc    edi
  722f31:	3b 7d 0c             	cmp    edi,DWORD PTR [ebp+0xc]
  722f34:	72 ea                	jb     0x722f20
  722f36:	5b                   	pop    ebx
  722f37:	5f                   	pop    edi
  722f38:	8b d6                	mov    edx,esi
  722f3a:	8b c1                	mov    eax,ecx
  722f3c:	5e                   	pop    esi
  722f3d:	c9                   	leave
  722f3e:	c3                   	ret
