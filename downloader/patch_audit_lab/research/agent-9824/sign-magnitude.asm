
agent-research/Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

006e3c46 <.text+0x2e2c46>:
  6e3c46:	55                   	push   ebp
  6e3c47:	8b ec                	mov    ebp,esp
  6e3c49:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  6e3c4c:	53                   	push   ebx
  6e3c4d:	56                   	push   esi
  6e3c4e:	57                   	push   edi
  6e3c4f:	8a 59 07             	mov    bl,BYTE PTR [ecx+0x7]
  6e3c52:	8a c3                	mov    al,bl
  6e3c54:	24 7f                	and    al,0x7f
  6e3c56:	0f b6 c0             	movzx  eax,al
  6e3c59:	99                   	cdq
  6e3c5a:	8b f8                	mov    edi,eax
  6e3c5c:	8b f2                	mov    esi,edx
  6e3c5e:	0f b6 41 06          	movzx  eax,BYTE PTR [ecx+0x6]
  6e3c62:	0f a4 fe 08          	shld   esi,edi,0x8
  6e3c66:	99                   	cdq
  6e3c67:	c1 e7 08             	shl    edi,0x8
  6e3c6a:	0b f2                	or     esi,edx
  6e3c6c:	0b f8                	or     edi,eax
  6e3c6e:	0f b6 41 05          	movzx  eax,BYTE PTR [ecx+0x5]
  6e3c72:	0f a4 fe 08          	shld   esi,edi,0x8
  6e3c76:	99                   	cdq
  6e3c77:	c1 e7 08             	shl    edi,0x8
  6e3c7a:	0b f2                	or     esi,edx
  6e3c7c:	0b f8                	or     edi,eax
  6e3c7e:	0f b6 41 04          	movzx  eax,BYTE PTR [ecx+0x4]
  6e3c82:	0f a4 fe 08          	shld   esi,edi,0x8
  6e3c86:	99                   	cdq
  6e3c87:	c1 e7 08             	shl    edi,0x8
  6e3c8a:	0b f2                	or     esi,edx
  6e3c8c:	0b f8                	or     edi,eax
  6e3c8e:	0f b6 41 03          	movzx  eax,BYTE PTR [ecx+0x3]
  6e3c92:	0f a4 fe 08          	shld   esi,edi,0x8
  6e3c96:	99                   	cdq
  6e3c97:	c1 e7 08             	shl    edi,0x8
  6e3c9a:	0b f2                	or     esi,edx
  6e3c9c:	0b f8                	or     edi,eax
  6e3c9e:	0f b6 41 02          	movzx  eax,BYTE PTR [ecx+0x2]
  6e3ca2:	0f a4 fe 08          	shld   esi,edi,0x8
  6e3ca6:	99                   	cdq
  6e3ca7:	c1 e7 08             	shl    edi,0x8
  6e3caa:	0b f2                	or     esi,edx
  6e3cac:	0b f8                	or     edi,eax
  6e3cae:	0f b6 41 01          	movzx  eax,BYTE PTR [ecx+0x1]
  6e3cb2:	0f a4 fe 08          	shld   esi,edi,0x8
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
