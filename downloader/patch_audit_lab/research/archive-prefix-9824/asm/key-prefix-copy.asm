
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00710b6a <.text+0x30fb6a>:
  710b6a:	55                   	push   ebp
  710b6b:	8b ec                	mov    ebp,esp
  710b6d:	83 ec 10             	sub    esp,0x10
  710b70:	56                   	push   esi
  710b71:	8b f1                	mov    esi,ecx
  710b73:	f6 46 0c 01          	test   BYTE PTR [esi+0xc],0x1
  710b77:	8d 46 10             	lea    eax,[esi+0x10]
  710b7a:	75 02                	jne    0x710b7e
  710b7c:	8b 00                	mov    eax,DWORD PTR [eax]
  710b7e:	50                   	push   eax
  710b7f:	8d 45 f0             	lea    eax,[ebp-0x10]
  710b82:	50                   	push   eax
  710b83:	e8 5b 1f 00 00       	call   0x712ae3
  710b88:	8b 46 34             	mov    eax,DWORD PTR [esi+0x34]
  710b8b:	59                   	pop    ecx
  710b8c:	59                   	pop    ecx
  710b8d:	8b 4e 30             	mov    ecx,DWORD PTR [esi+0x30]
  710b90:	0f ac c1 1e          	shrd   ecx,eax,0x1e
  710b94:	81 f9 ff 03 00 00    	cmp    ecx,0x3ff
  710b9a:	76 30                	jbe    0x710bcc
  710b9c:	ff 76 34             	push   DWORD PTR [esi+0x34]
  710b9f:	ff 76 30             	push   DWORD PTR [esi+0x30]
  710ba2:	68 e8 d2 9b 00       	push   0x9bd2e8
  710ba7:	6a 00                	push   0x0
  710ba9:	68 08 bc 8f 00       	push   0x8fbc08
  710bae:	6a 04                	push   0x4
  710bb0:	68 38 ba 9b 00       	push   0x9bba38
  710bb5:	e8 89 2c 1b 00       	call   0x8c3843
  710bba:	83 c4 1c             	add    esp,0x1c
  710bbd:	33 c9                	xor    ecx,ecx
  710bbf:	41                   	inc    ecx
  710bc0:	83 7e 2c 04          	cmp    DWORD PTR [esi+0x2c],0x4
  710bc4:	6a 09                	push   0x9
  710bc6:	58                   	pop    eax
  710bc7:	0f 44 c1             	cmove  eax,ecx
  710bca:	eb 32                	jmp    0x710bfe
  710bcc:	53                   	push   ebx
  710bcd:	8b 5d 10             	mov    ebx,DWORD PTR [ebp+0x10]
  710bd0:	8d 45 f0             	lea    eax,[ebp-0x10]
  710bd3:	57                   	push   edi
  710bd4:	53                   	push   ebx
  710bd5:	51                   	push   ecx
  710bd6:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  710bd9:	50                   	push   eax
  710bda:	e8 8e 1e 00 00       	call   0x712a6d
  710bdf:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  710be2:	83 c4 10             	add    esp,0x10
  710be5:	6a 10                	push   0x10
  710be7:	59                   	pop    ecx
  710be8:	8b f3                	mov    esi,ebx
  710bea:	8b f8                	mov    edi,eax
  710bec:	83 c3 10             	add    ebx,0x10
  710bef:	83 c0 09             	add    eax,0x9
  710bf2:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  710bf3:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  710bf4:	a4                   	movs   BYTE PTR es:[edi],BYTE PTR ds:[esi]
  710bf5:	83 e9 01             	sub    ecx,0x1
  710bf8:	75 ee                	jne    0x710be8
  710bfa:	5f                   	pop    edi
  710bfb:	33 c0                	xor    eax,eax
  710bfd:	5b                   	pop    ebx
  710bfe:	5e                   	pop    esi
  710bff:	c9                   	leave
  710c00:	c2 0c 00             	ret    0xc
