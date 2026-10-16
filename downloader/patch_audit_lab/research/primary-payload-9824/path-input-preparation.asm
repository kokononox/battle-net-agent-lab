
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00712bc9 <.text+0x311bc9>:
  712bc9:	55                   	push   ebp
  712bca:	8b ec                	mov    ebp,esp
  712bcc:	81 ec 1c 07 00 00    	sub    esp,0x71c
  712bd2:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  712bd7:	33 c5                	xor    eax,ebp
  712bd9:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  712bdc:	53                   	push   ebx
  712bdd:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  712be0:	56                   	push   esi
  712be1:	57                   	push   edi
  712be2:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  712be5:	57                   	push   edi
  712be6:	e8 e6 0b 15 00       	call   0x8637d1
  712beb:	59                   	pop    ecx
  712bec:	84 c0                	test   al,al
  712bee:	74 11                	je     0x712c01
  712bf0:	8d 85 f0 fb ff ff    	lea    eax,[ebp-0x410]
  712bf6:	57                   	push   edi
  712bf7:	50                   	push   eax
  712bf8:	e8 d9 79 f6 ff       	call   0x67a5d6
  712bfd:	59                   	pop    ecx
  712bfe:	59                   	pop    ecx
  712bff:	eb 5e                	jmp    0x712c5f
  712c01:	8d 85 e4 f8 ff ff    	lea    eax,[ebp-0x71c]
  712c07:	50                   	push   eax
  712c08:	e8 3f 57 f8 ff       	call   0x69834c
  712c0d:	8b f0                	mov    esi,eax
  712c0f:	59                   	pop    ecx
  712c10:	85 f6                	test   esi,esi
  712c12:	74 34                	je     0x712c48
  712c14:	8d 85 fc fe ff ff    	lea    eax,[ebp-0x104]
  712c1a:	56                   	push   esi
  712c1b:	50                   	push   eax
  712c1c:	e8 00 9e f6 ff       	call   0x67ca21
  712c21:	8d 85 fc fe ff ff    	lea    eax,[ebp-0x104]
  712c27:	50                   	push   eax
  712c28:	56                   	push   esi
  712c29:	68 18 cf 9b 00       	push   0x9bcf18
  712c2e:	6a 00                	push   0x0
  712c30:	68 08 bc 8f 00       	push   0x8fbc08
  712c35:	6a 04                	push   0x4
  712c37:	68 38 ba 9b 00       	push   0x9bba38
  712c3c:	e8 02 0c 1b 00       	call   0x8c3843
  712c41:	83 c4 24             	add    esp,0x24
  712c44:	32 c0                	xor    al,al
  712c46:	eb 3a                	jmp    0x712c82
  712c48:	57                   	push   edi
  712c49:	8d 85 e4 f8 ff ff    	lea    eax,[ebp-0x71c]
  712c4f:	50                   	push   eax
  712c50:	8d 85 f0 fb ff ff    	lea    eax,[ebp-0x410]
  712c56:	50                   	push   eax
  712c57:	e8 02 d8 de ff       	call   0x50045e
  712c5c:	83 c4 0c             	add    esp,0xc
  712c5f:	8d 95 f0 fb ff ff    	lea    edx,[ebp-0x410]
  712c65:	8d 4a 01             	lea    ecx,[edx+0x1]
  712c68:	8a 02                	mov    al,BYTE PTR [edx]
  712c6a:	42                   	inc    edx
  712c6b:	84 c0                	test   al,al
  712c6d:	75 f9                	jne    0x712c68
  712c6f:	2b d1                	sub    edx,ecx
  712c71:	8d 85 f0 fb ff ff    	lea    eax,[ebp-0x410]
  712c77:	52                   	push   edx
  712c78:	50                   	push   eax
  712c79:	8b cb                	mov    ecx,ebx
  712c7b:	e8 a9 77 15 00       	call   0x86a429
  712c80:	b0 01                	mov    al,0x1
  712c82:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  712c85:	5f                   	pop    edi
  712c86:	5e                   	pop    esi
  712c87:	33 cd                	xor    ecx,ebp
  712c89:	5b                   	pop    ebx
  712c8a:	e8 69 33 16 00       	call   0x875ff8
  712c8f:	c9                   	leave
  712c90:	c3                   	ret
