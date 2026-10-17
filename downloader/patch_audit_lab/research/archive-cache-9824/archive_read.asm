
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0070dbd5 <.text+0x30cbd5>:
  70dbd5:	6a 08                	push   0x8
  70dbd7:	b8 0d 1b 8f 00       	mov    eax,0x8f1b0d
  70dbdc:	e8 57 84 16 00       	call   0x876038
  70dbe1:	8b f1                	mov    esi,ecx
  70dbe3:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  70dbe6:	8b 7d 14             	mov    edi,DWORD PTR [ebp+0x14]
  70dbe9:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  70dbec:	83 65 f0 00          	and    DWORD PTR [ebp-0x10],0x0
  70dbf0:	83 20 00             	and    DWORD PTR [eax],0x0
  70dbf3:	8d 45 f0             	lea    eax,[ebp-0x10]
  70dbf6:	50                   	push   eax
  70dbf7:	57                   	push   edi
  70dbf8:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  70dbfb:	53                   	push   ebx
  70dbfc:	e8 90 fe ff ff       	call   0x70da91
  70dc01:	84 c0                	test   al,al
  70dc03:	75 08                	jne    0x70dc0d
  70dc05:	6a 0a                	push   0xa
  70dc07:	58                   	pop    eax
  70dc08:	e9 de 00 00 00       	jmp    0x70dceb
  70dc0d:	85 ff                	test   edi,edi
  70dc0f:	75 07                	jne    0x70dc18
  70dc11:	33 c0                	xor    eax,eax
  70dc13:	e9 d3 00 00 00       	jmp    0x70dceb
  70dc18:	83 65 ec 00          	and    DWORD PTR [ebp-0x14],0x0
  70dc1c:	80 be 51 01 00 00 00 	cmp    BYTE PTR [esi+0x151],0x0
  70dc23:	75 15                	jne    0x70dc3a
  70dc25:	6a 00                	push   0x0
  70dc27:	ff 75 f0             	push   DWORD PTR [ebp-0x10]
  70dc2a:	8b ce                	mov    ecx,esi
  70dc2c:	e8 58 ff ff ff       	call   0x70db89
  70dc31:	84 c0                	test   al,al
  70dc33:	75 05                	jne    0x70dc3a
  70dc35:	33 c0                	xor    eax,eax
  70dc37:	40                   	inc    eax
  70dc38:	eb 03                	jmp    0x70dc3d
  70dc3a:	6a 04                	push   0x4
  70dc3c:	58                   	pop    eax
  70dc3d:	33 d2                	xor    edx,edx
  70dc3f:	8d 8e 54 01 00 00    	lea    ecx,[esi+0x154]
  70dc45:	52                   	push   edx
  70dc46:	52                   	push   edx
  70dc47:	52                   	push   edx
  70dc48:	8d 55 ec             	lea    edx,[ebp-0x14]
  70dc4b:	52                   	push   edx
  70dc4c:	50                   	push   eax
  70dc4d:	ff b6 44 01 00 00    	push   DWORD PTR [esi+0x144]
  70dc53:	8d 45 14             	lea    eax,[ebp+0x14]
  70dc56:	6a 00                	push   0x0
  70dc58:	ff 75 f0             	push   DWORD PTR [ebp-0x10]
  70dc5b:	50                   	push   eax
  70dc5c:	e8 92 f5 00 00       	call   0x71d1f3
  70dc61:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  70dc65:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  70dc68:	8b 55 18             	mov    edx,DWORD PTR [ebp+0x18]
  70dc6b:	85 c0                	test   eax,eax
  70dc6d:	75 07                	jne    0x70dc76
  70dc6f:	21 02                	and    DWORD PTR [edx],eax
  70dc71:	8b 75 ec             	mov    esi,DWORD PTR [ebp-0x14]
  70dc74:	eb 61                	jmp    0x70dcd7
  70dc76:	8b 8e 4c 01 00 00    	mov    ecx,DWORD PTR [esi+0x14c]
  70dc7c:	21 4d 10             	and    DWORD PTR [ebp+0x10],ecx
  70dc7f:	8d 4e 04             	lea    ecx,[esi+0x4]
  70dc82:	23 9e 48 01 00 00    	and    ebx,DWORD PTR [esi+0x148]
  70dc88:	52                   	push   edx
  70dc89:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  70dc8c:	57                   	push   edi
  70dc8d:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  70dc90:	53                   	push   ebx
  70dc91:	51                   	push   ecx
  70dc92:	8b d4                	mov    edx,esp
  70dc94:	89 02                	mov    DWORD PTR [edx],eax
  70dc96:	83 65 14 00          	and    DWORD PTR [ebp+0x14],0x0
  70dc9a:	e8 0e e0 ff ff       	call   0x70bcad
  70dc9f:	8b f0                	mov    esi,eax
  70dca1:	85 f6                	test   esi,esi
  70dca3:	74 2d                	je     0x70dcd2
  70dca5:	56                   	push   esi
  70dca6:	e8 c6 51 ff ff       	call   0x702e71
  70dcab:	50                   	push   eax
  70dcac:	56                   	push   esi
  70dcad:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  70dcb0:	53                   	push   ebx
  70dcb1:	ff 75 f0             	push   DWORD PTR [ebp-0x10]
  70dcb4:	57                   	push   edi
  70dcb5:	68 60 cd 9b 00       	push   0x9bcd60
  70dcba:	6a 00                	push   0x0
  70dcbc:	68 08 bc 8f 00       	push   0x8fbc08
  70dcc1:	6a 04                	push   0x4
  70dcc3:	68 38 ba 9b 00       	push   0x9bba38
  70dcc8:	e8 76 5b 1b 00       	call   0x8c3843
  70dccd:	83 c4 30             	add    esp,0x30
  70dcd0:	eb 02                	jmp    0x70dcd4
  70dcd2:	33 f6                	xor    esi,esi
  70dcd4:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  70dcd7:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [ebp-0x4],0x3
  70dcde:	85 c0                	test   eax,eax
  70dce0:	74 07                	je     0x70dce9
  70dce2:	50                   	push   eax
  70dce3:	e8 ad d7 f6 ff       	call   0x67b495
  70dce8:	59                   	pop    ecx
  70dce9:	8b c6                	mov    eax,esi
  70dceb:	e8 16 83 16 00       	call   0x876006
  70dcf0:	c2 14 00             	ret    0x14
