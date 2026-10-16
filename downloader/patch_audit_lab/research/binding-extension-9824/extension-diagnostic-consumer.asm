
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071dc3a <.text+0x31cc3a>:
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
