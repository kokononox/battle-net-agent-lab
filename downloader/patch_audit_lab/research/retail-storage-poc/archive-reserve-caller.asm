
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00711b21 <.text+0x310b21>:
  711b21:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  711b24:	8b 4b 4c             	mov    ecx,DWORD PTR [ebx+0x4c]
  711b27:	e8 d9 0f 01 00       	call   0x722b05
  711b2c:	8b f0                	mov    esi,eax
  711b2e:	85 f6                	test   esi,esi
  711b30:	74 29                	je     0x711b5b
  711b32:	56                   	push   esi
  711b33:	e8 39 13 ff ff       	call   0x702e71
  711b38:	50                   	push   eax
  711b39:	56                   	push   esi
  711b3a:	68 e0 d0 9b 00       	push   0x9bd0e0
  711b3f:	57                   	push   edi
  711b40:	68 08 bc 8f 00       	push   0x8fbc08
  711b45:	6a 04                	push   0x4
  711b47:	68 38 ba 9b 00       	push   0x9bba38
  711b4c:	e8 f2 1c 1b 00       	call   0x8c3843
  711b51:	83 c4 20             	add    esp,0x20
  711b54:	8b c6                	mov    eax,esi
  711b56:	e9 9f 00 00 00       	jmp    0x711bfa
  711b5b:	6a 01                	push   0x1
  711b5d:	6a 01                	push   0x1
  711b5f:	8d 85 60 ff ff ff    	lea    eax,[ebp-0xa0]
  711b65:	8b cb                	mov    ecx,ebx
  711b67:	50                   	push   eax
  711b68:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  711b6b:	e8 ba 09 00 00       	call   0x71252a
  711b70:	85 c0                	test   eax,eax
  711b72:	0f 85 82 00 00 00    	jne    0x711bfa
