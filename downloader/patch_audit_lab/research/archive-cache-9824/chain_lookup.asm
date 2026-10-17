
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072d6b4 <.text+0x32c6b4>:
  72d6b4:	55                   	push   ebp
  72d6b5:	8b ec                	mov    ebp,esp
  72d6b7:	56                   	push   esi
  72d6b8:	57                   	push   edi
  72d6b9:	8b f9                	mov    edi,ecx
  72d6bb:	8b 37                	mov    esi,DWORD PTR [edi]
  72d6bd:	85 f6                	test   esi,esi
  72d6bf:	75 05                	jne    0x72d6c6
  72d6c1:	83 c8 ff             	or     eax,0xffffffff
  72d6c4:	eb 2a                	jmp    0x72d6f0
  72d6c6:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  72d6c9:	8b 34 86             	mov    esi,DWORD PTR [esi+eax*4]
  72d6cc:	eb 1b                	jmp    0x72d6e9
  72d6ce:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72d6d1:	6b c6 18             	imul   eax,esi,0x18
  72d6d4:	03 47 04             	add    eax,DWORD PTR [edi+0x4]
  72d6d7:	50                   	push   eax
  72d6d8:	e8 3f 01 00 00       	call   0x72d81c
  72d6dd:	59                   	pop    ecx
  72d6de:	59                   	pop    ecx
  72d6df:	84 c0                	test   al,al
  72d6e1:	75 0b                	jne    0x72d6ee
  72d6e3:	8b 4f 08             	mov    ecx,DWORD PTR [edi+0x8]
  72d6e6:	8b 34 b1             	mov    esi,DWORD PTR [ecx+esi*4]
  72d6e9:	83 fe ff             	cmp    esi,0xffffffff
  72d6ec:	75 e0                	jne    0x72d6ce
  72d6ee:	8b c6                	mov    eax,esi
  72d6f0:	5f                   	pop    edi
  72d6f1:	5e                   	pop    esi
  72d6f2:	5d                   	pop    ebp
  72d6f3:	c2 08 00             	ret    0x8
