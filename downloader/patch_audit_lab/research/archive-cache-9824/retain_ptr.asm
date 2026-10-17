
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00681aec <.text+0x280aec>:
  681aec:	55                   	push   ebp
  681aed:	8b ec                	mov    ebp,esp
  681aef:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  681af2:	8b 00                	mov    eax,DWORD PTR [eax]
  681af4:	89 01                	mov    DWORD PTR [ecx],eax
  681af6:	85 c0                	test   eax,eax
  681af8:	74 0a                	je     0x681b04
  681afa:	33 d2                	xor    edx,edx
  681afc:	83 c0 04             	add    eax,0x4
  681aff:	42                   	inc    edx
  681b00:	f0 0f c1 10          	lock xadd DWORD PTR [eax],edx
  681b04:	8b c1                	mov    eax,ecx
  681b06:	5d                   	pop    ebp
  681b07:	c2 04 00             	ret    0x4
