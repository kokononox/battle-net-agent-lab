
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0070349f <.text+0x30249f>:
  70349f:	55                   	push   ebp
  7034a0:	8b ec                	mov    ebp,esp
  7034a2:	56                   	push   esi
  7034a3:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  7034a6:	33 d2                	xor    edx,edx
  7034a8:	57                   	push   edi
  7034a9:	8b 7d 0c             	mov    edi,DWORD PTR [ebp+0xc]
  7034ac:	8b ca                	mov    ecx,edx
  7034ae:	8b 04 8e             	mov    eax,DWORD PTR [esi+ecx*4]
  7034b1:	3b 04 8f             	cmp    eax,DWORD PTR [edi+ecx*4]
  7034b4:	75 08                	jne    0x7034be
  7034b6:	41                   	inc    ecx
  7034b7:	83 f9 04             	cmp    ecx,0x4
  7034ba:	75 f2                	jne    0x7034ae
  7034bc:	b2 01                	mov    dl,0x1
  7034be:	5f                   	pop    edi
  7034bf:	8a c2                	mov    al,dl
  7034c1:	5e                   	pop    esi
  7034c2:	5d                   	pop    ebp
  7034c3:	c3                   	ret
