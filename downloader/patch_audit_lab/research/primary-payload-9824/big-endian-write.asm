
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

007100d0 <.text+0x30f0d0>:
  7100d0:	55                   	push   ebp
  7100d1:	8b ec                	mov    ebp,esp
  7100d3:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  7100d6:	85 c9                	test   ecx,ecx
  7100d8:	74 1d                	je     0x7100f7
  7100da:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  7100dd:	8b 55 10             	mov    edx,DWORD PTR [ebp+0x10]
  7100e0:	56                   	push   esi
  7100e1:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  7100e4:	4e                   	dec    esi
  7100e5:	03 f1                	add    esi,ecx
  7100e7:	88 16                	mov    BYTE PTR [esi],dl
  7100e9:	0f ac c2 08          	shrd   edx,eax,0x8
  7100ed:	c1 e8 08             	shr    eax,0x8
  7100f0:	4e                   	dec    esi
  7100f1:	83 e9 01             	sub    ecx,0x1
  7100f4:	75 f1                	jne    0x7100e7
  7100f6:	5e                   	pop    esi
  7100f7:	5d                   	pop    ebp
  7100f8:	c3                   	ret
