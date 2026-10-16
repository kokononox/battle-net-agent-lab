
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00700696 <.text+0x2ff696>:
  700696:	8b 41 10             	mov    eax,DWORD PTR [ecx+0x10]
  700699:	8b 51 14             	mov    edx,DWORD PTR [ecx+0x14]
  70069c:	0f ac d0 1e          	shrd   eax,edx,0x1e
  7006a0:	c1 ea 1e             	shr    edx,0x1e
  7006a3:	c3                   	ret
