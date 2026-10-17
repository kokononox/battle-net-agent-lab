
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0067a5ee <.text+0x2795ee>:
  67a5ee:	55                   	push   ebp
  67a5ef:	8b ec                	mov    ebp,esp
  67a5f1:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  67a5f4:	83 c9 ff             	or     ecx,0xffffffff
  67a5f7:	f0 0f c1 08          	lock xadd DWORD PTR [eax],ecx
  67a5fb:	83 f9 01             	cmp    ecx,0x1
  67a5fe:	75 05                	jne    0x67a605
  67a600:	90                   	nop
  67a601:	8a c1                	mov    al,cl
  67a603:	5d                   	pop    ebp
  67a604:	c3                   	ret
  67a605:	32 c0                	xor    al,al
  67a607:	5d                   	pop    ebp
  67a608:	c3                   	ret
