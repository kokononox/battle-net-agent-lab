
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0070db89 <.text+0x30cb89>:
  70db89:	55                   	push   ebp
  70db8a:	8b ec                	mov    ebp,esp
  70db8c:	8b 89 88 01 00 00    	mov    ecx,DWORD PTR [ecx+0x188]
  70db92:	85 c9                	test   ecx,ecx
  70db94:	74 0b                	je     0x70dba1
  70db96:	8d 45 08             	lea    eax,[ebp+0x8]
  70db99:	50                   	push   eax
  70db9a:	e8 55 b0 ff ff       	call   0x708bf4
  70db9f:	eb 02                	jmp    0x70dba3
  70dba1:	32 c0                	xor    al,al
  70dba3:	5d                   	pop    ebp
  70dba4:	c2 08 00             	ret    0x8
