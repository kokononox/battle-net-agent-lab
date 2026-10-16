
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00864dc2 <.text+0x463dc2>:
  864dc2:	55                   	push   ebp
  864dc3:	8b ec                	mov    ebp,esp
  864dc5:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  864dc8:	ff 30                	push   DWORD PTR [eax]
  864dca:	ff 15 8c b4 8f 00    	call   DWORD PTR ds:0x8fb48c
  864dd0:	85 c0                	test   eax,eax
  864dd2:	75 06                	jne    0x864dda
  864dd4:	5d                   	pop    ebp
  864dd5:	e9 d7 90 00 00       	jmp    0x86deb1
  864dda:	a1 60 d2 9a 00       	mov    eax,ds:0x9ad260
  864ddf:	5d                   	pop    ebp
  864de0:	c3                   	ret
