
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00722362 <.text+0x321362>:
  722362:	80 39 00             	cmp    BYTE PTR [ecx],0x0
  722365:	0f 85 32 fe ff ff    	jne    0x72219d
  72236b:	8d 41 08             	lea    eax,[ecx+0x8]
  72236e:	50                   	push   eax
  72236f:	e8 1c 13 05 00       	call   0x773690
  722374:	59                   	pop    ecx
  722375:	b0 01                	mov    al,0x1
  722377:	c3                   	ret
