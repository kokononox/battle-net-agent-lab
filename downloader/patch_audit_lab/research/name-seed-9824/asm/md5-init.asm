
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00864541 <.text+0x463541>:
  864541:	83 21 00             	and    DWORD PTR [ecx],0x0
  864544:	83 61 04 00          	and    DWORD PTR [ecx+0x4],0x0
  864548:	c7 41 08 01 23 45 67 	mov    DWORD PTR [ecx+0x8],0x67452301
  86454f:	c7 41 0c 89 ab cd ef 	mov    DWORD PTR [ecx+0xc],0xefcdab89
  864556:	c7 41 10 fe dc ba 98 	mov    DWORD PTR [ecx+0x10],0x98badcfe
  86455d:	c7 41 14 76 54 32 10 	mov    DWORD PTR [ecx+0x14],0x10325476
  864564:	c3                   	ret
