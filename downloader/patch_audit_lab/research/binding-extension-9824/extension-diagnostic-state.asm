
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071db05 <.text+0x31cb05>:
  71db05:	33 c0                	xor    eax,eax
  71db07:	40                   	inc    eax
  71db08:	39 01                	cmp    DWORD PTR [ecx],eax
  71db0a:	74 07                	je     0x71db13
  71db0c:	83 39 02             	cmp    DWORD PTR [ecx],0x2
  71db0f:	74 02                	je     0x71db13
  71db11:	32 c0                	xor    al,al
  71db13:	c3                   	ret
