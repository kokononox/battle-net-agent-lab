
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072dbcb <.text+0x32cbcb>:
  72dbcb:	55                   	push   ebp
  72dbcc:	8b ec                	mov    ebp,esp
  72dbce:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  72dbd1:	83 c2 2c             	add    edx,0x2c
  72dbd4:	8b 4a 04             	mov    ecx,DWORD PTR [edx+0x4]
  72dbd7:	8b 02                	mov    eax,DWORD PTR [edx]
  72dbd9:	89 01                	mov    DWORD PTR [ecx],eax
  72dbdb:	8b 0a                	mov    ecx,DWORD PTR [edx]
  72dbdd:	8b 42 04             	mov    eax,DWORD PTR [edx+0x4]
  72dbe0:	89 41 04             	mov    DWORD PTR [ecx+0x4],eax
  72dbe3:	89 52 04             	mov    DWORD PTR [edx+0x4],edx
  72dbe6:	89 12                	mov    DWORD PTR [edx],edx
  72dbe8:	5d                   	pop    ebp
  72dbe9:	c3                   	ret
