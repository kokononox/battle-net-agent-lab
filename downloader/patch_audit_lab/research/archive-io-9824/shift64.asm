
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00876d30 <.text+0x475d30>:
  876d30:	80 f9 40             	cmp    cl,0x40
  876d33:	73 15                	jae    0x876d4a
  876d35:	80 f9 20             	cmp    cl,0x20
  876d38:	73 06                	jae    0x876d40
  876d3a:	0f ad d0             	shrd   eax,edx,cl
  876d3d:	d3 ea                	shr    edx,cl
  876d3f:	c3                   	ret
  876d40:	8b c2                	mov    eax,edx
  876d42:	33 d2                	xor    edx,edx
  876d44:	80 e1 1f             	and    cl,0x1f
  876d47:	d3 e8                	shr    eax,cl
  876d49:	c3                   	ret
  876d4a:	33 c0                	xor    eax,eax
  876d4c:	33 d2                	xor    edx,edx
  876d4e:	c3                   	ret
