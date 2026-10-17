
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0068165e <.text+0x28065e>:
  68165e:	55                   	push   ebp
  68165f:	8b ec                	mov    ebp,esp
  681661:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  681664:	c1 e8 10             	shr    eax,0x10
  681667:	33 45 08             	xor    eax,DWORD PTR [ebp+0x8]
  68166a:	69 c8 6b ca eb 85    	imul   ecx,eax,0x85ebca6b
  681670:	8b c1                	mov    eax,ecx
  681672:	c1 e8 0d             	shr    eax,0xd
  681675:	33 c1                	xor    eax,ecx
  681677:	69 c8 35 ae b2 c2    	imul   ecx,eax,0xc2b2ae35
  68167d:	8b c1                	mov    eax,ecx
  68167f:	c1 e8 10             	shr    eax,0x10
  681682:	33 c1                	xor    eax,ecx
  681684:	5d                   	pop    ebp
  681685:	c3                   	ret
