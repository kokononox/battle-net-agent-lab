
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072d81c <.text+0x32c81c>:
  72d81c:	55                   	push   ebp
  72d81d:	8b ec                	mov    ebp,esp
  72d81f:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  72d822:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
  72d825:	8b 01                	mov    eax,DWORD PTR [ecx]
  72d827:	3b 02                	cmp    eax,DWORD PTR [edx]
  72d829:	75 14                	jne    0x72d83f
  72d82b:	8b 41 04             	mov    eax,DWORD PTR [ecx+0x4]
  72d82e:	3b 42 04             	cmp    eax,DWORD PTR [edx+0x4]
  72d831:	75 0c                	jne    0x72d83f
  72d833:	8a 41 08             	mov    al,BYTE PTR [ecx+0x8]
  72d836:	3a 42 08             	cmp    al,BYTE PTR [edx+0x8]
  72d839:	75 04                	jne    0x72d83f
  72d83b:	b0 01                	mov    al,0x1
  72d83d:	5d                   	pop    ebp
  72d83e:	c3                   	ret
  72d83f:	32 c0                	xor    al,al
  72d841:	5d                   	pop    ebp
  72d842:	c3                   	ret
