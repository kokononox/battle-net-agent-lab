
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072d18f <.text+0x32c18f>:
  72d18f:	55                   	push   ebp
  72d190:	8b ec                	mov    ebp,esp
  72d192:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  72d195:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
  72d198:	56                   	push   esi
  72d199:	57                   	push   edi
  72d19a:	8b 7d 10             	mov    edi,DWORD PTR [ebp+0x10]
  72d19d:	83 27 00             	and    DWORD PTR [edi],0x0
  72d1a0:	83 67 04 00          	and    DWORD PTR [edi+0x4],0x0
  72d1a4:	8b 41 04             	mov    eax,DWORD PTR [ecx+0x4]
  72d1a7:	3b 42 0c             	cmp    eax,DWORD PTR [edx+0xc]
  72d1aa:	77 46                	ja     0x72d1f2
  72d1ac:	72 07                	jb     0x72d1b5
  72d1ae:	8b 01                	mov    eax,DWORD PTR [ecx]
  72d1b0:	3b 42 08             	cmp    eax,DWORD PTR [edx+0x8]
  72d1b3:	77 3d                	ja     0x72d1f2
  72d1b5:	8b 71 08             	mov    esi,DWORD PTR [ecx+0x8]
  72d1b8:	8b c6                	mov    eax,esi
  72d1ba:	53                   	push   ebx
  72d1bb:	8b 59 0c             	mov    ebx,DWORD PTR [ecx+0xc]
  72d1be:	23 c3                	and    eax,ebx
  72d1c0:	89 37                	mov    DWORD PTR [edi],esi
  72d1c2:	89 5f 04             	mov    DWORD PTR [edi+0x4],ebx
  72d1c5:	83 f8 ff             	cmp    eax,0xffffffff
  72d1c8:	75 10                	jne    0x72d1da
  72d1ca:	8b 72 08             	mov    esi,DWORD PTR [edx+0x8]
  72d1cd:	2b 31                	sub    esi,DWORD PTR [ecx]
  72d1cf:	8b 5a 0c             	mov    ebx,DWORD PTR [edx+0xc]
  72d1d2:	1b 59 04             	sbb    ebx,DWORD PTR [ecx+0x4]
  72d1d5:	89 37                	mov    DWORD PTR [edi],esi
  72d1d7:	89 5f 04             	mov    DWORD PTR [edi+0x4],ebx
  72d1da:	03 31                	add    esi,DWORD PTR [ecx]
  72d1dc:	8b 41 04             	mov    eax,DWORD PTR [ecx+0x4]
  72d1df:	13 c3                	adc    eax,ebx
  72d1e1:	5b                   	pop    ebx
  72d1e2:	3b 42 0c             	cmp    eax,DWORD PTR [edx+0xc]
  72d1e5:	77 0b                	ja     0x72d1f2
  72d1e7:	72 05                	jb     0x72d1ee
  72d1e9:	3b 72 08             	cmp    esi,DWORD PTR [edx+0x8]
  72d1ec:	77 04                	ja     0x72d1f2
  72d1ee:	b0 01                	mov    al,0x1
  72d1f0:	eb 02                	jmp    0x72d1f4
  72d1f2:	32 c0                	xor    al,al
  72d1f4:	5f                   	pop    edi
  72d1f5:	5e                   	pop    esi
  72d1f6:	5d                   	pop    ebp
  72d1f7:	c3                   	ret
