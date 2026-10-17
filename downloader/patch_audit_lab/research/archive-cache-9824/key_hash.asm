
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072d843 <.text+0x32c843>:
  72d843:	55                   	push   ebp
  72d844:	8b ec                	mov    ebp,esp
  72d846:	56                   	push   esi
  72d847:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  72d84a:	57                   	push   edi
  72d84b:	ff 36                	push   DWORD PTR [esi]
  72d84d:	e8 0c 3e f5 ff       	call   0x68165e
  72d852:	0f b6 4e 08          	movzx  ecx,BYTE PTR [esi+0x8]
  72d856:	8b f8                	mov    edi,eax
  72d858:	51                   	push   ecx
  72d859:	e8 00 3e f5 ff       	call   0x68165e
  72d85e:	59                   	pop    ecx
  72d85f:	59                   	pop    ecx
  72d860:	8b d7                	mov    edx,edi
  72d862:	8b cf                	mov    ecx,edi
  72d864:	c1 e2 06             	shl    edx,0x6
  72d867:	05 b9 79 37 9e       	add    eax,0x9e3779b9
  72d86c:	c1 e9 02             	shr    ecx,0x2
  72d86f:	03 d1                	add    edx,ecx
  72d871:	03 c2                	add    eax,edx
  72d873:	33 c7                	xor    eax,edi
  72d875:	5f                   	pop    edi
  72d876:	5e                   	pop    esi
  72d877:	5d                   	pop    ebp
  72d878:	c2 04 00             	ret    0x4
