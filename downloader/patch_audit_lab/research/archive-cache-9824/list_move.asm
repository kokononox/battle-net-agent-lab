
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00687fb0 <.text+0x286fb0>:
  687fb0:	55                   	push   ebp
  687fb1:	8b ec                	mov    ebp,esp
  687fb3:	56                   	push   esi
  687fb4:	8b f1                	mov    esi,ecx
  687fb6:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  687fb9:	8b 56 04             	mov    edx,DWORD PTR [esi+0x4]
  687fbc:	8b 06                	mov    eax,DWORD PTR [esi]
  687fbe:	89 02                	mov    DWORD PTR [edx],eax
  687fc0:	8b 16                	mov    edx,DWORD PTR [esi]
  687fc2:	8b 46 04             	mov    eax,DWORD PTR [esi+0x4]
  687fc5:	89 42 04             	mov    DWORD PTR [edx+0x4],eax
  687fc8:	8b 41 04             	mov    eax,DWORD PTR [ecx+0x4]
  687fcb:	89 46 04             	mov    DWORD PTR [esi+0x4],eax
  687fce:	89 0e                	mov    DWORD PTR [esi],ecx
  687fd0:	89 71 04             	mov    DWORD PTR [ecx+0x4],esi
  687fd3:	8b 46 04             	mov    eax,DWORD PTR [esi+0x4]
  687fd6:	89 30                	mov    DWORD PTR [eax],esi
  687fd8:	5e                   	pop    esi
  687fd9:	5d                   	pop    ebp
  687fda:	c2 04 00             	ret    0x4
