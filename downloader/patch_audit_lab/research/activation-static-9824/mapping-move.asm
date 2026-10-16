
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0086c784 <.text+0x46b784>:
  86c784:	55                   	push   ebp
  86c785:	8b ec                	mov    ebp,esp
  86c787:	56                   	push   esi
  86c788:	8b f1                	mov    esi,ecx
  86c78a:	57                   	push   edi
  86c78b:	33 ff                	xor    edi,edi
  86c78d:	39 3e                	cmp    DWORD PTR [esi],edi
  86c78f:	74 07                	je     0x86c798
  86c791:	56                   	push   esi
  86c792:	e8 49 00 00 00       	call   0x86c7e0
  86c797:	59                   	pop    ecx
  86c798:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  86c79b:	8b 02                	mov    eax,DWORD PTR [edx]
  86c79d:	89 3a                	mov    DWORD PTR [edx],edi
  86c79f:	89 06                	mov    DWORD PTR [esi],eax
  86c7a1:	8b 42 08             	mov    eax,DWORD PTR [edx+0x8]
  86c7a4:	8b 4a 0c             	mov    ecx,DWORD PTR [edx+0xc]
  86c7a7:	89 7a 08             	mov    DWORD PTR [edx+0x8],edi
  86c7aa:	89 7a 0c             	mov    DWORD PTR [edx+0xc],edi
  86c7ad:	89 46 08             	mov    DWORD PTR [esi+0x8],eax
  86c7b0:	89 4e 0c             	mov    DWORD PTR [esi+0xc],ecx
  86c7b3:	8b 42 10             	mov    eax,DWORD PTR [edx+0x10]
  86c7b6:	8b 4a 14             	mov    ecx,DWORD PTR [edx+0x14]
  86c7b9:	89 7a 10             	mov    DWORD PTR [edx+0x10],edi
  86c7bc:	89 7a 14             	mov    DWORD PTR [edx+0x14],edi
  86c7bf:	89 46 10             	mov    DWORD PTR [esi+0x10],eax
  86c7c2:	89 4e 14             	mov    DWORD PTR [esi+0x14],ecx
  86c7c5:	8b 42 18             	mov    eax,DWORD PTR [edx+0x18]
  86c7c8:	89 7a 18             	mov    DWORD PTR [edx+0x18],edi
  86c7cb:	89 46 18             	mov    DWORD PTR [esi+0x18],eax
  86c7ce:	8b 42 1c             	mov    eax,DWORD PTR [edx+0x1c]
  86c7d1:	83 4a 1c ff          	or     DWORD PTR [edx+0x1c],0xffffffff
  86c7d5:	89 46 1c             	mov    DWORD PTR [esi+0x1c],eax
  86c7d8:	8b c6                	mov    eax,esi
  86c7da:	5f                   	pop    edi
  86c7db:	5e                   	pop    esi
  86c7dc:	5d                   	pop    ebp
  86c7dd:	c2 04 00             	ret    0x4
