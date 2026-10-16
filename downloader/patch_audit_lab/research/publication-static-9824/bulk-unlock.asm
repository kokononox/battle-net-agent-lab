
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071b87a <.text+0x31a87a>:
  71b87a:	55                   	push   ebp
  71b87b:	8b ec                	mov    ebp,esp
  71b87d:	6a ff                	push   0xffffffff
  71b87f:	68 53 94 8c 00       	push   0x8c9453
  71b884:	64 a1 00 00 00 00    	mov    eax,fs:0x0
  71b88a:	50                   	push   eax
  71b88b:	56                   	push   esi
  71b88c:	57                   	push   edi
  71b88d:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71b892:	33 c5                	xor    eax,ebp
  71b894:	50                   	push   eax
  71b895:	8d 45 f4             	lea    eax,[ebp-0xc]
  71b898:	64 a3 00 00 00 00    	mov    fs:0x0,eax
  71b89e:	8b f9                	mov    edi,ecx
  71b8a0:	33 f6                	xor    esi,esi
  71b8a2:	8b 07                	mov    eax,DWORD PTR [edi]
  71b8a4:	05 20 06 00 00       	add    eax,0x620
  71b8a9:	03 c6                	add    eax,esi
  71b8ab:	50                   	push   eax
  71b8ac:	e8 59 a8 14 00       	call   0x86610a
  71b8b1:	83 c6 04             	add    esi,0x4
  71b8b4:	59                   	pop    ecx
  71b8b5:	83 fe 40             	cmp    esi,0x40
  71b8b8:	72 e8                	jb     0x71b8a2
  71b8ba:	8b 4d f4             	mov    ecx,DWORD PTR [ebp-0xc]
  71b8bd:	64 89 0d 00 00 00 00 	mov    DWORD PTR fs:0x0,ecx
  71b8c4:	59                   	pop    ecx
  71b8c5:	5f                   	pop    edi
  71b8c6:	5e                   	pop    esi
  71b8c7:	c9                   	leave
  71b8c8:	c3                   	ret
