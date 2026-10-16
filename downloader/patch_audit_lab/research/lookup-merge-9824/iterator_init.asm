
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072e4f7 <.text+0x32d4f7>:
  72e4f7:	55                   	push   ebp
  72e4f8:	8b ec                	mov    ebp,esp
  72e4fa:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  72e4fd:	53                   	push   ebx
  72e4fe:	89 01                	mov    DWORD PTR [ecx],eax
  72e500:	33 db                	xor    ebx,ebx
  72e502:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  72e505:	56                   	push   esi
  72e506:	57                   	push   edi
  72e507:	89 41 04             	mov    DWORD PTR [ecx+0x4],eax
  72e50a:	8d 79 10             	lea    edi,[ecx+0x10]
  72e50d:	33 c0                	xor    eax,eax
  72e50f:	88 59 08             	mov    BYTE PTR [ecx+0x8],bl
  72e512:	ab                   	stos   DWORD PTR es:[edi],eax
  72e513:	8d 71 20             	lea    esi,[ecx+0x20]
  72e516:	6a 10                	push   0x10
  72e518:	ab                   	stos   DWORD PTR es:[edi],eax
  72e519:	ab                   	stos   DWORD PTR es:[edi],eax
  72e51a:	ab                   	stos   DWORD PTR es:[edi],eax
  72e51b:	8b c6                	mov    eax,esi
  72e51d:	5f                   	pop    edi
  72e51e:	8b d7                	mov    edx,edi
  72e520:	89 18                	mov    DWORD PTR [eax],ebx
  72e522:	89 58 04             	mov    DWORD PTR [eax+0x4],ebx
  72e525:	89 58 08             	mov    DWORD PTR [eax+0x8],ebx
  72e528:	03 c7                	add    eax,edi
  72e52a:	83 ea 01             	sub    edx,0x1
  72e52d:	75 f1                	jne    0x72e520
  72e52f:	89 b9 28 01 00 00    	mov    DWORD PTR [ecx+0x128],edi
  72e535:	8b c1                	mov    eax,ecx
  72e537:	5f                   	pop    edi
  72e538:	89 b1 20 01 00 00    	mov    DWORD PTR [ecx+0x120],esi
  72e53e:	5e                   	pop    esi
  72e53f:	89 99 24 01 00 00    	mov    DWORD PTR [ecx+0x124],ebx
  72e545:	5b                   	pop    ebx
  72e546:	5d                   	pop    ebp
  72e547:	c2 08 00             	ret    0x8
