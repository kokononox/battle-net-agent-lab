
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

007214f2 <.text+0x3204f2>:
  7214f2:	56                   	push   esi
  7214f3:	8b f1                	mov    esi,ecx
  7214f5:	83 7e 08 02          	cmp    DWORD PTR [esi+0x8],0x2
  7214f9:	75 0c                	jne    0x721507
  7214fb:	8b 0e                	mov    ecx,DWORD PTR [esi]
  7214fd:	ff 76 38             	push   DWORD PTR [esi+0x38]
  721500:	8b 01                	mov    eax,DWORD PTR [ecx]
  721502:	ff 50 18             	call   DWORD PTR [eax+0x18]
  721505:	eb 0a                	jmp    0x721511
  721507:	8d 46 10             	lea    eax,[esi+0x10]
  72150a:	50                   	push   eax
  72150b:	e8 d0 b2 14 00       	call   0x86c7e0
  721510:	59                   	pop    ecx
  721511:	33 c0                	xor    eax,eax
  721513:	89 46 30             	mov    DWORD PTR [esi+0x30],eax
  721516:	89 46 34             	mov    DWORD PTR [esi+0x34],eax
  721519:	89 46 38             	mov    DWORD PTR [esi+0x38],eax
  72151c:	89 46 3c             	mov    DWORD PTR [esi+0x3c],eax
  72151f:	89 46 40             	mov    DWORD PTR [esi+0x40],eax
  721522:	89 46 44             	mov    DWORD PTR [esi+0x44],eax
  721525:	89 46 48             	mov    DWORD PTR [esi+0x48],eax
  721528:	89 46 4c             	mov    DWORD PTR [esi+0x4c],eax
  72152b:	5e                   	pop    esi
  72152c:	c3                   	ret
