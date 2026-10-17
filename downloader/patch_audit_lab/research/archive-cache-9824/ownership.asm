
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0067b495 <.text+0x27a495>:
  67b495:	55                   	push   ebp
  67b496:	8b ec                	mov    ebp,esp
  67b498:	56                   	push   esi
  67b499:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  67b49c:	8d 46 04             	lea    eax,[esi+0x4]
  67b49f:	50                   	push   eax
  67b4a0:	e8 49 f1 ff ff       	call   0x67a5ee
  67b4a5:	59                   	pop    ecx
  67b4a6:	84 c0                	test   al,al
  67b4a8:	74 09                	je     0x67b4b3
  67b4aa:	8b 06                	mov    eax,DWORD PTR [esi]
  67b4ac:	8b ce                	mov    ecx,esi
  67b4ae:	5e                   	pop    esi
  67b4af:	5d                   	pop    ebp
  67b4b0:	ff 60 04             	jmp    DWORD PTR [eax+0x4]
  67b4b3:	5e                   	pop    esi
  67b4b4:	5d                   	pop    ebp
  67b4b5:	c3                   	ret
