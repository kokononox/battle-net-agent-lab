
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00712574 <.text+0x311574>:
  712574:	6b c8 1e             	imul   ecx,eax,0x1e
  712577:	33 c0                	xor    eax,eax
  712579:	c7 45 e8 1e 00 00 00 	mov    DWORD PTR [ebp-0x18],0x1e
  712580:	03 4d d0             	add    ecx,DWORD PTR [ebp-0x30]
  712583:	89 4d e0             	mov    DWORD PTR [ebp-0x20],ecx
  712586:	13 c2                	adc    eax,edx
  712588:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
  71258b:	84 ff                	test   bh,bh
  71258d:	74 0c                	je     0x71259b
  71258f:	57                   	push   edi
  712590:	e8 57 3b 15 00       	call   0x8660ec
  712595:	fe c3                	inc    bl
  712597:	59                   	pop    ecx
  712598:	88 5d c8             	mov    BYTE PTR [ebp-0x38],bl
  71259b:	8b 4d d4             	mov    ecx,DWORD PTR [ebp-0x2c]
  71259e:	8d 45 e0             	lea    eax,[ebp-0x20]
  7125a1:	6a 00                	push   0x0
  7125a3:	50                   	push   eax
  7125a4:	6a 01                	push   0x1
  7125a6:	56                   	push   esi
  7125a7:	ff 75 dc             	push   DWORD PTR [ebp-0x24]
  7125aa:	e8 44 fd ff ff       	call   0x7122f3
