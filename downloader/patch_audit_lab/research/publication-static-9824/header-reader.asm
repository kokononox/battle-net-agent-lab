
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071c555 <.text+0x31b555>:
  71c555:	55                   	push   ebp
  71c556:	8b ec                	mov    ebp,esp
  71c558:	56                   	push   esi
  71c559:	8b f1                	mov    esi,ecx
  71c55b:	83 7e 2c 02          	cmp    DWORD PTR [esi+0x2c],0x2
  71c55f:	74 35                	je     0x71c596
  71c561:	83 7e 2c 04          	cmp    DWORD PTR [esi+0x2c],0x4
  71c565:	74 2f                	je     0x71c596
  71c567:	83 7e 2c 05          	cmp    DWORD PTR [esi+0x2c],0x5
  71c56b:	74 29                	je     0x71c596
  71c56d:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  71c570:	8b 46 38             	mov    eax,DWORD PTR [esi+0x38]
  71c573:	8b 8c 90 10 01 00 00 	mov    ecx,DWORD PTR [eax+edx*4+0x110]
  71c57a:	6b c2 50             	imul   eax,edx,0x50
  71c57d:	05 20 01 00 00       	add    eax,0x120
  71c582:	03 c6                	add    eax,esi
  71c584:	50                   	push   eax
  71c585:	51                   	push   ecx
  71c586:	52                   	push   edx
  71c587:	8d 8e 94 00 00 00    	lea    ecx,[esi+0x94]
  71c58d:	e8 e3 26 00 00       	call   0x71ec75
  71c592:	85 c0                	test   eax,eax
  71c594:	75 02                	jne    0x71c598
  71c596:	33 c0                	xor    eax,eax
  71c598:	5e                   	pop    esi
  71c599:	5d                   	pop    ebp
  71c59a:	c2 04 00             	ret    0x4
