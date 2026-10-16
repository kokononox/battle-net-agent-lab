
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071f0d3 <.text+0x31e0d3>:
  71f0d3:	55                   	push   ebp
  71f0d4:	8b ec                	mov    ebp,esp
  71f0d6:	56                   	push   esi
  71f0d7:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  71f0da:	6a 10                	push   0x10
  71f0dc:	58                   	pop    eax
  71f0dd:	39 45 10             	cmp    DWORD PTR [ebp+0x10],eax
  71f0e0:	c6 06 30             	mov    BYTE PTR [esi],0x30
  71f0e3:	0f 42 45 10          	cmovb  eax,DWORD PTR [ebp+0x10]
  71f0e7:	6a 01                	push   0x1
  71f0e9:	6a 04                	push   0x4
  71f0eb:	8a 80 cc 89 91 00    	mov    al,BYTE PTR [eax+0x9189cc]
  71f0f1:	88 46 01             	mov    BYTE PTR [esi+0x1],al
  71f0f4:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  71f0f7:	0f c8                	bswap  eax
  71f0f9:	89 45 10             	mov    DWORD PTR [ebp+0x10],eax
  71f0fc:	8d 45 10             	lea    eax,[ebp+0x10]
  71f0ff:	50                   	push   eax
  71f100:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71f103:	83 c0 fe             	add    eax,0xfffffffe
  71f106:	50                   	push   eax
  71f107:	8d 46 02             	lea    eax,[esi+0x2]
  71f10a:	50                   	push   eax
  71f10b:	e8 b9 70 14 00       	call   0x8661c9
  71f110:	a1 00 e6 9b 00       	mov    eax,ds:0x9be600
  71f115:	83 c4 14             	add    esp,0x14
  71f118:	89 46 0a             	mov    DWORD PTR [esi+0xa],eax
  71f11b:	a0 04 e6 9b 00       	mov    al,ds:0x9be604
  71f120:	88 46 0e             	mov    BYTE PTR [esi+0xe],al
  71f123:	5e                   	pop    esi
  71f124:	5d                   	pop    ebp
  71f125:	c3                   	ret
