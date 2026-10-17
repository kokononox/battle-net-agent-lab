
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072d655 <.text+0x32c655>:
  72d655:	55                   	push   ebp
  72d656:	8b ec                	mov    ebp,esp
  72d658:	51                   	push   ecx
  72d659:	56                   	push   esi
  72d65a:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72d65d:	8b f1                	mov    esi,ecx
  72d65f:	8d 4d ff             	lea    ecx,[ebp-0x1]
  72d662:	e8 dc 01 00 00       	call   0x72d843
  72d667:	8b 56 10             	mov    edx,DWORD PTR [esi+0x10]
  72d66a:	8b ce                	mov    ecx,esi
  72d66c:	4a                   	dec    edx
  72d66d:	23 c2                	and    eax,edx
  72d66f:	50                   	push   eax
  72d670:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72d673:	e8 3c 00 00 00       	call   0x72d6b4
  72d678:	83 f8 ff             	cmp    eax,0xffffffff
  72d67b:	74 08                	je     0x72d685
  72d67d:	6b c0 18             	imul   eax,eax,0x18
  72d680:	03 46 04             	add    eax,DWORD PTR [esi+0x4]
  72d683:	eb 02                	jmp    0x72d687
  72d685:	33 c0                	xor    eax,eax
  72d687:	5e                   	pop    esi
  72d688:	c9                   	leave
  72d689:	c2 04 00             	ret    0x4
