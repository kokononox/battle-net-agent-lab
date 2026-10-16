
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071c6cd <.text+0x31b6cd>:
  71c6cd:	33 c0                	xor    eax,eax
  71c6cf:	89 bd c8 fe ff ff    	mov    DWORD PTR [ebp-0x138],edi
  71c6d5:	40                   	inc    eax
  71c6d6:	88 85 cc fe ff ff    	mov    BYTE PTR [ebp-0x134],al
  71c6dc:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  71c6e0:	83 7f 2c 05          	cmp    DWORD PTR [edi+0x2c],0x5
  71c6e4:	8b 4f 38             	mov    ecx,DWORD PTR [edi+0x38]
  71c6e7:	74 0c                	je     0x71c6f5
  71c6e9:	83 7f 2c 04          	cmp    DWORD PTR [edi+0x2c],0x4
  71c6ed:	88 85 e8 fe ff ff    	mov    BYTE PTR [ebp-0x118],al
  71c6f3:	75 07                	jne    0x71c6fc
  71c6f5:	c6 85 e8 fe ff ff 00 	mov    BYTE PTR [ebp-0x118],0x0
  71c6fc:	8d 41 08             	lea    eax,[ecx+0x8]
  71c6ff:	50                   	push   eax
  71c700:	ff b5 e8 fe ff ff    	push   DWORD PTR [ebp-0x118]
  71c706:	8d 77 70             	lea    esi,[edi+0x70]
  71c709:	8b ce                	mov    ecx,esi
  71c70b:	89 b5 d4 fe ff ff    	mov    DWORD PTR [ebp-0x12c],esi
  71c711:	e8 62 5c 00 00       	call   0x722378
  71c716:	8b ce                	mov    ecx,esi
  71c718:	e8 45 5c 00 00       	call   0x722362
  71c71d:	84 c0                	test   al,al
  71c71f:	75 08                	jne    0x71c729
  71c721:	6a 0b                	push   0xb
  71c723:	5e                   	pop    esi
  71c724:	e9 43 01 00 00       	jmp    0x71c86c
  71c729:	89 bd c4 fe ff ff    	mov    DWORD PTR [ebp-0x13c],edi
  71c72f:	f6 47 0c 01          	test   BYTE PTR [edi+0xc],0x1
  71c733:	8d 8f 94 00 00 00    	lea    ecx,[edi+0x94]
  71c739:	c6 45 fc 02          	mov    BYTE PTR [ebp-0x4],0x2
  71c73d:	75 02                	jne    0x71c741
  71c73f:	8b 1b                	mov    ebx,DWORD PTR [ebx]
  71c741:	8d 47 38             	lea    eax,[edi+0x38]
  71c744:	50                   	push   eax
  71c745:	ff b5 e4 fe ff ff    	push   DWORD PTR [ebp-0x11c]
  71c74b:	53                   	push   ebx
  71c74c:	e8 83 22 00 00       	call   0x71e9d4
