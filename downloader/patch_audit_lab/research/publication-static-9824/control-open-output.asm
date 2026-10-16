
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071c59d <.text+0x31b59d>:
  71c59d:	68 38 01 00 00       	push   0x138
  71c5a2:	b8 f1 2b 8f 00       	mov    eax,0x8f2bf1
  71c5a7:	e8 bf 9a 15 00       	call   0x87606b
  71c5ac:	8b f9                	mov    edi,ecx
  71c5ae:	33 c0                	xor    eax,eax
  71c5b0:	8d 5f 10             	lea    ebx,[edi+0x10]
  71c5b3:	40                   	inc    eax
  71c5b4:	8b cb                	mov    ecx,ebx
  71c5b6:	89 85 d8 fe ff ff    	mov    DWORD PTR [ebp-0x128],eax
  71c5bc:	84 47 0c             	test   BYTE PTR [edi+0xc],al
  71c5bf:	75 02                	jne    0x71c5c3
  71c5c1:	8b 0b                	mov    ecx,DWORD PTR [ebx]
  71c5c3:	50                   	push   eax
  71c5c4:	51                   	push   ecx
  71c5c5:	e8 88 81 14 00       	call   0x864752
  71c5ca:	8b f0                	mov    esi,eax
  71c5cc:	59                   	pop    ecx
  71c5cd:	59                   	pop    ecx
  71c5ce:	85 f6                	test   esi,esi
  71c5d0:	74 46                	je     0x71c618
  71c5d2:	8d 85 f0 fe ff ff    	lea    eax,[ebp-0x110]
  71c5d8:	56                   	push   esi
  71c5d9:	50                   	push   eax
  71c5da:	e8 42 04 f6 ff       	call   0x67ca21
  71c5df:	f6 47 0c 01          	test   BYTE PTR [edi+0xc],0x1
  71c5e3:	59                   	pop    ecx
  71c5e4:	59                   	pop    ecx
  71c5e5:	75 02                	jne    0x71c5e9
  71c5e7:	8b 1b                	mov    ebx,DWORD PTR [ebx]
  71c5e9:	8d 85 f0 fe ff ff    	lea    eax,[ebp-0x110]
  71c5ef:	50                   	push   eax
  71c5f0:	56                   	push   esi
  71c5f1:	53                   	push   ebx
  71c5f2:	68 b0 d1 9b 00       	push   0x9bd1b0
  71c5f7:	6a 00                	push   0x0
  71c5f9:	68 08 bc 8f 00       	push   0x8fbc08
  71c5fe:	6a 04                	push   0x4
  71c600:	68 38 ba 9b 00       	push   0x9bba38
  71c605:	e8 39 72 1a 00       	call   0x8c3843
  71c60a:	56                   	push   esi
  71c60b:	e8 11 ac ff ff       	call   0x717221
  71c610:	83 c4 24             	add    esp,0x24
  71c613:	e9 72 02 00 00       	jmp    0x71c88a
  71c618:	ff 77 2c             	push   DWORD PTR [edi+0x2c]
  71c61b:	e8 5f 04 00 00       	call   0x71ca7f
  71c620:	8d 4f 38             	lea    ecx,[edi+0x38]
  71c623:	89 85 e4 fe ff ff    	mov    DWORD PTR [ebp-0x11c],eax
  71c629:	83 c4 04             	add    esp,0x4
  71c62c:	89 8d d0 fe ff ff    	mov    DWORD PTR [ebp-0x130],ecx
  71c632:	33 f6                	xor    esi,esi
  71c634:	f6 47 0c 01          	test   BYTE PTR [edi+0xc],0x1
  71c638:	8b c3                	mov    eax,ebx
  71c63a:	c6 85 ef fe ff ff 00 	mov    BYTE PTR [ebp-0x111],0x0
  71c641:	75 02                	jne    0x71c645
  71c643:	8b 03                	mov    eax,DWORD PTR [ebx]
  71c645:	8d 95 ef fe ff ff    	lea    edx,[ebp-0x111]
  71c64b:	52                   	push   edx
  71c64c:	8b 95 e4 fe ff ff    	mov    edx,DWORD PTR [ebp-0x11c]
  71c652:	51                   	push   ecx
  71c653:	ff 77 04             	push   DWORD PTR [edi+0x4]
  71c656:	52                   	push   edx
  71c657:	50                   	push   eax
  71c658:	ff 37                	push   DWORD PTR [edi]
  71c65a:	e8 43 1a 00 00       	call   0x71e0a2
  71c65f:	83 c4 18             	add    esp,0x18
  71c662:	85 c0                	test   eax,eax
  71c664:	74 3f                	je     0x71c6a5
  71c666:	80 bd ef fe ff ff 00 	cmp    BYTE PTR [ebp-0x111],0x0
  71c66d:	0f 84 17 02 00 00    	je     0x71c88a
  71c673:	6a 00                	push   0x0
  71c675:	68 00 2d 31 01       	push   0x1312d00
  71c67a:	e8 e2 6c 14 00       	call   0x863361
  71c67f:	68 e8 d1 9b 00       	push   0x9bd1e8
  71c684:	6a 00                	push   0x0
  71c686:	68 08 bc 8f 00       	push   0x8fbc08
  71c68b:	6a 03                	push   0x3
  71c68d:	68 38 ba 9b 00       	push   0x9bba38
  71c692:	e8 ac 71 1a 00       	call   0x8c3843
  71c697:	83 c4 1c             	add    esp,0x1c
  71c69a:	8d 4f 38             	lea    ecx,[edi+0x38]
  71c69d:	46                   	inc    esi
  71c69e:	83 fe 03             	cmp    esi,0x3
  71c6a1:	72 91                	jb     0x71c634
  71c6a3:	eb 05                	jmp    0x71c6aa
  71c6a5:	83 fe 03             	cmp    esi,0x3
  71c6a8:	72 23                	jb     0x71c6cd
  71c6aa:	68 08 d2 9b 00       	push   0x9bd208
  71c6af:	6a 00                	push   0x0
  71c6b1:	68 08 bc 8f 00       	push   0x8fbc08
  71c6b6:	6a 04                	push   0x4
  71c6b8:	68 38 ba 9b 00       	push   0x9bba38
  71c6bd:	e8 81 71 1a 00       	call   0x8c3843
  71c6c2:	83 c4 14             	add    esp,0x14
  71c6c5:	6a 0b                	push   0xb
  71c6c7:	58                   	pop    eax
  71c6c8:	e9 bd 01 00 00       	jmp    0x71c88a
