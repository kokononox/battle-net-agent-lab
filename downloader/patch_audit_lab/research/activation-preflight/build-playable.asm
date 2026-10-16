
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0047d570 <.text+0x7c570>:
  47d570:	8b ec                	mov    ebp,esp
  47d572:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  47d575:	83 20 00             	and    DWORD PTR [eax],0x0
  47d578:	5d                   	pop    ebp
  47d579:	c2 08 00             	ret    0x8
  47d57c:	6a 08                	push   0x8
  47d57e:	68 40 01 00 00       	push   0x140
  47d583:	b8 95 b0 8d 00       	mov    eax,0x8db095
  47d588:	e8 97 95 3f 00       	call   0x876b24
  47d58d:	8b f9                	mov    edi,ecx
  47d58f:	89 bd 1c ff ff ff    	mov    DWORD PTR [ebp-0xe4],edi
  47d595:	8b 73 08             	mov    esi,DWORD PTR [ebx+0x8]
  47d598:	8d 87 cc 00 00 00    	lea    eax,[edi+0xcc]
  47d59e:	50                   	push   eax
  47d59f:	89 85 18 ff ff ff    	mov    DWORD PTR [ebp-0xe8],eax
  47d5a5:	e8 13 68 3f 00       	call   0x873dbd
  47d5aa:	50                   	push   eax
  47d5ab:	e8 f2 6f f8 ff       	call   0x4045a2
  47d5b0:	59                   	pop    ecx
  47d5b1:	59                   	pop    ecx
  47d5b2:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  47d5b6:	8b cf                	mov    ecx,edi
  47d5b8:	56                   	push   esi
  47d5b9:	e8 11 66 f9 ff       	call   0x413bcf
  47d5be:	8b 37                	mov    esi,DWORD PTR [edi]
  47d5c0:	8b 47 04             	mov    eax,DWORD PTR [edi+0x4]
  47d5c3:	89 b5 28 ff ff ff    	mov    DWORD PTR [ebp-0xd8],esi
  47d5c9:	89 85 20 ff ff ff    	mov    DWORD PTR [ebp-0xe0],eax
  47d5cf:	3b f0                	cmp    esi,eax
  47d5d1:	0f 84 47 02 00 00    	je     0x47d81e
  47d5d7:	8b 0e                	mov    ecx,DWORD PTR [esi]
  47d5d9:	81 c1 08 01 00 00    	add    ecx,0x108
  47d5df:	e8 03 12 ff ff       	call   0x46e7e7
  47d5e4:	84 c0                	test   al,al
  47d5e6:	0f 84 17 02 00 00    	je     0x47d803
  47d5ec:	8b 06                	mov    eax,DWORD PTR [esi]
  47d5ee:	83 c0 60             	add    eax,0x60
  47d5f1:	50                   	push   eax
  47d5f2:	8d 85 b0 fe ff ff    	lea    eax,[ebp-0x150]
  47d5f8:	50                   	push   eax
  47d5f9:	e8 27 f4 fe ff       	call   0x46ca25
  47d5fe:	59                   	pop    ecx
  47d5ff:	59                   	pop    ecx
  47d600:	8b 06                	mov    eax,DWORD PTR [esi]
  47d602:	8d 8d b0 fe ff ff    	lea    ecx,[ebp-0x150]
  47d608:	83 c0 18             	add    eax,0x18
  47d60b:	c6 45 fc 01          	mov    BYTE PTR [ebp-0x4],0x1
  47d60f:	50                   	push   eax
  47d610:	e8 f8 f5 fe ff       	call   0x46cc0d
  47d615:	8b f8                	mov    edi,eax
  47d617:	89 bd 24 ff ff ff    	mov    DWORD PTR [ebp-0xdc],edi
  47d61d:	85 ff                	test   edi,edi
  47d61f:	0f 84 7a 01 00 00    	je     0x47d79f
  47d625:	8b 0e                	mov    ecx,DWORD PTR [esi]
  47d627:	57                   	push   edi
  47d628:	81 c1 e8 01 00 00    	add    ecx,0x1e8
  47d62e:	e8 44 69 f9 ff       	call   0x413f77
  47d633:	8b 06                	mov    eax,DWORD PTR [esi]
  47d635:	6a 10                	push   0x10
  47d637:	05 70 01 00 00       	add    eax,0x170
  47d63c:	68 60 5b 90 00       	push   0x905b60
  47d641:	50                   	push   eax
  47d642:	89 85 2c ff ff ff    	mov    DWORD PTR [ebp-0xd4],eax
  47d648:	e8 c5 aa 3f 00       	call   0x878112
  47d64d:	83 c4 0c             	add    esp,0xc
  47d650:	8d 4f 34             	lea    ecx,[edi+0x34]
  47d653:	85 c0                	test   eax,eax
  47d655:	75 51                	jne    0x47d6a8
  47d657:	8b f1                	mov    esi,ecx
  47d659:	8b 85 28 ff ff ff    	mov    eax,DWORD PTR [ebp-0xd8]
  47d65f:	8d bd 08 ff ff ff    	lea    edi,[ebp-0xf8]
  47d665:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d666:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d667:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d668:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d669:	8b bd 2c ff ff ff    	mov    edi,DWORD PTR [ebp-0xd4]
  47d66f:	8d b5 08 ff ff ff    	lea    esi,[ebp-0xf8]
  47d675:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d676:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d677:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d678:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d679:	8b b5 24 ff ff ff    	mov    esi,DWORD PTR [ebp-0xdc]
  47d67f:	8d bd f8 fe ff ff    	lea    edi,[ebp-0x108]
  47d685:	8d 76 64             	lea    esi,[esi+0x64]
  47d688:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d689:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d68a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d68b:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d68c:	8b 38                	mov    edi,DWORD PTR [eax]
  47d68e:	8d b5 f8 fe ff ff    	lea    esi,[ebp-0x108]
  47d694:	81 c7 80 01 00 00    	add    edi,0x180
  47d69a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d69b:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d69c:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d69d:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d69e:	8b bd 24 ff ff ff    	mov    edi,DWORD PTR [ebp-0xdc]
  47d6a4:	8b f0                	mov    esi,eax
  47d6a6:	eb 60                	jmp    0x47d708
  47d6a8:	6a 10                	push   0x10
  47d6aa:	51                   	push   ecx
  47d6ab:	ff b5 2c ff ff ff    	push   DWORD PTR [ebp-0xd4]
  47d6b1:	e8 5c aa 3f 00       	call   0x878112
  47d6b6:	83 c4 0c             	add    esp,0xc
  47d6b9:	85 c0                	test   eax,eax
  47d6bb:	74 4b                	je     0x47d708
  47d6bd:	e8 04 a2 f8 ff       	call   0x4078c6
  47d6c2:	6a 02                	push   0x2
  47d6c4:	50                   	push   eax
  47d6c5:	8d 8d 30 ff ff ff    	lea    ecx,[ebp-0xd0]
  47d6cb:	e8 12 9a f8 ff       	call   0x4070e2
  47d6d0:	8d 85 30 ff ff ff    	lea    eax,[ebp-0xd0]
  47d6d6:	c6 45 fc 02          	mov    BYTE PTR [ebp-0x4],0x2
  47d6da:	68 e8 60 90 00       	push   0x9060e8
  47d6df:	50                   	push   eax
  47d6e0:	e8 91 4d f8 ff       	call   0x402476
  47d6e5:	ff 36                	push   DWORD PTR [esi]
  47d6e7:	50                   	push   eax
  47d6e8:	e8 92 8a f8 ff       	call   0x40617f
  47d6ed:	83 c4 10             	add    esp,0x10
  47d6f0:	c6 45 fc 01          	mov    BYTE PTR [ebp-0x4],0x1
  47d6f4:	8d 8d 30 ff ff ff    	lea    ecx,[ebp-0xd0]
  47d6fa:	e8 4f 9c f8 ff       	call   0x40734e
  47d6ff:	8b 06                	mov    eax,DWORD PTR [esi]
  47d701:	c6 80 09 01 00 00 00 	mov    BYTE PTR [eax+0x109],0x0
  47d708:	8b 06                	mov    eax,DWORD PTR [esi]
  47d70a:	6a 10                	push   0x10
  47d70c:	05 a0 01 00 00       	add    eax,0x1a0
  47d711:	68 60 5b 90 00       	push   0x905b60
  47d716:	50                   	push   eax
  47d717:	89 85 2c ff ff ff    	mov    DWORD PTR [ebp-0xd4],eax
  47d71d:	e8 f0 a9 3f 00       	call   0x878112
  47d722:	83 c4 0c             	add    esp,0xc
  47d725:	83 c7 54             	add    edi,0x54
  47d728:	85 c0                	test   eax,eax
  47d72a:	75 40                	jne    0x47d76c
  47d72c:	8b f7                	mov    esi,edi
  47d72e:	8b 85 24 ff ff ff    	mov    eax,DWORD PTR [ebp-0xdc]
  47d734:	8d bd e8 fe ff ff    	lea    edi,[ebp-0x118]
  47d73a:	05 bc 00 00 00       	add    eax,0xbc
  47d73f:	50                   	push   eax
  47d740:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d741:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d742:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d743:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d744:	8b bd 2c ff ff ff    	mov    edi,DWORD PTR [ebp-0xd4]
  47d74a:	8d b5 e8 fe ff ff    	lea    esi,[ebp-0x118]
  47d750:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d751:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d752:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d753:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  47d754:	8b b5 28 ff ff ff    	mov    esi,DWORD PTR [ebp-0xd8]
  47d75a:	8b 0e                	mov    ecx,DWORD PTR [esi]
  47d75c:	81 c1 d0 01 00 00    	add    ecx,0x1d0
  47d762:	e8 ef 5f f8 ff       	call   0x403756
  47d767:	e9 88 00 00 00       	jmp    0x47d7f4
  47d76c:	6a 10                	push   0x10
  47d76e:	57                   	push   edi
  47d76f:	ff b5 2c ff ff ff    	push   DWORD PTR [ebp-0xd4]
  47d775:	e8 98 a9 3f 00       	call   0x878112
  47d77a:	83 c4 0c             	add    esp,0xc
  47d77d:	85 c0                	test   eax,eax
  47d77f:	74 73                	je     0x47d7f4
  47d781:	e8 40 a1 f8 ff       	call   0x4078c6
  47d786:	6a 02                	push   0x2
  47d788:	50                   	push   eax
  47d789:	8d 8d 30 ff ff ff    	lea    ecx,[ebp-0xd0]
  47d78f:	e8 4e 99 f8 ff       	call   0x4070e2
  47d794:	c6 45 fc 03          	mov    BYTE PTR [ebp-0x4],0x3
  47d798:	68 30 61 90 00       	push   0x906130
  47d79d:	eb 2a                	jmp    0x47d7c9
  47d79f:	8b 85 d0 fe ff ff    	mov    eax,DWORD PTR [ebp-0x130]
  47d7a5:	3b 85 d4 fe ff ff    	cmp    eax,DWORD PTR [ebp-0x12c]
  47d7ab:	74 47                	je     0x47d7f4
  47d7ad:	e8 14 a1 f8 ff       	call   0x4078c6
  47d7b2:	6a 02                	push   0x2
  47d7b4:	50                   	push   eax
  47d7b5:	8d 8d 30 ff ff ff    	lea    ecx,[ebp-0xd0]
  47d7bb:	e8 22 99 f8 ff       	call   0x4070e2
  47d7c0:	c6 45 fc 04          	mov    BYTE PTR [ebp-0x4],0x4
  47d7c4:	68 88 61 90 00       	push   0x906188
  47d7c9:	8d 85 30 ff ff ff    	lea    eax,[ebp-0xd0]
  47d7cf:	50                   	push   eax
  47d7d0:	e8 a1 4c f8 ff       	call   0x402476
  47d7d5:	ff 36                	push   DWORD PTR [esi]
  47d7d7:	50                   	push   eax
  47d7d8:	e8 a2 89 f8 ff       	call   0x40617f
  47d7dd:	83 c4 10             	add    esp,0x10
  47d7e0:	8d 8d 30 ff ff ff    	lea    ecx,[ebp-0xd0]
  47d7e6:	e8 63 9b f8 ff       	call   0x40734e
  47d7eb:	8b 06                	mov    eax,DWORD PTR [esi]
  47d7ed:	c6 80 09 01 00 00 00 	mov    BYTE PTR [eax+0x109],0x0
  47d7f4:	8d 8d b0 fe ff ff    	lea    ecx,[ebp-0x150]
  47d7fa:	c6 45 fc 00          	mov    BYTE PTR [ebp-0x4],0x0
  47d7fe:	e8 1f 57 f9 ff       	call   0x412f22
  47d803:	83 c6 08             	add    esi,0x8
  47d806:	89 b5 28 ff ff ff    	mov    DWORD PTR [ebp-0xd8],esi
  47d80c:	3b b5 20 ff ff ff    	cmp    esi,DWORD PTR [ebp-0xe0]
  47d812:	0f 85 bf fd ff ff    	jne    0x47d5d7
  47d818:	8b bd 1c ff ff ff    	mov    edi,DWORD PTR [ebp-0xe4]
  47d81e:	8d 87 cc 00 00 00    	lea    eax,[edi+0xcc]
  47d824:	50                   	push   eax
  47d825:	e8 b8 65 3f 00       	call   0x873de2
  47d82a:	59                   	pop    ecx
  47d82b:	8b 4d ec             	mov    ecx,DWORD PTR [ebp-0x14]
  47d82e:	e8 cf 92 3f 00       	call   0x876b02
  47d833:	c2 04 00             	ret    0x4
  47d836:	68 2c 01 00 00       	push   0x12c
  47d83b:	b8 1a b1 8d 00       	mov    eax,0x8db11a
  47d840:	e8 26 88 3f 00       	call   0x87606b
  47d845:	8b f1                	mov    esi,ecx
  47d847:	89 b5 e8 fe ff ff    	mov    DWORD PTR [ebp-0x118],esi
  47d84d:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
