
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072c56e <.text+0x32b56e>:
  72c56e:	68 bc 00 00 00       	push   0xbc
  72c573:	b8 09 2f 8f 00       	mov    eax,0x8f2f09
  72c578:	e8 ee 9a 14 00       	call   0x87606b
  72c57d:	8b f1                	mov    esi,ecx
  72c57f:	89 b5 54 ff ff ff    	mov    DWORD PTR [ebp-0xac],esi
  72c585:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  72c588:	8d 8d 50 ff ff ff    	lea    ecx,[ebp-0xb0]
  72c58e:	51                   	push   ecx
  72c58f:	89 85 40 ff ff ff    	mov    DWORD PTR [ebp-0xc0],eax
  72c595:	8d 8d 4c ff ff ff    	lea    ecx,[ebp-0xb4]
  72c59b:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  72c59e:	33 ff                	xor    edi,edi
  72c5a0:	51                   	push   ecx
  72c5a1:	ff 76 44             	push   DWORD PTR [esi+0x44]
  72c5a4:	89 85 3c ff ff ff    	mov    DWORD PTR [ebp-0xc4],eax
  72c5aa:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  72c5ad:	89 85 38 ff ff ff    	mov    DWORD PTR [ebp-0xc8],eax
  72c5b3:	8b 46 40             	mov    eax,DWORD PTR [esi+0x40]
  72c5b6:	50                   	push   eax
  72c5b7:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72c5ba:	89 85 44 ff ff ff    	mov    DWORD PTR [ebp-0xbc],eax
  72c5c0:	89 bd 4c ff ff ff    	mov    DWORD PTR [ebp-0xb4],edi
  72c5c6:	89 bd 50 ff ff ff    	mov    DWORD PTR [ebp-0xb0],edi
  72c5cc:	e8 9b 0e 00 00       	call   0x72d46c
  72c5d1:	8b 06                	mov    eax,DWORD PTR [esi]
  72c5d3:	8d 8d 70 ff ff ff    	lea    ecx,[ebp-0x90]
  72c5d9:	89 85 60 ff ff ff    	mov    DWORD PTR [ebp-0xa0],eax
  72c5df:	83 c4 14             	add    esp,0x14
  72c5e2:	8b c7                	mov    eax,edi
  72c5e4:	89 8d 64 ff ff ff    	mov    DWORD PTR [ebp-0x9c],ecx
  72c5ea:	89 85 68 ff ff ff    	mov    DWORD PTR [ebp-0x98],eax
  72c5f0:	c7 85 6c ff ff ff 20 	mov    DWORD PTR [ebp-0x94],0x80000020
  72c5f7:	00 00 80 
  72c5fa:	8b 95 54 ff ff ff    	mov    edx,DWORD PTR [ebp-0xac]
  72c600:	8b f7                	mov    esi,edi
  72c602:	89 7d fc             	mov    DWORD PTR [ebp-0x4],edi
  72c605:	89 bd 5c ff ff ff    	mov    DWORD PTR [ebp-0xa4],edi
  72c60b:	39 72 4c             	cmp    DWORD PTR [edx+0x4c],esi
  72c60e:	0f 86 8a 00 00 00    	jbe    0x72c69e
  72c614:	8b 42 48             	mov    eax,DWORD PTR [edx+0x48]
  72c617:	83 c0 04             	add    eax,0x4
  72c61a:	89 85 58 ff ff ff    	mov    DWORD PTR [ebp-0xa8],eax
  72c620:	33 ff                	xor    edi,edi
  72c622:	8b f0                	mov    esi,eax
  72c624:	83 7e fc 00          	cmp    DWORD PTR [esi-0x4],0x0
  72c628:	74 62                	je     0x72c68c
  72c62a:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  72c62d:	8a 06                	mov    al,BYTE PTR [esi]
  72c62f:	3a 01                	cmp    al,BYTE PTR [ecx]
  72c631:	75 25                	jne    0x72c658
  72c633:	51                   	push   ecx
  72c634:	56                   	push   esi
  72c635:	e8 65 6e fd ff       	call   0x70349f
  72c63a:	59                   	pop    ecx
  72c63b:	59                   	pop    ecx
  72c63c:	84 c0                	test   al,al
  72c63e:	74 18                	je     0x72c658
  72c640:	8d 85 48 ff ff ff    	lea    eax,[ebp-0xb8]
  72c646:	89 b5 48 ff ff ff    	mov    DWORD PTR [ebp-0xb8],esi
  72c64c:	50                   	push   eax
  72c64d:	8d 8d 60 ff ff ff    	lea    ecx,[ebp-0xa0]
  72c653:	e8 84 85 f6 ff       	call   0x694bdc
  72c658:	47                   	inc    edi
  72c659:	83 c6 28             	add    esi,0x28
  72c65c:	83 ff 19             	cmp    edi,0x19
  72c65f:	72 c3                	jb     0x72c624
  72c661:	8b b5 5c ff ff ff    	mov    esi,DWORD PTR [ebp-0xa4]
  72c667:	8b 8d 54 ff ff ff    	mov    ecx,DWORD PTR [ebp-0xac]
  72c66d:	46                   	inc    esi
  72c66e:	8b 85 58 ff ff ff    	mov    eax,DWORD PTR [ebp-0xa8]
  72c674:	05 00 04 00 00       	add    eax,0x400
  72c679:	89 b5 5c ff ff ff    	mov    DWORD PTR [ebp-0xa4],esi
  72c67f:	89 85 58 ff ff ff    	mov    DWORD PTR [ebp-0xa8],eax
  72c685:	3b 71 4c             	cmp    esi,DWORD PTR [ecx+0x4c]
  72c688:	72 96                	jb     0x72c620
  72c68a:	eb 06                	jmp    0x72c692
  72c68c:	8b b5 5c ff ff ff    	mov    esi,DWORD PTR [ebp-0xa4]
  72c692:	8b 85 68 ff ff ff    	mov    eax,DWORD PTR [ebp-0x98]
  72c698:	8b 8d 64 ff ff ff    	mov    ecx,DWORD PTR [ebp-0x9c]
  72c69e:	8d 04 81             	lea    eax,[ecx+eax*4]
  72c6a1:	6a 00                	push   0x0
  72c6a3:	6a 00                	push   0x0
  72c6a5:	50                   	push   eax
  72c6a6:	8b 85 50 ff ff ff    	mov    eax,DWORD PTR [ebp-0xb0]
  72c6ac:	c1 e0 05             	shl    eax,0x5
  72c6af:	03 85 44 ff ff ff    	add    eax,DWORD PTR [ebp-0xbc]
  72c6b5:	51                   	push   ecx
  72c6b6:	8b 8d 40 ff ff ff    	mov    ecx,DWORD PTR [ebp-0xc0]
  72c6bc:	50                   	push   eax
  72c6bd:	8b 85 4c ff ff ff    	mov    eax,DWORD PTR [ebp-0xb4]
  72c6c3:	c1 e0 05             	shl    eax,0x5
  72c6c6:	03 85 44 ff ff ff    	add    eax,DWORD PTR [ebp-0xbc]
  72c6cc:	50                   	push   eax
  72c6cd:	e8 49 2c 00 00       	call   0x72f31b
  72c6d2:	8b 85 3c ff ff ff    	mov    eax,DWORD PTR [ebp-0xc4]
  72c6d8:	85 c0                	test   eax,eax
  72c6da:	74 02                	je     0x72c6de
  72c6dc:	89 30                	mov    DWORD PTR [eax],esi
  72c6de:	8b 85 38 ff ff ff    	mov    eax,DWORD PTR [ebp-0xc8]
  72c6e4:	85 c0                	test   eax,eax
  72c6e6:	74 02                	je     0x72c6ea
  72c6e8:	89 38                	mov    DWORD PTR [eax],edi
  72c6ea:	8d 8d 60 ff ff ff    	lea    ecx,[ebp-0xa0]
  72c6f0:	e8 68 2b f5 ff       	call   0x67f25d
  72c6f5:	e8 20 99 14 00       	call   0x87601a
  72c6fa:	c2 10 00             	ret    0x10
