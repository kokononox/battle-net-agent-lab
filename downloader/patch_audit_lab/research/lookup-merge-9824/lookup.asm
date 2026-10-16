
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072c6fd <.text+0x32b6fd>:
  72c6fd:	68 54 01 00 00       	push   0x154
  72c702:	b8 d1 33 8f 00       	mov    eax,0x8f33d1
  72c707:	e8 5f 99 14 00       	call   0x87606b
  72c70c:	8b f1                	mov    esi,ecx
  72c70e:	ff 76 04             	push   DWORD PTR [esi+0x4]
  72c711:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  72c714:	8d 8d c0 fe ff ff    	lea    ecx,[ebp-0x140]
  72c71a:	ff 36                	push   DWORD PTR [esi]
  72c71c:	89 85 bc fe ff ff    	mov    DWORD PTR [ebp-0x144],eax
  72c722:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  72c725:	89 85 b8 fe ff ff    	mov    DWORD PTR [ebp-0x148],eax
  72c72b:	e8 c7 1d 00 00       	call   0x72e4f7
  72c730:	33 db                	xor    ebx,ebx
  72c732:	8d 85 c0 fe ff ff    	lea    eax,[ebp-0x140]
  72c738:	53                   	push   ebx
  72c739:	53                   	push   ebx
  72c73a:	50                   	push   eax
  72c73b:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72c73e:	8b ce                	mov    ecx,esi
  72c740:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  72c743:	e8 26 fe ff ff       	call   0x72c56e
  72c748:	38 9d c8 fe ff ff    	cmp    BYTE PTR [ebp-0x138],bl
  72c74e:	75 07                	jne    0x72c757
  72c750:	6a 02                	push   0x2
  72c752:	e9 87 00 00 00       	jmp    0x72c7de
  72c757:	8d b5 d0 fe ff ff    	lea    esi,[ebp-0x130]
  72c75d:	0f 57 c0             	xorps  xmm0,xmm0
  72c760:	8d bd a0 fe ff ff    	lea    edi,[ebp-0x160]
  72c766:	66 0f 13 85 b0 fe ff 	movlpd QWORD PTR [ebp-0x150],xmm0
  72c76d:	ff 
  72c76e:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72c76f:	8d 85 b0 fe ff ff    	lea    eax,[ebp-0x150]
  72c775:	50                   	push   eax
  72c776:	8d 85 a0 fe ff ff    	lea    eax,[ebp-0x160]
  72c77c:	50                   	push   eax
  72c77d:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72c77e:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72c77f:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72c780:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  72c783:	56                   	push   esi
  72c784:	e8 06 0a 00 00       	call   0x72d18f
  72c789:	83 c4 0c             	add    esp,0xc
  72c78c:	84 c0                	test   al,al
  72c78e:	75 04                	jne    0x72c794
  72c790:	6a 04                	push   0x4
  72c792:	eb 4a                	jmp    0x72c7de
  72c794:	8b 46 04             	mov    eax,DWORD PTR [esi+0x4]
  72c797:	8b 95 bc fe ff ff    	mov    edx,DWORD PTR [ebp-0x144]
  72c79d:	8b 8d d0 fe ff ff    	mov    ecx,DWORD PTR [ebp-0x130]
  72c7a3:	03 0e                	add    ecx,DWORD PTR [esi]
  72c7a5:	13 85 d4 fe ff ff    	adc    eax,DWORD PTR [ebp-0x12c]
  72c7ab:	89 42 04             	mov    DWORD PTR [edx+0x4],eax
  72c7ae:	8b 85 b4 fe ff ff    	mov    eax,DWORD PTR [ebp-0x14c]
  72c7b4:	89 0a                	mov    DWORD PTR [edx],ecx
  72c7b6:	8b 8d b0 fe ff ff    	mov    ecx,DWORD PTR [ebp-0x150]
  72c7bc:	89 4a 08             	mov    DWORD PTR [edx+0x8],ecx
  72c7bf:	89 42 0c             	mov    DWORD PTR [edx+0xc],eax
  72c7c2:	3b c3                	cmp    eax,ebx
  72c7c4:	77 04                	ja     0x72c7ca
  72c7c6:	3b cb                	cmp    ecx,ebx
  72c7c8:	76 17                	jbe    0x72c7e1
  72c7ca:	6a 01                	push   0x1
  72c7cc:	52                   	push   edx
  72c7cd:	8d 8d c0 fe ff ff    	lea    ecx,[ebp-0x140]
  72c7d3:	e8 44 2c 00 00       	call   0x72f41c
  72c7d8:	84 c0                	test   al,al
  72c7da:	75 05                	jne    0x72c7e1
  72c7dc:	6a 03                	push   0x3
  72c7de:	5b                   	pop    ebx
  72c7df:	eb 16                	jmp    0x72c7f7
  72c7e1:	8b 85 b8 fe ff ff    	mov    eax,DWORD PTR [ebp-0x148]
  72c7e7:	85 c0                	test   eax,eax
  72c7e9:	74 0c                	je     0x72c7f7
  72c7eb:	8b f8                	mov    edi,eax
  72c7ed:	8d b5 a0 fe ff ff    	lea    esi,[ebp-0x160]
  72c7f3:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72c7f4:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72c7f5:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72c7f6:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72c7f7:	8d 8d c0 fe ff ff    	lea    ecx,[ebp-0x140]
  72c7fd:	e8 48 1d 00 00       	call   0x72e54a
  72c802:	8b c3                	mov    eax,ebx
  72c804:	e8 11 98 14 00       	call   0x87601a
  72c809:	c2 10 00             	ret    0x10
