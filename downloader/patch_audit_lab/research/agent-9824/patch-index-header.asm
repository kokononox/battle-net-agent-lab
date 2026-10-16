
agent-research/Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0068c3a0 <.text+0x28b3a0>:
  68c3a0:	00 ff                	add    bh,bh
  68c3a2:	75 0c                	jne    0x68c3b0
  68c3a4:	50                   	push   eax
  68c3a5:	8d 81 58 01 00 00    	lea    eax,[ecx+0x158]
  68c3ab:	50                   	push   eax
  68c3ac:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  68c3af:	e8 40 f0 ff ff       	call   0x68b3f4
  68c3b4:	5d                   	pop    ebp
  68c3b5:	c2 0c 00             	ret    0xc
  68c3b8:	55                   	push   ebp
  68c3b9:	8b ec                	mov    ebp,esp
  68c3bb:	56                   	push   esi
  68c3bc:	57                   	push   edi
  68c3bd:	8b f1                	mov    esi,ecx
  68c3bf:	e8 25 fe ff ff       	call   0x68c1e9
  68c3c4:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  68c3c7:	8b ce                	mov    ecx,esi
  68c3c9:	ff 77 08             	push   DWORD PTR [edi+0x8]
  68c3cc:	ff 77 04             	push   DWORD PTR [edi+0x4]
  68c3cf:	e8 d3 bb 02 00       	call   0x6b7fa7
  68c3d4:	8b 07                	mov    eax,DWORD PTR [edi]
  68c3d6:	89 46 0c             	mov    DWORD PTR [esi+0xc],eax
  68c3d9:	85 c0                	test   eax,eax
  68c3db:	74 05                	je     0x68c3e2
  68c3dd:	8a 47 0c             	mov    al,BYTE PTR [edi+0xc]
  68c3e0:	eb 02                	jmp    0x68c3e4
  68c3e2:	32 c0                	xor    al,al
  68c3e4:	88 46 10             	mov    BYTE PTR [esi+0x10],al
  68c3e7:	83 7f 08 0e          	cmp    DWORD PTR [edi+0x8],0xe
  68c3eb:	73 27                	jae    0x68c414
  68c3ed:	6a 0e                	push   0xe
  68c3ef:	ff 77 08             	push   DWORD PTR [edi+0x8]
  68c3f2:	68 80 a7 9a 00       	push   0x9aa780
  68c3f7:	6a 00                	push   0x0
  68c3f9:	68 08 bc 8f 00       	push   0x8fbc08
  68c3fe:	6a 04                	push   0x4
  68c400:	68 a4 82 9a 00       	push   0x9a82a4
  68c405:	e8 39 74 23 00       	call   0x8c3843
  68c40a:	83 c4 1c             	add    esp,0x1c
  68c40d:	b0 08                	mov    al,0x8
  68c40f:	e9 1b 01 00 00       	jmp    0x68c52f
  68c414:	ff 77 08             	push   DWORD PTR [edi+0x8]
  68c417:	8b ce                	mov    ecx,esi
  68c419:	e8 0e 0c 00 00       	call   0x68d02c
  68c41e:	84 c0                	test   al,al
  68c420:	0f 85 09 01 00 00    	jne    0x68c52f
  68c426:	53                   	push   ebx
  68c427:	8d 46 70             	lea    eax,[esi+0x70]
  68c42a:	8b ce                	mov    ecx,esi
  68c42c:	50                   	push   eax
  68c42d:	e8 d8 0f 00 00       	call   0x68d40a
  68c432:	8b 7e 74             	mov    edi,DWORD PTR [esi+0x74]
  68c435:	8b 46 78             	mov    eax,DWORD PTR [esi+0x78]
  68c438:	8b 5e 14             	mov    ebx,DWORD PTR [esi+0x14]
  68c43b:	8d 04 c7             	lea    eax,[edi+eax*8]
  68c43e:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  68c441:	eb 16                	jmp    0x68c459
  68c443:	83 3f 01             	cmp    DWORD PTR [edi],0x1
  68c446:	75 0b                	jne    0x68c453
  68c448:	53                   	push   ebx
  68c449:	8b ce                	mov    ecx,esi
  68c44b:	e8 97 0b 00 00       	call   0x68cfe7
  68c450:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  68c453:	03 5f 04             	add    ebx,DWORD PTR [edi+0x4]
  68c456:	83 c7 08             	add    edi,0x8
  68c459:	3b f8                	cmp    edi,eax
  68c45b:	75 e6                	jne    0x68c443
  68c45d:	8b 7e 74             	mov    edi,DWORD PTR [esi+0x74]
  68c460:	8b 46 78             	mov    eax,DWORD PTR [esi+0x78]
  68c463:	8d 1c c7             	lea    ebx,[edi+eax*8]
  68c466:	3b fb                	cmp    edi,ebx
  68c468:	0f 84 be 00 00 00    	je     0x68c52c
  68c46e:	8d 86 80 00 00 00    	lea    eax,[esi+0x80]
  68c474:	57                   	push   edi
  68c475:	8b c8                	mov    ecx,eax
  68c477:	e8 ac e9 ff ff       	call   0x68ae28
  68c47c:	8b 17                	mov    edx,DWORD PTR [edi]
  68c47e:	8b 4e 14             	mov    ecx,DWORD PTR [esi+0x14]
  68c481:	03 08                	add    ecx,DWORD PTR [eax]
  68c483:	8d 42 ff             	lea    eax,[edx-0x1]
  68c486:	83 f8 09             	cmp    eax,0x9
  68c489:	77 57                	ja     0x68c4e2
  68c48b:	ff 24 85 38 c5 68 00 	jmp    DWORD PTR [eax*4+0x68c538]
  68c492:	51                   	push   ecx
  68c493:	8b ce                	mov    ecx,esi
  68c495:	e8 c6 00 00 00       	call   0x68c560
  68c49a:	eb 7f                	jmp    0x68c51b
  68c49c:	51                   	push   ecx
  68c49d:	8b ce                	mov    ecx,esi
  68c49f:	e8 f9 01 00 00       	call   0x68c69d
  68c4a4:	eb 75                	jmp    0x68c51b
  68c4a6:	51                   	push   ecx
  68c4a7:	8b ce                	mov    ecx,esi
  68c4a9:	e8 34 04 00 00       	call   0x68c8e2
  68c4ae:	eb 6b                	jmp    0x68c51b
  68c4b0:	51                   	push   ecx
  68c4b1:	8b ce                	mov    ecx,esi
  68c4b3:	e8 c3 06 00 00       	call   0x68cb7b
  68c4b8:	eb 61                	jmp    0x68c51b
  68c4ba:	51                   	push   ecx
  68c4bb:	8b ce                	mov    ecx,esi
  68c4bd:	e8 f3 07 00 00       	call   0x68ccb5
  68c4c2:	eb 57                	jmp    0x68c51b
  68c4c4:	51                   	push   ecx
  68c4c5:	8b ce                	mov    ecx,esi
  68c4c7:	e8 52 09 00 00       	call   0x68ce1e
  68c4cc:	eb 4d                	jmp    0x68c51b
  68c4ce:	51                   	push   ecx
  68c4cf:	8b ce                	mov    ecx,esi
  68c4d1:	e8 a8 0c 00 00       	call   0x68d17e
  68c4d6:	eb 43                	jmp    0x68c51b
  68c4d8:	51                   	push   ecx
  68c4d9:	8b ce                	mov    ecx,esi
  68c4db:	e8 97 0d 00 00       	call   0x68d277
  68c4e0:	eb 39                	jmp    0x68c51b
  68c4e2:	52                   	push   edx
  68c4e3:	68 d8 a7 9a 00       	push   0x9aa7d8
  68c4e8:	6a 00                	push   0x0
  68c4ea:	68 08 bc 8f 00       	push   0x8fbc08
  68c4ef:	6a 03                	push   0x3
  68c4f1:	68 a4 82 9a 00       	push   0x9a82a4
  68c4f6:	e8 48 73 23 00       	call   0x8c3843
  68c4fb:	8b 46 0c             	mov    eax,DWORD PTR [esi+0xc]
  68c4fe:	83 c4 18             	add    esp,0x18
  68c501:	85 c0                	test   eax,eax
  68c503:	74 16                	je     0x68c51b
  68c505:	ff 37                	push   DWORD PTR [edi]
  68c507:	05 9c 03 00 00       	add    eax,0x39c
  68c50c:	ff 35 b4 8f 9a 00    	push   DWORD PTR ds:0x9a8fb4
  68c512:	50                   	push   eax
  68c513:	e8 25 64 ff ff       	call   0x68293d
  68c518:	83 c4 0c             	add    esp,0xc
  68c51b:	83 c7 08             	add    edi,0x8
  68c51e:	8d 86 80 00 00 00    	lea    eax,[esi+0x80]
  68c524:	3b fb                	cmp    edi,ebx
  68c526:	0f 85 48 ff ff ff    	jne    0x68c474
  68c52c:	32 c0                	xor    al,al
  68c52e:	5b                   	pop    ebx
  68c52f:	5f                   	pop    edi
  68c530:	5e                   	pop    esi
  68c531:	5d                   	pop    ebp
  68c532:	c2 04 00             	ret    0x4
  68c535:	0f 1f 00             	nop    DWORD PTR [eax]
  68c538:	1b c5                	sbb    eax,ebp
  68c53a:	68 00 b0 c4 68       	push   0x68c4b000
  68c53f:	00 ce                	add    dh,cl
  68c541:	c4 68 00             	les    ebp,FWORD PTR [eax+0x0]
  68c544:	e2 c4                	loop   0x68c50a
  68c546:	68 00 92 c4 68       	push   0x68c49200
  68c54b:	00 9c c4 68 00 ba c4 	add    BYTE PTR [esp+eax*8-0x3b45ff98],bl
  68c552:	68 00 c4 c4 68       	push   0x68c4c400
  68c557:	00 d8                	add    al,bl
  68c559:	c4 68 00             	les    ebp,FWORD PTR [eax+0x0]
  68c55c:	a6                   	cmps   BYTE PTR ds:[esi],BYTE PTR es:[edi]
  68c55d:	c4 68 00             	les    ebp,FWORD PTR [eax+0x0]
  68c560:	55                   	push   ebp
  68c561:	8b ec                	mov    ebp,esp
  68c563:	83 ec 6c             	sub    esp,0x6c
  68c566:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  68c56b:	33 c5                	xor    eax,ebp
  68c56d:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  68c570:	53                   	push   ebx
  68c571:	56                   	push   esi
  68c572:	57                   	push   edi
  68c573:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  68c576:	8b d9                	mov    ebx,ecx
  68c578:	e8 1b ba 02 00       	call   0x6b7f98
  68c57d:	8b cb                	mov    ecx,ebx
  68c57f:	e8 fe b9 02 00       	call   0x6b7f82
  68c584:	8b cb                	mov    ecx,ebx
  68c586:	e8 f7 b9 02 00       	call   0x6b7f82
  68c58b:	8b f0                	mov    esi,eax
  68c58d:	8b cb                	mov    ecx,ebx
  68c58f:	89 75 98             	mov    DWORD PTR [ebp-0x68],esi
  68c592:	e8 f7 b9 02 00       	call   0x6b7f8e
  68c597:	8b cb                	mov    ecx,ebx
  68c599:	88 45 9f             	mov    BYTE PTR [ebp-0x61],al
  68c59c:	e8 e1 b9 02 00       	call   0x6b7f82
  68c5a1:	0f b6 0d 7a a7 9a 00 	movzx  ecx,BYTE PTR ds:0x9aa77a
  68c5a8:	8d bb a0 00 00 00    	lea    edi,[ebx+0xa0]
  68c5ae:	51                   	push   ecx
  68c5af:	50                   	push   eax
