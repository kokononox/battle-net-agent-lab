
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072345c <.text+0x32245c>:
  72345c:	55                   	push   ebp
  72345d:	8b ec                	mov    ebp,esp
  72345f:	51                   	push   ecx
  723460:	8b 55 10             	mov    edx,DWORD PTR [ebp+0x10]
  723463:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  723466:	81 c2 ef be ad de    	add    edx,0xdeadbeef
  72346c:	53                   	push   ebx
  72346d:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
  723470:	03 d1                	add    edx,ecx
  723472:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  723475:	56                   	push   esi
  723476:	8b f2                	mov    esi,edx
  723478:	89 75 10             	mov    DWORD PTR [ebp+0x10],esi
  72347b:	57                   	push   edi
  72347c:	8b fa                	mov    edi,edx
  72347e:	6a 0c                	push   0xc
  723480:	58                   	pop    eax
  723481:	f6 c3 03             	test   bl,0x3
  723484:	0f 85 d8 00 00 00    	jne    0x723562
  72348a:	3b c8                	cmp    ecx,eax
  72348c:	76 7d                	jbe    0x72350b
  72348e:	8d 41 f3             	lea    eax,[ecx-0xd]
  723491:	33 d2                	xor    edx,edx
  723493:	6a 0c                	push   0xc
  723495:	59                   	pop    ecx
  723496:	f7 f1                	div    ecx
  723498:	8b d6                	mov    edx,esi
  72349a:	40                   	inc    eax
  72349b:	89 45 10             	mov    DWORD PTR [ebp+0x10],eax
  72349e:	03 53 08             	add    edx,DWORD PTR [ebx+0x8]
  7234a1:	03 7b 04             	add    edi,DWORD PTR [ebx+0x4]
  7234a4:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  7234a7:	2b 75 fc             	sub    esi,DWORD PTR [ebp-0x4]
  7234aa:	03 33                	add    esi,DWORD PTR [ebx]
  7234ac:	c1 c2 04             	rol    edx,0x4
  7234af:	33 d6                	xor    edx,esi
  7234b1:	8b 75 fc             	mov    esi,DWORD PTR [ebp-0x4]
  7234b4:	03 f7                	add    esi,edi
  7234b6:	8b c2                	mov    eax,edx
  7234b8:	2b fa                	sub    edi,edx
  7234ba:	c1 c0 06             	rol    eax,0x6
  7234bd:	33 c7                	xor    eax,edi
  7234bf:	03 d6                	add    edx,esi
  7234c1:	2b f0                	sub    esi,eax
  7234c3:	8b c8                	mov    ecx,eax
  7234c5:	c1 c1 08             	rol    ecx,0x8
  7234c8:	03 c2                	add    eax,edx
  7234ca:	33 ce                	xor    ecx,esi
  7234cc:	2b d1                	sub    edx,ecx
  7234ce:	8b f1                	mov    esi,ecx
  7234d0:	c1 c6 10             	rol    esi,0x10
  7234d3:	03 c8                	add    ecx,eax
  7234d5:	33 f2                	xor    esi,edx
  7234d7:	8b fe                	mov    edi,esi
  7234d9:	2b c6                	sub    eax,esi
  7234db:	c1 cf 0d             	ror    edi,0xd
  7234de:	03 f1                	add    esi,ecx
  7234e0:	33 f8                	xor    edi,eax
  7234e2:	2b cf                	sub    ecx,edi
  7234e4:	8b d7                	mov    edx,edi
  7234e6:	c1 c2 04             	rol    edx,0x4
  7234e9:	03 fe                	add    edi,esi
  7234eb:	33 d1                	xor    edx,ecx
  7234ed:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  7234f0:	6a 0c                	push   0xc
  7234f2:	58                   	pop    eax
  7234f3:	2b c8                	sub    ecx,eax
  7234f5:	03 d8                	add    ebx,eax
  7234f7:	83 6d 10 01          	sub    DWORD PTR [ebp+0x10],0x1
  7234fb:	89 4d 0c             	mov    DWORD PTR [ebp+0xc],ecx
  7234fe:	75 9e                	jne    0x72349e
  723500:	89 75 10             	mov    DWORD PTR [ebp+0x10],esi
  723503:	3b c8                	cmp    ecx,eax
  723505:	0f 87 ee 02 00 00    	ja     0x7237f9
  72350b:	ff 24 8d 48 38 72 00 	jmp    DWORD PTR [ecx*4+0x723848]
  723512:	03 53 08             	add    edx,DWORD PTR [ebx+0x8]
  723515:	03 7b 04             	add    edi,DWORD PTR [ebx+0x4]
  723518:	03 33                	add    esi,DWORD PTR [ebx]
  72351a:	e9 d7 02 00 00       	jmp    0x7237f6
  72351f:	8b 43 08             	mov    eax,DWORD PTR [ebx+0x8]
  723522:	25 ff ff ff 00       	and    eax,0xffffff
  723527:	03 d0                	add    edx,eax
  723529:	eb ea                	jmp    0x723515
  72352b:	0f b7 43 08          	movzx  eax,WORD PTR [ebx+0x8]
  72352f:	eb f6                	jmp    0x723527
  723531:	0f b6 43 08          	movzx  eax,BYTE PTR [ebx+0x8]
  723535:	eb f0                	jmp    0x723527
  723537:	8b 43 04             	mov    eax,DWORD PTR [ebx+0x4]
  72353a:	25 ff ff ff 00       	and    eax,0xffffff
  72353f:	03 f8                	add    edi,eax
  723541:	eb d5                	jmp    0x723518
  723543:	0f b7 43 04          	movzx  eax,WORD PTR [ebx+0x4]
  723547:	eb f6                	jmp    0x72353f
  723549:	0f b6 43 04          	movzx  eax,BYTE PTR [ebx+0x4]
  72354d:	eb f0                	jmp    0x72353f
  72354f:	8b 03                	mov    eax,DWORD PTR [ebx]
  723551:	25 ff ff ff 00       	and    eax,0xffffff
  723556:	e9 99 02 00 00       	jmp    0x7237f4
  72355b:	8b c2                	mov    eax,edx
  72355d:	e9 e1 02 00 00       	jmp    0x723843
  723562:	f6 c3 01             	test   bl,0x1
  723565:	0f 85 45 01 00 00    	jne    0x7236b0
  72356b:	3b c8                	cmp    ecx,eax
  72356d:	0f 86 a3 00 00 00    	jbe    0x723616
  723573:	8d 41 f3             	lea    eax,[ecx-0xd]
  723576:	33 d2                	xor    edx,edx
  723578:	6a 0c                	push   0xc
  72357a:	59                   	pop    ecx
  72357b:	f7 f1                	div    ecx
  72357d:	40                   	inc    eax
  72357e:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  723581:	0f b7 53 06          	movzx  edx,WORD PTR [ebx+0x6]
  723585:	0f b7 4b 04          	movzx  ecx,WORD PTR [ebx+0x4]
  723589:	0f b7 73 08          	movzx  esi,WORD PTR [ebx+0x8]
  72358d:	03 cf                	add    ecx,edi
  72358f:	03 75 fc             	add    esi,DWORD PTR [ebp-0x4]
  723592:	0f b7 03             	movzx  eax,WORD PTR [ebx]
  723595:	c1 e2 10             	shl    edx,0x10
  723598:	03 d1                	add    edx,ecx
  72359a:	0f b7 4b 0a          	movzx  ecx,WORD PTR [ebx+0xa]
  72359e:	c1 e1 10             	shl    ecx,0x10
  7235a1:	03 f1                	add    esi,ecx
  7235a3:	0f b7 4b 02          	movzx  ecx,WORD PTR [ebx+0x2]
  7235a7:	c1 e1 10             	shl    ecx,0x10
  7235aa:	8b fe                	mov    edi,esi
  7235ac:	03 c8                	add    ecx,eax
  7235ae:	c1 c7 04             	rol    edi,0x4
  7235b1:	2b ce                	sub    ecx,esi
  7235b3:	03 f2                	add    esi,edx
  7235b5:	03 4d 10             	add    ecx,DWORD PTR [ebp+0x10]
  7235b8:	33 f9                	xor    edi,ecx
  7235ba:	2b d7                	sub    edx,edi
  7235bc:	8b c7                	mov    eax,edi
  7235be:	03 fe                	add    edi,esi
  7235c0:	c1 c0 06             	rol    eax,0x6
  7235c3:	33 c2                	xor    eax,edx
  7235c5:	2b f0                	sub    esi,eax
  7235c7:	8b c8                	mov    ecx,eax
  7235c9:	c1 c1 08             	rol    ecx,0x8
  7235cc:	03 c7                	add    eax,edi
  7235ce:	33 ce                	xor    ecx,esi
  7235d0:	2b f9                	sub    edi,ecx
  7235d2:	8b f1                	mov    esi,ecx
  7235d4:	c1 c6 10             	rol    esi,0x10
  7235d7:	03 c8                	add    ecx,eax
  7235d9:	33 f7                	xor    esi,edi
  7235db:	8b fe                	mov    edi,esi
  7235dd:	2b c6                	sub    eax,esi
  7235df:	c1 cf 0d             	ror    edi,0xd
  7235e2:	03 f1                	add    esi,ecx
  7235e4:	33 f8                	xor    edi,eax
  7235e6:	89 75 10             	mov    DWORD PTR [ebp+0x10],esi
  7235e9:	2b cf                	sub    ecx,edi
  7235eb:	8b d7                	mov    edx,edi
  7235ed:	c1 c2 04             	rol    edx,0x4
  7235f0:	03 fe                	add    edi,esi
  7235f2:	33 d1                	xor    edx,ecx
  7235f4:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  7235f7:	6a 0c                	push   0xc
  7235f9:	58                   	pop    eax
  7235fa:	2b c8                	sub    ecx,eax
  7235fc:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  7235ff:	03 d8                	add    ebx,eax
  723601:	89 4d 0c             	mov    DWORD PTR [ebp+0xc],ecx
  723604:	83 6d 08 01          	sub    DWORD PTR [ebp+0x8],0x1
  723608:	0f 85 73 ff ff ff    	jne    0x723581
  72360e:	3b c8                	cmp    ecx,eax
  723610:	0f 87 e3 01 00 00    	ja     0x7237f9
  723616:	ff 24 8d 7c 38 72 00 	jmp    DWORD PTR [ecx*4+0x72387c]
  72361d:	0f b7 43 08          	movzx  eax,WORD PTR [ebx+0x8]
  723621:	0f b7 4b 0a          	movzx  ecx,WORD PTR [ebx+0xa]
  723625:	03 d0                	add    edx,eax
  723627:	0f b7 43 04          	movzx  eax,WORD PTR [ebx+0x4]
  72362b:	c1 e1 10             	shl    ecx,0x10
  72362e:	03 f8                	add    edi,eax
  723630:	0f b7 03             	movzx  eax,WORD PTR [ebx]
  723633:	03 d1                	add    edx,ecx
  723635:	0f b7 4b 06          	movzx  ecx,WORD PTR [ebx+0x6]
  723639:	03 f0                	add    esi,eax
  72363b:	c1 e1 10             	shl    ecx,0x10
  72363e:	03 f9                	add    edi,ecx
  723640:	0f b7 4b 02          	movzx  ecx,WORD PTR [ebx+0x2]
  723644:	c1 e1 10             	shl    ecx,0x10
  723647:	03 f1                	add    esi,ecx
  723649:	e9 a8 01 00 00       	jmp    0x7237f6
  72364e:	0f b6 43 0a          	movzx  eax,BYTE PTR [ebx+0xa]
  723652:	c1 e0 10             	shl    eax,0x10
  723655:	03 d0                	add    edx,eax
  723657:	0f b7 43 08          	movzx  eax,WORD PTR [ebx+0x8]
  72365b:	03 d0                	add    edx,eax
  72365d:	0f b7 4b 06          	movzx  ecx,WORD PTR [ebx+0x6]
  723661:	0f b7 43 04          	movzx  eax,WORD PTR [ebx+0x4]
  723665:	c1 e1 10             	shl    ecx,0x10
  723668:	03 f8                	add    edi,eax
  72366a:	03 f9                	add    edi,ecx
  72366c:	0f b7 4b 02          	movzx  ecx,WORD PTR [ebx+0x2]
  723670:	0f b7 03             	movzx  eax,WORD PTR [ebx]
  723673:	c1 e1 10             	shl    ecx,0x10
  723676:	03 c6                	add    eax,esi
  723678:	03 c1                	add    eax,ecx
  72367a:	89 45 10             	mov    DWORD PTR [ebp+0x10],eax
  72367d:	e9 77 01 00 00       	jmp    0x7237f9
  723682:	0f b6 43 08          	movzx  eax,BYTE PTR [ebx+0x8]
  723686:	eb d3                	jmp    0x72365b
  723688:	0f b6 43 06          	movzx  eax,BYTE PTR [ebx+0x6]
  72368c:	c1 e0 10             	shl    eax,0x10
  72368f:	03 f8                	add    edi,eax
  723691:	0f b7 43 04          	movzx  eax,WORD PTR [ebx+0x4]
  723695:	03 f8                	add    edi,eax
  723697:	eb d3                	jmp    0x72366c
  723699:	0f b6 43 04          	movzx  eax,BYTE PTR [ebx+0x4]
  72369d:	eb f6                	jmp    0x723695
  72369f:	0f b6 43 02          	movzx  eax,BYTE PTR [ebx+0x2]
  7236a3:	c1 e0 10             	shl    eax,0x10
  7236a6:	03 f0                	add    esi,eax
  7236a8:	0f b7 03             	movzx  eax,WORD PTR [ebx]
  7236ab:	e9 44 01 00 00       	jmp    0x7237f4
  7236b0:	3b c8                	cmp    ecx,eax
  7236b2:	0f 86 d5 00 00 00    	jbe    0x72378d
  7236b8:	8d 41 f3             	lea    eax,[ecx-0xd]
  7236bb:	33 d2                	xor    edx,edx
  7236bd:	6a 0c                	push   0xc
  7236bf:	59                   	pop    ecx
  7236c0:	f7 f1                	div    ecx
  7236c2:	40                   	inc    eax
  7236c3:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  7236c6:	0f b6 53 07          	movzx  edx,BYTE PTR [ebx+0x7]
  7236ca:	0f b6 4b 06          	movzx  ecx,BYTE PTR [ebx+0x6]
  7236ce:	0f b6 43 05          	movzx  eax,BYTE PTR [ebx+0x5]
  7236d2:	0f b6 73 04          	movzx  esi,BYTE PTR [ebx+0x4]
  7236d6:	c1 e2 08             	shl    edx,0x8
  7236d9:	03 f7                	add    esi,edi
  7236db:	03 d1                	add    edx,ecx
  7236dd:	0f b6 4b 0b          	movzx  ecx,BYTE PTR [ebx+0xb]
  7236e1:	c1 e1 08             	shl    ecx,0x8
  7236e4:	c1 e2 08             	shl    edx,0x8
  7236e7:	03 d0                	add    edx,eax
  7236e9:	0f b6 43 0a          	movzx  eax,BYTE PTR [ebx+0xa]
  7236ed:	03 c8                	add    ecx,eax
  7236ef:	c1 e2 08             	shl    edx,0x8
  7236f2:	0f b6 43 09          	movzx  eax,BYTE PTR [ebx+0x9]
  7236f6:	03 f2                	add    esi,edx
  7236f8:	0f b6 53 08          	movzx  edx,BYTE PTR [ebx+0x8]
  7236fc:	03 55 fc             	add    edx,DWORD PTR [ebp-0x4]
  7236ff:	c1 e1 08             	shl    ecx,0x8
  723702:	03 c8                	add    ecx,eax
  723704:	0f b6 43 02          	movzx  eax,BYTE PTR [ebx+0x2]
  723708:	c1 e1 08             	shl    ecx,0x8
  72370b:	03 d1                	add    edx,ecx
  72370d:	0f b6 4b 03          	movzx  ecx,BYTE PTR [ebx+0x3]
  723711:	c1 e1 08             	shl    ecx,0x8
  723714:	8b fa                	mov    edi,edx
  723716:	03 c8                	add    ecx,eax
  723718:	c1 c7 04             	rol    edi,0x4
  72371b:	0f b6 43 01          	movzx  eax,BYTE PTR [ebx+0x1]
  72371f:	c1 e1 08             	shl    ecx,0x8
  723722:	03 c8                	add    ecx,eax
  723724:	0f b6 03             	movzx  eax,BYTE PTR [ebx]
  723727:	c1 e1 08             	shl    ecx,0x8
  72372a:	03 c8                	add    ecx,eax
  72372c:	2b ca                	sub    ecx,edx
  72372e:	03 d6                	add    edx,esi
  723730:	03 4d 10             	add    ecx,DWORD PTR [ebp+0x10]
  723733:	33 f9                	xor    edi,ecx
  723735:	2b f7                	sub    esi,edi
  723737:	8b c7                	mov    eax,edi
  723739:	03 fa                	add    edi,edx
  72373b:	c1 c0 06             	rol    eax,0x6
  72373e:	33 c6                	xor    eax,esi
  723740:	2b d0                	sub    edx,eax
  723742:	8b c8                	mov    ecx,eax
  723744:	c1 c1 08             	rol    ecx,0x8
  723747:	03 c7                	add    eax,edi
  723749:	33 ca                	xor    ecx,edx
  72374b:	2b f9                	sub    edi,ecx
  72374d:	8b f1                	mov    esi,ecx
  72374f:	c1 c6 10             	rol    esi,0x10
  723752:	03 c8                	add    ecx,eax
  723754:	33 f7                	xor    esi,edi
  723756:	8b fe                	mov    edi,esi
  723758:	2b c6                	sub    eax,esi
  72375a:	c1 cf 0d             	ror    edi,0xd
  72375d:	03 f1                	add    esi,ecx
  72375f:	33 f8                	xor    edi,eax
  723761:	89 75 10             	mov    DWORD PTR [ebp+0x10],esi
  723764:	2b cf                	sub    ecx,edi
  723766:	8b d7                	mov    edx,edi
  723768:	c1 c2 04             	rol    edx,0x4
  72376b:	03 fe                	add    edi,esi
  72376d:	33 d1                	xor    edx,ecx
  72376f:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  723772:	6a 0c                	push   0xc
  723774:	58                   	pop    eax
  723775:	2b c8                	sub    ecx,eax
  723777:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  72377a:	03 d8                	add    ebx,eax
  72377c:	89 4d 0c             	mov    DWORD PTR [ebp+0xc],ecx
  72377f:	83 6d 08 01          	sub    DWORD PTR [ebp+0x8],0x1
  723783:	0f 85 3d ff ff ff    	jne    0x7236c6
  723789:	3b c8                	cmp    ecx,eax
  72378b:	77 6c                	ja     0x7237f9
  72378d:	ff 24 8d b0 38 72 00 	jmp    DWORD PTR [ecx*4+0x7238b0]
  723794:	0f b6 43 0b          	movzx  eax,BYTE PTR [ebx+0xb]
  723798:	c1 e0 18             	shl    eax,0x18
  72379b:	03 d0                	add    edx,eax
  72379d:	0f b6 43 0a          	movzx  eax,BYTE PTR [ebx+0xa]
  7237a1:	c1 e0 10             	shl    eax,0x10
  7237a4:	03 d0                	add    edx,eax
  7237a6:	0f b6 43 09          	movzx  eax,BYTE PTR [ebx+0x9]
  7237aa:	c1 e0 08             	shl    eax,0x8
  7237ad:	03 d0                	add    edx,eax
  7237af:	0f b6 43 08          	movzx  eax,BYTE PTR [ebx+0x8]
  7237b3:	03 d0                	add    edx,eax
  7237b5:	0f b6 43 07          	movzx  eax,BYTE PTR [ebx+0x7]
  7237b9:	c1 e0 18             	shl    eax,0x18
  7237bc:	03 f8                	add    edi,eax
  7237be:	0f b6 43 06          	movzx  eax,BYTE PTR [ebx+0x6]
  7237c2:	c1 e0 10             	shl    eax,0x10
  7237c5:	03 f8                	add    edi,eax
  7237c7:	0f b6 43 05          	movzx  eax,BYTE PTR [ebx+0x5]
  7237cb:	c1 e0 08             	shl    eax,0x8
  7237ce:	03 f8                	add    edi,eax
  7237d0:	0f b6 43 04          	movzx  eax,BYTE PTR [ebx+0x4]
  7237d4:	03 f8                	add    edi,eax
  7237d6:	0f b6 43 03          	movzx  eax,BYTE PTR [ebx+0x3]
  7237da:	c1 e0 18             	shl    eax,0x18
  7237dd:	03 f0                	add    esi,eax
  7237df:	0f b6 43 02          	movzx  eax,BYTE PTR [ebx+0x2]
  7237e3:	c1 e0 10             	shl    eax,0x10
  7237e6:	03 f0                	add    esi,eax
  7237e8:	0f b6 43 01          	movzx  eax,BYTE PTR [ebx+0x1]
  7237ec:	c1 e0 08             	shl    eax,0x8
  7237ef:	03 f0                	add    esi,eax
  7237f1:	0f b6 03             	movzx  eax,BYTE PTR [ebx]
  7237f4:	03 f0                	add    esi,eax
  7237f6:	89 75 10             	mov    DWORD PTR [ebp+0x10],esi
  7237f9:	33 d7                	xor    edx,edi
  7237fb:	8b c7                	mov    eax,edi
  7237fd:	c1 c0 0e             	rol    eax,0xe
  723800:	2b d0                	sub    edx,eax
  723802:	8b c2                	mov    eax,edx
  723804:	89 55 fc             	mov    DWORD PTR [ebp-0x4],edx
  723807:	33 55 10             	xor    edx,DWORD PTR [ebp+0x10]
  72380a:	8b 5d fc             	mov    ebx,DWORD PTR [ebp-0x4]
  72380d:	c1 c0 0b             	rol    eax,0xb
  723810:	2b d0                	sub    edx,eax
  723812:	33 fa                	xor    edi,edx
  723814:	8b c2                	mov    eax,edx
  723816:	c1 c8 07             	ror    eax,0x7
  723819:	2b f8                	sub    edi,eax
  72381b:	8b c7                	mov    eax,edi
  72381d:	33 df                	xor    ebx,edi
  72381f:	c1 c0 10             	rol    eax,0x10
  723822:	2b d8                	sub    ebx,eax
  723824:	8b c3                	mov    eax,ebx
  723826:	8b cb                	mov    ecx,ebx
  723828:	c1 c0 04             	rol    eax,0x4
  72382b:	33 ca                	xor    ecx,edx
  72382d:	2b c8                	sub    ecx,eax
  72382f:	8b c1                	mov    eax,ecx
  723831:	33 f9                	xor    edi,ecx
  723833:	c1 c0 0e             	rol    eax,0xe
  723836:	2b f8                	sub    edi,eax
  723838:	8b c7                	mov    eax,edi
  72383a:	33 df                	xor    ebx,edi
  72383c:	c1 c8 08             	ror    eax,0x8
  72383f:	2b d8                	sub    ebx,eax
  723841:	8b c3                	mov    eax,ebx
  723843:	5f                   	pop    edi
  723844:	5e                   	pop    esi
  723845:	5b                   	pop    ebx
  723846:	c9                   	leave
  723847:	c3                   	ret
