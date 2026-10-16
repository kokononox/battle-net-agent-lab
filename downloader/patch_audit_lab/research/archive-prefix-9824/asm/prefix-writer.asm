
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

007014aa <.text+0x3004aa>:
  7014aa:	55                   	push   ebp
  7014ab:	8b ec                	mov    ebp,esp
  7014ad:	81 ec 00 02 00 00    	sub    esp,0x200
  7014b3:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  7014b8:	33 c5                	xor    eax,ebp
  7014ba:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  7014bd:	56                   	push   esi
  7014be:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  7014c1:	57                   	push   edi
  7014c2:	8b 7d 10             	mov    edi,DWORD PTR [ebp+0x10]
  7014c5:	56                   	push   esi
  7014c6:	e8 0f 09 00 00       	call   0x701dda
  7014cb:	59                   	pop    ecx
  7014cc:	84 c0                	test   al,al
  7014ce:	75 08                	jne    0x7014d8
  7014d0:	6a 06                	push   0x6
  7014d2:	58                   	pop    eax
  7014d3:	e9 bf 00 00 00       	jmp    0x701597
  7014d8:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  7014db:	b9 00 00 00 40       	mov    ecx,0x40000000
  7014e0:	f7 e1                	mul    ecx
  7014e2:	53                   	push   ebx
  7014e3:	89 95 04 fe ff ff    	mov    DWORD PTR [ebp-0x1fc],edx
  7014e9:	33 db                	xor    ebx,ebx
  7014eb:	8d 95 1c fe ff ff    	lea    edx,[ebp-0x1e4]
  7014f1:	89 85 00 fe ff ff    	mov    DWORD PTR [ebp-0x200],eax
  7014f7:	89 95 08 fe ff ff    	mov    DWORD PTR [ebp-0x1f8],edx
  7014fd:	6b cb 1e             	imul   ecx,ebx,0x1e
  701500:	33 c0                	xor    eax,eax
  701502:	6a 1e                	push   0x1e
  701504:	03 8d 00 fe ff ff    	add    ecx,DWORD PTR [ebp-0x200]
  70150a:	89 8d 0c fe ff ff    	mov    DWORD PTR [ebp-0x1f4],ecx
  701510:	13 85 04 fe ff ff    	adc    eax,DWORD PTR [ebp-0x1fc]
  701516:	59                   	pop    ecx
  701517:	6a 01                	push   0x1
  701519:	89 85 10 fe ff ff    	mov    DWORD PTR [ebp-0x1f0],eax
  70151f:	8d 85 0c fe ff ff    	lea    eax,[ebp-0x1f4]
  701525:	50                   	push   eax
  701526:	57                   	push   edi
  701527:	51                   	push   ecx
  701528:	52                   	push   edx
  701529:	89 8d 14 fe ff ff    	mov    DWORD PTR [ebp-0x1ec],ecx
  70152f:	e8 f6 27 01 00       	call   0x713d2a
  701534:	83 c4 14             	add    esp,0x14
  701537:	84 c0                	test   al,al
  701539:	74 3d                	je     0x701578
  70153b:	8b 95 08 fe ff ff    	mov    edx,DWORD PTR [ebp-0x1f8]
  701541:	83 c7 10             	add    edi,0x10
  701544:	83 c2 1e             	add    edx,0x1e
  701547:	43                   	inc    ebx
  701548:	89 95 08 fe ff ff    	mov    DWORD PTR [ebp-0x1f8],edx
  70154e:	83 fb 10             	cmp    ebx,0x10
  701551:	72 aa                	jb     0x7014fd
  701553:	8b 8e 50 07 00 00    	mov    ecx,DWORD PTR [esi+0x750]
  701559:	8d 85 1c fe ff ff    	lea    eax,[ebp-0x1e4]
  70155f:	68 e0 01 00 00       	push   0x1e0
  701564:	ff b5 04 fe ff ff    	push   DWORD PTR [ebp-0x1fc]
  70156a:	ff b5 00 fe ff ff    	push   DWORD PTR [ebp-0x200]
  701570:	50                   	push   eax
  701571:	e8 56 ca 00 00       	call   0x70dfcc
  701576:	eb 1e                	jmp    0x701596
  701578:	68 e8 ba 9b 00       	push   0x9bbae8
  70157d:	6a 00                	push   0x0
  70157f:	68 08 bc 8f 00       	push   0x8fbc08
  701584:	6a 04                	push   0x4
  701586:	68 38 ba 9b 00       	push   0x9bba38
  70158b:	e8 b3 22 1c 00       	call   0x8c3843
  701590:	33 c0                	xor    eax,eax
  701592:	83 c4 14             	add    esp,0x14
  701595:	40                   	inc    eax
  701596:	5b                   	pop    ebx
  701597:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  70159a:	5f                   	pop    edi
  70159b:	33 cd                	xor    ecx,ebp
  70159d:	5e                   	pop    esi
  70159e:	e8 55 4a 17 00       	call   0x875ff8
  7015a3:	c9                   	leave
  7015a4:	c3                   	ret
