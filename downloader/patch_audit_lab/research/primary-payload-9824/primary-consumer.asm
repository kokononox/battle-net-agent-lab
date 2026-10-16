
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

007114e2 <.text+0x3104e2>:
  7114e2:	6a 58                	push   0x58
  7114e4:	b8 55 1f 8f 00       	mov    eax,0x8f1f55
  7114e9:	e8 4a 4b 16 00       	call   0x876038
  7114ee:	8b f1                	mov    esi,ecx
  7114f0:	89 75 e8             	mov    DWORD PTR [ebp-0x18],esi
  7114f3:	8b 46 4c             	mov    eax,DWORD PTR [esi+0x4c]
  7114f6:	8b c8                	mov    ecx,eax
  7114f8:	89 45 d0             	mov    DWORD PTR [ebp-0x30],eax
  7114fb:	e8 05 c6 00 00       	call   0x71db05
  711500:	84 c0                	test   al,al
  711502:	74 19                	je     0x71151d
  711504:	83 7d 08 00          	cmp    DWORD PTR [ebp+0x8],0x0
  711508:	0f 84 c6 01 00 00    	je     0x7116d4
  71150e:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  711511:	8b ce                	mov    ecx,esi
  711513:	e8 6f ed ff ff       	call   0x710287
  711518:	e9 b9 01 00 00       	jmp    0x7116d6
  71151d:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  711520:	8d be 30 01 00 00    	lea    edi,[esi+0x130]
  711526:	6a 10                	push   0x10
  711528:	5b                   	pop    ebx
  711529:	89 86 0c 07 00 00    	mov    DWORD PTR [esi+0x70c],eax
  71152f:	8b f3                	mov    esi,ebx
  711531:	c7 45 dc 01 00 00 00 	mov    DWORD PTR [ebp-0x24],0x1
  711538:	8b 5d dc             	mov    ebx,DWORD PTR [ebp-0x24]
  71153b:	89 7d d4             	mov    DWORD PTR [ebp-0x2c],edi
  71153e:	8b cf                	mov    ecx,edi
  711540:	e8 b7 f6 00 00       	call   0x720bfc
  711545:	03 d8                	add    ebx,eax
  711547:	83 c7 50             	add    edi,0x50
  71154a:	83 ee 01             	sub    esi,0x1
  71154d:	75 ef                	jne    0x71153e
  71154f:	8b 75 e8             	mov    esi,DWORD PTR [ebp-0x18]
  711552:	53                   	push   ebx
  711553:	8b 0e                	mov    ecx,DWORD PTR [esi]
  711555:	e8 b8 cb ff ff       	call   0x70e112
  71155a:	8d 4d ec             	lea    ecx,[ebp-0x14]
  71155d:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
  711560:	89 75 e0             	mov    DWORD PTR [ebp-0x20],esi
  711563:	89 4d e4             	mov    DWORD PTR [ebp-0x1c],ecx
  711566:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  71156a:	8d 4d ac             	lea    ecx,[ebp-0x54]
  71156d:	83 65 a4 00          	and    DWORD PTR [ebp-0x5c],0x0
  711571:	6a 10                	push   0x10
  711573:	89 5d a0             	mov    DWORD PTR [ebp-0x60],ebx
  711576:	5b                   	pop    ebx
  711577:	53                   	push   ebx
  711578:	ff 36                	push   DWORD PTR [esi]
  71157a:	89 45 9c             	mov    DWORD PTR [ebp-0x64],eax
  71157d:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  711580:	89 45 a8             	mov    DWORD PTR [ebp-0x58],eax
  711583:	e8 8f ab f6 ff       	call   0x67c117
  711588:	8b 7d d4             	mov    edi,DWORD PTR [ebp-0x2c]
  71158b:	c6 45 fc 01          	mov    BYTE PTR [ebp-0x4],0x1
  71158f:	6a 00                	push   0x0
  711591:	6a 1e                	push   0x1e
  711593:	8d 45 9c             	lea    eax,[ebp-0x64]
  711596:	8b cf                	mov    ecx,edi
  711598:	50                   	push   eax
  711599:	68 b1 17 71 00       	push   0x7117b1
  71159e:	e8 0f ed 00 00       	call   0x7202b2
  7115a3:	83 c7 50             	add    edi,0x50
  7115a6:	83 eb 01             	sub    ebx,0x1
  7115a9:	75 e4                	jne    0x71158f
  7115ab:	8b 45 a4             	mov    eax,DWORD PTR [ebp-0x5c]
  7115ae:	ff 76 34             	push   DWORD PTR [esi+0x34]
  7115b1:	6b f8 09             	imul   edi,eax,0x9
  7115b4:	ff 76 30             	push   DWORD PTR [esi+0x30]
  7115b7:	8d 58 01             	lea    ebx,[eax+0x1]
  7115ba:	6a 05                	push   0x5
  7115bc:	89 5d d4             	mov    DWORD PTR [ebp-0x2c],ebx
  7115bf:	03 7d ec             	add    edi,DWORD PTR [ebp-0x14]
  7115c2:	57                   	push   edi
  7115c3:	e8 08 eb ff ff       	call   0x7100d0
  7115c8:	83 c4 10             	add    esp,0x10
  7115cb:	83 c9 ff             	or     ecx,0xffffffff
  7115ce:	33 c0                	xor    eax,eax
  7115d0:	33 d2                	xor    edx,edx
  7115d2:	88 4c 3a 05          	mov    BYTE PTR [edx+edi*1+0x5],cl
  7115d6:	0f ac c1 08          	shrd   ecx,eax,0x8
  7115da:	c1 e8 08             	shr    eax,0x8
  7115dd:	42                   	inc    edx
  7115de:	83 fa 04             	cmp    edx,0x4
  7115e1:	72 ef                	jb     0x7115d2
  7115e3:	8b 0e                	mov    ecx,DWORD PTR [esi]
  7115e5:	53                   	push   ebx
  7115e6:	e8 e5 ca ff ff       	call   0x70e0d0
  7115eb:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  7115ee:	8d 45 f0             	lea    eax,[ebp-0x10]
  7115f1:	89 75 c8             	mov    DWORD PTR [ebp-0x38],esi
  7115f4:	89 45 cc             	mov    DWORD PTR [ebp-0x34],eax
  7115f7:	33 d2                	xor    edx,edx
  7115f9:	c6 45 fc 02          	mov    BYTE PTR [ebp-0x4],0x2
  7115fd:	85 db                	test   ebx,ebx
  7115ff:	74 15                	je     0x711616
  711601:	33 ff                	xor    edi,edi
  711603:	8b 4d ec             	mov    ecx,DWORD PTR [ebp-0x14]
  711606:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
  711609:	03 cf                	add    ecx,edi
  71160b:	83 c7 09             	add    edi,0x9
  71160e:	89 0c 90             	mov    DWORD PTR [eax+edx*4],ecx
  711611:	42                   	inc    edx
  711612:	3b d3                	cmp    edx,ebx
  711614:	72 ed                	jb     0x711603
  711616:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
  711619:	85 db                	test   ebx,ebx
  71161b:	74 7e                	je     0x71169b
  71161d:	8b 7d b0             	mov    edi,DWORD PTR [ebp-0x50]
  711620:	8b 45 c0             	mov    eax,DWORD PTR [ebp-0x40]
  711623:	8d 04 c7             	lea    eax,[edi+eax*8]
  711626:	3b f8                	cmp    edi,eax
  711628:	74 3f                	je     0x711669
  71162a:	8b f0                	mov    esi,eax
  71162c:	8b 47 04             	mov    eax,DWORD PTR [edi+0x4]
  71162f:	8b 0f                	mov    ecx,DWORD PTR [edi]
  711631:	50                   	push   eax
  711632:	51                   	push   ecx
  711633:	68 74 d2 9b 00       	push   0x9bd274
  711638:	6a 00                	push   0x0
  71163a:	68 08 bc 8f 00       	push   0x8fbc08
  71163f:	6a 01                	push   0x1
  711641:	68 38 ba 9b 00       	push   0x9bba38
  711646:	89 4d d8             	mov    DWORD PTR [ebp-0x28],ecx
  711649:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
  71164c:	e8 f2 21 1b 00       	call   0x8c3843
  711651:	83 c4 1c             	add    esp,0x1c
  711654:	8d 45 d8             	lea    eax,[ebp-0x28]
  711657:	8b cb                	mov    ecx,ebx
  711659:	50                   	push   eax
  71165a:	e8 e9 75 ff ff       	call   0x708c48
  71165f:	83 c7 08             	add    edi,0x8
  711662:	3b fe                	cmp    edi,esi
  711664:	75 c6                	jne    0x71162c
  711666:	8b 75 e8             	mov    esi,DWORD PTR [ebp-0x18]
  711669:	8b 7b 04             	mov    edi,DWORD PTR [ebx+0x4]
  71166c:	8b 43 14             	mov    eax,DWORD PTR [ebx+0x14]
  71166f:	8d 1c c7             	lea    ebx,[edi+eax*8]
  711672:	eb 23                	jmp    0x711697
  711674:	ff 77 04             	push   DWORD PTR [edi+0x4]
  711677:	ff 37                	push   DWORD PTR [edi]
  711679:	68 8c d2 9b 00       	push   0x9bd28c
  71167e:	6a 00                	push   0x0
  711680:	68 08 bc 8f 00       	push   0x8fbc08
  711685:	6a 01                	push   0x1
  711687:	68 38 ba 9b 00       	push   0x9bba38
  71168c:	e8 b2 21 1b 00       	call   0x8c3843
  711691:	83 c4 1c             	add    esp,0x1c
  711694:	83 c7 08             	add    edi,0x8
  711697:	3b fb                	cmp    edi,ebx
  711699:	75 d9                	jne    0x711674
  71169b:	ff 75 d4             	push   DWORD PTR [ebp-0x2c]
  71169e:	8b 4d d0             	mov    ecx,DWORD PTR [ebp-0x30]
  7116a1:	ff 75 f0             	push   DWORD PTR [ebp-0x10]
  7116a4:	e8 2d 15 01 00       	call   0x722bd6
  7116a9:	8b 0e                	mov    ecx,DWORD PTR [esi]
  7116ab:	ff 75 f0             	push   DWORD PTR [ebp-0x10]
  7116ae:	c6 45 fc 03          	mov    BYTE PTR [ebp-0x4],0x3
  7116b2:	8b 01                	mov    eax,DWORD PTR [ecx]
  7116b4:	ff 50 18             	call   DWORD PTR [eax+0x18]
  7116b7:	8d 4d ac             	lea    ecx,[ebp-0x54]
  7116ba:	c6 45 fc 04          	mov    BYTE PTR [ebp-0x4],0x4
  7116be:	e8 73 99 f6 ff       	call   0x67b036
  7116c3:	8b 0e                	mov    ecx,DWORD PTR [esi]
  7116c5:	ff 75 ec             	push   DWORD PTR [ebp-0x14]
  7116c8:	c7 45 fc 05 00 00 00 	mov    DWORD PTR [ebp-0x4],0x5
  7116cf:	8b 01                	mov    eax,DWORD PTR [ecx]
  7116d1:	ff 50 18             	call   DWORD PTR [eax+0x18]
  7116d4:	33 c0                	xor    eax,eax
  7116d6:	e8 2b 49 16 00       	call   0x876006
  7116db:	c2 04 00             	ret    0x4
