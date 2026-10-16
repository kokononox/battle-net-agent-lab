
Agent.9824.exe:     file format pei-i386


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
