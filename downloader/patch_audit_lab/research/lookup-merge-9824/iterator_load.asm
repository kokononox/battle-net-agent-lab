
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072f31b <.text+0x32e31b>:
  72f31b:	55                   	push   ebp
  72f31c:	8b ec                	mov    ebp,esp
  72f31e:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  72f321:	83 ec 10             	sub    esp,0x10
  72f324:	53                   	push   ebx
  72f325:	8b d9                	mov    ebx,ecx
  72f327:	56                   	push   esi
  72f328:	57                   	push   edi
  72f329:	83 a3 24 01 00 00 00 	and    DWORD PTR [ebx+0x124],0x0
  72f330:	85 d2                	test   edx,edx
  72f332:	74 68                	je     0x72f39c
  72f334:	39 55 0c             	cmp    DWORD PTR [ebp+0xc],edx
  72f337:	76 63                	jbe    0x72f39c
  72f339:	8b 42 10             	mov    eax,DWORD PTR [edx+0x10]
  72f33c:	8d 72 20             	lea    esi,[edx+0x20]
  72f33f:	8b 4a 14             	mov    ecx,DWORD PTR [edx+0x14]
  72f342:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  72f345:	8b 42 18             	mov    eax,DWORD PTR [edx+0x18]
  72f348:	89 4d f4             	mov    DWORD PTR [ebp-0xc],ecx
  72f34b:	8b 4a 1c             	mov    ecx,DWORD PTR [edx+0x1c]
  72f34e:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  72f351:	8d 45 f0             	lea    eax,[ebp-0x10]
  72f354:	89 4d fc             	mov    DWORD PTR [ebp-0x4],ecx
  72f357:	8b cb                	mov    ecx,ebx
  72f359:	50                   	push   eax
  72f35a:	3b 75 0c             	cmp    esi,DWORD PTR [ebp+0xc]
  72f35d:	75 09                	jne    0x72f368
  72f35f:	6a 01                	push   0x1
  72f361:	e8 58 fd ff ff       	call   0x72f0be
  72f366:	eb 34                	jmp    0x72f39c
  72f368:	6a 02                	push   0x2
  72f36a:	e8 4f fd ff ff       	call   0x72f0be
  72f36f:	8b 46 10             	mov    eax,DWORD PTR [esi+0x10]
  72f372:	8b 4e 14             	mov    ecx,DWORD PTR [esi+0x14]
  72f375:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  72f378:	8b 46 18             	mov    eax,DWORD PTR [esi+0x18]
  72f37b:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
  72f37e:	8d 45 f0             	lea    eax,[ebp-0x10]
  72f381:	89 4d f4             	mov    DWORD PTR [ebp-0xc],ecx
  72f384:	8b 4e 1c             	mov    ecx,DWORD PTR [esi+0x1c]
  72f387:	83 c6 20             	add    esi,0x20
  72f38a:	50                   	push   eax
  72f38b:	89 4d fc             	mov    DWORD PTR [ebp-0x4],ecx
  72f38e:	8b cb                	mov    ecx,ebx
  72f390:	6a 06                	push   0x6
  72f392:	e8 27 fd ff ff       	call   0x72f0be
  72f397:	3b 75 0c             	cmp    esi,DWORD PTR [ebp+0xc]
  72f39a:	75 d3                	jne    0x72f36f
  72f39c:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  72f39f:	85 c0                	test   eax,eax
  72f3a1:	74 2f                	je     0x72f3d2
  72f3a3:	39 45 14             	cmp    DWORD PTR [ebp+0x14],eax
  72f3a6:	76 2a                	jbe    0x72f3d2
  72f3a8:	8b 00                	mov    eax,DWORD PTR [eax]
  72f3aa:	8d 7d f0             	lea    edi,[ebp-0x10]
  72f3ad:	8d 4d f0             	lea    ecx,[ebp-0x10]
  72f3b0:	51                   	push   ecx
  72f3b1:	8b cb                	mov    ecx,ebx
  72f3b3:	8d 70 10             	lea    esi,[eax+0x10]
  72f3b6:	0f b6 40 20          	movzx  eax,BYTE PTR [eax+0x20]
  72f3ba:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f3bb:	50                   	push   eax
  72f3bc:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f3bd:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f3be:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f3bf:	e8 fa fc ff ff       	call   0x72f0be
  72f3c4:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  72f3c7:	83 c0 04             	add    eax,0x4
  72f3ca:	89 45 10             	mov    DWORD PTR [ebp+0x10],eax
  72f3cd:	3b 45 14             	cmp    eax,DWORD PTR [ebp+0x14]
  72f3d0:	75 d6                	jne    0x72f3a8
  72f3d2:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  72f3d5:	85 c0                	test   eax,eax
  72f3d7:	74 35                	je     0x72f40e
  72f3d9:	39 45 1c             	cmp    DWORD PTR [ebp+0x1c],eax
  72f3dc:	76 30                	jbe    0x72f40e
  72f3de:	8d 48 20             	lea    ecx,[eax+0x20]
  72f3e1:	89 4d 0c             	mov    DWORD PTR [ebp+0xc],ecx
  72f3e4:	8d 71 f0             	lea    esi,[ecx-0x10]
  72f3e7:	8d 7d f0             	lea    edi,[ebp-0x10]
  72f3ea:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f3eb:	8d 45 f0             	lea    eax,[ebp-0x10]
  72f3ee:	50                   	push   eax
  72f3ef:	0f b6 01             	movzx  eax,BYTE PTR [ecx]
  72f3f2:	8b cb                	mov    ecx,ebx
  72f3f4:	50                   	push   eax
  72f3f5:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f3f6:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f3f7:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  72f3f8:	e8 c1 fc ff ff       	call   0x72f0be
  72f3fd:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  72f400:	83 c1 21             	add    ecx,0x21
  72f403:	89 4d 0c             	mov    DWORD PTR [ebp+0xc],ecx
  72f406:	8d 41 e0             	lea    eax,[ecx-0x20]
  72f409:	3b 45 1c             	cmp    eax,DWORD PTR [ebp+0x1c]
  72f40c:	75 d6                	jne    0x72f3e4
  72f40e:	8b cb                	mov    ecx,ebx
  72f410:	e8 c9 f3 ff ff       	call   0x72e7de
  72f415:	5f                   	pop    edi
  72f416:	5e                   	pop    esi
  72f417:	5b                   	pop    ebx
  72f418:	c9                   	leave
  72f419:	c2 18 00             	ret    0x18
