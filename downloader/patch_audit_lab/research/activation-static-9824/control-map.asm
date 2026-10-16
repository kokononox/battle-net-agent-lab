
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072e265 <.text+0x32d265>:
  72e265:	68 3c 01 00 00       	push   0x13c
  72e26a:	b8 29 35 8f 00       	mov    eax,0x8f3529
  72e26f:	e8 f7 7d 14 00       	call   0x87606b
  72e274:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  72e277:	8d 8d e4 fe ff ff    	lea    ecx,[ebp-0x11c]
  72e27d:	8b 7d 0c             	mov    edi,DWORD PTR [ebp+0xc]
  72e280:	8b 75 20             	mov    esi,DWORD PTR [ebp+0x20]
  72e283:	89 85 dc fe ff ff    	mov    DWORD PTR [ebp-0x124],eax
  72e289:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  72e28c:	89 85 e0 fe ff ff    	mov    DWORD PTR [ebp-0x120],eax
  72e292:	8b 45 24             	mov    eax,DWORD PTR [ebp+0x24]
  72e295:	89 85 d8 fe ff ff    	mov    DWORD PTR [ebp-0x128],eax
  72e29b:	e8 24 13 00 00       	call   0x72f5c4
  72e2a0:	33 db                	xor    ebx,ebx
  72e2a2:	8d 8d e8 fe ff ff    	lea    ecx,[ebp-0x118]
  72e2a8:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  72e2ab:	e8 14 13 00 00       	call   0x72f5c4
  72e2b0:	8d 8d b8 fe ff ff    	lea    ecx,[ebp-0x148]
  72e2b6:	c6 45 fc 01          	mov    BYTE PTR [ebp-0x4],0x1
  72e2ba:	e8 a3 e4 13 00       	call   0x86c762
  72e2bf:	8d 85 e4 fe ff ff    	lea    eax,[ebp-0x11c]
  72e2c5:	c6 45 fc 02          	mov    BYTE PTR [ebp-0x4],0x2
  72e2c9:	50                   	push   eax
  72e2ca:	57                   	push   edi
  72e2cb:	88 9d ef fe ff ff    	mov    BYTE PTR [ebp-0x111],bl
  72e2d1:	e8 47 fd ff ff       	call   0x72e01d
  72e2d6:	59                   	pop    ecx
  72e2d7:	59                   	pop    ecx
  72e2d8:	85 c0                	test   eax,eax
  72e2da:	0f 85 92 01 00 00    	jne    0x72e472
  72e2e0:	8d 85 ef fe ff ff    	lea    eax,[ebp-0x111]
  72e2e6:	50                   	push   eax
  72e2e7:	8d 85 e8 fe ff ff    	lea    eax,[ebp-0x118]
  72e2ed:	50                   	push   eax
  72e2ee:	56                   	push   esi
  72e2ef:	57                   	push   edi
  72e2f0:	e8 7b fb ff ff       	call   0x72de70
  72e2f5:	83 c4 10             	add    esp,0x10
  72e2f8:	85 c0                	test   eax,eax
  72e2fa:	0f 85 72 01 00 00    	jne    0x72e472
  72e300:	83 7d 14 04          	cmp    DWORD PTR [ebp+0x14],0x4
  72e304:	0f 84 a5 00 00 00    	je     0x72e3af
  72e30a:	83 7d 14 05          	cmp    DWORD PTR [ebp+0x14],0x5
  72e30e:	0f 84 9b 00 00 00    	je     0x72e3af
  72e314:	8a 85 ef fe ff ff    	mov    al,BYTE PTR [ebp-0x111]
  72e31a:	88 85 ef fe ff ff    	mov    BYTE PTR [ebp-0x111],al
  72e320:	84 c0                	test   al,al
  72e322:	74 2e                	je     0x72e352
  72e324:	53                   	push   ebx
  72e325:	53                   	push   ebx
  72e326:	53                   	push   ebx
  72e327:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  72e32a:	ff b5 e8 fe ff ff    	push   DWORD PTR [ebp-0x118]
  72e330:	ff 15 50 b4 8f 00    	call   DWORD PTR ds:0x8fb450
  72e336:	85 c0                	test   eax,eax
  72e338:	0f 84 0a 01 00 00    	je     0x72e448
  72e33e:	ff b5 e8 fe ff ff    	push   DWORD PTR [ebp-0x118]
  72e344:	ff 15 4c b4 8f 00    	call   DWORD PTR ds:0x8fb44c
  72e34a:	85 c0                	test   eax,eax
  72e34c:	0f 84 f6 00 00 00    	je     0x72e448
  72e352:	53                   	push   ebx
  72e353:	53                   	push   ebx
  72e354:	53                   	push   ebx
  72e355:	53                   	push   ebx
  72e356:	6a 01                	push   0x1
  72e358:	8d 85 e8 fe ff ff    	lea    eax,[ebp-0x118]
  72e35e:	50                   	push   eax
  72e35f:	8d 85 b8 fe ff ff    	lea    eax,[ebp-0x148]
  72e365:	50                   	push   eax
  72e366:	e8 7a e5 13 00       	call   0x86c8e5
  72e36b:	8b f0                	mov    esi,eax
  72e36d:	83 c4 1c             	add    esp,0x1c
  72e370:	85 f6                	test   esi,esi
  72e372:	74 74                	je     0x72e3e8
  72e374:	8d 85 f0 fe ff ff    	lea    eax,[ebp-0x110]
  72e37a:	56                   	push   esi
  72e37b:	50                   	push   eax
  72e37c:	e8 a0 e6 f4 ff       	call   0x67ca21
  72e381:	8d 85 f0 fe ff ff    	lea    eax,[ebp-0x110]
  72e387:	50                   	push   eax
  72e388:	56                   	push   esi
  72e389:	57                   	push   edi
  72e38a:	68 c0 fe 9b 00       	push   0x9bfec0
  72e38f:	53                   	push   ebx
  72e390:	68 08 bc 8f 00       	push   0x8fbc08
  72e395:	6a 04                	push   0x4
  72e397:	68 38 ba 9b 00       	push   0x9bba38
  72e39c:	e8 a2 54 19 00       	call   0x8c3843
  72e3a1:	56                   	push   esi
  72e3a2:	e8 a2 fe ff ff       	call   0x72e249
  72e3a7:	83 c4 2c             	add    esp,0x2c
  72e3aa:	e9 c3 00 00 00       	jmp    0x72e472
  72e3af:	8a 85 ef fe ff ff    	mov    al,BYTE PTR [ebp-0x111]
  72e3b5:	88 85 ef fe ff ff    	mov    BYTE PTR [ebp-0x111],al
  72e3bb:	84 c0                	test   al,al
  72e3bd:	0f 85 61 ff ff ff    	jne    0x72e324
  72e3c3:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  72e3c6:	68 40 fe 9b 00       	push   0x9bfe40
  72e3cb:	53                   	push   ebx
  72e3cc:	68 08 bc 8f 00       	push   0x8fbc08
  72e3d1:	6a 04                	push   0x4
  72e3d3:	68 38 ba 9b 00       	push   0x9bba38
  72e3d8:	e8 66 54 19 00       	call   0x8c3843
  72e3dd:	83 c4 18             	add    esp,0x18
  72e3e0:	6a 0b                	push   0xb
  72e3e2:	58                   	pop    eax
  72e3e3:	e9 8a 00 00 00       	jmp    0x72e472
  72e3e8:	8a 85 ef fe ff ff    	mov    al,BYTE PTR [ebp-0x111]
  72e3ee:	84 c0                	test   al,al
  72e3f0:	74 3c                	je     0x72e42e
  72e3f2:	8b b5 e0 fe ff ff    	mov    esi,DWORD PTR [ebp-0x120]
  72e3f8:	56                   	push   esi
  72e3f9:	ff b5 dc fe ff ff    	push   DWORD PTR [ebp-0x124]
  72e3ff:	ff b5 b8 fe ff ff    	push   DWORD PTR [ebp-0x148]
  72e405:	e8 86 b3 14 00       	call   0x879790
  72e40a:	8b 85 c0 fe ff ff    	mov    eax,DWORD PTR [ebp-0x140]
  72e410:	2b c6                	sub    eax,esi
  72e412:	50                   	push   eax
  72e413:	8b 85 b8 fe ff ff    	mov    eax,DWORD PTR [ebp-0x148]
  72e419:	03 c6                	add    eax,esi
  72e41b:	53                   	push   ebx
  72e41c:	50                   	push   eax
  72e41d:	e8 ee b8 14 00       	call   0x879d10
  72e422:	0f ae f0             	mfence
  72e425:	8a 85 ef fe ff ff    	mov    al,BYTE PTR [ebp-0x111]
  72e42b:	83 c4 18             	add    esp,0x18
  72e42e:	8b 8d d8 fe ff ff    	mov    ecx,DWORD PTR [ebp-0x128]
  72e434:	88 41 14             	mov    BYTE PTR [ecx+0x14],al
  72e437:	8d 85 b8 fe ff ff    	lea    eax,[ebp-0x148]
  72e43d:	50                   	push   eax
  72e43e:	83 c1 18             	add    ecx,0x18
  72e441:	e8 3e e3 13 00       	call   0x86c784
  72e446:	eb 2c                	jmp    0x72e474
  72e448:	ff 15 48 b2 8f 00    	call   DWORD PTR ds:0x8fb248
  72e44e:	8b f0                	mov    esi,eax
  72e450:	56                   	push   esi
  72e451:	57                   	push   edi
  72e452:	68 88 fe 9b 00       	push   0x9bfe88
  72e457:	53                   	push   ebx
  72e458:	68 08 bc 8f 00       	push   0x8fbc08
  72e45d:	6a 04                	push   0x4
  72e45f:	68 38 ba 9b 00       	push   0x9bba38
  72e464:	e8 da 53 19 00       	call   0x8c3843
  72e469:	56                   	push   esi
  72e46a:	e8 da fd ff ff       	call   0x72e249
  72e46f:	83 c4 20             	add    esp,0x20
  72e472:	8b d8                	mov    ebx,eax
  72e474:	8d 8d b8 fe ff ff    	lea    ecx,[ebp-0x148]
  72e47a:	e8 fd e2 13 00       	call   0x86c77c
  72e47f:	8d 8d e8 fe ff ff    	lea    ecx,[ebp-0x118]
  72e485:	e8 c0 67 13 00       	call   0x864c4a
  72e48a:	8d 8d e4 fe ff ff    	lea    ecx,[ebp-0x11c]
  72e490:	e8 b5 67 13 00       	call   0x864c4a
  72e495:	8b c3                	mov    eax,ebx
  72e497:	e8                   	.byte 0xe8
  72e498:	7e 7b                	jle    0x72e515
  72e49a:	14                   	.byte 0x14
