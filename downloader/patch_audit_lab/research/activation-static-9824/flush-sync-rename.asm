
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071f1f1 <.text+0x31e1f1>:
  71f1f1:	55                   	push   ebp
  71f1f2:	8b ec                	mov    ebp,esp
  71f1f4:	81 ec 30 04 00 00    	sub    esp,0x430
  71f1fa:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71f1ff:	33 c5                	xor    eax,ebp
  71f201:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71f204:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  71f207:	8b 4d 1c             	mov    ecx,DWORD PTR [ebp+0x1c]
  71f20a:	53                   	push   ebx
  71f20b:	8b 5d 14             	mov    ebx,DWORD PTR [ebp+0x14]
  71f20e:	89 85 d0 fb ff ff    	mov    DWORD PTR [ebp-0x430],eax
  71f214:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  71f217:	56                   	push   esi
  71f218:	50                   	push   eax
  71f219:	89 8d d4 fb ff ff    	mov    DWORD PTR [ebp-0x42c],ecx
  71f21f:	e8 9e 5b 14 00       	call   0x864dc2
  71f224:	8b f0                	mov    esi,eax
  71f226:	59                   	pop    ecx
  71f227:	85 f6                	test   esi,esi
  71f229:	74 3c                	je     0x71f267
  71f22b:	8d 85 ec fe ff ff    	lea    eax,[ebp-0x114]
  71f231:	56                   	push   esi
  71f232:	50                   	push   eax
  71f233:	e8 e9 d7 f5 ff       	call   0x67ca21
  71f238:	8d 85 ec fe ff ff    	lea    eax,[ebp-0x114]
  71f23e:	50                   	push   eax
  71f23f:	56                   	push   esi
  71f240:	53                   	push   ebx
  71f241:	68 54 e6 9b 00       	push   0x9be654
  71f246:	6a 00                	push   0x0
  71f248:	68 08 bc 8f 00       	push   0x8fbc08
  71f24d:	6a 04                	push   0x4
  71f24f:	68 38 ba 9b 00       	push   0x9bba38
  71f254:	e8 ea 45 1a 00       	call   0x8c3843
  71f259:	56                   	push   esi
  71f25a:	e8 c2 7f ff ff       	call   0x717221
  71f25f:	83 c4 2c             	add    esp,0x2c
  71f262:	e9 de 00 00 00       	jmp    0x71f345
  71f267:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  71f26a:	57                   	push   edi
  71f26b:	33 ff                	xor    edi,edi
  71f26d:	21 bd dc fb ff ff    	and    DWORD PTR [ebp-0x424],edi
  71f273:	40                   	inc    eax
  71f274:	89 85 d8 fb ff ff    	mov    DWORD PTR [ebp-0x428],eax
  71f27a:	8b 8d d4 fb ff ff    	mov    ecx,DWORD PTR [ebp-0x42c]
  71f280:	50                   	push   eax
  71f281:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  71f284:	89 01                	mov    DWORD PTR [ecx],eax
  71f286:	8d 45 ec             	lea    eax,[ebp-0x14]
  71f289:	6a 0f                	push   0xf
  71f28b:	50                   	push   eax
  71f28c:	e8 42 fe ff ff       	call   0x71f0d3
  71f291:	8d 45 ec             	lea    eax,[ebp-0x14]
  71f294:	50                   	push   eax
  71f295:	ff b5 d0 fb ff ff    	push   DWORD PTR [ebp-0x430]
  71f29b:	8d 85 e0 fb ff ff    	lea    eax,[ebp-0x420]
  71f2a1:	50                   	push   eax
  71f2a2:	e8 b7 11 de ff       	call   0x50045e
  71f2a7:	8d 85 e0 fb ff ff    	lea    eax,[ebp-0x420]
  71f2ad:	50                   	push   eax
  71f2ae:	53                   	push   ebx
  71f2af:	e8 9f 5f 14 00       	call   0x865253
  71f2b4:	8b f0                	mov    esi,eax
  71f2b6:	83 c4 24             	add    esp,0x24
  71f2b9:	85 f6                	test   esi,esi
  71f2bb:	0f 84 81 00 00 00    	je     0x71f342
  71f2c1:	8d 85 ec fe ff ff    	lea    eax,[ebp-0x114]
  71f2c7:	56                   	push   esi
  71f2c8:	50                   	push   eax
  71f2c9:	e8 53 d7 f5 ff       	call   0x67ca21
  71f2ce:	8d 85 ec fe ff ff    	lea    eax,[ebp-0x114]
  71f2d4:	50                   	push   eax
  71f2d5:	56                   	push   esi
  71f2d6:	8d 85 e0 fb ff ff    	lea    eax,[ebp-0x420]
  71f2dc:	50                   	push   eax
  71f2dd:	53                   	push   ebx
  71f2de:	68 88 e6 9b 00       	push   0x9be688
  71f2e3:	6a 00                	push   0x0
  71f2e5:	68 08 bc 8f 00       	push   0x8fbc08
  71f2ea:	6a 04                	push   0x4
  71f2ec:	68 38 ba 9b 00       	push   0x9bba38
  71f2f1:	e8 4d 45 1a 00       	call   0x8c3843
  71f2f6:	56                   	push   esi
  71f2f7:	e8 25 7f ff ff       	call   0x717221
  71f2fc:	8b 8d dc fb ff ff    	mov    ecx,DWORD PTR [ebp-0x424]
  71f302:	83 c4 30             	add    esp,0x30
  71f305:	8b f8                	mov    edi,eax
  71f307:	41                   	inc    ecx
  71f308:	8b 85 d8 fb ff ff    	mov    eax,DWORD PTR [ebp-0x428]
  71f30e:	40                   	inc    eax
  71f30f:	89 8d dc fb ff ff    	mov    DWORD PTR [ebp-0x424],ecx
  71f315:	89 85 d8 fb ff ff    	mov    DWORD PTR [ebp-0x428],eax
  71f31b:	83 f9 03             	cmp    ecx,0x3
  71f31e:	0f 82 56 ff ff ff    	jb     0x71f27a
  71f324:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  71f327:	68 c8 e6 9b 00       	push   0x9be6c8
  71f32c:	6a 00                	push   0x0
  71f32e:	68 08 bc 8f 00       	push   0x8fbc08
  71f333:	6a 04                	push   0x4
  71f335:	68 38 ba 9b 00       	push   0x9bba38
  71f33a:	e8 04 45 1a 00       	call   0x8c3843
  71f33f:	83 c4 18             	add    esp,0x18
  71f342:	8b c7                	mov    eax,edi
  71f344:	5f                   	pop    edi
  71f345:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  71f348:	5e                   	pop    esi
  71f349:	33 cd                	xor    ecx,ebp
  71f34b:	5b                   	pop    ebx
  71f34c:	e8 a7 6c 15 00       	call   0x875ff8
  71f351:	c9                   	leave
  71f352:	c3                   	ret
