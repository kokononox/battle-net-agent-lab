
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071d1f3 <.text+0x31c1f3>:
  71d1f3:	68 40 03 00 00       	push   0x340
  71d1f8:	b8 ed 2c 8f 00       	mov    eax,0x8f2ced
  71d1fd:	e8 69 8e 15 00       	call   0x87606b
  71d202:	89 8d d0 fc ff ff    	mov    DWORD PTR [ebp-0x330],ecx
  71d208:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71d20b:	8d 71 30             	lea    esi,[ecx+0x30]
  71d20e:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  71d211:	8b 5d 1c             	mov    ebx,DWORD PTR [ebp+0x1c]
  71d214:	89 85 d8 fc ff ff    	mov    DWORD PTR [ebp-0x328],eax
  71d21a:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  71d21d:	89 85 dc fc ff ff    	mov    DWORD PTR [ebp-0x324],eax
  71d223:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  71d226:	83 23 00             	and    DWORD PTR [ebx],0x0
  71d229:	89 85 c4 fc ff ff    	mov    DWORD PTR [ebp-0x33c],eax
  71d22f:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  71d232:	89 bd c8 fc ff ff    	mov    DWORD PTR [ebp-0x338],edi
  71d238:	89 85 c8 fc ff ff    	mov    DWORD PTR [ebp-0x338],eax
  71d23e:	8a 45 20             	mov    al,BYTE PTR [ebp+0x20]
  71d241:	88 85 d4 fc ff ff    	mov    BYTE PTR [ebp-0x32c],al
  71d247:	8b 45 24             	mov    eax,DWORD PTR [ebp+0x24]
  71d24a:	89 85 bc fc ff ff    	mov    DWORD PTR [ebp-0x344],eax
  71d250:	8b 45 28             	mov    eax,DWORD PTR [ebp+0x28]
  71d253:	56                   	push   esi
  71d254:	89 85 c0 fc ff ff    	mov    DWORD PTR [ebp-0x340],eax
  71d25a:	89 b5 b4 fc ff ff    	mov    DWORD PTR [ebp-0x34c],esi
  71d260:	e8 87 8e 14 00       	call   0x8660ec
  71d265:	59                   	pop    ecx
  71d266:	ff b5 d4 fc ff ff    	push   DWORD PTR [ebp-0x32c]
  71d26c:	8b 8d d0 fc ff ff    	mov    ecx,DWORD PTR [ebp-0x330]
  71d272:	8d 85 e0 fc ff ff    	lea    eax,[ebp-0x320]
  71d278:	ff b5 dc fc ff ff    	push   DWORD PTR [ebp-0x324]
  71d27e:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  71d282:	ff b5 d8 fc ff ff    	push   DWORD PTR [ebp-0x328]
  71d288:	50                   	push   eax
  71d289:	e8 ab 08 01 00       	call   0x72db39
  71d28e:	8b 8d e0 fc ff ff    	mov    ecx,DWORD PTR [ebp-0x320]
  71d294:	c6 45 fc 01          	mov    BYTE PTR [ebp-0x4],0x1
  71d298:	85 c9                	test   ecx,ecx
  71d29a:	74 15                	je     0x71d2b1
  71d29c:	83 a5 e0 fc ff ff 00 	and    DWORD PTR [ebp-0x320],0x0
  71d2a3:	89 0f                	mov    DWORD PTR [edi],ecx
  71d2a5:	c7 45 fc 03 00 00 00 	mov    DWORD PTR [ebp-0x4],0x3
  71d2ac:	e9 1a 01 00 00       	jmp    0x71d3cb
  71d2b1:	68 0c 03 00 00       	push   0x30c
  71d2b6:	8d 85 e4 fc ff ff    	lea    eax,[ebp-0x31c]
  71d2bc:	6a 00                	push   0x0
  71d2be:	50                   	push   eax
  71d2bf:	e8 4c ca 15 00       	call   0x879d10
  71d2c4:	ff b5 c4 fc ff ff    	push   DWORD PTR [ebp-0x33c]
  71d2ca:	8d 85 e4 fc ff ff    	lea    eax,[ebp-0x31c]
  71d2d0:	ff b5 dc fc ff ff    	push   DWORD PTR [ebp-0x324]
  71d2d6:	ff b5 d8 fc ff ff    	push   DWORD PTR [ebp-0x328]
  71d2dc:	68 0c 03 00 00       	push   0x30c
  71d2e1:	50                   	push   eax
  71d2e2:	e8 d3 fe ff ff       	call   0x71d1ba
  71d2e7:	b9 0c 03 00 00       	mov    ecx,0x30c
  71d2ec:	83 c4 20             	add    esp,0x20
  71d2ef:	3b c1                	cmp    eax,ecx
  71d2f1:	72 4b                	jb     0x71d33e
  71d2f3:	51                   	push   ecx
  71d2f4:	50                   	push   eax
  71d2f5:	68 6c cb 9b 00       	push   0x9bcb6c
  71d2fa:	6a 00                	push   0x0
  71d2fc:	68 08 bc 8f 00       	push   0x8fbc08
  71d301:	6a 04                	push   0x4
  71d303:	68 38 ba 9b 00       	push   0x9bba38
  71d308:	e8 36 65 1a 00       	call   0x8c3843
  71d30d:	c7 03 0a 00 00 00    	mov    DWORD PTR [ebx],0xa
  71d313:	83 c4 1c             	add    esp,0x1c
  71d316:	83 27 00             	and    DWORD PTR [edi],0x0
  71d319:	83 bd e0 fc ff ff 00 	cmp    DWORD PTR [ebp-0x320],0x0
  71d320:	c6 45 fc 04          	mov    BYTE PTR [ebp-0x4],0x4
  71d324:	74 0c                	je     0x71d332
  71d326:	ff b5 e0 fc ff ff    	push   DWORD PTR [ebp-0x320]
  71d32c:	e8 64 e1 f5 ff       	call   0x67b495
  71d331:	59                   	pop    ecx
  71d332:	c7 45 fc 05 00 00 00 	mov    DWORD PTR [ebp-0x4],0x5
  71d339:	e9 8d 00 00 00       	jmp    0x71d3cb
  71d33e:	8b 8d d0 fc ff ff    	mov    ecx,DWORD PTR [ebp-0x330]
  71d344:	8d 85 e4 fc ff ff    	lea    eax,[ebp-0x31c]
  71d34a:	53                   	push   ebx
  71d34b:	ff b5 c0 fc ff ff    	push   DWORD PTR [ebp-0x340]
  71d351:	ff b5 bc fc ff ff    	push   DWORD PTR [ebp-0x344]
  71d357:	ff b5 d4 fc ff ff    	push   DWORD PTR [ebp-0x32c]
  71d35d:	ff b5 c8 fc ff ff    	push   DWORD PTR [ebp-0x338]
  71d363:	50                   	push   eax
  71d364:	ff b5 dc fc ff ff    	push   DWORD PTR [ebp-0x324]
  71d36a:	8d 85 cc fc ff ff    	lea    eax,[ebp-0x334]
  71d370:	ff b5 d8 fc ff ff    	push   DWORD PTR [ebp-0x328]
  71d376:	50                   	push   eax
  71d377:	e8 21 05 01 00       	call   0x72d89d
  71d37c:	8b 95 e0 fc ff ff    	mov    edx,DWORD PTR [ebp-0x320]
  71d382:	8b 08                	mov    ecx,DWORD PTR [eax]
  71d384:	89 8d e0 fc ff ff    	mov    DWORD PTR [ebp-0x320],ecx
  71d38a:	83 20 00             	and    DWORD PTR [eax],0x0
  71d38d:	c6 45 fc 06          	mov    BYTE PTR [ebp-0x4],0x6
  71d391:	85 d2                	test   edx,edx
  71d393:	74 07                	je     0x71d39c
  71d395:	52                   	push   edx
  71d396:	e8 fa e0 f5 ff       	call   0x67b495
  71d39b:	59                   	pop    ecx
  71d39c:	83 bd cc fc ff ff 00 	cmp    DWORD PTR [ebp-0x334],0x0
  71d3a3:	c6 45 fc 07          	mov    BYTE PTR [ebp-0x4],0x7
  71d3a7:	74 0c                	je     0x71d3b5
  71d3a9:	ff b5 cc fc ff ff    	push   DWORD PTR [ebp-0x334]
  71d3af:	e8 e1 e0 f5 ff       	call   0x67b495
  71d3b4:	59                   	pop    ecx
  71d3b5:	8b 85 e0 fc ff ff    	mov    eax,DWORD PTR [ebp-0x320]
  71d3bb:	83 a5 e0 fc ff ff 00 	and    DWORD PTR [ebp-0x320],0x0
  71d3c2:	89 07                	mov    DWORD PTR [edi],eax
  71d3c4:	c7 45 fc 09 00 00 00 	mov    DWORD PTR [ebp-0x4],0x9
  71d3cb:	56                   	push   esi
  71d3cc:	e8 39 8d 14 00       	call   0x86610a
  71d3d1:	59                   	pop    ecx
  71d3d2:	8b c7                	mov    eax,edi
  71d3d4:	e8 41 8c 15 00       	call   0x87601a
  71d3d9:	c2 24 00             	ret    0x24
