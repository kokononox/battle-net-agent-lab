
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072221f <.text+0x32121f>:
  72221f:	6a 1c                	push   0x1c
  722221:	b8 de 2f 8f 00       	mov    eax,0x8f2fde
  722226:	e8 40 3e 15 00       	call   0x87606b
  72222b:	8b f1                	mov    esi,ecx
  72222d:	33 db                	xor    ebx,ebx
  72222f:	c7 45 dc 0c 00 00 00 	mov    DWORD PTR [ebp-0x24],0xc
  722236:	53                   	push   ebx
  722237:	8d 45 e0             	lea    eax,[ebp-0x20]
  72223a:	89 5d e4             	mov    DWORD PTR [ebp-0x1c],ebx
  72223d:	50                   	push   eax
  72223e:	6a 01                	push   0x1
  722240:	68 c8 ec 9b 00       	push   0x9becc8
  722245:	e8 24 a5 18 00       	call   0x8ac76e
  72224a:	85 c0                	test   eax,eax
  72224c:	75 28                	jne    0x722276
  72224e:	ff 15 48 b2 8f 00    	call   DWORD PTR ds:0x8fb248
  722254:	50                   	push   eax
  722255:	68 1c ed 9b 00       	push   0x9bed1c
  72225a:	53                   	push   ebx
  72225b:	68 08 bc 8f 00       	push   0x8fbc08
  722260:	6a 04                	push   0x4
  722262:	68 38 ba 9b 00       	push   0x9bba38
  722267:	e8 d7 15 1a 00       	call   0x8c3843
  72226c:	83 c4 18             	add    esp,0x18
  72226f:	32 c0                	xor    al,al
  722271:	e9 e1 00 00 00       	jmp    0x722357
  722276:	8d 45 dc             	lea    eax,[ebp-0x24]
  722279:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
  72227c:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72227f:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  722282:	e8 c2 71 14 00       	call   0x869449
  722287:	59                   	pop    ecx
  722288:	8d 04 45 02 00 00 00 	lea    eax,[eax*2+0x2]
  72228f:	e8 bc 4e 15 00       	call   0x877150
  722294:	8b c4                	mov    eax,esp
  722296:	6a ff                	push   0xffffffff
  722298:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72229b:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
  72229e:	68 ff ff ff 3f       	push   0x3fffffff
  7222a3:	50                   	push   eax
  7222a4:	e8 3c 70 14 00       	call   0x8692e5
  7222a9:	8b 3d 48 b2 8f 00    	mov    edi,DWORD PTR ds:0x8fb248
  7222af:	83 c4 10             	add    esp,0x10
  7222b2:	89 5d e8             	mov    DWORD PTR [ebp-0x18],ebx
  7222b5:	ff 75 ec             	push   DWORD PTR [ebp-0x14]
  7222b8:	8d 45 dc             	lea    eax,[ebp-0x24]
  7222bb:	53                   	push   ebx
  7222bc:	50                   	push   eax
  7222bd:	ff 15 38 b4 8f 00    	call   DWORD PTR ds:0x8fb438
  7222c3:	89 46 04             	mov    DWORD PTR [esi+0x4],eax
  7222c6:	85 c0                	test   eax,eax
  7222c8:	75 34                	jne    0x7222fe
  7222ca:	ff d7                	call   edi
  7222cc:	8b c8                	mov    ecx,eax
  7222ce:	83 f9 05             	cmp    ecx,0x5
  7222d1:	75 59                	jne    0x72232c
  7222d3:	ff 75 ec             	push   DWORD PTR [ebp-0x14]
  7222d6:	53                   	push   ebx
  7222d7:	68 00 00 10 00       	push   0x100000
  7222dc:	ff 15 3c b4 8f 00    	call   DWORD PTR ds:0x8fb43c
  7222e2:	89 46 04             	mov    DWORD PTR [esi+0x4],eax
  7222e5:	85 c0                	test   eax,eax
  7222e7:	75 15                	jne    0x7222fe
  7222e9:	ff d7                	call   edi
  7222eb:	8b c8                	mov    ecx,eax
  7222ed:	83 f9 02             	cmp    ecx,0x2
  7222f0:	75 33                	jne    0x722325
  7222f2:	8b 45 e8             	mov    eax,DWORD PTR [ebp-0x18]
  7222f5:	40                   	inc    eax
  7222f6:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
  7222f9:	83 f8 05             	cmp    eax,0x5
  7222fc:	72 b7                	jb     0x7222b5
  7222fe:	39 5e 04             	cmp    DWORD PTR [esi+0x4],ebx
  722301:	75 47                	jne    0x72234a
  722303:	ff d7                	call   edi
  722305:	50                   	push   eax
  722306:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  722309:	68 b0 ed 9b 00       	push   0x9bedb0
  72230e:	53                   	push   ebx
  72230f:	68 08 bc 8f 00       	push   0x8fbc08
  722314:	6a 04                	push   0x4
  722316:	68 38 ba 9b 00       	push   0x9bba38
  72231b:	e8 23 15 1a 00       	call   0x8c3843
  722320:	83 c4 1c             	add    esp,0x1c
  722323:	eb 27                	jmp    0x72234c
  722325:	b8 88 ed 9b 00       	mov    eax,0x9bed88
  72232a:	eb 05                	jmp    0x722331
  72232c:	b8 5c ed 9b 00       	mov    eax,0x9bed5c
  722331:	51                   	push   ecx
  722332:	50                   	push   eax
  722333:	53                   	push   ebx
  722334:	68 08 bc 8f 00       	push   0x8fbc08
  722339:	6a 04                	push   0x4
  72233b:	68 38 ba 9b 00       	push   0x9bba38
  722340:	e8 fe 14 1a 00       	call   0x8c3843
  722345:	83 c4 18             	add    esp,0x18
  722348:	eb 02                	jmp    0x72234c
  72234a:	b3 01                	mov    bl,0x1
  72234c:	ff 75 e0             	push   DWORD PTR [ebp-0x20]
  72234f:	ff 15 98 b2 8f 00    	call   DWORD PTR ds:0x8fb298
  722355:	8a c3                	mov    al,bl
  722357:	8d 65 c8             	lea    esp,[ebp-0x38]
  72235a:	e8 bb 3c 15 00       	call   0x87601a
  72235f:	c2 04 00             	ret    0x4
