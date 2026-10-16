
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00722fc0 <.text+0x321fc0>:
  722fc0:	55                   	push   ebp
  722fc1:	8b ec                	mov    ebp,esp
  722fc3:	51                   	push   ecx
  722fc4:	51                   	push   ecx
  722fc5:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  722fc8:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  722fcb:	53                   	push   ebx
  722fcc:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
  722fcf:	8d 91 ef be ad de    	lea    edx,[ecx-0x21524111]
  722fd5:	03 10                	add    edx,DWORD PTR [eax]
  722fd7:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  722fda:	56                   	push   esi
  722fdb:	57                   	push   edi
  722fdc:	8b f2                	mov    esi,edx
  722fde:	8b fa                	mov    edi,edx
  722fe0:	03 10                	add    edx,DWORD PTR [eax]
  722fe2:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  722fe5:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  722fe8:	6a 0c                	push   0xc
  722fea:	58                   	pop    eax
  722feb:	f6 c3 03             	test   bl,0x3
  722fee:	0f 85 d8 00 00 00    	jne    0x7230cc
  722ff4:	3b c8                	cmp    ecx,eax
  722ff6:	0f 86 80 00 00 00    	jbe    0x72307c
  722ffc:	8d 41 f3             	lea    eax,[ecx-0xd]
  722fff:	33 d2                	xor    edx,edx
  723001:	6a 0c                	push   0xc
  723003:	59                   	pop    ecx
  723004:	f7 f1                	div    ecx
  723006:	8b 55 f8             	mov    edx,DWORD PTR [ebp-0x8]
  723009:	40                   	inc    eax
  72300a:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  72300d:	03 53 08             	add    edx,DWORD PTR [ebx+0x8]
  723010:	8b 03                	mov    eax,DWORD PTR [ebx]
  723012:	03 7b 04             	add    edi,DWORD PTR [ebx+0x4]
  723015:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  723018:	2b 45 f8             	sub    eax,DWORD PTR [ebp-0x8]
  72301b:	03 c6                	add    eax,esi
  72301d:	c1 c2 04             	rol    edx,0x4
  723020:	8b 75 f8             	mov    esi,DWORD PTR [ebp-0x8]
  723023:	33 d0                	xor    edx,eax
  723025:	03 f7                	add    esi,edi
  723027:	8b c2                	mov    eax,edx
  723029:	2b fa                	sub    edi,edx
  72302b:	c1 c0 06             	rol    eax,0x6
  72302e:	33 c7                	xor    eax,edi
  723030:	03 d6                	add    edx,esi
  723032:	2b f0                	sub    esi,eax
  723034:	8b c8                	mov    ecx,eax
  723036:	c1 c1 08             	rol    ecx,0x8
  723039:	03 c2                	add    eax,edx
  72303b:	33 ce                	xor    ecx,esi
  72303d:	2b d1                	sub    edx,ecx
  72303f:	8b f1                	mov    esi,ecx
  723041:	c1 c6 10             	rol    esi,0x10
  723044:	03 c8                	add    ecx,eax
  723046:	33 f2                	xor    esi,edx
  723048:	8b fe                	mov    edi,esi
  72304a:	2b c6                	sub    eax,esi
  72304c:	c1 cf 0d             	ror    edi,0xd
  72304f:	03 f1                	add    esi,ecx
  723051:	33 f8                	xor    edi,eax
  723053:	2b cf                	sub    ecx,edi
  723055:	8b d7                	mov    edx,edi
  723057:	c1 c2 04             	rol    edx,0x4
  72305a:	03 fe                	add    edi,esi
  72305c:	33 d1                	xor    edx,ecx
  72305e:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  723061:	6a 0c                	push   0xc
  723063:	58                   	pop    eax
  723064:	2b c8                	sub    ecx,eax
  723066:	03 d8                	add    ebx,eax
  723068:	83 6d 08 01          	sub    DWORD PTR [ebp+0x8],0x1
  72306c:	89 4d 0c             	mov    DWORD PTR [ebp+0xc],ecx
  72306f:	75 9c                	jne    0x72300d
  723071:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  723074:	3b c8                	cmp    ecx,eax
  723076:	0f 87 e7 02 00 00    	ja     0x723363
  72307c:	ff 24 8d c0 33 72 00 	jmp    DWORD PTR [ecx*4+0x7233c0]
  723083:	03 53 08             	add    edx,DWORD PTR [ebx+0x8]
  723086:	03 7b 04             	add    edi,DWORD PTR [ebx+0x4]
  723089:	03 33                	add    esi,DWORD PTR [ebx]
  72308b:	e9 d0 02 00 00       	jmp    0x723360
  723090:	8b 43 08             	mov    eax,DWORD PTR [ebx+0x8]
  723093:	25 ff ff ff 00       	and    eax,0xffffff
  723098:	03 d0                	add    edx,eax
  72309a:	eb ea                	jmp    0x723086
  72309c:	0f b7 43 08          	movzx  eax,WORD PTR [ebx+0x8]
  7230a0:	eb f6                	jmp    0x723098
  7230a2:	0f b6 43 08          	movzx  eax,BYTE PTR [ebx+0x8]
  7230a6:	eb f0                	jmp    0x723098
  7230a8:	8b 43 04             	mov    eax,DWORD PTR [ebx+0x4]
  7230ab:	25 ff ff ff 00       	and    eax,0xffffff
  7230b0:	03 f8                	add    edi,eax
  7230b2:	eb d5                	jmp    0x723089
  7230b4:	0f b7 43 04          	movzx  eax,WORD PTR [ebx+0x4]
  7230b8:	eb f6                	jmp    0x7230b0
  7230ba:	0f b6 43 04          	movzx  eax,BYTE PTR [ebx+0x4]
  7230be:	eb f0                	jmp    0x7230b0
  7230c0:	8b 03                	mov    eax,DWORD PTR [ebx]
  7230c2:	25 ff ff ff 00       	and    eax,0xffffff
  7230c7:	e9 92 02 00 00       	jmp    0x72335e
  7230cc:	f6 c3 01             	test   bl,0x1
  7230cf:	0f 85 45 01 00 00    	jne    0x72321a
  7230d5:	3b c8                	cmp    ecx,eax
  7230d7:	0f 86 a3 00 00 00    	jbe    0x723180
  7230dd:	8d 41 f3             	lea    eax,[ecx-0xd]
  7230e0:	33 d2                	xor    edx,edx
  7230e2:	6a 0c                	push   0xc
  7230e4:	59                   	pop    ecx
  7230e5:	f7 f1                	div    ecx
  7230e7:	40                   	inc    eax
  7230e8:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  7230eb:	0f b7 53 06          	movzx  edx,WORD PTR [ebx+0x6]
  7230ef:	0f b7 4b 04          	movzx  ecx,WORD PTR [ebx+0x4]
  7230f3:	0f b7 73 08          	movzx  esi,WORD PTR [ebx+0x8]
  7230f7:	03 cf                	add    ecx,edi
  7230f9:	03 75 f8             	add    esi,DWORD PTR [ebp-0x8]
  7230fc:	0f b7 03             	movzx  eax,WORD PTR [ebx]
  7230ff:	c1 e2 10             	shl    edx,0x10
  723102:	03 d1                	add    edx,ecx
  723104:	0f b7 4b 0a          	movzx  ecx,WORD PTR [ebx+0xa]
  723108:	c1 e1 10             	shl    ecx,0x10
  72310b:	03 f1                	add    esi,ecx
  72310d:	0f b7 4b 02          	movzx  ecx,WORD PTR [ebx+0x2]
  723111:	c1 e1 10             	shl    ecx,0x10
  723114:	8b fe                	mov    edi,esi
  723116:	03 c8                	add    ecx,eax
  723118:	c1 c7 04             	rol    edi,0x4
  72311b:	2b ce                	sub    ecx,esi
  72311d:	03 f2                	add    esi,edx
  72311f:	03 4d fc             	add    ecx,DWORD PTR [ebp-0x4]
  723122:	33 f9                	xor    edi,ecx
  723124:	2b d7                	sub    edx,edi
  723126:	8b c7                	mov    eax,edi
  723128:	03 fe                	add    edi,esi
  72312a:	c1 c0 06             	rol    eax,0x6
  72312d:	33 c2                	xor    eax,edx
  72312f:	2b f0                	sub    esi,eax
  723131:	8b c8                	mov    ecx,eax
  723133:	c1 c1 08             	rol    ecx,0x8
  723136:	03 c7                	add    eax,edi
  723138:	33 ce                	xor    ecx,esi
  72313a:	2b f9                	sub    edi,ecx
  72313c:	8b f1                	mov    esi,ecx
  72313e:	c1 c6 10             	rol    esi,0x10
  723141:	03 c8                	add    ecx,eax
  723143:	33 f7                	xor    esi,edi
  723145:	8b fe                	mov    edi,esi
  723147:	2b c6                	sub    eax,esi
  723149:	c1 cf 0d             	ror    edi,0xd
  72314c:	03 f1                	add    esi,ecx
  72314e:	33 f8                	xor    edi,eax
  723150:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  723153:	2b cf                	sub    ecx,edi
  723155:	8b d7                	mov    edx,edi
  723157:	c1 c2 04             	rol    edx,0x4
  72315a:	03 fe                	add    edi,esi
  72315c:	33 d1                	xor    edx,ecx
  72315e:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  723161:	6a 0c                	push   0xc
  723163:	58                   	pop    eax
  723164:	2b c8                	sub    ecx,eax
  723166:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  723169:	03 d8                	add    ebx,eax
  72316b:	89 4d 0c             	mov    DWORD PTR [ebp+0xc],ecx
  72316e:	83 6d 08 01          	sub    DWORD PTR [ebp+0x8],0x1
  723172:	0f 85 73 ff ff ff    	jne    0x7230eb
  723178:	3b c8                	cmp    ecx,eax
  72317a:	0f 87 e3 01 00 00    	ja     0x723363
  723180:	ff 24 8d f4 33 72 00 	jmp    DWORD PTR [ecx*4+0x7233f4]
  723187:	0f b7 43 08          	movzx  eax,WORD PTR [ebx+0x8]
  72318b:	0f b7 4b 0a          	movzx  ecx,WORD PTR [ebx+0xa]
  72318f:	03 d0                	add    edx,eax
  723191:	0f b7 43 04          	movzx  eax,WORD PTR [ebx+0x4]
  723195:	c1 e1 10             	shl    ecx,0x10
  723198:	03 f8                	add    edi,eax
  72319a:	0f b7 03             	movzx  eax,WORD PTR [ebx]
  72319d:	03 d1                	add    edx,ecx
  72319f:	0f b7 4b 06          	movzx  ecx,WORD PTR [ebx+0x6]
  7231a3:	03 f0                	add    esi,eax
  7231a5:	c1 e1 10             	shl    ecx,0x10
  7231a8:	03 f9                	add    edi,ecx
  7231aa:	0f b7 4b 02          	movzx  ecx,WORD PTR [ebx+0x2]
  7231ae:	c1 e1 10             	shl    ecx,0x10
  7231b1:	03 f1                	add    esi,ecx
  7231b3:	e9 a8 01 00 00       	jmp    0x723360
  7231b8:	0f b6 43 0a          	movzx  eax,BYTE PTR [ebx+0xa]
  7231bc:	c1 e0 10             	shl    eax,0x10
  7231bf:	03 d0                	add    edx,eax
  7231c1:	0f b7 43 08          	movzx  eax,WORD PTR [ebx+0x8]
  7231c5:	03 d0                	add    edx,eax
  7231c7:	0f b7 4b 06          	movzx  ecx,WORD PTR [ebx+0x6]
  7231cb:	0f b7 43 04          	movzx  eax,WORD PTR [ebx+0x4]
  7231cf:	c1 e1 10             	shl    ecx,0x10
  7231d2:	03 f8                	add    edi,eax
  7231d4:	03 f9                	add    edi,ecx
  7231d6:	0f b7 4b 02          	movzx  ecx,WORD PTR [ebx+0x2]
  7231da:	0f b7 03             	movzx  eax,WORD PTR [ebx]
  7231dd:	c1 e1 10             	shl    ecx,0x10
  7231e0:	03 c6                	add    eax,esi
  7231e2:	03 c1                	add    eax,ecx
  7231e4:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  7231e7:	e9 77 01 00 00       	jmp    0x723363
  7231ec:	0f b6 43 08          	movzx  eax,BYTE PTR [ebx+0x8]
  7231f0:	eb d3                	jmp    0x7231c5
  7231f2:	0f b6 43 06          	movzx  eax,BYTE PTR [ebx+0x6]
  7231f6:	c1 e0 10             	shl    eax,0x10
  7231f9:	03 f8                	add    edi,eax
  7231fb:	0f b7 43 04          	movzx  eax,WORD PTR [ebx+0x4]
  7231ff:	03 f8                	add    edi,eax
  723201:	eb d3                	jmp    0x7231d6
  723203:	0f b6 43 04          	movzx  eax,BYTE PTR [ebx+0x4]
  723207:	eb f6                	jmp    0x7231ff
  723209:	0f b6 43 02          	movzx  eax,BYTE PTR [ebx+0x2]
  72320d:	c1 e0 10             	shl    eax,0x10
  723210:	03 f0                	add    esi,eax
  723212:	0f b7 03             	movzx  eax,WORD PTR [ebx]
  723215:	e9 44 01 00 00       	jmp    0x72335e
  72321a:	3b c8                	cmp    ecx,eax
  72321c:	0f 86 d5 00 00 00    	jbe    0x7232f7
  723222:	8d 41 f3             	lea    eax,[ecx-0xd]
  723225:	33 d2                	xor    edx,edx
  723227:	6a 0c                	push   0xc
  723229:	59                   	pop    ecx
  72322a:	f7 f1                	div    ecx
  72322c:	40                   	inc    eax
  72322d:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  723230:	0f b6 53 07          	movzx  edx,BYTE PTR [ebx+0x7]
  723234:	0f b6 4b 06          	movzx  ecx,BYTE PTR [ebx+0x6]
  723238:	0f b6 43 05          	movzx  eax,BYTE PTR [ebx+0x5]
  72323c:	0f b6 73 04          	movzx  esi,BYTE PTR [ebx+0x4]
  723240:	c1 e2 08             	shl    edx,0x8
  723243:	03 f7                	add    esi,edi
  723245:	03 d1                	add    edx,ecx
  723247:	0f b6 4b 0b          	movzx  ecx,BYTE PTR [ebx+0xb]
  72324b:	c1 e1 08             	shl    ecx,0x8
  72324e:	c1 e2 08             	shl    edx,0x8
  723251:	03 d0                	add    edx,eax
  723253:	0f b6 43 0a          	movzx  eax,BYTE PTR [ebx+0xa]
  723257:	03 c8                	add    ecx,eax
  723259:	c1 e2 08             	shl    edx,0x8
  72325c:	0f b6 43 09          	movzx  eax,BYTE PTR [ebx+0x9]
  723260:	03 f2                	add    esi,edx
  723262:	0f b6 53 08          	movzx  edx,BYTE PTR [ebx+0x8]
  723266:	03 55 f8             	add    edx,DWORD PTR [ebp-0x8]
  723269:	c1 e1 08             	shl    ecx,0x8
  72326c:	03 c8                	add    ecx,eax
  72326e:	0f b6 43 02          	movzx  eax,BYTE PTR [ebx+0x2]
  723272:	c1 e1 08             	shl    ecx,0x8
  723275:	03 d1                	add    edx,ecx
  723277:	0f b6 4b 03          	movzx  ecx,BYTE PTR [ebx+0x3]
  72327b:	c1 e1 08             	shl    ecx,0x8
  72327e:	8b fa                	mov    edi,edx
  723280:	03 c8                	add    ecx,eax
  723282:	c1 c7 04             	rol    edi,0x4
  723285:	0f b6 43 01          	movzx  eax,BYTE PTR [ebx+0x1]
  723289:	c1 e1 08             	shl    ecx,0x8
  72328c:	03 c8                	add    ecx,eax
  72328e:	0f b6 03             	movzx  eax,BYTE PTR [ebx]
  723291:	c1 e1 08             	shl    ecx,0x8
  723294:	03 c8                	add    ecx,eax
  723296:	2b ca                	sub    ecx,edx
  723298:	03 d6                	add    edx,esi
  72329a:	03 4d fc             	add    ecx,DWORD PTR [ebp-0x4]
  72329d:	33 f9                	xor    edi,ecx
  72329f:	2b f7                	sub    esi,edi
  7232a1:	8b c7                	mov    eax,edi
  7232a3:	03 fa                	add    edi,edx
  7232a5:	c1 c0 06             	rol    eax,0x6
  7232a8:	33 c6                	xor    eax,esi
  7232aa:	2b d0                	sub    edx,eax
  7232ac:	8b c8                	mov    ecx,eax
  7232ae:	c1 c1 08             	rol    ecx,0x8
  7232b1:	03 c7                	add    eax,edi
  7232b3:	33 ca                	xor    ecx,edx
  7232b5:	2b f9                	sub    edi,ecx
  7232b7:	8b f1                	mov    esi,ecx
  7232b9:	c1 c6 10             	rol    esi,0x10
  7232bc:	03 c8                	add    ecx,eax
  7232be:	33 f7                	xor    esi,edi
  7232c0:	8b fe                	mov    edi,esi
  7232c2:	2b c6                	sub    eax,esi
  7232c4:	c1 cf 0d             	ror    edi,0xd
  7232c7:	03 f1                	add    esi,ecx
  7232c9:	33 f8                	xor    edi,eax
  7232cb:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  7232ce:	2b cf                	sub    ecx,edi
  7232d0:	8b d7                	mov    edx,edi
  7232d2:	c1 c2 04             	rol    edx,0x4
  7232d5:	03 fe                	add    edi,esi
  7232d7:	33 d1                	xor    edx,ecx
  7232d9:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
  7232dc:	6a 0c                	push   0xc
  7232de:	58                   	pop    eax
  7232df:	2b c8                	sub    ecx,eax
  7232e1:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  7232e4:	03 d8                	add    ebx,eax
  7232e6:	89 4d 0c             	mov    DWORD PTR [ebp+0xc],ecx
  7232e9:	83 6d 08 01          	sub    DWORD PTR [ebp+0x8],0x1
  7232ed:	0f 85 3d ff ff ff    	jne    0x723230
  7232f3:	3b c8                	cmp    ecx,eax
  7232f5:	77 6c                	ja     0x723363
  7232f7:	ff 24 8d 28 34 72 00 	jmp    DWORD PTR [ecx*4+0x723428]
  7232fe:	0f b6 43 0b          	movzx  eax,BYTE PTR [ebx+0xb]
  723302:	c1 e0 18             	shl    eax,0x18
  723305:	03 d0                	add    edx,eax
  723307:	0f b6 43 0a          	movzx  eax,BYTE PTR [ebx+0xa]
  72330b:	c1 e0 10             	shl    eax,0x10
  72330e:	03 d0                	add    edx,eax
  723310:	0f b6 43 09          	movzx  eax,BYTE PTR [ebx+0x9]
  723314:	c1 e0 08             	shl    eax,0x8
  723317:	03 d0                	add    edx,eax
  723319:	0f b6 43 08          	movzx  eax,BYTE PTR [ebx+0x8]
  72331d:	03 d0                	add    edx,eax
  72331f:	0f b6 43 07          	movzx  eax,BYTE PTR [ebx+0x7]
  723323:	c1 e0 18             	shl    eax,0x18
  723326:	03 f8                	add    edi,eax
  723328:	0f b6 43 06          	movzx  eax,BYTE PTR [ebx+0x6]
  72332c:	c1 e0 10             	shl    eax,0x10
  72332f:	03 f8                	add    edi,eax
  723331:	0f b6 43 05          	movzx  eax,BYTE PTR [ebx+0x5]
  723335:	c1 e0 08             	shl    eax,0x8
  723338:	03 f8                	add    edi,eax
  72333a:	0f b6 43 04          	movzx  eax,BYTE PTR [ebx+0x4]
  72333e:	03 f8                	add    edi,eax
  723340:	0f b6 43 03          	movzx  eax,BYTE PTR [ebx+0x3]
  723344:	c1 e0 18             	shl    eax,0x18
  723347:	03 f0                	add    esi,eax
  723349:	0f b6 43 02          	movzx  eax,BYTE PTR [ebx+0x2]
  72334d:	c1 e0 10             	shl    eax,0x10
  723350:	03 f0                	add    esi,eax
  723352:	0f b6 43 01          	movzx  eax,BYTE PTR [ebx+0x1]
  723356:	c1 e0 08             	shl    eax,0x8
  723359:	03 f0                	add    esi,eax
  72335b:	0f b6 03             	movzx  eax,BYTE PTR [ebx]
  72335e:	03 f0                	add    esi,eax
  723360:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  723363:	33 d7                	xor    edx,edi
  723365:	8b c7                	mov    eax,edi
  723367:	c1 c0 0e             	rol    eax,0xe
  72336a:	2b d0                	sub    edx,eax
  72336c:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  72336f:	8b c2                	mov    eax,edx
  723371:	33 55 fc             	xor    edx,DWORD PTR [ebp-0x4]
  723374:	8b 4d f8             	mov    ecx,DWORD PTR [ebp-0x8]
  723377:	c1 c0 0b             	rol    eax,0xb
  72337a:	2b d0                	sub    edx,eax
  72337c:	8b c2                	mov    eax,edx
  72337e:	33 fa                	xor    edi,edx
  723380:	c1 c8 07             	ror    eax,0x7
  723383:	2b f8                	sub    edi,eax
  723385:	33 cf                	xor    ecx,edi
  723387:	8b c7                	mov    eax,edi
  723389:	c1 c0 10             	rol    eax,0x10
  72338c:	2b c8                	sub    ecx,eax
  72338e:	8b c1                	mov    eax,ecx
  723390:	89 4d f8             	mov    DWORD PTR [ebp-0x8],ecx
  723393:	c1 c0 04             	rol    eax,0x4
  723396:	33 ca                	xor    ecx,edx
  723398:	8b 55 f8             	mov    edx,DWORD PTR [ebp-0x8]
  72339b:	2b c8                	sub    ecx,eax
  72339d:	8b c1                	mov    eax,ecx
  72339f:	33 f9                	xor    edi,ecx
  7233a1:	c1 c0 0e             	rol    eax,0xe
  7233a4:	2b f8                	sub    edi,eax
  7233a6:	8b c7                	mov    eax,edi
  7233a8:	33 d7                	xor    edx,edi
  7233aa:	c1 c8 08             	ror    eax,0x8
  7233ad:	2b d0                	sub    edx,eax
  7233af:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  7233b2:	89 10                	mov    DWORD PTR [eax],edx
  7233b4:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  7233b7:	89 38                	mov    DWORD PTR [eax],edi
  7233b9:	5f                   	pop    edi
  7233ba:	5e                   	pop    esi
  7233bb:	5b                   	pop    ebx
  7233bc:	c9                   	leave
  7233bd:	c3                   	ret
