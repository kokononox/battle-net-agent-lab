
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071e0dd <.text+0x31d0dd>:
  71e0dd:	6a 08                	push   0x8
  71e0df:	b8 24 2d 8f 00       	mov    eax,0x8f2d24
  71e0e4:	e8 4f 7f 15 00       	call   0x876038
  71e0e9:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  71e0ec:	33 db                	xor    ebx,ebx
  71e0ee:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  71e0f1:	56                   	push   esi
  71e0f2:	88 18                	mov    BYTE PTR [eax],bl
  71e0f4:	e8 18 43 00 00       	call   0x722411
  71e0f9:	59                   	pop    ecx
  71e0fa:	83 f8 01             	cmp    eax,0x1
  71e0fd:	75 23                	jne    0x71e122
  71e0ff:	56                   	push   esi
  71e100:	68 44 e5 9b 00       	push   0x9be544
  71e105:	53                   	push   ebx
  71e106:	68 08 bc 8f 00       	push   0x8fbc08
  71e10b:	6a 04                	push   0x4
  71e10d:	68 38 ba 9b 00       	push   0x9bba38
  71e112:	e8 2c 57 1a 00       	call   0x8c3843
  71e117:	83 c4 18             	add    esp,0x18
  71e11a:	6a 0d                	push   0xd
  71e11c:	58                   	pop    eax
  71e11d:	e9 6d 01 00 00       	jmp    0x71e28f
  71e122:	85 c0                	test   eax,eax
  71e124:	75 1b                	jne    0x71e141
  71e126:	56                   	push   esi
  71e127:	68 e4 cf 9b 00       	push   0x9bcfe4
  71e12c:	53                   	push   ebx
  71e12d:	68 08 bc 8f 00       	push   0x8fbc08
  71e132:	6a 03                	push   0x3
  71e134:	68 38 ba 9b 00       	push   0x9bba38
  71e139:	e8 05 57 1a 00       	call   0x8c3843
  71e13e:	83 c4 18             	add    esp,0x18
  71e141:	ff 75 20             	push   DWORD PTR [ebp+0x20]
  71e144:	8b 7d 18             	mov    edi,DWORD PTR [ebp+0x18]
  71e147:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  71e14a:	57                   	push   edi
  71e14b:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  71e14e:	50                   	push   eax
  71e14f:	56                   	push   esi
  71e150:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  71e153:	e8 c8 fb ff ff       	call   0x71dd20
  71e158:	83 c4 18             	add    esp,0x18
  71e15b:	85 c0                	test   eax,eax
  71e15d:	0f 85 2c 01 00 00    	jne    0x71e28f
  71e163:	8b 4d 10             	mov    ecx,DWORD PTR [ebp+0x10]
  71e166:	6a 04                	push   0x4
  71e168:	5a                   	pop    edx
  71e169:	0f ae f0             	mfence
  71e16c:	8b 77 18             	mov    esi,DWORD PTR [edi+0x18]
  71e16f:	3b ca                	cmp    ecx,edx
  71e171:	0f 84 09 01 00 00    	je     0x71e280
  71e177:	6a 05                	push   0x5
  71e179:	58                   	pop    eax
  71e17a:	3b c8                	cmp    ecx,eax
  71e17c:	0f 84 fe 00 00 00    	je     0x71e280
  71e182:	89 7d ec             	mov    DWORD PTR [ebp-0x14],edi
  71e185:	c6 45 f0 01          	mov    BYTE PTR [ebp-0x10],0x1
  71e189:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  71e18c:	39 16                	cmp    DWORD PTR [esi],edx
  71e18e:	0f 82 b5 00 00 00    	jb     0x71e249
  71e194:	39 06                	cmp    DWORD PTR [esi],eax
  71e196:	0f 87 ad 00 00 00    	ja     0x71e249
  71e19c:	81 be 08 01 00 00 b8 	cmp    DWORD PTR [esi+0x108],0x2ab8
  71e1a3:	2a 00 00 
  71e1a6:	74 1e                	je     0x71e1c6
  71e1a8:	68 a0 e5 9b 00       	push   0x9be5a0
  71e1ad:	53                   	push   ebx
  71e1ae:	68 08 bc 8f 00       	push   0x8fbc08
  71e1b3:	52                   	push   edx
  71e1b4:	68 38 ba 9b 00       	push   0x9bba38
  71e1b9:	e8 85 56 1a 00       	call   0x8c3843
  71e1be:	83 c4 14             	add    esp,0x14
  71e1c1:	e9 9e 00 00 00       	jmp    0x71e264
  71e1c6:	39 06                	cmp    DWORD PTR [esi],eax
  71e1c8:	75 3a                	jne    0x71e204
  71e1ca:	8b 86 50 01 00 00    	mov    eax,DWORD PTR [esi+0x150]
  71e1d0:	a8 01                	test   al,0x1
  71e1d2:	74 30                	je     0x71e204
  71e1d4:	50                   	push   eax
  71e1d5:	68 f8 e4 9b 00       	push   0x9be4f8
  71e1da:	53                   	push   ebx
  71e1db:	68 08 bc 8f 00       	push   0x8fbc08
  71e1e0:	52                   	push   edx
  71e1e1:	68 38 ba 9b 00       	push   0x9bba38
  71e1e6:	e8 58 56 1a 00       	call   0x8c3843
  71e1eb:	8b 4d 1c             	mov    ecx,DWORD PTR [ebp+0x1c]
  71e1ee:	57                   	push   edi
  71e1ef:	56                   	push   esi
  71e1f0:	c6 01 01             	mov    BYTE PTR [ecx],0x1
  71e1f3:	8b 47 18             	mov    eax,DWORD PTR [edi+0x18]
  71e1f6:	89 07                	mov    DWORD PTR [edi],eax
  71e1f8:	e8 3d fa ff ff       	call   0x71dc3a
  71e1fd:	83 c4 20             	add    esp,0x20
  71e200:	6a 0b                	push   0xb
  71e202:	eb 62                	jmp    0x71e266
  71e204:	39 9e 0c 01 00 00    	cmp    DWORD PTR [esi+0x10c],ebx
  71e20a:	74 17                	je     0x71e223
  71e20c:	80 7e 08 00          	cmp    BYTE PTR [esi+0x8],0x0
  71e210:	74 11                	je     0x71e223
  71e212:	89 37                	mov    DWORD PTR [edi],esi
  71e214:	8b 86 0c 01 00 00    	mov    eax,DWORD PTR [esi+0x10c]
  71e21a:	03 c6                	add    eax,esi
  71e21c:	89 47 04             	mov    DWORD PTR [edi+0x4],eax
  71e21f:	8a c3                	mov    al,bl
  71e221:	eb 47                	jmp    0x71e26a
  71e223:	68 d0 e5 9b 00       	push   0x9be5d0
  71e228:	53                   	push   ebx
  71e229:	68 08 bc 8f 00       	push   0x8fbc08
  71e22e:	6a 03                	push   0x3
  71e230:	68 38 ba 9b 00       	push   0x9bba38
  71e235:	e8 09 56 1a 00       	call   0x8c3843
  71e23a:	8b 4d 1c             	mov    ecx,DWORD PTR [ebp+0x1c]
  71e23d:	83 c4 14             	add    esp,0x14
  71e240:	33 c0                	xor    eax,eax
  71e242:	40                   	inc    eax
  71e243:	88 01                	mov    BYTE PTR [ecx],al
  71e245:	6a 0b                	push   0xb
  71e247:	eb 20                	jmp    0x71e269
  71e249:	ff 36                	push   DWORD PTR [esi]
  71e24b:	68 74 e5 9b 00       	push   0x9be574
  71e250:	53                   	push   ebx
  71e251:	68 08 bc 8f 00       	push   0x8fbc08
  71e256:	52                   	push   edx
  71e257:	68 38 ba 9b 00       	push   0x9bba38
  71e25c:	e8 e2 55 1a 00       	call   0x8c3843
  71e261:	83 c4 18             	add    esp,0x18
  71e264:	6a 05                	push   0x5
  71e266:	33 c0                	xor    eax,eax
  71e268:	40                   	inc    eax
  71e269:	5b                   	pop    ebx
  71e26a:	c7 45 fc 06 00 00 00 	mov    DWORD PTR [ebp-0x4],0x6
  71e271:	84 c0                	test   al,al
  71e273:	74 07                	je     0x71e27c
  71e275:	57                   	push   edi
  71e276:	e8 1a 00 00 00       	call   0x71e295
  71e27b:	59                   	pop    ecx
  71e27c:	8b c3                	mov    eax,ebx
  71e27e:	eb 0f                	jmp    0x71e28f
  71e280:	89 37                	mov    DWORD PTR [edi],esi
  71e282:	8b 86 0c 01 00 00    	mov    eax,DWORD PTR [esi+0x10c]
  71e288:	03 c6                	add    eax,esi
  71e28a:	89 47 04             	mov    DWORD PTR [edi+0x4],eax
  71e28d:	33 c0                	xor    eax,eax
  71e28f:	e8 72 7d 15 00       	call   0x876006
  71e294:	c3                   	ret
