
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00712030 <.text+0x311030>:
  712030:	68 30 01 00 00       	push   0x130
  712035:	b8 91 20 8f 00       	mov    eax,0x8f2091
  71203a:	e8 2c 40 16 00       	call   0x87606b
  71203f:	8b f9                	mov    edi,ecx
  712041:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  712044:	33 db                	xor    ebx,ebx
  712046:	89 85 dc fe ff ff    	mov    DWORD PTR [ebp-0x124],eax
  71204c:	43                   	inc    ebx
  71204d:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  712050:	89 85 e0 fe ff ff    	mov    DWORD PTR [ebp-0x120],eax
  712056:	8d 47 10             	lea    eax,[edi+0x10]
  712059:	89 85 ec fe ff ff    	mov    DWORD PTR [ebp-0x114],eax
  71205f:	89 9d e4 fe ff ff    	mov    DWORD PTR [ebp-0x11c],ebx
  712065:	84 5f 0c             	test   BYTE PTR [edi+0xc],bl
  712068:	75 02                	jne    0x71206c
  71206a:	8b 00                	mov    eax,DWORD PTR [eax]
  71206c:	53                   	push   ebx
  71206d:	50                   	push   eax
  71206e:	e8 df 26 15 00       	call   0x864752
  712073:	8b f0                	mov    esi,eax
  712075:	59                   	pop    ecx
  712076:	59                   	pop    ecx
  712077:	85 f6                	test   esi,esi
  712079:	74 4c                	je     0x7120c7
  71207b:	8d 85 f0 fe ff ff    	lea    eax,[ebp-0x110]
  712081:	56                   	push   esi
  712082:	50                   	push   eax
  712083:	e8 99 a9 f6 ff       	call   0x67ca21
  712088:	8b 85 ec fe ff ff    	mov    eax,DWORD PTR [ebp-0x114]
  71208e:	59                   	pop    ecx
  71208f:	59                   	pop    ecx
  712090:	84 5f 0c             	test   BYTE PTR [edi+0xc],bl
  712093:	75 03                	jne    0x712098
  712095:	8b 47 10             	mov    eax,DWORD PTR [edi+0x10]
  712098:	8d 8d f0 fe ff ff    	lea    ecx,[ebp-0x110]
  71209e:	51                   	push   ecx
  71209f:	56                   	push   esi
  7120a0:	50                   	push   eax
  7120a1:	68 b0 d1 9b 00       	push   0x9bd1b0
  7120a6:	6a 00                	push   0x0
  7120a8:	68 08 bc 8f 00       	push   0x8fbc08
  7120ad:	6a 04                	push   0x4
  7120af:	68 38 ba 9b 00       	push   0x9bba38
  7120b4:	e8 8a 17 1b 00       	call   0x8c3843
  7120b9:	56                   	push   esi
  7120ba:	e8 62 51 00 00       	call   0x717221
  7120bf:	83 c4 24             	add    esp,0x24
  7120c2:	e9 24 02 00 00       	jmp    0x7122eb
  7120c7:	33 db                	xor    ebx,ebx
  7120c9:	8d 47 48             	lea    eax,[edi+0x48]
  7120cc:	89 9d ec fe ff ff    	mov    DWORD PTR [ebp-0x114],ebx
  7120d2:	89 85 d0 fe ff ff    	mov    DWORD PTR [ebp-0x130],eax
  7120d8:	f6 47 0c 01          	test   BYTE PTR [edi+0xc],0x1
  7120dc:	8d 77 10             	lea    esi,[edi+0x10]
  7120df:	88 9d eb fe ff ff    	mov    BYTE PTR [ebp-0x115],bl
  7120e5:	8b ce                	mov    ecx,esi
  7120e7:	75 02                	jne    0x7120eb
  7120e9:	8b 0e                	mov    ecx,DWORD PTR [esi]
  7120eb:	8d 95 eb fe ff ff    	lea    edx,[ebp-0x115]
  7120f1:	52                   	push   edx
  7120f2:	50                   	push   eax
  7120f3:	ff 77 04             	push   DWORD PTR [edi+0x4]
  7120f6:	ff 77 2c             	push   DWORD PTR [edi+0x2c]
  7120f9:	51                   	push   ecx
  7120fa:	ff 37                	push   DWORD PTR [edi]
  7120fc:	e8 a1 bf 00 00       	call   0x71e0a2
  712101:	83 c4 18             	add    esp,0x18
  712104:	85 c0                	test   eax,eax
  712106:	74 48                	je     0x712150
  712108:	38 9d eb fe ff ff    	cmp    BYTE PTR [ebp-0x115],bl
  71210e:	0f 84 d7 01 00 00    	je     0x7122eb
  712114:	53                   	push   ebx
  712115:	68 00 2d 31 01       	push   0x1312d00
  71211a:	e8 42 12 15 00       	call   0x863361
  71211f:	68 e8 d1 9b 00       	push   0x9bd1e8
  712124:	53                   	push   ebx
  712125:	68 08 bc 8f 00       	push   0x8fbc08
  71212a:	6a 03                	push   0x3
  71212c:	68 38 ba 9b 00       	push   0x9bba38
  712131:	e8 0d 17 1b 00       	call   0x8c3843
  712136:	8b 85 ec fe ff ff    	mov    eax,DWORD PTR [ebp-0x114]
  71213c:	83 c4 1c             	add    esp,0x1c
  71213f:	40                   	inc    eax
  712140:	89 85 ec fe ff ff    	mov    DWORD PTR [ebp-0x114],eax
  712146:	83 f8 03             	cmp    eax,0x3
  712149:	8d 47 48             	lea    eax,[edi+0x48]
  71214c:	72 8a                	jb     0x7120d8
  71214e:	eb 09                	jmp    0x712159
  712150:	83 bd ec fe ff ff 03 	cmp    DWORD PTR [ebp-0x114],0x3
  712157:	72 22                	jb     0x71217b
  712159:	68 08 d2 9b 00       	push   0x9bd208
  71215e:	53                   	push   ebx
  71215f:	68 08 bc 8f 00       	push   0x8fbc08
  712164:	6a 04                	push   0x4
  712166:	68 38 ba 9b 00       	push   0x9bba38
  71216b:	e8 d3 16 1b 00       	call   0x8c3843
  712170:	83 c4 14             	add    esp,0x14
  712173:	6a 0b                	push   0xb
  712175:	58                   	pop    eax
  712176:	e9 70 01 00 00       	jmp    0x7122eb
