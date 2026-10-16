
agent-research/Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0068e00f <.text+0x28d00f>:
  68e00f:	6a 24                	push   0x24
  68e011:	b8 e2 c6 8e 00       	mov    eax,0x8ec6e2
  68e016:	e8 1d 80 1e 00       	call   0x876038
  68e01b:	8b c1                	mov    eax,ecx
  68e01d:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
  68e020:	8d 70 08             	lea    esi,[eax+0x8]
  68e023:	56                   	push   esi
  68e024:	89 75 d0             	mov    DWORD PTR [ebp-0x30],esi
  68e027:	e8 c0 80 1d 00       	call   0x8660ec
  68e02c:	59                   	pop    ecx
  68e02d:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  68e030:	33 db                	xor    ebx,ebx
  68e032:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  68e035:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  68e038:	89 18                	mov    DWORD PTR [eax],ebx
  68e03a:	85 ff                	test   edi,edi
  68e03c:	75 1e                	jne    0x68e05c
  68e03e:	b3 03                	mov    bl,0x3
  68e040:	8a c3                	mov    al,bl
  68e042:	8a d8                	mov    bl,al
  68e044:	56                   	push   esi
  68e045:	c7 45 fc 07 00 00 00 	mov    DWORD PTR [ebp-0x4],0x7
  68e04c:	e8 b9 80 1d 00       	call   0x86610a
  68e051:	59                   	pop    ecx
  68e052:	8a c3                	mov    al,bl
  68e054:	e8 ad 7f 1e 00       	call   0x876006
  68e059:	c2 18 00             	ret    0x18
  68e05c:	8b 45 ec             	mov    eax,DWORD PTR [ebp-0x14]
  68e05f:	39 07                	cmp    DWORD PTR [edi],eax
  68e061:	74 1e                	je     0x68e081
  68e063:	68 38 a9 9a 00       	push   0x9aa938
  68e068:	53                   	push   ebx
  68e069:	68 08 bc 8f 00       	push   0x8fbc08
  68e06e:	6a 04                	push   0x4
  68e070:	68 a4 82 9a 00       	push   0x9a82a4
  68e075:	e8 c9 57 23 00       	call   0x8c3843
  68e07a:	83 c4 14             	add    esp,0x14
  68e07d:	b3 05                	mov    bl,0x5
  68e07f:	eb bf                	jmp    0x68e040
  68e081:	8d 48 20             	lea    ecx,[eax+0x20]
  68e084:	8a 01                	mov    al,BYTE PTR [ecx]
  68e086:	8d 55 10             	lea    edx,[ebp+0x10]
  68e089:	3a 45 10             	cmp    al,BYTE PTR [ebp+0x10]
  68e08c:	0f 42 d1             	cmovb  edx,ecx
  68e08f:	8a 02                	mov    al,BYTE PTR [edx]
  68e091:	8b 55 ec             	mov    edx,DWORD PTR [ebp-0x14]
  68e094:	88 45 13             	mov    BYTE PTR [ebp+0x13],al
  68e097:	8b 42 34             	mov    eax,DWORD PTR [edx+0x34]
  68e09a:	8b 4a 30             	mov    ecx,DWORD PTR [edx+0x30]
  68e09d:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
  68e0a0:	6b c0 24             	imul   eax,eax,0x24
  68e0a3:	89 4d e8             	mov    DWORD PTR [ebp-0x18],ecx
  68e0a6:	8b 4f 04             	mov    ecx,DWORD PTR [edi+0x4]
  68e0a9:	03 42 30             	add    eax,DWORD PTR [edx+0x30]
  68e0ac:	3b c8                	cmp    ecx,eax
  68e0ae:	74 65                	je     0x68e115
  68e0b0:	8b 45 e8             	mov    eax,DWORD PTR [ebp-0x18]
  68e0b3:	8b 75 e4             	mov    esi,DWORD PTR [ebp-0x1c]
  68e0b6:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
  68e0b9:	0f b6 45 13          	movzx  eax,BYTE PTR [ebp+0x13]
  68e0bd:	89 4d dc             	mov    DWORD PTR [ebp-0x24],ecx
  68e0c0:	89 45 d8             	mov    DWORD PTR [ebp-0x28],eax
  68e0c3:	50                   	push   eax
  68e0c4:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  68e0c7:	89 4d e0             	mov    DWORD PTR [ebp-0x20],ecx
  68e0ca:	ff 75 dc             	push   DWORD PTR [ebp-0x24]
  68e0cd:	e8 40 a0 1e 00       	call   0x878112
  68e0d2:	8b 4d e8             	mov    ecx,DWORD PTR [ebp-0x18]
  68e0d5:	83 c4 0c             	add    esp,0xc
  68e0d8:	8b 55 ec             	mov    edx,DWORD PTR [ebp-0x14]
  68e0db:	89 75 e4             	mov    DWORD PTR [ebp-0x1c],esi
  68e0de:	89 4d e8             	mov    DWORD PTR [ebp-0x18],ecx
  68e0e1:	85 c0                	test   eax,eax
  68e0e3:	79 2a                	jns    0x68e10f
  68e0e5:	8b 4d dc             	mov    ecx,DWORD PTR [ebp-0x24]
  68e0e8:	83 c1 24             	add    ecx,0x24
  68e0eb:	89 5f 08             	mov    DWORD PTR [edi+0x8],ebx
  68e0ee:	89 4f 04             	mov    DWORD PTR [edi+0x4],ecx
  68e0f1:	8b 42 30             	mov    eax,DWORD PTR [edx+0x30]
  68e0f4:	8b 72 34             	mov    esi,DWORD PTR [edx+0x34]
  68e0f7:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
  68e0fa:	6b c6 24             	imul   eax,esi,0x24
  68e0fd:	89 75 e4             	mov    DWORD PTR [ebp-0x1c],esi
  68e100:	89 4d dc             	mov    DWORD PTR [ebp-0x24],ecx
  68e103:	03 42 30             	add    eax,DWORD PTR [edx+0x30]
  68e106:	3b c8                	cmp    ecx,eax
  68e108:	8b 45 d8             	mov    eax,DWORD PTR [ebp-0x28]
  68e10b:	75 b6                	jne    0x68e0c3
  68e10d:	eb 03                	jmp    0x68e112
  68e10f:	8b 4d e0             	mov    ecx,DWORD PTR [ebp-0x20]
  68e112:	8d 72 08             	lea    esi,[edx+0x8]
  68e115:	6b 45 e4 24          	imul   eax,DWORD PTR [ebp-0x1c],0x24
  68e119:	03 45 e8             	add    eax,DWORD PTR [ebp-0x18]
  68e11c:	e9 bc 00 00 00       	jmp    0x68e1dd
  68e121:	8b c3                	mov    eax,ebx
  68e123:	89 5d dc             	mov    DWORD PTR [ebp-0x24],ebx
  68e126:	8b 7d dc             	mov    edi,DWORD PTR [ebp-0x24]
  68e129:	8b 04 81             	mov    eax,DWORD PTR [ecx+eax*4]
  68e12c:	3b 44 ba 3c          	cmp    eax,DWORD PTR [edx+edi*4+0x3c]
  68e130:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  68e133:	75 0e                	jne    0x68e143
  68e135:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
  68e138:	40                   	inc    eax
  68e139:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
  68e13c:	83 f8 04             	cmp    eax,0x4
  68e13f:	75 e5                	jne    0x68e126
  68e141:	eb 13                	jmp    0x68e156
  68e143:	51                   	push   ecx
  68e144:	8b ca                	mov    ecx,edx
  68e146:	e8 9f fd ff ff       	call   0x68deea
  68e14b:	84 c0                	test   al,al
  68e14d:	0f 85 ef fe ff ff    	jne    0x68e042
  68e153:	8b 55 ec             	mov    edx,DWORD PTR [ebp-0x14]
  68e156:	8b 42 60             	mov    eax,DWORD PTR [edx+0x60]
  68e159:	03 47 08             	add    eax,DWORD PTR [edi+0x8]
  68e15c:	8b 4f 04             	mov    ecx,DWORD PTR [edi+0x4]
  68e15f:	89 45 dc             	mov    DWORD PTR [ebp-0x24],eax
  68e162:	89 4d e0             	mov    DWORD PTR [ebp-0x20],ecx
  68e165:	8a 00                	mov    al,BYTE PTR [eax]
  68e167:	88 45 f3             	mov    BYTE PTR [ebp-0xd],al
  68e16a:	84 c0                	test   al,al
  68e16c:	74 5f                	je     0x68e1cd
  68e16e:	8b 45 ec             	mov    eax,DWORD PTR [ebp-0x14]
  68e171:	8b 52 1c             	mov    edx,DWORD PTR [edx+0x1c]
  68e174:	83 c0 28             	add    eax,0x28
  68e177:	2b 51 20             	sub    edx,DWORD PTR [ecx+0x20]
  68e17a:	8d 4d d4             	lea    ecx,[ebp-0x2c]
  68e17d:	89 55 d4             	mov    DWORD PTR [ebp-0x2c],edx
  68e180:	3b 10                	cmp    edx,DWORD PTR [eax]
  68e182:	0f 43 c8             	cmovae ecx,eax
  68e185:	8b 01                	mov    eax,DWORD PTR [ecx]
  68e187:	8b 4d ec             	mov    ecx,DWORD PTR [ebp-0x14]
  68e18a:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
  68e18d:	0f b6 45 f3          	movzx  eax,BYTE PTR [ebp-0xd]
  68e191:	50                   	push   eax
  68e192:	e8 9d 02 00 00       	call   0x68e434
  68e197:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
  68e19a:	0f b6 45 13          	movzx  eax,BYTE PTR [ebp+0x13]
  68e19e:	50                   	push   eax
  68e19f:	8b 45 dc             	mov    eax,DWORD PTR [ebp-0x24]
  68e1a2:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  68e1a5:	40                   	inc    eax
  68e1a6:	50                   	push   eax
  68e1a7:	e8 66 9f 1e 00       	call   0x878112
  68e1ac:	83 c4 0c             	add    esp,0xc
  68e1af:	85 c0                	test   eax,eax
  68e1b1:	74 37                	je     0x68e1ea
  68e1b3:	0f 89 8b fe ff ff    	jns    0x68e044
  68e1b9:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
  68e1bc:	03 47 08             	add    eax,DWORD PTR [edi+0x8]
  68e1bf:	8b 4d e0             	mov    ecx,DWORD PTR [ebp-0x20]
  68e1c2:	8b 55 ec             	mov    edx,DWORD PTR [ebp-0x14]
  68e1c5:	89 47 08             	mov    DWORD PTR [edi+0x8],eax
  68e1c8:	3b 45 e8             	cmp    eax,DWORD PTR [ebp-0x18]
  68e1cb:	72 09                	jb     0x68e1d6
  68e1cd:	83 c1 24             	add    ecx,0x24
  68e1d0:	89 5f 08             	mov    DWORD PTR [edi+0x8],ebx
  68e1d3:	89 4f 04             	mov    DWORD PTR [edi+0x4],ecx
  68e1d6:	6b 42 34 24          	imul   eax,DWORD PTR [edx+0x34],0x24
  68e1da:	03 42 30             	add    eax,DWORD PTR [edx+0x30]
  68e1dd:	3b c8                	cmp    ecx,eax
  68e1df:	0f 85 3c ff ff ff    	jne    0x68e121
  68e1e5:	e9 56 fe ff ff       	jmp    0x68e040
  68e1ea:	ff 75 1c             	push   DWORD PTR [ebp+0x1c]
  68e1ed:	8b 4d ec             	mov    ecx,DWORD PTR [ebp-0x14]
  68e1f0:	ff 75 dc             	push   DWORD PTR [ebp-0x24]
  68e1f3:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  68e1f6:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  68e1f9:	e8 1e 05 00 00       	call   0x68e71c
  68e1fe:	84 c0                	test   al,al
  68e200:	0f 85 3c fe ff ff    	jne    0x68e042
  68e206:	8b 45 e4             	mov    eax,DWORD PTR [ebp-0x1c]
  68e209:	01 47 08             	add    DWORD PTR [edi+0x8],eax
  68e20c:	8b 4d e8             	mov    ecx,DWORD PTR [ebp-0x18]
  68e20f:	39 4f 08             	cmp    DWORD PTR [edi+0x8],ecx
  68e212:	0f 82 2c fe ff ff    	jb     0x68e044
  68e218:	83 47 04 24          	add    DWORD PTR [edi+0x4],0x24
  68e21c:	89 5f 08             	mov    DWORD PTR [edi+0x8],ebx
  68e21f:	e9 20 fe ff ff       	jmp    0x68e044
