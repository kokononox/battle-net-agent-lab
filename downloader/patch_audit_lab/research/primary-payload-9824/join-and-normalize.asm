
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0086367d <.text+0x46267d>:
  86367d:	55                   	push   ebp
  86367e:	8b ec                	mov    ebp,esp
  863680:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  863683:	56                   	push   esi
  863684:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  863687:	57                   	push   edi
  863688:	85 c0                	test   eax,eax
  86368a:	74 11                	je     0x86369d
  86368c:	3b c6                	cmp    eax,esi
  86368e:	74 0d                	je     0x86369d
  863690:	50                   	push   eax
  863691:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  863694:	56                   	push   esi
  863695:	e8 7d 88 e1 ff       	call   0x67bf17
  86369a:	83 c4 0c             	add    esp,0xc
  86369d:	8b ce                	mov    ecx,esi
  86369f:	8d 51 01             	lea    edx,[ecx+0x1]
  8636a2:	8a 01                	mov    al,BYTE PTR [ecx]
  8636a4:	41                   	inc    ecx
  8636a5:	84 c0                	test   al,al
  8636a7:	75 f9                	jne    0x8636a2
  8636a9:	2b ca                	sub    ecx,edx
  8636ab:	8d 04 31             	lea    eax,[ecx+esi*1]
  8636ae:	3b c6                	cmp    eax,esi
  8636b0:	76 24                	jbe    0x8636d6
  8636b2:	8a 48 ff             	mov    cl,BYTE PTR [eax-0x1]
  8636b5:	80 f9 5c             	cmp    cl,0x5c
  8636b8:	75 06                	jne    0x8636c0
  8636ba:	c6 40 ff 2f          	mov    BYTE PTR [eax-0x1],0x2f
  8636be:	eb 16                	jmp    0x8636d6
  8636c0:	80 f9 2f             	cmp    cl,0x2f
  8636c3:	74 11                	je     0x8636d6
  8636c5:	68 58 c3 8f 00       	push   0x8fc358
  8636ca:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  8636cd:	56                   	push   esi
  8636ce:	e8 42 04 00 00       	call   0x863b15
  8636d3:	83 c4 0c             	add    esp,0xc
  8636d6:	8b 7d 14             	mov    edi,DWORD PTR [ebp+0x14]
  8636d9:	85 ff                	test   edi,edi
  8636db:	74 20                	je     0x8636fd
  8636dd:	80 3f 00             	cmp    BYTE PTR [edi],0x0
  8636e0:	74 1b                	je     0x8636fd
  8636e2:	57                   	push   edi
  8636e3:	e8 e9 00 00 00       	call   0x8637d1
  8636e8:	59                   	pop    ecx
  8636e9:	84 c0                	test   al,al
  8636eb:	74 03                	je     0x8636f0
  8636ed:	c6 06 00             	mov    BYTE PTR [esi],0x0
  8636f0:	57                   	push   edi
  8636f1:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  8636f4:	56                   	push   esi
  8636f5:	e8 1b 04 00 00       	call   0x863b15
  8636fa:	83 c4 0c             	add    esp,0xc
  8636fd:	56                   	push   esi
  8636fe:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  863701:	56                   	push   esi
  863702:	e8 84 02 00 00       	call   0x86398b
  863707:	83 c4 0c             	add    esp,0xc
  86370a:	5f                   	pop    edi
  86370b:	5e                   	pop    esi
  86370c:	5d                   	pop    ebp
  86370d:	c3                   	ret
