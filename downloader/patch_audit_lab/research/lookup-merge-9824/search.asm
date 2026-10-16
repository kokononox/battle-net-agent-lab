
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072d46c <.text+0x32c46c>:
  72d46c:	55                   	push   ebp
  72d46d:	8b ec                	mov    ebp,esp
  72d46f:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  72d472:	53                   	push   ebx
  72d473:	8b 5d 18             	mov    ebx,DWORD PTR [ebp+0x18]
  72d476:	56                   	push   esi
  72d477:	57                   	push   edi
  72d478:	8b 7d 14             	mov    edi,DWORD PTR [ebp+0x14]
  72d47b:	83 27 00             	and    DWORD PTR [edi],0x0
  72d47e:	89 03                	mov    DWORD PTR [ebx],eax
  72d480:	eb 3d                	jmp    0x72d4bf
  72d482:	03 f0                	add    esi,eax
  72d484:	d1 ee                	shr    esi,1
  72d486:	8b c6                	mov    eax,esi
  72d488:	c1 e0 05             	shl    eax,0x5
  72d48b:	03 45 0c             	add    eax,DWORD PTR [ebp+0xc]
  72d48e:	50                   	push   eax
  72d48f:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72d492:	89 45 14             	mov    DWORD PTR [ebp+0x14],eax
  72d495:	e8 05 60 fd ff       	call   0x70349f
  72d49a:	59                   	pop    ecx
  72d49b:	59                   	pop    ecx
  72d49c:	84 c0                	test   al,al
  72d49e:	75 27                	jne    0x72d4c7
  72d4a0:	6a 10                	push   0x10
  72d4a2:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  72d4a5:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72d4a8:	e8 65 ac 14 00       	call   0x878112
  72d4ad:	83 c4 0c             	add    esp,0xc
  72d4b0:	85 c0                	test   eax,eax
  72d4b2:	79 04                	jns    0x72d4b8
  72d4b4:	89 33                	mov    DWORD PTR [ebx],esi
  72d4b6:	eb 05                	jmp    0x72d4bd
  72d4b8:	8d 46 01             	lea    eax,[esi+0x1]
  72d4bb:	89 07                	mov    DWORD PTR [edi],eax
  72d4bd:	8b 03                	mov    eax,DWORD PTR [ebx]
  72d4bf:	8b 37                	mov    esi,DWORD PTR [edi]
  72d4c1:	3b f0                	cmp    esi,eax
  72d4c3:	75 bd                	jne    0x72d482
  72d4c5:	eb 02                	jmp    0x72d4c9
  72d4c7:	89 37                	mov    DWORD PTR [edi],esi
  72d4c9:	3b 33                	cmp    esi,DWORD PTR [ebx]
  72d4cb:	74 5d                	je     0x72d52a
  72d4cd:	8d 46 01             	lea    eax,[esi+0x1]
  72d4d0:	89 03                	mov    DWORD PTR [ebx],eax
  72d4d2:	8b 37                	mov    esi,DWORD PTR [edi]
  72d4d4:	85 f6                	test   esi,esi
  72d4d6:	74 29                	je     0x72d501
  72d4d8:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  72d4db:	8b c6                	mov    eax,esi
  72d4dd:	c1 e0 05             	shl    eax,0x5
  72d4e0:	83 c3 e0             	add    ebx,0xffffffe0
  72d4e3:	03 d8                	add    ebx,eax
  72d4e5:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72d4e8:	53                   	push   ebx
  72d4e9:	e8 b1 5f fd ff       	call   0x70349f
  72d4ee:	59                   	pop    ecx
  72d4ef:	59                   	pop    ecx
  72d4f0:	84 c0                	test   al,al
  72d4f2:	74 0a                	je     0x72d4fe
  72d4f4:	4e                   	dec    esi
  72d4f5:	83 eb 20             	sub    ebx,0x20
  72d4f8:	89 37                	mov    DWORD PTR [edi],esi
  72d4fa:	85 f6                	test   esi,esi
  72d4fc:	75 e7                	jne    0x72d4e5
  72d4fe:	8b 5d 18             	mov    ebx,DWORD PTR [ebp+0x18]
  72d501:	8b 3b                	mov    edi,DWORD PTR [ebx]
  72d503:	3b 7d 10             	cmp    edi,DWORD PTR [ebp+0x10]
  72d506:	73 22                	jae    0x72d52a
  72d508:	8b f7                	mov    esi,edi
  72d50a:	c1 e6 05             	shl    esi,0x5
  72d50d:	03 75 0c             	add    esi,DWORD PTR [ebp+0xc]
  72d510:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72d513:	56                   	push   esi
  72d514:	e8 86 5f fd ff       	call   0x70349f
  72d519:	59                   	pop    ecx
  72d51a:	59                   	pop    ecx
  72d51b:	84 c0                	test   al,al
  72d51d:	74 0b                	je     0x72d52a
  72d51f:	47                   	inc    edi
  72d520:	83 c6 20             	add    esi,0x20
  72d523:	89 3b                	mov    DWORD PTR [ebx],edi
  72d525:	3b 7d 10             	cmp    edi,DWORD PTR [ebp+0x10]
  72d528:	72 e6                	jb     0x72d510
  72d52a:	5f                   	pop    edi
  72d52b:	5e                   	pop    esi
  72d52c:	5b                   	pop    ebx
  72d52d:	5d                   	pop    ebp
  72d52e:	c3                   	ret
