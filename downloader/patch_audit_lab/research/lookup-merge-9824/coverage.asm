
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072f41c <.text+0x32e41c>:
  72f41c:	55                   	push   ebp
  72f41d:	8b ec                	mov    ebp,esp
  72f41f:	83 ec 0c             	sub    esp,0xc
  72f422:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  72f425:	53                   	push   ebx
  72f426:	56                   	push   esi
  72f427:	57                   	push   edi
  72f428:	8b 10                	mov    edx,DWORD PTR [eax]
  72f42a:	8b da                	mov    ebx,edx
  72f42c:	8b 70 04             	mov    esi,DWORD PTR [eax+0x4]
  72f42f:	03 58 08             	add    ebx,DWORD PTR [eax+0x8]
  72f432:	8b 40 0c             	mov    eax,DWORD PTR [eax+0xc]
  72f435:	13 c6                	adc    eax,esi
  72f437:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  72f43a:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  72f43d:	33 d2                	xor    edx,edx
  72f43f:	8b 81 20 01 00 00    	mov    eax,DWORD PTR [ecx+0x120]
  72f445:	8b fa                	mov    edi,edx
  72f447:	8b 89 24 01 00 00    	mov    ecx,DWORD PTR [ecx+0x124]
  72f44d:	c1 e1 04             	shl    ecx,0x4
  72f450:	03 c8                	add    ecx,eax
  72f452:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  72f455:	89 4d f4             	mov    DWORD PTR [ebp-0xc],ecx
  72f458:	3b c1                	cmp    eax,ecx
  72f45a:	74 1c                	je     0x72f478
  72f45c:	8b 70 04             	mov    esi,DWORD PTR [eax+0x4]
  72f45f:	8b 08                	mov    ecx,DWORD PTR [eax]
  72f461:	3b 75 fc             	cmp    esi,DWORD PTR [ebp-0x4]
  72f464:	77 1e                	ja     0x72f484
  72f466:	72 05                	jb     0x72f46d
  72f468:	3b 4d f8             	cmp    ecx,DWORD PTR [ebp-0x8]
  72f46b:	77 17                	ja     0x72f484
  72f46d:	03 78 08             	add    edi,DWORD PTR [eax+0x8]
  72f470:	83 c0 10             	add    eax,0x10
  72f473:	3b 45 f4             	cmp    eax,DWORD PTR [ebp-0xc]
  72f476:	75 e4                	jne    0x72f45c
  72f478:	8a 45 0c             	mov    al,BYTE PTR [ebp+0xc]
  72f47b:	34 01                	xor    al,0x1
  72f47d:	5f                   	pop    edi
  72f47e:	5e                   	pop    esi
  72f47f:	5b                   	pop    ebx
  72f480:	c9                   	leave
  72f481:	c2 08 00             	ret    0x8
  72f484:	85 ff                	test   edi,edi
  72f486:	7e 16                	jle    0x72f49e
  72f488:	38 55 0c             	cmp    BYTE PTR [ebp+0xc],dl
  72f48b:	74 16                	je     0x72f4a3
  72f48d:	3b 75 08             	cmp    esi,DWORD PTR [ebp+0x8]
  72f490:	72 08                	jb     0x72f49a
  72f492:	77 04                	ja     0x72f498
  72f494:	3b cb                	cmp    ecx,ebx
  72f496:	72 02                	jb     0x72f49a
  72f498:	b2 01                	mov    dl,0x1
  72f49a:	8a c2                	mov    al,dl
  72f49c:	eb df                	jmp    0x72f47d
  72f49e:	38 55 0c             	cmp    BYTE PTR [ebp+0xc],dl
  72f4a1:	74 ea                	je     0x72f48d
  72f4a3:	32 c0                	xor    al,al
  72f4a5:	eb d6                	jmp    0x72f47d
