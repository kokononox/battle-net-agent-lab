
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072b9bf <.text+0x32a9bf>:
  72b9bf:	55                   	push   ebp
  72b9c0:	8b ec                	mov    ebp,esp
  72b9c2:	56                   	push   esi
  72b9c3:	8b f1                	mov    esi,ecx
  72b9c5:	e8 28 5b ff ff       	call   0x7214f2
  72b9ca:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  72b9cd:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72b9d0:	89 46 08             	mov    DWORD PTR [esi+0x8],eax
  72b9d3:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  72b9d6:	89 46 0c             	mov    DWORD PTR [esi+0xc],eax
  72b9d9:	e8 56 21 f7 ff       	call   0x69db34
  72b9de:	0b c2                	or     eax,edx
  72b9e0:	59                   	pop    ecx
  72b9e1:	75 1f                	jne    0x72ba02
  72b9e3:	83 7e 08 02          	cmp    DWORD PTR [esi+0x8],0x2
  72b9e7:	75 05                	jne    0x72b9ee
  72b9e9:	6a 09                	push   0x9
  72b9eb:	58                   	pop    eax
  72b9ec:	eb 2f                	jmp    0x72ba1d
  72b9ee:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  72b9f1:	8b ce                	mov    ecx,esi
  72b9f3:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  72b9f6:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72b9f9:	e8 ea 0f 00 00       	call   0x72c9e8
  72b9fe:	85 c0                	test   eax,eax
  72ba00:	75 1b                	jne    0x72ba1d
  72ba02:	57                   	push   edi
  72ba03:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  72ba06:	8b ce                	mov    ecx,esi
  72ba08:	e8 ec fe ff ff       	call   0x72b8f9
  72ba0d:	8b f8                	mov    edi,eax
  72ba0f:	85 ff                	test   edi,edi
  72ba11:	74 07                	je     0x72ba1a
  72ba13:	8b ce                	mov    ecx,esi
  72ba15:	e8 d8 5a ff ff       	call   0x7214f2
  72ba1a:	8b c7                	mov    eax,edi
  72ba1c:	5f                   	pop    edi
  72ba1d:	5e                   	pop    esi
  72ba1e:	5d                   	pop    ebp
  72ba1f:	c2 14 00             	ret    0x14
