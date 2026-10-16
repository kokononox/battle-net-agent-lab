
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00712a6d <.text+0x311a6d>:
  712a6d:	55                   	push   ebp
  712a6e:	8b ec                	mov    ebp,esp
  712a70:	83 ec 0c             	sub    esp,0xc
  712a73:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
  712a76:	83 65 f8 00          	and    DWORD PTR [ebp-0x8],0x0
  712a7a:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  712a7d:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  712a80:	53                   	push   ebx
  712a81:	8b 5d 14             	mov    ebx,DWORD PTR [ebp+0x14]
  712a84:	56                   	push   esi
  712a85:	57                   	push   edi
  712a86:	89 55 f4             	mov    DWORD PTR [ebp-0xc],edx
  712a89:	8b f1                	mov    esi,ecx
  712a8b:	8b fb                	mov    edi,ebx
  712a8d:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  712a8e:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  712a8f:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  712a90:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  712a91:	3d 00 01 00 00       	cmp    eax,0x100
  712a96:	76 08                	jbe    0x712aa0
  712a98:	8b c2                	mov    eax,edx
  712a9a:	c1 e8 08             	shr    eax,0x8
  712a9d:	88 43 02             	mov    BYTE PTR [ebx+0x2],al
  712aa0:	88 53 01             	mov    BYTE PTR [ebx+0x1],dl
  712aa3:	c6 03 00             	mov    BYTE PTR [ebx],0x0
  712aa6:	c6 45 ff 00          	mov    BYTE PTR [ebp-0x1],0x0
  712aaa:	6a 01                	push   0x1
  712aac:	53                   	push   ebx
  712aad:	e8 ed 00 00 00       	call   0x712b9f
  712ab2:	59                   	pop    ecx
  712ab3:	59                   	pop    ecx
  712ab4:	8b 4d f8             	mov    ecx,DWORD PTR [ebp-0x8]
  712ab7:	3b c1                	cmp    eax,ecx
  712ab9:	74 0e                	je     0x712ac9
  712abb:	8a 45 ff             	mov    al,BYTE PTR [ebp-0x1]
  712abe:	fe c0                	inc    al
  712ac0:	88 45 ff             	mov    BYTE PTR [ebp-0x1],al
  712ac3:	88 03                	mov    BYTE PTR [ebx],al
  712ac5:	3c ff                	cmp    al,0xff
  712ac7:	72 e1                	jb     0x712aaa
  712ac9:	8b 55 f4             	mov    edx,DWORD PTR [ebp-0xc]
  712acc:	41                   	inc    ecx
  712acd:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  712ad0:	83 c3 10             	add    ebx,0x10
  712ad3:	89 4d f8             	mov    DWORD PTR [ebp-0x8],ecx
  712ad6:	83 f9 10             	cmp    ecx,0x10
  712ad9:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  712adc:	72 ab                	jb     0x712a89
  712ade:	5f                   	pop    edi
  712adf:	5e                   	pop    esi
  712ae0:	5b                   	pop    ebx
  712ae1:	c9                   	leave
  712ae2:	c3                   	ret
