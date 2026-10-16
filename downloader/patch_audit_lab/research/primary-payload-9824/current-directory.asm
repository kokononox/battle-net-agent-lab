
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00864910 <.text+0x463910>:
  864910:	55                   	push   ebp
  864911:	8b ec                	mov    ebp,esp
  864913:	81 ec 0c 02 00 00    	sub    esp,0x20c
  864919:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  86491e:	33 c5                	xor    eax,ebp
  864920:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  864923:	83 7d 0c 00          	cmp    DWORD PTR [ebp+0xc],0x0
  864927:	56                   	push   esi
  864928:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  86492b:	57                   	push   edi
  86492c:	76 03                	jbe    0x864931
  86492e:	c6 06 00             	mov    BYTE PTR [esi],0x0
  864931:	8d 85 f4 fd ff ff    	lea    eax,[ebp-0x20c]
  864937:	bf 04 01 00 00       	mov    edi,0x104
  86493c:	50                   	push   eax
  86493d:	57                   	push   edi
  86493e:	ff 15 08 b5 8f 00    	call   DWORD PTR ds:0x8fb508
  864944:	85 c0                	test   eax,eax
  864946:	75 07                	jne    0x86494f
  864948:	e8 64 95 00 00       	call   0x86deb1
  86494d:	eb 21                	jmp    0x864970
  86494f:	3b c7                	cmp    eax,edi
  864951:	76 0a                	jbe    0x86495d
  864953:	6a 01                	push   0x1
  864955:	e8 89 94 00 00       	call   0x86dde3
  86495a:	59                   	pop    ecx
  86495b:	eb 13                	jmp    0x864970
  86495d:	8d 85 f4 fd ff ff    	lea    eax,[ebp-0x20c]
  864963:	50                   	push   eax
  864964:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  864967:	56                   	push   esi
  864968:	e8 73 fc ff ff       	call   0x8645e0
  86496d:	83 c4 0c             	add    esp,0xc
  864970:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  864973:	5f                   	pop    edi
  864974:	33 cd                	xor    ecx,ebp
  864976:	5e                   	pop    esi
  864977:	e8 7c 16 01 00       	call   0x875ff8
  86497c:	c9                   	leave
  86497d:	c3                   	ret
