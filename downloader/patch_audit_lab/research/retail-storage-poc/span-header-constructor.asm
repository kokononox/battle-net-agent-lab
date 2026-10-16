
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00713d2a <.text+0x312d2a>:
  713d2a:	55                   	push   ebp
  713d2b:	8b ec                	mov    ebp,esp
  713d2d:	83 7d 0c 1e          	cmp    DWORD PTR [ebp+0xc],0x1e
  713d31:	73 04                	jae    0x713d37
  713d33:	32 c0                	xor    al,al
  713d35:	5d                   	pop    ebp
  713d36:	c3                   	ret
  713d37:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  713d3a:	33 c0                	xor    eax,eax
  713d3c:	56                   	push   esi
  713d3d:	57                   	push   edi
  713d3e:	6a 07                	push   0x7
  713d40:	59                   	pop    ecx
  713d41:	8b fa                	mov    edi,edx
  713d43:	8d 72 0f             	lea    esi,[edx+0xf]
  713d46:	f3 ab                	rep stos DWORD PTR es:[edi],eax
  713d48:	33 c9                	xor    ecx,ecx
  713d4a:	66 ab                	stos   WORD PTR es:[edi],ax
  713d4c:	8b 7d 10             	mov    edi,DWORD PTR [ebp+0x10]
  713d4f:	8a 04 39             	mov    al,BYTE PTR [ecx+edi*1]
  713d52:	41                   	inc    ecx
  713d53:	88 06                	mov    BYTE PTR [esi],al
  713d55:	4e                   	dec    esi
  713d56:	83 f9 10             	cmp    ecx,0x10
  713d59:	72 f4                	jb     0x713d4f
  713d5b:	8b 75 14             	mov    esi,DWORD PTR [ebp+0x14]
  713d5e:	33 ff                	xor    edi,edi
  713d60:	33 c9                	xor    ecx,ecx
  713d62:	8b 46 08             	mov    eax,DWORD PTR [esi+0x8]
  713d65:	d3 e8                	shr    eax,cl
  713d67:	83 c1 08             	add    ecx,0x8
  713d6a:	88 44 3a 10          	mov    BYTE PTR [edx+edi*1+0x10],al
  713d6e:	47                   	inc    edi
  713d6f:	83 f9 20             	cmp    ecx,0x20
  713d72:	72 ee                	jb     0x713d62
  713d74:	8a 45 18             	mov    al,BYTE PTR [ebp+0x18]
  713d77:	88 42 14             	mov    BYTE PTR [edx+0x14],al
  713d7a:	c6 42 15 00          	mov    BYTE PTR [edx+0x15],0x0
  713d7e:	ff 76 04             	push   DWORD PTR [esi+0x4]
  713d81:	ff 36                	push   DWORD PTR [esi]
  713d83:	52                   	push   edx
  713d84:	e8 07 fe ff ff       	call   0x713b90
  713d89:	83 c4 0c             	add    esp,0xc
  713d8c:	b0 01                	mov    al,0x1
  713d8e:	5f                   	pop    edi
  713d8f:	5e                   	pop    esi
  713d90:	5d                   	pop    ebp
  713d91:	c3                   	ret
