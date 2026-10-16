
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00713c27 <.text+0x312c27>:
  713c27:	55                   	push   ebp
  713c28:	8b ec                	mov    ebp,esp
  713c2a:	51                   	push   ecx
  713c2b:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  713c2e:	33 c0                	xor    eax,eax
  713c30:	53                   	push   ebx
  713c31:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  713c34:	56                   	push   esi
  713c35:	57                   	push   edi
  713c36:	8b f3                	mov    esi,ebx
  713c38:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  713c3b:	6a 1e                	push   0x1e
  713c3d:	2b f2                	sub    esi,edx
  713c3f:	5f                   	pop    edi
  713c40:	8a 02                	mov    al,BYTE PTR [edx]
  713c42:	8d 0c 16             	lea    ecx,[esi+edx*1]
  713c45:	83 e1 03             	and    ecx,0x3
  713c48:	30 44 0d fc          	xor    BYTE PTR [ebp+ecx*1-0x4],al
  713c4c:	42                   	inc    edx
  713c4d:	83 ef 01             	sub    edi,0x1
  713c50:	75 ee                	jne    0x713c40
  713c52:	0f b6 55 ff          	movzx  edx,BYTE PTR [ebp-0x1]
  713c56:	8d 4b 1e             	lea    ecx,[ebx+0x1e]
  713c59:	0f b6 45 fe          	movzx  eax,BYTE PTR [ebp-0x2]
  713c5d:	c1 e2 08             	shl    edx,0x8
  713c60:	0b d0                	or     edx,eax
  713c62:	0f b6 45 fd          	movzx  eax,BYTE PTR [ebp-0x3]
  713c66:	c1 e2 08             	shl    edx,0x8
  713c69:	0b d0                	or     edx,eax
  713c6b:	0f b6 45 fc          	movzx  eax,BYTE PTR [ebp-0x4]
  713c6f:	c1 e2 08             	shl    edx,0x8
  713c72:	0b d0                	or     edx,eax
  713c74:	8b c1                	mov    eax,ecx
  713c76:	83 e0 0f             	and    eax,0xf
  713c79:	5f                   	pop    edi
  713c7a:	5e                   	pop    esi
  713c7b:	5b                   	pop    ebx
  713c7c:	8b 04 85 50 d6 9b 00 	mov    eax,DWORD PTR [eax*4+0x9bd650]
  713c83:	33 c1                	xor    eax,ecx
  713c85:	3b d0                	cmp    edx,eax
  713c87:	0f 94 c0             	sete   al
  713c8a:	c9                   	leave
  713c8b:	c3                   	ret
