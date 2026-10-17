
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072db39 <.text+0x32cb39>:
  72db39:	55                   	push   ebp
  72db3a:	8b ec                	mov    ebp,esp
  72db3c:	83 ec 14             	sub    esp,0x14
  72db3f:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  72db42:	8b 55 10             	mov    edx,DWORD PTR [ebp+0x10]
  72db45:	57                   	push   edi
  72db46:	89 45 ec             	mov    DWORD PTR [ebp-0x14],eax
  72db49:	8b f9                	mov    edi,ecx
  72db4b:	8a 45 14             	mov    al,BYTE PTR [ebp+0x14]
  72db4e:	88 45 f4             	mov    BYTE PTR [ebp-0xc],al
  72db51:	8d 45 ec             	lea    eax,[ebp-0x14]
  72db54:	50                   	push   eax
  72db55:	8d 4f 10             	lea    ecx,[edi+0x10]
  72db58:	89 55 f0             	mov    DWORD PTR [ebp-0x10],edx
  72db5b:	e8 f5 fa ff ff       	call   0x72d655
  72db60:	85 c0                	test   eax,eax
  72db62:	74 3a                	je     0x72db9e
  72db64:	83 c7 08             	add    edi,0x8
  72db67:	33 d2                	xor    edx,edx
  72db69:	56                   	push   esi
  72db6a:	8d 70 10             	lea    esi,[eax+0x10]
  72db6d:	8b 07                	mov    eax,DWORD PTR [edi]
  72db6f:	3b c7                	cmp    eax,edi
  72db71:	8d 48 d4             	lea    ecx,[eax-0x2c]
  72db74:	0f 44 ca             	cmove  ecx,edx
  72db77:	39 0e                	cmp    DWORD PTR [esi],ecx
  72db79:	74 14                	je     0x72db8f
  72db7b:	ff 36                	push   DWORD PTR [esi]
  72db7d:	e8 49 00 00 00       	call   0x72dbcb
  72db82:	59                   	pop    ecx
  72db83:	8b 0e                	mov    ecx,DWORD PTR [esi]
  72db85:	ff 37                	push   DWORD PTR [edi]
  72db87:	83 c1 2c             	add    ecx,0x2c
  72db8a:	e8 21 a4 f5 ff       	call   0x687fb0
  72db8f:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  72db92:	56                   	push   esi
  72db93:	e8 54 3f f5 ff       	call   0x681aec
  72db98:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  72db9b:	5e                   	pop    esi
  72db9c:	eb 06                	jmp    0x72dba4
  72db9e:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  72dba1:	83 20 00             	and    DWORD PTR [eax],0x0
  72dba4:	5f                   	pop    edi
  72dba5:	c9                   	leave
  72dba6:	c2 10 00             	ret    0x10
