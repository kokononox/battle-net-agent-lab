
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071c119 <.text+0x31b119>:
  71c119:	55                   	push   ebp
  71c11a:	8b ec                	mov    ebp,esp
  71c11c:	51                   	push   ecx
  71c11d:	53                   	push   ebx
  71c11e:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  71c122:	8d 45 fc             	lea    eax,[ebp-0x4]
  71c125:	56                   	push   esi
  71c126:	57                   	push   edi
  71c127:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71c12a:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  71c12d:	8b d9                	mov    ebx,ecx
  71c12f:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  71c132:	50                   	push   eax
  71c133:	6b c7 50             	imul   eax,edi,0x50
  71c136:	8d 8b 94 00 00 00    	lea    ecx,[ebx+0x94]
  71c13c:	05 20 01 00 00       	add    eax,0x120
  71c141:	03 c3                	add    eax,ebx
  71c143:	50                   	push   eax
  71c144:	57                   	push   edi
  71c145:	e8 3d 27 00 00       	call   0x71e887
  71c14a:	8b f0                	mov    esi,eax
  71c14c:	85 f6                	test   esi,esi
  71c14e:	74 28                	je     0x71c178
  71c150:	56                   	push   esi
  71c151:	e8 1b 6d fe ff       	call   0x702e71
  71c156:	50                   	push   eax
  71c157:	56                   	push   esi
  71c158:	57                   	push   edi
  71c159:	68 90 d4 9b 00       	push   0x9bd490
  71c15e:	6a 00                	push   0x0
  71c160:	68 08 bc 8f 00       	push   0x8fbc08
  71c165:	6a 04                	push   0x4
  71c167:	68 38 ba 9b 00       	push   0x9bba38
  71c16c:	e8 d2 76 1a 00       	call   0x8c3843
  71c171:	83 c4 24             	add    esp,0x24
  71c174:	8b c6                	mov    eax,esi
  71c176:	eb 0f                	jmp    0x71c187
  71c178:	8b 4b 38             	mov    ecx,DWORD PTR [ebx+0x38]
  71c17b:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  71c17e:	89 84 b9 10 01 00 00 	mov    DWORD PTR [ecx+edi*4+0x110],eax
  71c185:	33 c0                	xor    eax,eax
  71c187:	5f                   	pop    edi
  71c188:	5e                   	pop    esi
  71c189:	5b                   	pop    ebx
  71c18a:	c9                   	leave
  71c18b:	c2 0c 00             	ret    0xc
