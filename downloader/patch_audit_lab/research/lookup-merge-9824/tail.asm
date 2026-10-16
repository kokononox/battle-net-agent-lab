
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072d004 <.text+0x32c004>:
  72d004:	55                   	push   ebp
  72d005:	8b ec                	mov    ebp,esp
  72d007:	51                   	push   ecx
  72d008:	8b 51 3c             	mov    edx,DWORD PTR [ecx+0x3c]
  72d00b:	56                   	push   esi
  72d00c:	33 f6                	xor    esi,esi
  72d00e:	89 4d fc             	mov    DWORD PTR [ebp-0x4],ecx
  72d011:	57                   	push   edi
  72d012:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  72d015:	2b d7                	sub    edx,edi
  72d017:	1b 75 0c             	sbb    esi,DWORD PTR [ebp+0xc]
  72d01a:	85 f6                	test   esi,esi
  72d01c:	77 2a                	ja     0x72d048
  72d01e:	72 08                	jb     0x72d028
  72d020:	81 fa 00 78 00 00    	cmp    edx,0x7800
  72d026:	73 20                	jae    0x72d048
  72d028:	68 18 ec 9b 00       	push   0x9bec18
  72d02d:	6a 00                	push   0x0
  72d02f:	68 08 bc 8f 00       	push   0x8fbc08
  72d034:	6a 04                	push   0x4
  72d036:	68 38 ba 9b 00       	push   0x9bba38
  72d03b:	e8 03 68 19 00       	call   0x8c3843
  72d040:	83 c4 14             	add    esp,0x14
  72d043:	6a 09                	push   0x9
  72d045:	58                   	pop    eax
  72d046:	eb 5b                	jmp    0x72d0a3
  72d048:	83 65 0c 00          	and    DWORD PTR [ebp+0xc],0x0
  72d04c:	53                   	push   ebx
  72d04d:	8b 59 38             	mov    ebx,DWORD PTR [ecx+0x38]
  72d050:	0f ac f2 0a          	shrd   edx,esi,0xa
  72d054:	03 df                	add    ebx,edi
  72d056:	89 59 48             	mov    DWORD PTR [ecx+0x48],ebx
  72d059:	89 51 4c             	mov    DWORD PTR [ecx+0x4c],edx
  72d05c:	85 d2                	test   edx,edx
  72d05e:	74 40                	je     0x72d0a0
  72d060:	33 ff                	xor    edi,edi
  72d062:	8b f3                	mov    esi,ebx
  72d064:	83 3e 00             	cmp    DWORD PTR [esi],0x0
  72d067:	74 37                	je     0x72d0a0
  72d069:	6a 00                	push   0x0
  72d06b:	8d 46 04             	lea    eax,[esi+0x4]
  72d06e:	6a 21                	push   0x21
  72d070:	50                   	push   eax
  72d071:	e8 e6 63 ff ff       	call   0x72345c
  72d076:	0d 00 00 00 80       	or     eax,0x80000000
  72d07b:	83 c4 0c             	add    esp,0xc
  72d07e:	3b 06                	cmp    eax,DWORD PTR [esi]
  72d080:	75 27                	jne    0x72d0a9
  72d082:	47                   	inc    edi
  72d083:	83 c6 28             	add    esi,0x28
  72d086:	83 ff 19             	cmp    edi,0x19
  72d089:	72 d9                	jb     0x72d064
  72d08b:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  72d08e:	81 c3 00 04 00 00    	add    ebx,0x400
  72d094:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  72d097:	40                   	inc    eax
  72d098:	89 45 0c             	mov    DWORD PTR [ebp+0xc],eax
  72d09b:	3b 41 4c             	cmp    eax,DWORD PTR [ecx+0x4c]
  72d09e:	72 c0                	jb     0x72d060
  72d0a0:	33 c0                	xor    eax,eax
  72d0a2:	5b                   	pop    ebx
  72d0a3:	5f                   	pop    edi
  72d0a4:	5e                   	pop    esi
  72d0a5:	c9                   	leave
  72d0a6:	c2 08 00             	ret    0x8
  72d0a9:	68 40 ec 9b 00       	push   0x9bec40
  72d0ae:	6a 00                	push   0x0
  72d0b0:	68 08 bc 8f 00       	push   0x8fbc08
  72d0b5:	6a 04                	push   0x4
  72d0b7:	68 38 ba 9b 00       	push   0x9bba38
  72d0bc:	e8 82 67 19 00       	call   0x8c3843
  72d0c1:	83 c4 14             	add    esp,0x14
  72d0c4:	6a 09                	push   0x9
  72d0c6:	58                   	pop    eax
  72d0c7:	eb d9                	jmp    0x72d0a2
