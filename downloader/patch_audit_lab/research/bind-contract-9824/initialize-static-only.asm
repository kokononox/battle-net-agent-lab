
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072c9e8 <.text+0x32b9e8>:
  72c9e8:	55                   	push   ebp
  72c9e9:	8b ec                	mov    ebp,esp
  72c9eb:	83 ec 24             	sub    esp,0x24
  72c9ee:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  72c9f3:	33 c5                	xor    eax,ebp
  72c9f5:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  72c9f8:	8a 41 0c             	mov    al,BYTE PTR [ecx+0xc]
  72c9fb:	8b 4d 10             	mov    ecx,DWORD PTR [ebp+0x10]
  72c9fe:	53                   	push   ebx
  72c9ff:	56                   	push   esi
  72ca00:	57                   	push   edi
  72ca01:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  72ca04:	33 db                	xor    ebx,ebx
  72ca06:	88 45 ee             	mov    BYTE PTR [ebp-0x12],al
  72ca09:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  72ca0c:	6a 08                	push   0x8
  72ca0e:	5a                   	pop    edx
  72ca0f:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
  72ca12:	8d 45 dc             	lea    eax,[ebp-0x24]
  72ca15:	50                   	push   eax
  72ca16:	8d 45 e8             	lea    eax,[ebp-0x18]
  72ca19:	66 89 55 ec          	mov    WORD PTR [ebp-0x14],dx
  72ca1d:	50                   	push   eax
  72ca1e:	8d 45 ec             	lea    eax,[ebp-0x14]
  72ca21:	88 5d ef             	mov    BYTE PTR [ebp-0x11],bl
  72ca24:	6a 10                	push   0x10
  72ca26:	50                   	push   eax
  72ca27:	88 55 f0             	mov    BYTE PTR [ebp-0x10],dl
  72ca2a:	88 55 f1             	mov    BYTE PTR [ebp-0xf],dl
  72ca2d:	66 c7 45 f2 10 1e    	mov    WORD PTR [ebp-0xe],0x1e10
  72ca33:	89 4d f8             	mov    DWORD PTR [ebp-0x8],ecx
  72ca36:	89 5d e8             	mov    DWORD PTR [ebp-0x18],ebx
  72ca39:	89 5d dc             	mov    DWORD PTR [ebp-0x24],ebx
  72ca3c:	e8 7f 65 ff ff       	call   0x722fc0
  72ca41:	8b 45 e8             	mov    eax,DWORD PTR [ebp-0x18]
  72ca44:	6a 10                	push   0x10
  72ca46:	5e                   	pop    esi
  72ca47:	89 45 e4             	mov    DWORD PTR [ebp-0x1c],eax
  72ca4a:	8d 45 e0             	lea    eax,[ebp-0x20]
  72ca4d:	6a 08                	push   0x8
  72ca4f:	50                   	push   eax
  72ca50:	68 fc e9 9b 00       	push   0x9be9fc
  72ca55:	57                   	push   edi
  72ca56:	89 75 e0             	mov    DWORD PTR [ebp-0x20],esi
  72ca59:	e8 01 22 00 00       	call   0x72ec5f
  72ca5e:	83 c4 20             	add    esp,0x20
  72ca61:	85 c0                	test   eax,eax
  72ca63:	0f 85 81 00 00 00    	jne    0x72caea
  72ca69:	56                   	push   esi
  72ca6a:	8d 45 ec             	lea    eax,[ebp-0x14]
  72ca6d:	50                   	push   eax
  72ca6e:	68 0c ea 9b 00       	push   0x9bea0c
  72ca73:	57                   	push   edi
  72ca74:	e8 e6 21 00 00       	call   0x72ec5f
  72ca79:	83 c4 10             	add    esp,0x10
  72ca7c:	85 c0                	test   eax,eax
  72ca7e:	75 6a                	jne    0x72caea
  72ca80:	57                   	push   edi
  72ca81:	e8 49 84 13 00       	call   0x864ecf
  72ca86:	8b f0                	mov    esi,eax
  72ca88:	8b ca                	mov    ecx,edx
  72ca8a:	83 c6 0f             	add    esi,0xf
  72ca8d:	13 cb                	adc    ecx,ebx
  72ca8f:	83 e6 f0             	and    esi,0xfffffff0
  72ca92:	2b f0                	sub    esi,eax
  72ca94:	1b ca                	sbb    ecx,edx
  72ca96:	51                   	push   ecx
  72ca97:	56                   	push   esi
  72ca98:	57                   	push   edi
  72ca99:	e8 6f 22 00 00       	call   0x72ed0d
  72ca9e:	83 c4 10             	add    esp,0x10
  72caa1:	85 c0                	test   eax,eax
  72caa3:	75 45                	jne    0x72caea
  72caa5:	6a 08                	push   0x8
  72caa7:	8d 45 e0             	lea    eax,[ebp-0x20]
  72caaa:	89 5d e0             	mov    DWORD PTR [ebp-0x20],ebx
  72caad:	50                   	push   eax
  72caae:	68 fc e9 9b 00       	push   0x9be9fc
  72cab3:	57                   	push   edi
  72cab4:	89 5d e4             	mov    DWORD PTR [ebp-0x1c],ebx
  72cab7:	e8 a3 21 00 00       	call   0x72ec5f
  72cabc:	83 c4 10             	add    esp,0x10
  72cabf:	85 c0                	test   eax,eax
  72cac1:	75 27                	jne    0x72caea
  72cac3:	57                   	push   edi
  72cac4:	e8 06 84 13 00       	call   0x864ecf
  72cac9:	8b f0                	mov    esi,eax
  72cacb:	8b ca                	mov    ecx,edx
  72cacd:	81 c6 ff 7f 02 00    	add    esi,0x27fff
  72cad3:	13 cb                	adc    ecx,ebx
  72cad5:	81 e6 00 00 fe ff    	and    esi,0xfffe0000
  72cadb:	2b f0                	sub    esi,eax
  72cadd:	1b ca                	sbb    ecx,edx
  72cadf:	51                   	push   ecx
  72cae0:	56                   	push   esi
  72cae1:	57                   	push   edi
  72cae2:	e8 26 22 00 00       	call   0x72ed0d
  72cae7:	83 c4 10             	add    esp,0x10
  72caea:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  72caed:	5f                   	pop    edi
  72caee:	5e                   	pop    esi
  72caef:	33 cd                	xor    ecx,ebp
  72caf1:	5b                   	pop    ebx
  72caf2:	e8 01 95 14 00       	call   0x875ff8
  72caf7:	c9                   	leave
  72caf8:	c2 0c 00             	ret    0xc
