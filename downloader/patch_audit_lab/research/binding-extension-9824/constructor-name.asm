
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071e01f <.text+0x31d01f>:
  71e01f:	55                   	push   ebp
  71e020:	8b ec                	mov    ebp,esp
  71e022:	8b 4d 10             	mov    ecx,DWORD PTR [ebp+0x10]
  71e025:	83 ec 0c             	sub    esp,0xc
  71e028:	8d 51 01             	lea    edx,[ecx+0x1]
  71e02b:	8a 01                	mov    al,BYTE PTR [ecx]
  71e02d:	41                   	inc    ecx
  71e02e:	84 c0                	test   al,al
  71e030:	75 f9                	jne    0x71e02b
  71e032:	2b ca                	sub    ecx,edx
  71e034:	c7 45 f4 47 6c 6f 62 	mov    DWORD PTR [ebp-0xc],0x626f6c47
  71e03b:	66 c7 45 f8 61 6c    	mov    WORD PTR [ebp-0x8],0x6c61
  71e041:	c6 45 fa 5c          	mov    BYTE PTR [ebp-0x6],0x5c
  71e045:	8d 41 07             	lea    eax,[ecx+0x7]
  71e048:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71e04b:	3d ff 00 00 00       	cmp    eax,0xff
  71e050:	76 23                	jbe    0x71e075
  71e052:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71e055:	68 78 e4 9b 00       	push   0x9be478
  71e05a:	6a 00                	push   0x0
  71e05c:	68 08 bc 8f 00       	push   0x8fbc08
  71e061:	6a 04                	push   0x4
  71e063:	68 38 ba 9b 00       	push   0x9bba38
  71e068:	e8 d6 57 1a 00       	call   0x8c3843
  71e06d:	83 c4 18             	add    esp,0x18
  71e070:	6a 13                	push   0x13
  71e072:	58                   	pop    eax
  71e073:	c9                   	leave
  71e074:	c3                   	ret
  71e075:	53                   	push   ebx
  71e076:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
  71e079:	56                   	push   esi
  71e07a:	57                   	push   edi
  71e07b:	8b fb                	mov    edi,ebx
  71e07d:	8d 75 f4             	lea    esi,[ebp-0xc]
  71e080:	51                   	push   ecx
  71e081:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71e084:	8d 43 07             	lea    eax,[ebx+0x7]
  71e087:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71e088:	50                   	push   eax
  71e089:	66 a5                	movs   WORD PTR es:[edi],WORD PTR ds:[esi]
  71e08b:	a4                   	movs   BYTE PTR es:[edi],BYTE PTR ds:[esi]
  71e08c:	e8 ff b6 15 00       	call   0x879790
  71e091:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  71e094:	83 c4 0c             	add    esp,0xc
  71e097:	5f                   	pop    edi
  71e098:	c6 04 18 00          	mov    BYTE PTR [eax+ebx*1],0x0
  71e09c:	33 c0                	xor    eax,eax
  71e09e:	5e                   	pop    esi
  71e09f:	5b                   	pop    ebx
  71e0a0:	c9                   	leave
  71e0a1:	c3                   	ret
