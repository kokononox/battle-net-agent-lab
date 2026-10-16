
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00712ae3 <.text+0x311ae3>:
  712ae3:	55                   	push   ebp
  712ae4:	8b ec                	mov    ebp,esp
  712ae6:	81 ec 78 03 00 00    	sub    esp,0x378
  712aec:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  712af1:	33 c5                	xor    eax,ebp
  712af3:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  712af6:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  712af9:	85 c0                	test   eax,eax
  712afb:	56                   	push   esi
  712afc:	57                   	push   edi
  712afd:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  712b00:	be 08 bc 8f 00       	mov    esi,0x8fbc08
  712b05:	68 0c 03 00 00       	push   0x30c
  712b0a:	0f 45 f0             	cmovne esi,eax
  712b0d:	8d 85 f0 fc ff ff    	lea    eax,[ebp-0x310]
  712b13:	6a 00                	push   0x0
  712b15:	50                   	push   eax
  712b16:	e8 f5 71 16 00       	call   0x879d10
  712b1b:	8d 85 f0 fc ff ff    	lea    eax,[ebp-0x310]
  712b21:	50                   	push   eax
  712b22:	e8 ee c2 ff ff       	call   0x70ee15
  712b27:	83 c4 10             	add    esp,0x10
  712b2a:	8d 8d 88 fc ff ff    	lea    ecx,[ebp-0x378]
  712b30:	e8 0c 1a 15 00       	call   0x864541
  712b35:	8d 8d f0 fc ff ff    	lea    ecx,[ebp-0x310]
  712b3b:	8d 51 01             	lea    edx,[ecx+0x1]
  712b3e:	8a 01                	mov    al,BYTE PTR [ecx]
  712b40:	41                   	inc    ecx
  712b41:	84 c0                	test   al,al
  712b43:	75 f9                	jne    0x712b3e
  712b45:	2b ca                	sub    ecx,edx
  712b47:	8d 85 f0 fc ff ff    	lea    eax,[ebp-0x310]
  712b4d:	51                   	push   ecx
  712b4e:	50                   	push   eax
  712b4f:	8d 8d 88 fc ff ff    	lea    ecx,[ebp-0x378]
  712b55:	e8 95 18 15 00       	call   0x8643ef
  712b5a:	8b ce                	mov    ecx,esi
  712b5c:	8d 51 01             	lea    edx,[ecx+0x1]
  712b5f:	8a 01                	mov    al,BYTE PTR [ecx]
  712b61:	41                   	inc    ecx
  712b62:	84 c0                	test   al,al
  712b64:	75 f9                	jne    0x712b5f
  712b66:	2b ca                	sub    ecx,edx
  712b68:	51                   	push   ecx
  712b69:	56                   	push   esi
  712b6a:	8d 8d 88 fc ff ff    	lea    ecx,[ebp-0x378]
  712b70:	e8 7a 18 15 00       	call   0x8643ef
  712b75:	8d 85 e0 fc ff ff    	lea    eax,[ebp-0x320]
  712b7b:	50                   	push   eax
  712b7c:	8d 8d 88 fc ff ff    	lea    ecx,[ebp-0x378]
  712b82:	e8 10 19 15 00       	call   0x864497
  712b87:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  712b8a:	8d b5 e0 fc ff ff    	lea    esi,[ebp-0x320]
  712b90:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  712b91:	33 cd                	xor    ecx,ebp
  712b93:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  712b94:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  712b95:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  712b96:	5f                   	pop    edi
  712b97:	5e                   	pop    esi
  712b98:	e8 5b 34 16 00       	call   0x875ff8
  712b9d:	c9                   	leave
  712b9e:	c3                   	ret
