
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071ddc3 <.text+0x31cdc3>:
  71ddc3:	55                   	push   ebp
  71ddc4:	8b ec                	mov    ebp,esp
  71ddc6:	81 ec 5c 01 00 00    	sub    esp,0x15c
  71ddcc:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71ddd1:	33 c5                	xor    eax,ebp
  71ddd3:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71ddd6:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  71ddd9:	53                   	push   ebx
  71ddda:	8b 5d 14             	mov    ebx,DWORD PTR [ebp+0x14]
  71dddd:	56                   	push   esi
  71ddde:	8b 75 0c             	mov    esi,DWORD PTR [ebp+0xc]
  71dde1:	57                   	push   edi
  71dde2:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  71dde5:	89 85 a8 fe ff ff    	mov    DWORD PTR [ebp-0x158],eax
  71ddeb:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  71ddee:	68 48 01 00 00       	push   0x148
  71ddf3:	89 85 a4 fe ff ff    	mov    DWORD PTR [ebp-0x15c],eax
  71ddf9:	8d 85 b4 fe ff ff    	lea    eax,[ebp-0x14c]
  71ddff:	6a 00                	push   0x0
  71de01:	50                   	push   eax
  71de02:	e8 09 bf 15 00       	call   0x879d10
  71de07:	56                   	push   esi
  71de08:	8d 85 b4 fe ff ff    	lea    eax,[ebp-0x14c]
  71de0e:	c7 85 ac fe ff ff 04 	mov    DWORD PTR [ebp-0x154],0x4
  71de15:	00 00 00 
  71de18:	68 00 01 00 00       	push   0x100
  71de1d:	50                   	push   eax
  71de1e:	c7 85 b0 fe ff ff 50 	mov    DWORD PTR [ebp-0x150],0x150
  71de25:	01 00 00 
  71de28:	e8 f2 01 00 00       	call   0x71e01f
  71de2d:	83 c4 18             	add    esp,0x18
  71de30:	85 c0                	test   eax,eax
  71de32:	75 50                	jne    0x71de84
  71de34:	83 bd ac fe ff ff 04 	cmp    DWORD PTR [ebp-0x154],0x4
  71de3b:	c7 45 b4 b8 2a 00 00 	mov    DWORD PTR [ebp-0x4c],0x2ab8
  71de42:	75 0e                	jne    0x71de52
  71de44:	c7 45 b8 50 01 00 00 	mov    DWORD PTR [ebp-0x48],0x150
  71de4b:	b8 10 2c 00 00       	mov    eax,0x2c10
  71de50:	eb 0c                	jmp    0x71de5e
  71de52:	c7 45 b8 00 10 00 00 	mov    DWORD PTR [ebp-0x48],0x1000
  71de59:	b8 00 40 00 00       	mov    eax,0x4000
  71de5e:	ff b5 a8 fe ff ff    	push   DWORD PTR [ebp-0x158]
  71de64:	8d 8d ac fe ff ff    	lea    ecx,[ebp-0x154]
  71de6a:	53                   	push   ebx
  71de6b:	68 50 01 00 00       	push   0x150
  71de70:	51                   	push   ecx
  71de71:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71de74:	50                   	push   eax
  71de75:	ff b5 a4 fe ff ff    	push   DWORD PTR [ebp-0x15c]
  71de7b:	57                   	push   edi
  71de7c:	e8 e4 03 01 00       	call   0x72e265
  71de81:	83 c4 20             	add    esp,0x20
  71de84:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  71de87:	5f                   	pop    edi
  71de88:	5e                   	pop    esi
  71de89:	33 cd                	xor    ecx,ebp
  71de8b:	5b                   	pop    ebx
  71de8c:	e8 67 81 15 00       	call   0x875ff8
  71de91:	c9                   	leave
  71de92:	c3                   	ret
