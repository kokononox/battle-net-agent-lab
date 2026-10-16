
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071de93 <.text+0x31ce93>:
  71de93:	55                   	push   ebp
  71de94:	8b ec                	mov    ebp,esp
  71de96:	81 ec 6c 02 00 00    	sub    esp,0x26c
  71de9c:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  71dea1:	33 c5                	xor    eax,ebp
  71dea3:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  71dea6:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  71dea9:	89 85 94 fd ff ff    	mov    DWORD PTR [ebp-0x26c],eax
  71deaf:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  71deb2:	53                   	push   ebx
  71deb3:	8b 5d 0c             	mov    ebx,DWORD PTR [ebp+0xc]
  71deb6:	89 85 9c fd ff ff    	mov    DWORD PTR [ebp-0x264],eax
  71debc:	8b 45 18             	mov    eax,DWORD PTR [ebp+0x18]
  71debf:	89 85 a0 fd ff ff    	mov    DWORD PTR [ebp-0x260],eax
  71dec5:	8b 45 20             	mov    eax,DWORD PTR [ebp+0x20]
  71dec8:	56                   	push   esi
  71dec9:	57                   	push   edi
  71deca:	8b 7d 1c             	mov    edi,DWORD PTR [ebp+0x1c]
  71decd:	89 85 98 fd ff ff    	mov    DWORD PTR [ebp-0x268],eax
  71ded3:	b8 58 02 00 00       	mov    eax,0x258
  71ded8:	50                   	push   eax
  71ded9:	8d 85 a4 fd ff ff    	lea    eax,[ebp-0x25c]
  71dedf:	6a 00                	push   0x0
  71dee1:	50                   	push   eax
  71dee2:	e8 29 be 15 00       	call   0x879d10
  71dee7:	8b 47 04             	mov    eax,DWORD PTR [edi+0x4]
  71deea:	83 c4 0c             	add    esp,0xc
  71deed:	83 e0 fe             	and    eax,0xfffffffe
  71def0:	be 54 01 00 00       	mov    esi,0x154
  71def5:	b9 58 02 00 00       	mov    ecx,0x258
  71defa:	89 b5 a8 fd ff ff    	mov    DWORD PTR [ebp-0x258],esi
  71df00:	0f 45 f1             	cmovne esi,ecx
  71df03:	89 47 04             	mov    DWORD PTR [edi+0x4],eax
  71df06:	83 7d 10 04          	cmp    DWORD PTR [ebp+0x10],0x4
  71df0a:	6a 05                	push   0x5
  71df0c:	5a                   	pop    edx
  71df0d:	89 95 a4 fd ff ff    	mov    DWORD PTR [ebp-0x25c],edx
  71df13:	89 85 f4 fe ff ff    	mov    DWORD PTR [ebp-0x10c],eax
  71df19:	74 05                	je     0x71df20
  71df1b:	39 55 10             	cmp    DWORD PTR [ebp+0x10],edx
  71df1e:	75 09                	jne    0x71df29
  71df20:	83 c8 01             	or     eax,0x1
  71df23:	89 85 f4 fe ff ff    	mov    DWORD PTR [ebp-0x10c],eax
  71df29:	53                   	push   ebx
  71df2a:	8d 85 ac fd ff ff    	lea    eax,[ebp-0x254]
  71df30:	68 00 01 00 00       	push   0x100
  71df35:	50                   	push   eax
  71df36:	e8 e4 00 00 00       	call   0x71e01f
  71df3b:	83 c4 0c             	add    esp,0xc
  71df3e:	85 c0                	test   eax,eax
  71df40:	75 65                	jne    0x71dfa7
  71df42:	83 bd a4 fd ff ff 04 	cmp    DWORD PTR [ebp-0x25c],0x4
  71df49:	c7 85 ac fe ff ff b8 	mov    DWORD PTR [ebp-0x154],0x2ab8
  71df50:	2a 00 00 
  71df53:	75 08                	jne    0x71df5d
  71df55:	8d 46 0f             	lea    eax,[esi+0xf]
  71df58:	83 e0 f0             	and    eax,0xfffffff0
  71df5b:	eb 0b                	jmp    0x71df68
  71df5d:	8d 86 ff 0f 00 00    	lea    eax,[esi+0xfff]
  71df63:	25 00 f0 ff ff       	and    eax,0xfffff000
  71df68:	89 85 b0 fe ff ff    	mov    DWORD PTR [ebp-0x150],eax
  71df6e:	8d 85 a4 fd ff ff    	lea    eax,[ebp-0x25c]
  71df74:	57                   	push   edi
  71df75:	50                   	push   eax
  71df76:	e8 3b 00 00 00       	call   0x71dfb6
  71df7b:	ff b5 a0 fd ff ff    	push   DWORD PTR [ebp-0x260]
  71df81:	8d 8d a4 fd ff ff    	lea    ecx,[ebp-0x25c]
  71df87:	ff b5 9c fd ff ff    	push   DWORD PTR [ebp-0x264]
  71df8d:	56                   	push   esi
  71df8e:	51                   	push   ecx
  71df8f:	ff 75 10             	push   DWORD PTR [ebp+0x10]
  71df92:	50                   	push   eax
  71df93:	ff b5 98 fd ff ff    	push   DWORD PTR [ebp-0x268]
  71df99:	ff b5 94 fd ff ff    	push   DWORD PTR [ebp-0x26c]
  71df9f:	e8 c1 02 01 00       	call   0x72e265
  71dfa4:	83 c4 28             	add    esp,0x28
  71dfa7:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  71dfaa:	5f                   	pop    edi
  71dfab:	5e                   	pop    esi
  71dfac:	33 cd                	xor    ecx,ebp
  71dfae:	5b                   	pop    ebx
  71dfaf:	e8 44 80 15 00       	call   0x875ff8
  71dfb4:	c9                   	leave
  71dfb5:	c3                   	ret
