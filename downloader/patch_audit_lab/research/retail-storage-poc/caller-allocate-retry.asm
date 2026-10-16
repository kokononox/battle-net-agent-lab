
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0070ffed <.text+0x30efed>:
  70ffed:	6a 08                	push   0x8
  70ffef:	b8 34 e5 8e 00       	mov    eax,0x8ee534
  70fff4:	e8 3f 60 16 00       	call   0x876038
  70fff9:	8b d9                	mov    ebx,ecx
  70fffb:	83 7b 2c 02          	cmp    DWORD PTR [ebx+0x2c],0x2
  70ffff:	0f 84 c0 00 00 00    	je     0x7100c5
  710005:	83 7b 2c 04          	cmp    DWORD PTR [ebx+0x2c],0x4
  710009:	0f 84 b6 00 00 00    	je     0x7100c5
  71000f:	80 7b 09 00          	cmp    BYTE PTR [ebx+0x9],0x0
  710013:	8b 7d 0c             	mov    edi,DWORD PTR [ebp+0xc]
  710016:	74 17                	je     0x71002f
  710018:	57                   	push   edi
  710019:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  71001c:	8d 8b 30 06 00 00    	lea    ecx,[ebx+0x630]
  710022:	e8 27 d5 00 00       	call   0x71d54e
  710027:	85 c0                	test   eax,eax
  710029:	0f 84 99 00 00 00    	je     0x7100c8
  71002f:	8d 73 44             	lea    esi,[ebx+0x44]
  710032:	56                   	push   esi
  710033:	89 75 ec             	mov    DWORD PTR [ebp-0x14],esi
  710036:	e8 b1 60 15 00       	call   0x8660ec
  71003b:	59                   	pop    ecx
  71003c:	8b 43 4c             	mov    eax,DWORD PTR [ebx+0x4c]
  71003f:	8b c8                	mov    ecx,eax
  710041:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  710045:	57                   	push   edi
  710046:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  710049:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  71004c:	e8 92 29 01 00       	call   0x7229e3
  710051:	8b f8                	mov    edi,eax
  710053:	83 ff 10             	cmp    edi,0x10
  710056:	75 2b                	jne    0x710083
  710058:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71005b:	8b cb                	mov    ecx,ebx
  71005d:	8b 10                	mov    edx,DWORD PTR [eax]
  71005f:	8b 40 04             	mov    eax,DWORD PTR [eax+0x4]
  710062:	0f ac c2 1e          	shrd   edx,eax,0x1e
  710066:	52                   	push   edx
  710067:	e8 e4 19 00 00       	call   0x711a50
  71006c:	8b f8                	mov    edi,eax
  71006e:	85 ff                	test   edi,edi
  710070:	75 41                	jne    0x7100b3
  710072:	8b 7d 0c             	mov    edi,DWORD PTR [ebp+0xc]
  710075:	8b 4d f0             	mov    ecx,DWORD PTR [ebp-0x10]
  710078:	57                   	push   edi
  710079:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  71007c:	e8 62 29 01 00       	call   0x7229e3
  710081:	8b f8                	mov    edi,eax
  710083:	85 ff                	test   edi,edi
  710085:	74 2c                	je     0x7100b3
  710087:	57                   	push   edi
  710088:	e8 e4 2d ff ff       	call   0x702e71
  71008d:	50                   	push   eax
  71008e:	57                   	push   edi
  71008f:	68 1c d1 9b 00       	push   0x9bd11c
  710094:	6a 00                	push   0x0
  710096:	68 08 bc 8f 00       	push   0x8fbc08
  71009b:	6a 04                	push   0x4
  71009d:	68 38 ba 9b 00       	push   0x9bba38
  7100a2:	e8 9c 37 1b 00       	call   0x8c3843
  7100a7:	83 c4 20             	add    esp,0x20
  7100aa:	83 ff 10             	cmp    edi,0x10
  7100ad:	6a 0e                	push   0xe
  7100af:	58                   	pop    eax
  7100b0:	0f 44 f8             	cmove  edi,eax
  7100b3:	56                   	push   esi
  7100b4:	c7 45 fc 02 00 00 00 	mov    DWORD PTR [ebp-0x4],0x2
  7100bb:	e8 4a 60 15 00       	call   0x86610a
  7100c0:	59                   	pop    ecx
  7100c1:	8b c7                	mov    eax,edi
  7100c3:	eb 03                	jmp    0x7100c8
  7100c5:	6a 05                	push   0x5
  7100c7:	58                   	pop    eax
  7100c8:	e8 39 5f 16 00       	call   0x876006
  7100cd:	c2 08 00             	ret    0x8
