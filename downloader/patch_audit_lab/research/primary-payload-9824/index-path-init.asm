
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071c325 <.text+0x31b325>:
  71c325:	55                   	push   ebp
  71c326:	8b ec                	mov    ebp,esp
  71c328:	56                   	push   esi
  71c329:	8b f1                	mov    esi,ecx
  71c32b:	8d 46 0c             	lea    eax,[esi+0xc]
  71c32e:	50                   	push   eax
  71c32f:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  71c332:	e8 92 68 ff ff       	call   0x712bc9
  71c337:	59                   	pop    ecx
  71c338:	59                   	pop    ecx
  71c339:	84 c0                	test   al,al
  71c33b:	75 05                	jne    0x71c342
  71c33d:	6a 08                	push   0x8
  71c33f:	58                   	pop    eax
  71c340:	eb 2d                	jmp    0x71c36f
  71c342:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71c345:	8d 8e 60 06 00 00    	lea    ecx,[esi+0x660]
  71c34b:	89 46 2c             	mov    DWORD PTR [esi+0x2c],eax
  71c34e:	e8 35 ea f5 ff       	call   0x67ad88
  71c353:	83 7e 2c 02          	cmp    DWORD PTR [esi+0x2c],0x2
  71c357:	8b ce                	mov    ecx,esi
  71c359:	75 07                	jne    0x71c362
  71c35b:	e8 b1 00 00 00       	call   0x71c411
  71c360:	eb 05                	jmp    0x71c367
  71c362:	e8 36 02 00 00       	call   0x71c59d
