
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00711445 <.text+0x310445>:
  711445:	55                   	push   ebp
  711446:	8b ec                	mov    ebp,esp
  711448:	56                   	push   esi
  711449:	8b f1                	mov    esi,ecx
  71144b:	8d 46 0c             	lea    eax,[esi+0xc]
  71144e:	50                   	push   eax
  71144f:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  711452:	e8 72 17 00 00       	call   0x712bc9
  711457:	59                   	pop    ecx
  711458:	59                   	pop    ecx
  711459:	84 c0                	test   al,al
  71145b:	75 05                	jne    0x711462
  71145d:	6a 08                	push   0x8
  71145f:	58                   	pop    eax
  711460:	eb 4b                	jmp    0x7114ad
  711462:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  711465:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
  711468:	8b 4d 14             	mov    ecx,DWORD PTR [ebp+0x14]
  71146b:	89 46 30             	mov    DWORD PTR [esi+0x30],eax
  71146e:	8a 45 18             	mov    al,BYTE PTR [ebp+0x18]
  711471:	88 46 09             	mov    BYTE PTR [esi+0x9],al
  711474:	8b 45 1c             	mov    eax,DWORD PTR [ebp+0x1c]
  711477:	89 46 38             	mov    DWORD PTR [esi+0x38],eax
  71147a:	8b 45 20             	mov    eax,DWORD PTR [ebp+0x20]
  71147d:	89 46 3c             	mov    DWORD PTR [esi+0x3c],eax
  711480:	8a 45 2c             	mov    al,BYTE PTR [ebp+0x2c]
  711483:	89 4e 34             	mov    DWORD PTR [esi+0x34],ecx
  711486:	8b ce                	mov    ecx,esi
  711488:	89 56 2c             	mov    DWORD PTR [esi+0x2c],edx
  71148b:	88 46 40             	mov    BYTE PTR [esi+0x40],al
  71148e:	83 fa 02             	cmp    edx,0x2
  711491:	75 07                	jne    0x71149a
  711493:	e8 b4 07 00 00       	call   0x711c4c
  711498:	eb 0b                	jmp    0x7114a5
  71149a:	ff 75 28             	push   DWORD PTR [ebp+0x28]
  71149d:	ff 75 24             	push   DWORD PTR [ebp+0x24]
  7114a0:	e8 8b 0b 00 00       	call   0x712030
  7114a5:	85 c0                	test   eax,eax
  7114a7:	75 04                	jne    0x7114ad
  7114a9:	c6 46 08 01          	mov    BYTE PTR [esi+0x8],0x1
  7114ad:	5e                   	pop    esi
  7114ae:	5d                   	pop    ebp
  7114af:	c2 28 00             	ret    0x28
