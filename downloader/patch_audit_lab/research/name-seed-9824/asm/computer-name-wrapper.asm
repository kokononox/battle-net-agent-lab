
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0086cfed <.text+0x46bfed>:
  86cfed:	55                   	push   ebp
  86cfee:	8b ec                	mov    ebp,esp
  86cff0:	83 ec 28             	sub    esp,0x28
  86cff3:	a1 90 22 a6 00       	mov    eax,ds:0xa62290
  86cff8:	33 c5                	xor    eax,ebp
  86cffa:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  86cffd:	83 7d 0c 00          	cmp    DWORD PTR [ebp+0xc],0x0
  86d001:	56                   	push   esi
  86d002:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  86d005:	76 03                	jbe    0x86d00a
  86d007:	c6 06 00             	mov    BYTE PTR [esi],0x0
  86d00a:	8d 45 d8             	lea    eax,[ebp-0x28]
  86d00d:	c7 45 d8 10 00 00 00 	mov    DWORD PTR [ebp-0x28],0x10
  86d014:	50                   	push   eax
  86d015:	8d 45 dc             	lea    eax,[ebp-0x24]
  86d018:	50                   	push   eax
  86d019:	ff 15 5c b5 8f 00    	call   DWORD PTR ds:0x8fb55c
  86d01f:	85 c0                	test   eax,eax
  86d021:	75 07                	jne    0x86d02a
  86d023:	e8 89 0e 00 00       	call   0x86deb1
  86d028:	eb 10                	jmp    0x86d03a
  86d02a:	8d 45 dc             	lea    eax,[ebp-0x24]
  86d02d:	50                   	push   eax
  86d02e:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  86d031:	56                   	push   esi
  86d032:	e8 4a 76 ff ff       	call   0x864681
  86d037:	83 c4 0c             	add    esp,0xc
  86d03a:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  86d03d:	33 cd                	xor    ecx,ebp
  86d03f:	5e                   	pop    esi
  86d040:	e8 b3 8f 00 00       	call   0x875ff8
  86d045:	c9                   	leave
  86d046:	c3                   	ret
