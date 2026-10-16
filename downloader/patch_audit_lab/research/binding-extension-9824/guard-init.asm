
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00722378 <.text+0x321378>:
  722378:	55                   	push   ebp
  722379:	8b ec                	mov    ebp,esp
  72237b:	51                   	push   ecx
  72237c:	51                   	push   ecx
  72237d:	8a 45 08             	mov    al,BYTE PTR [ebp+0x8]
  722380:	c6 41 20 01          	mov    BYTE PTR [ecx+0x20],0x1
  722384:	88 01                	mov    BYTE PTR [ecx],al
  722386:	84 c0                	test   al,al
  722388:	74 0e                	je     0x722398
  72238a:	ff 75 0c             	push   DWORD PTR [ebp+0xc]
  72238d:	e8 8d fe ff ff       	call   0x72221f
  722392:	84 c0                	test   al,al
  722394:	74 10                	je     0x7223a6
  722396:	eb 0a                	jmp    0x7223a2
  722398:	8d 41 08             	lea    eax,[ecx+0x8]
  72239b:	50                   	push   eax
  72239c:	e8 bc 8c 14 00       	call   0x86b05d
  7223a1:	59                   	pop    ecx
  7223a2:	c9                   	leave
  7223a3:	c2 08 00             	ret    0x8
  7223a6:	6a 00                	push   0x0
  7223a8:	68 08 bc 8f 00       	push   0x8fbc08
  7223ad:	8d 4d f8             	lea    ecx,[ebp-0x8]
  7223b0:	c6 45 0b 00          	mov    BYTE PTR [ebp+0xb],0x0
  7223b4:	e8 f5 fc ff ff       	call   0x7220ae
  7223b9:	ff 70 04             	push   DWORD PTR [eax+0x4]
  7223bc:	ff 30                	push   DWORD PTR [eax]
  7223be:	8d 45 0b             	lea    eax,[ebp+0xb]
  7223c1:	50                   	push   eax
  7223c2:	e8 07 fd ff ff       	call   0x7220ce
  7223c7:	83 c4 0c             	add    esp,0xc
  7223ca:	84 c0                	test   al,al
  7223cc:	74 01                	je     0x7223cf
  7223ce:	cc                   	int3
  7223cf:	e8 ac b9 14 00       	call   0x86dd80
  7223d4:	cc                   	int3
