
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071dfb6 <.text+0x31cfb6>:
  71dfb6:	55                   	push   ebp
  71dfb7:	8b ec                	mov    ebp,esp
  71dfb9:	8b 55 08             	mov    edx,DWORD PTR [ebp+0x8]
  71dfbc:	56                   	push   esi
  71dfbd:	8b 82 0c 01 00 00    	mov    eax,DWORD PTR [edx+0x10c]
  71dfc3:	ff 32                	push   DWORD PTR [edx]
  71dfc5:	03 82 08 01 00 00    	add    eax,DWORD PTR [edx+0x108]
  71dfcb:	50                   	push   eax
  71dfcc:	e8 2f fd ff ff       	call   0x71dd00
  71dfd1:	8b f0                	mov    esi,eax
  71dfd3:	83 c4 08             	add    esp,0x8
  71dfd6:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71dfd9:	8b 48 04             	mov    ecx,DWORD PTR [eax+0x4]
  71dfdc:	d1 e9                	shr    ecx,1
  71dfde:	f6 c1 01             	test   cl,0x1
  71dfe1:	74 37                	je     0x71e01a
  71dfe3:	f6 40 08 01          	test   BYTE PTR [eax+0x8],0x1
  71dfe7:	74 31                	je     0x71e01a
  71dfe9:	33 c9                	xor    ecx,ecx
  71dfeb:	41                   	inc    ecx
  71dfec:	0f bc c1             	bsf    eax,ecx
  71dfef:	c7 84 82 58 01 00 00 	mov    DWORD PTR [edx+eax*4+0x158],0x228
  71dff6:	28 02 00 00 
  71dffa:	89 b4 82 d8 01 00 00 	mov    DWORD PTR [edx+eax*4+0x1d8],esi
  71e001:	8d 86 28 02 00 00    	lea    eax,[esi+0x228]
  71e007:	09 8a 54 01 00 00    	or     DWORD PTR [edx+0x154],ecx
  71e00d:	ff 32                	push   DWORD PTR [edx]
  71e00f:	50                   	push   eax
  71e010:	e8 eb fc ff ff       	call   0x71dd00
  71e015:	83 c4 08             	add    esp,0x8
  71e018:	8b f0                	mov    esi,eax
  71e01a:	8b c6                	mov    eax,esi
  71e01c:	5e                   	pop    esi
  71e01d:	5d                   	pop    ebp
  71e01e:	c3                   	ret
