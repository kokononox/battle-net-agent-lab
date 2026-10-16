
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00694bdc <.text+0x293bdc>:
  694bdc:	55                   	push   ebp
  694bdd:	8b ec                	mov    ebp,esp
  694bdf:	56                   	push   esi
  694be0:	8b f1                	mov    esi,ecx
  694be2:	8b 46 0c             	mov    eax,DWORD PTR [esi+0xc]
  694be5:	8b 4e 08             	mov    ecx,DWORD PTR [esi+0x8]
  694be8:	25 ff ff ff 7f       	and    eax,0x7fffffff
  694bed:	3b c8                	cmp    ecx,eax
  694bef:	75 0b                	jne    0x694bfc
  694bf1:	8d 41 01             	lea    eax,[ecx+0x1]
  694bf4:	8b ce                	mov    ecx,esi
  694bf6:	50                   	push   eax
  694bf7:	e8 5d 11 00 00       	call   0x695d59
  694bfc:	8b 4e 08             	mov    ecx,DWORD PTR [esi+0x8]
  694bff:	8b 46 04             	mov    eax,DWORD PTR [esi+0x4]
  694c02:	8d 04 88             	lea    eax,[eax+ecx*4]
  694c05:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  694c08:	8b 09                	mov    ecx,DWORD PTR [ecx]
  694c0a:	89 08                	mov    DWORD PTR [eax],ecx
  694c0c:	ff 46 08             	inc    DWORD PTR [esi+0x8]
  694c0f:	5e                   	pop    esi
  694c10:	5d                   	pop    ebp
  694c11:	c2 04 00             	ret    0x4
