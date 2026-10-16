
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00712b9f <.text+0x311b9f>:
  712b9f:	55                   	push   ebp
  712ba0:	8b ec                	mov    ebp,esp
  712ba2:	33 c9                	xor    ecx,ecx
  712ba4:	56                   	push   esi
  712ba5:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
  712ba8:	8b d1                	mov    edx,ecx
  712baa:	0f b6 04 32          	movzx  eax,BYTE PTR [edx+esi*1]
  712bae:	33 c8                	xor    ecx,eax
  712bb0:	42                   	inc    edx
  712bb1:	83 fa 09             	cmp    edx,0x9
  712bb4:	72 f4                	jb     0x712baa
  712bb6:	8b c1                	mov    eax,ecx
  712bb8:	c1 e8 04             	shr    eax,0x4
  712bbb:	33 c1                	xor    eax,ecx
  712bbd:	0f b6 4d 0c          	movzx  ecx,BYTE PTR [ebp+0xc]
  712bc1:	03 c1                	add    eax,ecx
  712bc3:	83 e0 0f             	and    eax,0xf
  712bc6:	5e                   	pop    esi
  712bc7:	5d                   	pop    ebp
  712bc8:	c3                   	ret
