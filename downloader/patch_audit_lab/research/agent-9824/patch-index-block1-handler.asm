
agent-research/Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0068cfe7 <.text+0x28bfe7>:
  68cfe7:	55                   	push   ebp
  68cfe8:	8b ec                	mov    ebp,esp
  68cfea:	53                   	push   ebx
  68cfeb:	56                   	push   esi
  68cfec:	57                   	push   edi
  68cfed:	ff 75 08             	push   DWORD PTR [ebp+0x8]
  68cff0:	8b f9                	mov    edi,ecx
  68cff2:	e8 a1 af 02 00       	call   0x6b7f98
  68cff7:	8b cf                	mov    ecx,edi
  68cff9:	e8 84 af 02 00       	call   0x6b7f82
  68cffe:	0f b6 15 7a a7 9a 00 	movzx  edx,BYTE PTR ds:0x9aa77a
  68d005:	8d 4f 50             	lea    ecx,[edi+0x50]
  68d008:	8b d8                	mov    ebx,eax
  68d00a:	52                   	push   edx
  68d00b:	53                   	push   ebx
  68d00c:	e8 2c d5 1d 00       	call   0x86a53d
  68d011:	f6 47 50 01          	test   BYTE PTR [edi+0x50],0x1
  68d015:	8d 4f 54             	lea    ecx,[edi+0x54]
  68d018:	75 02                	jne    0x68d01c
  68d01a:	8b 09                	mov    ecx,DWORD PTR [ecx]
  68d01c:	51                   	push   ecx
  68d01d:	53                   	push   ebx
  68d01e:	8b cf                	mov    ecx,edi
  68d020:	e8 fa ae 02 00       	call   0x6b7f1f
  68d025:	5f                   	pop    edi
  68d026:	5e                   	pop    esi
  68d027:	5b                   	pop    ebx
  68d028:	5d                   	pop    ebp
  68d029:	c2 04 00             	ret    0x4
