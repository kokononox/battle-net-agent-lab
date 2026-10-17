
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0070da91 <.text+0x30ca91>:
  70da91:	55                   	push   ebp
  70da92:	8b ec                	mov    ebp,esp
  70da94:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  70da97:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
  70da9a:	56                   	push   esi
  70da9b:	57                   	push   edi
  70da9c:	0f b6 b9 50 01 00 00 	movzx  edi,BYTE PTR [ecx+0x150]
  70daa3:	8b cf                	mov    ecx,edi
  70daa5:	e8 86 92 16 00       	call   0x876d30
  70daaa:	8b f0                	mov    esi,eax
  70daac:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  70daaf:	85 c0                	test   eax,eax
  70dab1:	74 17                	je     0x70daca
  70dab3:	33 d2                	xor    edx,edx
  70dab5:	8b cf                	mov    ecx,edi
  70dab7:	03 45 08             	add    eax,DWORD PTR [ebp+0x8]
  70daba:	13 55 0c             	adc    edx,DWORD PTR [ebp+0xc]
  70dabd:	83 c0 ff             	add    eax,0xffffffff
  70dac0:	83 d2 ff             	adc    edx,0xffffffff
  70dac3:	e8 68 92 16 00       	call   0x876d30
  70dac8:	eb 02                	jmp    0x70dacc
  70daca:	8b c6                	mov    eax,esi
  70dacc:	81 fe ff 03 00 00    	cmp    esi,0x3ff
  70dad2:	73 0d                	jae    0x70dae1
  70dad4:	3b c6                	cmp    eax,esi
  70dad6:	75 09                	jne    0x70dae1
  70dad8:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  70dadb:	89 30                	mov    DWORD PTR [eax],esi
  70dadd:	b0 01                	mov    al,0x1
  70dadf:	eb 1d                	jmp    0x70dafe
  70dae1:	68 74 ce 9b 00       	push   0x9bce74
  70dae6:	6a 00                	push   0x0
  70dae8:	68 08 bc 8f 00       	push   0x8fbc08
  70daed:	6a 04                	push   0x4
  70daef:	68 38 ba 9b 00       	push   0x9bba38
  70daf4:	e8 4a 5d 1b 00       	call   0x8c3843
  70daf9:	83 c4 14             	add    esp,0x14
  70dafc:	32 c0                	xor    al,al
  70dafe:	5f                   	pop    edi
  70daff:	5e                   	pop    esi
  70db00:	5d                   	pop    ebp
  70db01:	c2 10 00             	ret    0x10
