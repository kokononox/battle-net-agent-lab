
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072cd8d <.text+0x32bd8d>:
  72cd8d:	55                   	push   ebp
  72cd8e:	8b ec                	mov    ebp,esp
  72cd90:	83 ec 10             	sub    esp,0x10
  72cd93:	53                   	push   ebx
  72cd94:	56                   	push   esi
  72cd95:	57                   	push   edi
  72cd96:	8b f9                	mov    edi,ecx
  72cd98:	6a 08                	push   0x8
  72cd9a:	59                   	pop    ecx
  72cd9b:	39 4f 3c             	cmp    DWORD PTR [edi+0x3c],ecx
  72cd9e:	0f 82 71 01 00 00    	jb     0x72cf15
  72cda4:	8b 5f 38             	mov    ebx,DWORD PTR [edi+0x38]
  72cda7:	8b 03                	mov    eax,DWORD PTR [ebx]
  72cda9:	03 c1                	add    eax,ecx
  72cdab:	39 47 3c             	cmp    DWORD PTR [edi+0x3c],eax
  72cdae:	0f 82 61 01 00 00    	jb     0x72cf15
  72cdb4:	8d 45 f8             	lea    eax,[ebp-0x8]
  72cdb7:	33 f6                	xor    esi,esi
  72cdb9:	50                   	push   eax
  72cdba:	8d 45 fc             	lea    eax,[ebp-0x4]
  72cdbd:	89 75 fc             	mov    DWORD PTR [ebp-0x4],esi
  72cdc0:	50                   	push   eax
  72cdc1:	89 75 f8             	mov    DWORD PTR [ebp-0x8],esi
  72cdc4:	8d 43 08             	lea    eax,[ebx+0x8]
  72cdc7:	ff 33                	push   DWORD PTR [ebx]
  72cdc9:	50                   	push   eax
  72cdca:	e8 f1 61 ff ff       	call   0x722fc0
  72cdcf:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  72cdd2:	83 c4 10             	add    esp,0x10
  72cdd5:	3b 43 04             	cmp    eax,DWORD PTR [ebx+0x4]
  72cdd8:	74 0b                	je     0x72cde5
  72cdda:	68 58 ea 9b 00       	push   0x9bea58
  72cddf:	56                   	push   esi
  72cde0:	e9 37 01 00 00       	jmp    0x72cf1c
  72cde5:	83 3b 10             	cmp    DWORD PTR [ebx],0x10
  72cde8:	73 21                	jae    0x72ce0b
  72cdea:	68 88 ea 9b 00       	push   0x9bea88
  72cdef:	56                   	push   esi
  72cdf0:	68 08 bc 8f 00       	push   0x8fbc08
  72cdf5:	6a 04                	push   0x4
  72cdf7:	68 38 ba 9b 00       	push   0x9bba38
  72cdfc:	e8 42 6a 19 00       	call   0x8c3843
  72ce01:	83 c4 14             	add    esp,0x14
  72ce04:	6a 05                	push   0x5
  72ce06:	e9 27 01 00 00       	jmp    0x72cf32
  72ce0b:	8b 77 38             	mov    esi,DWORD PTR [edi+0x38]
  72ce0e:	6a 08                	push   0x8
  72ce10:	59                   	pop    ecx
  72ce11:	03 f1                	add    esi,ecx
  72ce13:	0f b6 46 02          	movzx  eax,BYTE PTR [esi+0x2]
  72ce17:	3b 47 0c             	cmp    eax,DWORD PTR [edi+0xc]
  72ce1a:	74 0a                	je     0x72ce26
  72ce1c:	68 ac ea 9b 00       	push   0x9beaac
  72ce21:	e9 f4 00 00 00       	jmp    0x72cf1a
  72ce26:	0f b7 06             	movzx  eax,WORD PTR [esi]
  72ce29:	66 3b c1             	cmp    ax,cx
  72ce2c:	73 1e                	jae    0x72ce4c
  72ce2e:	50                   	push   eax
  72ce2f:	68 e4 ea 9b 00       	push   0x9beae4
  72ce34:	6a 00                	push   0x0
  72ce36:	68 08 bc 8f 00       	push   0x8fbc08
  72ce3b:	6a 04                	push   0x4
  72ce3d:	68 38 ba 9b 00       	push   0x9bba38
  72ce42:	e8 fc 69 19 00       	call   0x8c3843
  72ce47:	83 c4 18             	add    esp,0x18
  72ce4a:	eb b8                	jmp    0x72ce04
  72ce4c:	80 7e 04 08          	cmp    BYTE PTR [esi+0x4],0x8
  72ce50:	0f 85 b4 00 00 00    	jne    0x72cf0a
  72ce56:	80 7e 05 08          	cmp    BYTE PTR [esi+0x5],0x8
  72ce5a:	0f 85 aa 00 00 00    	jne    0x72cf0a
  72ce60:	80 7e 06 10          	cmp    BYTE PTR [esi+0x6],0x10
  72ce64:	0f 85 a0 00 00 00    	jne    0x72cf0a
  72ce6a:	8a 46 03             	mov    al,BYTE PTR [esi+0x3]
  72ce6d:	84 c0                	test   al,al
  72ce6f:	74 1f                	je     0x72ce90
  72ce71:	0f b6 c0             	movzx  eax,al
  72ce74:	50                   	push   eax
  72ce75:	68 34 eb 9b 00       	push   0x9beb34
  72ce7a:	6a 00                	push   0x0
  72ce7c:	68 08 bc 8f 00       	push   0x8fbc08
  72ce81:	6a 02                	push   0x2
  72ce83:	68 38 ba 9b 00       	push   0x9bba38
  72ce88:	e8 b6 69 19 00       	call   0x8c3843
  72ce8d:	83 c4 18             	add    esp,0x18
  72ce90:	8b 46 08             	mov    eax,DWORD PTR [esi+0x8]
  72ce93:	8b 4e 0c             	mov    ecx,DWORD PTR [esi+0xc]
  72ce96:	89 47 30             	mov    DWORD PTR [edi+0x30],eax
  72ce99:	89 4f 34             	mov    DWORD PTR [edi+0x34],ecx
  72ce9c:	8b 33                	mov    esi,DWORD PTR [ebx]
  72ce9e:	33 db                	xor    ebx,ebx
  72cea0:	83 c6 08             	add    esi,0x8
  72cea3:	83 c6 0f             	add    esi,0xf
  72cea6:	13 db                	adc    ebx,ebx
  72cea8:	83 e6 f0             	and    esi,0xfffffff0
  72ceab:	85 db                	test   ebx,ebx
  72cead:	72 0e                	jb     0x72cebd
  72ceaf:	77 05                	ja     0x72ceb6
  72ceb1:	3b 77 3c             	cmp    esi,DWORD PTR [edi+0x3c]
  72ceb4:	72 07                	jb     0x72cebd
  72ceb6:	68 58 eb 9b 00       	push   0x9beb58
  72cebb:	eb 5d                	jmp    0x72cf1a
  72cebd:	8d 45 f0             	lea    eax,[ebp-0x10]
  72cec0:	0f 57 c0             	xorps  xmm0,xmm0
  72cec3:	50                   	push   eax
  72cec4:	53                   	push   ebx
  72cec5:	56                   	push   esi
  72cec6:	8b cf                	mov    ecx,edi
  72cec8:	66 0f 13 45 f0       	movlpd QWORD PTR [ebp-0x10],xmm0
  72cecd:	e8 66 00 00 00       	call   0x72cf38
  72ced2:	85 c0                	test   eax,eax
  72ced4:	75 5d                	jne    0x72cf33
  72ced6:	8b 45 f0             	mov    eax,DWORD PTR [ebp-0x10]
  72ced9:	8b 4d f4             	mov    ecx,DWORD PTR [ebp-0xc]
  72cedc:	03 c6                	add    eax,esi
  72cede:	13 cb                	adc    ecx,ebx
  72cee0:	05 ff 0f 00 00       	add    eax,0xfff
  72cee5:	83 d1 00             	adc    ecx,0x0
  72cee8:	25 00 f0 ff ff       	and    eax,0xfffff000
  72ceed:	85 c9                	test   ecx,ecx
  72ceef:	72 0e                	jb     0x72ceff
  72cef1:	77 05                	ja     0x72cef8
  72cef3:	3b 47 3c             	cmp    eax,DWORD PTR [edi+0x3c]
  72cef6:	72 07                	jb     0x72ceff
  72cef8:	68 88 eb 9b 00       	push   0x9beb88
  72cefd:	eb 1b                	jmp    0x72cf1a
  72ceff:	51                   	push   ecx
  72cf00:	50                   	push   eax
  72cf01:	8b cf                	mov    ecx,edi
  72cf03:	e8 fc 00 00 00       	call   0x72d004
  72cf08:	eb 29                	jmp    0x72cf33
  72cf0a:	50                   	push   eax
  72cf0b:	68 0c eb 9b 00       	push   0x9beb0c
  72cf10:	e9 1f ff ff ff       	jmp    0x72ce34
  72cf15:	68 38 ea 9b 00       	push   0x9bea38
  72cf1a:	6a 00                	push   0x0
  72cf1c:	68 08 bc 8f 00       	push   0x8fbc08
  72cf21:	6a 04                	push   0x4
  72cf23:	68 38 ba 9b 00       	push   0x9bba38
  72cf28:	e8 16 69 19 00       	call   0x8c3843
  72cf2d:	83 c4 14             	add    esp,0x14
  72cf30:	6a 09                	push   0x9
  72cf32:	58                   	pop    eax
  72cf33:	5f                   	pop    edi
  72cf34:	5e                   	pop    esi
  72cf35:	5b                   	pop    ebx
  72cf36:	c9                   	leave
  72cf37:	c3                   	ret
