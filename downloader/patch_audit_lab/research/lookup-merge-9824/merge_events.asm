
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0072e7de <.text+0x32d7de>:
  72e7de:	55                   	push   ebp
  72e7df:	8b ec                	mov    ebp,esp
  72e7e1:	83 ec 18             	sub    esp,0x18
  72e7e4:	53                   	push   ebx
  72e7e5:	8b d9                	mov    ebx,ecx
  72e7e7:	56                   	push   esi
  72e7e8:	57                   	push   edi
  72e7e9:	89 5d e8             	mov    DWORD PTR [ebp-0x18],ebx
  72e7ec:	8b 93 24 01 00 00    	mov    edx,DWORD PTR [ebx+0x124]
  72e7f2:	8b 83 20 01 00 00    	mov    eax,DWORD PTR [ebx+0x120]
  72e7f8:	ff 75 e8             	push   DWORD PTR [ebp-0x18]
  72e7fb:	c1 e2 04             	shl    edx,0x4
  72e7fe:	8d 3c 10             	lea    edi,[eax+edx*1]
  72e801:	c1 fa 04             	sar    edx,0x4
  72e804:	52                   	push   edx
  72e805:	57                   	push   edi
  72e806:	50                   	push   eax
  72e807:	89 7d fc             	mov    DWORD PTR [ebp-0x4],edi
  72e80a:	e8 bd a5 fe ff       	call   0x718dcc
  72e80f:	8b 93 20 01 00 00    	mov    edx,DWORD PTR [ebx+0x120]
  72e815:	83 c4 10             	add    esp,0x10
  72e818:	8b f2                	mov    esi,edx
  72e81a:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  72e81d:	3b f7                	cmp    esi,edi
  72e81f:	74 76                	je     0x72e897
  72e821:	8b c7                	mov    eax,edi
  72e823:	33 db                	xor    ebx,ebx
  72e825:	8b ce                	mov    ecx,esi
  72e827:	83 c6 10             	add    esi,0x10
  72e82a:	89 4d ec             	mov    DWORD PTR [ebp-0x14],ecx
  72e82d:	8b 79 08             	mov    edi,DWORD PTR [ecx+0x8]
  72e830:	03 fb                	add    edi,ebx
  72e832:	3b f0                	cmp    esi,eax
  72e834:	74 27                	je     0x72e85d
  72e836:	8b 41 04             	mov    eax,DWORD PTR [ecx+0x4]
  72e839:	8b 09                	mov    ecx,DWORD PTR [ecx]
  72e83b:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  72e83e:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  72e841:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
  72e844:	39 0e                	cmp    DWORD PTR [esi],ecx
  72e846:	75 0f                	jne    0x72e857
  72e848:	39 56 04             	cmp    DWORD PTR [esi+0x4],edx
  72e84b:	75 0a                	jne    0x72e857
  72e84d:	03 7e 08             	add    edi,DWORD PTR [esi+0x8]
  72e850:	83 c6 10             	add    esi,0x10
  72e853:	3b f0                	cmp    esi,eax
  72e855:	75 ed                	jne    0x72e844
  72e857:	8b 55 f8             	mov    edx,DWORD PTR [ebp-0x8]
  72e85a:	8b 4d ec             	mov    ecx,DWORD PTR [ebp-0x14]
  72e85d:	85 db                	test   ebx,ebx
  72e85f:	7f 12                	jg     0x72e873
  72e861:	85 ff                	test   edi,edi
  72e863:	7e 29                	jle    0x72e88e
  72e865:	8b 01                	mov    eax,DWORD PTR [ecx]
  72e867:	8b 49 04             	mov    ecx,DWORD PTR [ecx+0x4]
  72e86a:	c7 42 08 01 00 00 00 	mov    DWORD PTR [edx+0x8],0x1
  72e871:	eb 0d                	jmp    0x72e880
  72e873:	85 ff                	test   edi,edi
  72e875:	7f 17                	jg     0x72e88e
  72e877:	8b 01                	mov    eax,DWORD PTR [ecx]
  72e879:	8b 49 04             	mov    ecx,DWORD PTR [ecx+0x4]
  72e87c:	83 4a 08 ff          	or     DWORD PTR [edx+0x8],0xffffffff
  72e880:	89 02                	mov    DWORD PTR [edx],eax
  72e882:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  72e885:	89 4a 04             	mov    DWORD PTR [edx+0x4],ecx
  72e888:	83 c2 10             	add    edx,0x10
  72e88b:	89 55 f8             	mov    DWORD PTR [ebp-0x8],edx
  72e88e:	8b df                	mov    ebx,edi
  72e890:	3b f0                	cmp    esi,eax
  72e892:	75 91                	jne    0x72e825
  72e894:	8b 5d e8             	mov    ebx,DWORD PTR [ebp-0x18]
  72e897:	2b 93 20 01 00 00    	sub    edx,DWORD PTR [ebx+0x120]
  72e89d:	5f                   	pop    edi
  72e89e:	c1 fa 04             	sar    edx,0x4
  72e8a1:	5e                   	pop    esi
  72e8a2:	89 93 24 01 00 00    	mov    DWORD PTR [ebx+0x124],edx
  72e8a8:	5b                   	pop    ebx
  72e8a9:	c9                   	leave
  72e8aa:	c3                   	ret
