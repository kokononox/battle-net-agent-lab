
Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

0071e887 <.text+0x31d887>:
  71e887:	68 20 03 00 00       	push   0x320
  71e88c:	b8 51 2d 8f 00       	mov    eax,0x8f2d51
  71e891:	e8 d5 77 15 00       	call   0x87606b
  71e896:	8b d9                	mov    ebx,ecx
  71e898:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
  71e89b:	8d 8d e0 fc ff ff    	lea    ecx,[ebp-0x320]
  71e8a1:	8b 7d 08             	mov    edi,DWORD PTR [ebp+0x8]
  71e8a4:	89 85 dc fc ff ff    	mov    DWORD PTR [ebp-0x324],eax
  71e8aa:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  71e8ad:	89 85 d8 fc ff ff    	mov    DWORD PTR [ebp-0x328],eax
  71e8b3:	8b 45 14             	mov    eax,DWORD PTR [ebp+0x14]
  71e8b6:	89 85 d4 fc ff ff    	mov    DWORD PTR [ebp-0x32c],eax
  71e8bc:	e8 03 0d 01 00       	call   0x72f5c4
  71e8c1:	83 65 fc 00          	and    DWORD PTR [ebp-0x4],0x0
  71e8c5:	8d 85 e0 fc ff ff    	lea    eax,[ebp-0x320]
  71e8cb:	50                   	push   eax
  71e8cc:	68 0c 03 00 00       	push   0x30c
  71e8d1:	8d 85 e4 fc ff ff    	lea    eax,[ebp-0x31c]
  71e8d7:	50                   	push   eax
  71e8d8:	57                   	push   edi
  71e8d9:	ff 73 04             	push   DWORD PTR [ebx+0x4]
  71e8dc:	e8 45 08 00 00       	call   0x71f126
  71e8e1:	8b f0                	mov    esi,eax
  71e8e3:	83 c4 14             	add    esp,0x14
  71e8e6:	85 f6                	test   esi,esi
  71e8e8:	0f 85 be 00 00 00    	jne    0x71e9ac
  71e8ee:	8d 85 e0 fc ff ff    	lea    eax,[ebp-0x320]
  71e8f4:	8b 8d dc fc ff ff    	mov    ecx,DWORD PTR [ebp-0x324]
  71e8fa:	39 75 18             	cmp    DWORD PTR [ebp+0x18],esi
  71e8fd:	76 11                	jbe    0x71e910
  71e8ff:	ff 75 18             	push   DWORD PTR [ebp+0x18]
  71e902:	ff b5 d4 fc ff ff    	push   DWORD PTR [ebp-0x32c]
  71e908:	50                   	push   eax
  71e909:	e8 95 d4 00 00       	call   0x72bda3
  71e90e:	eb 06                	jmp    0x71e916
  71e910:	50                   	push   eax
  71e911:	e8 a6 d2 00 00       	call   0x72bbbc
  71e916:	8b f0                	mov    esi,eax
  71e918:	85 f6                	test   esi,esi
  71e91a:	0f 85 8c 00 00 00    	jne    0x71e9ac
  71e920:	ff b5 d8 fc ff ff    	push   DWORD PTR [ebp-0x328]
  71e926:	8d 85 e0 fc ff ff    	lea    eax,[ebp-0x320]
  71e92c:	50                   	push   eax
  71e92d:	8d 85 e4 fc ff ff    	lea    eax,[ebp-0x31c]
  71e933:	50                   	push   eax
  71e934:	ff 74 fb 0c          	push   DWORD PTR [ebx+edi*8+0xc]
  71e938:	57                   	push   edi
  71e939:	ff 73 04             	push   DWORD PTR [ebx+0x4]
  71e93c:	e8 b0 08 00 00       	call   0x71f1f1
  71e941:	8b f0                	mov    esi,eax
  71e943:	83 c4 18             	add    esp,0x18
  71e946:	85 f6                	test   esi,esi
  71e948:	75 62                	jne    0x71e9ac
  71e94a:	8b 85 d8 fc ff ff    	mov    eax,DWORD PTR [ebp-0x328]
  71e950:	8d 77 02             	lea    esi,[edi+0x2]
  71e953:	8d 34 f3             	lea    esi,[ebx+esi*8]
  71e956:	8b ce                	mov    ecx,esi
  71e958:	8b 00                	mov    eax,DWORD PTR [eax]
  71e95a:	89 44 fb 0c          	mov    DWORD PTR [ebx+edi*8+0xc],eax
  71e95e:	8d 85 e0 fc ff ff    	lea    eax,[ebp-0x320]
  71e964:	50                   	push   eax
  71e965:	e8 1b 63 14 00       	call   0x864c85
  71e96a:	8b 85 dc fc ff ff    	mov    eax,DWORD PTR [ebp-0x324]
  71e970:	8b c8                	mov    ecx,eax
  71e972:	ff 70 34             	push   DWORD PTR [eax+0x34]
  71e975:	ff 70 30             	push   DWORD PTR [eax+0x30]
  71e978:	57                   	push   edi
  71e979:	ff 73 08             	push   DWORD PTR [ebx+0x8]
  71e97c:	56                   	push   esi
  71e97d:	e8 cd ce 00 00       	call   0x72b84f
  71e982:	8b f0                	mov    esi,eax
  71e984:	85 f6                	test   esi,esi
  71e986:	74 24                	je     0x71e9ac
  71e988:	56                   	push   esi
  71e989:	e8 e3 44 fe ff       	call   0x702e71
  71e98e:	50                   	push   eax
  71e98f:	56                   	push   esi
  71e990:	57                   	push   edi
  71e991:	68 74 e7 9b 00       	push   0x9be774
  71e996:	6a 00                	push   0x0
  71e998:	68 08 bc 8f 00       	push   0x8fbc08
  71e99d:	6a 04                	push   0x4
  71e99f:	68 38 ba 9b 00       	push   0x9bba38
  71e9a4:	e8 9a 4e 1a 00       	call   0x8c3843
  71e9a9:	83 c4 24             	add    esp,0x24
  71e9ac:	8d 8d e0 fc ff ff    	lea    ecx,[ebp-0x320]
  71e9b2:	e8 93 62 14 00       	call   0x864c4a
  71e9b7:	8b c6                	mov    eax,esi
  71e9b9:	e8 5c 76 15 00       	call   0x87601a
  71e9be:	c2 14 00             	ret    0x14
