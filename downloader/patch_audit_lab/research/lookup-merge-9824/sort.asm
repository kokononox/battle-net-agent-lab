
PINNED-Agent.9824.exe:     file format pei-i386


Disassembly of section .text:

00718dcc <.text+0x317dcc>:
  718dcc:	55                   	push   ebp
  718dcd:	8b ec                	mov    ebp,esp
  718dcf:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
  718dd2:	81 ec 88 00 00 00    	sub    esp,0x88
  718dd8:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  718ddb:	8b c2                	mov    eax,edx
  718ddd:	2b c1                	sub    eax,ecx
  718ddf:	53                   	push   ebx
  718de0:	56                   	push   esi
  718de1:	57                   	push   edi
  718de2:	e9 82 02 00 00       	jmp    0x719069
  718de7:	83 7d 10 00          	cmp    DWORD PTR [ebp+0x10],0x0
  718deb:	0f 8e 88 02 00 00    	jle    0x719079
  718df1:	8b c2                	mov    eax,edx
  718df3:	8b 75 14             	mov    esi,DWORD PTR [ebp+0x14]
  718df6:	2b c1                	sub    eax,ecx
  718df8:	89 4d f4             	mov    DWORD PTR [ebp-0xc],ecx
  718dfb:	c1 f8 04             	sar    eax,0x4
  718dfe:	8d 5a f0             	lea    ebx,[edx-0x10]
  718e01:	99                   	cdq
  718e02:	2b c2                	sub    eax,edx
  718e04:	89 5d f8             	mov    DWORD PTR [ebp-0x8],ebx
  718e07:	d1 f8                	sar    eax,1
  718e09:	c1 e0 04             	shl    eax,0x4
  718e0c:	03 c1                	add    eax,ecx
  718e0e:	89 5d fc             	mov    DWORD PTR [ebp-0x4],ebx
  718e11:	89 45 f0             	mov    DWORD PTR [ebp-0x10],eax
  718e14:	8b c3                	mov    eax,ebx
  718e16:	2b c1                	sub    eax,ecx
  718e18:	89 5d e8             	mov    DWORD PTR [ebp-0x18],ebx
  718e1b:	c1 f8 04             	sar    eax,0x4
  718e1e:	40                   	inc    eax
  718e1f:	89 4d ec             	mov    DWORD PTR [ebp-0x14],ecx
  718e22:	8b 4d f8             	mov    ecx,DWORD PTR [ebp-0x8]
  718e25:	99                   	cdq
  718e26:	83 e2 07             	and    edx,0x7
  718e29:	56                   	push   esi
  718e2a:	56                   	push   esi
  718e2b:	51                   	push   ecx
  718e2c:	8d 1c 02             	lea    ebx,[edx+eax*1]
  718e2f:	8b c1                	mov    eax,ecx
  718e31:	c1 fb 03             	sar    ebx,0x3
  718e34:	8b fb                	mov    edi,ebx
  718e36:	c1 e3 05             	shl    ebx,0x5
  718e39:	c1 e7 04             	shl    edi,0x4
  718e3c:	2b cb                	sub    ecx,ebx
  718e3e:	2b c7                	sub    eax,edi
  718e40:	50                   	push   eax
  718e41:	51                   	push   ecx
  718e42:	e8 a6 02 00 00       	call   0x7190ed
  718e47:	8b 4d f0             	mov    ecx,DWORD PTR [ebp-0x10]
  718e4a:	83 c4 10             	add    esp,0x10
  718e4d:	50                   	push   eax
  718e4e:	56                   	push   esi
  718e4f:	8d 04 0f             	lea    eax,[edi+ecx*1]
  718e52:	50                   	push   eax
  718e53:	51                   	push   ecx
  718e54:	2b cf                	sub    ecx,edi
  718e56:	51                   	push   ecx
  718e57:	e8 91 02 00 00       	call   0x7190ed
  718e5c:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  718e5f:	83 c4 10             	add    esp,0x10
  718e62:	50                   	push   eax
  718e63:	56                   	push   esi
  718e64:	8d 04 0b             	lea    eax,[ebx+ecx*1]
  718e67:	50                   	push   eax
  718e68:	8d 04 0f             	lea    eax,[edi+ecx*1]
  718e6b:	50                   	push   eax
  718e6c:	51                   	push   ecx
  718e6d:	e8 7b 02 00 00       	call   0x7190ed
  718e72:	83 c4 10             	add    esp,0x10
  718e75:	50                   	push   eax
  718e76:	e8 72 02 00 00       	call   0x7190ed
  718e7b:	8b f0                	mov    esi,eax
  718e7d:	8b 5d f4             	mov    ebx,DWORD PTR [ebp-0xc]
  718e80:	8d 7d d8             	lea    edi,[ebp-0x28]
  718e83:	83 c4 10             	add    esp,0x10
  718e86:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e87:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e88:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e89:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e8a:	8b 75 f8             	mov    esi,DWORD PTR [ebp-0x8]
  718e8d:	8b f8                	mov    edi,eax
  718e8f:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e90:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e91:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e92:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e93:	8b 7d f8             	mov    edi,DWORD PTR [ebp-0x8]
  718e96:	8d 75 d8             	lea    esi,[ebp-0x28]
  718e99:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e9a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e9b:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e9c:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718e9d:	8b 7d f8             	mov    edi,DWORD PTR [ebp-0x8]
  718ea0:	57                   	push   edi
  718ea1:	53                   	push   ebx
  718ea2:	8d 4d 14             	lea    ecx,[ebp+0x14]
  718ea5:	e8 15 06 00 00       	call   0x7194bf
  718eaa:	84 c0                	test   al,al
  718eac:	74 14                	je     0x718ec2
  718eae:	57                   	push   edi
  718eaf:	83 c3 10             	add    ebx,0x10
  718eb2:	8d 4d 14             	lea    ecx,[ebp+0x14]
  718eb5:	53                   	push   ebx
  718eb6:	e8 04 06 00 00       	call   0x7194bf
  718ebb:	84 c0                	test   al,al
  718ebd:	75 ef                	jne    0x718eae
  718ebf:	89 5d f4             	mov    DWORD PTR [ebp-0xc],ebx
  718ec2:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
  718ec5:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  718ec8:	83 e8 10             	sub    eax,0x10
  718ecb:	8d 4d 14             	lea    ecx,[ebp+0x14]
  718ece:	50                   	push   eax
  718ecf:	57                   	push   edi
  718ed0:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  718ed3:	e8 e7 05 00 00       	call   0x7194bf
  718ed8:	84 c0                	test   al,al
  718eda:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  718edd:	74 04                	je     0x718ee3
  718edf:	3b c3                	cmp    eax,ebx
  718ee1:	75 e5                	jne    0x718ec8
  718ee3:	8b 5d f4             	mov    ebx,DWORD PTR [ebp-0xc]
  718ee6:	8b f3                	mov    esi,ebx
  718ee8:	3b d8                	cmp    ebx,eax
  718eea:	0f 83 ae 00 00 00    	jae    0x718f9e
  718ef0:	8d 7d c8             	lea    edi,[ebp-0x38]
  718ef3:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ef4:	8d 4d 14             	lea    ecx,[ebp+0x14]
  718ef7:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ef8:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ef9:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718efa:	8b f0                	mov    esi,eax
  718efc:	8b fb                	mov    edi,ebx
  718efe:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718eff:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f00:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f01:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f02:	8b f8                	mov    edi,eax
  718f04:	8d 75 c8             	lea    esi,[ebp-0x38]
  718f07:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f08:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f09:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f0a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f0b:	8b 7d f8             	mov    edi,DWORD PTR [ebp-0x8]
  718f0e:	57                   	push   edi
  718f0f:	53                   	push   ebx
  718f10:	e8 aa 05 00 00       	call   0x7194bf
  718f15:	84 c0                	test   al,al
  718f17:	75 36                	jne    0x718f4f
  718f19:	53                   	push   ebx
  718f1a:	57                   	push   edi
  718f1b:	8d 4d 14             	lea    ecx,[ebp+0x14]
  718f1e:	e8 9c 05 00 00       	call   0x7194bf
  718f23:	84 c0                	test   al,al
  718f25:	75 28                	jne    0x718f4f
  718f27:	8b 4d ec             	mov    ecx,DWORD PTR [ebp-0x14]
  718f2a:	8d 7d b8             	lea    edi,[ebp-0x48]
  718f2d:	8b c1                	mov    eax,ecx
  718f2f:	83 c1 10             	add    ecx,0x10
  718f32:	8b f0                	mov    esi,eax
  718f34:	89 4d ec             	mov    DWORD PTR [ebp-0x14],ecx
  718f37:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f38:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f39:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f3a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f3b:	8b f3                	mov    esi,ebx
  718f3d:	8b f8                	mov    edi,eax
  718f3f:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f40:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f41:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f42:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f43:	8b fb                	mov    edi,ebx
  718f45:	8d 75 b8             	lea    esi,[ebp-0x48]
  718f48:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f49:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f4a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f4b:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f4c:	8b 7d f8             	mov    edi,DWORD PTR [ebp-0x8]
  718f4f:	8b 75 fc             	mov    esi,DWORD PTR [ebp-0x4]
  718f52:	8d 4d 14             	lea    ecx,[ebp+0x14]
  718f55:	56                   	push   esi
  718f56:	57                   	push   edi
  718f57:	e8 63 05 00 00       	call   0x7194bf
  718f5c:	84 c0                	test   al,al
  718f5e:	75 33                	jne    0x718f93
  718f60:	57                   	push   edi
  718f61:	56                   	push   esi
  718f62:	8d 4d 14             	lea    ecx,[ebp+0x14]
  718f65:	e8 55 05 00 00       	call   0x7194bf
  718f6a:	84 c0                	test   al,al
  718f6c:	75 25                	jne    0x718f93
  718f6e:	8b 45 e8             	mov    eax,DWORD PTR [ebp-0x18]
  718f71:	8d 7d a8             	lea    edi,[ebp-0x58]
  718f74:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f75:	83 e8 10             	sub    eax,0x10
  718f78:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
  718f7b:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f7c:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f7d:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f7e:	8b 7d fc             	mov    edi,DWORD PTR [ebp-0x4]
  718f81:	8b f0                	mov    esi,eax
  718f83:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f84:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f85:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f86:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f87:	8b f8                	mov    edi,eax
  718f89:	8d 75 a8             	lea    esi,[ebp-0x58]
  718f8c:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f8d:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f8e:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f8f:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718f90:	8b 7d f8             	mov    edi,DWORD PTR [ebp-0x8]
  718f93:	83 c3 10             	add    ebx,0x10
  718f96:	89 5d f4             	mov    DWORD PTR [ebp-0xc],ebx
  718f99:	e9 02 ff ff ff       	jmp    0x718ea0
  718f9e:	8b 55 f8             	mov    edx,DWORD PTR [ebp-0x8]
  718fa1:	8d 7d 98             	lea    edi,[ebp-0x68]
  718fa4:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fa5:	8d 43 f0             	lea    eax,[ebx-0x10]
  718fa8:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  718fab:	89 45 fc             	mov    DWORD PTR [ebp-0x4],eax
  718fae:	89 4d f0             	mov    DWORD PTR [ebp-0x10],ecx
  718fb1:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fb2:	8d 41 10             	lea    eax,[ecx+0x10]
  718fb5:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fb6:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fb7:	8b fb                	mov    edi,ebx
  718fb9:	8b f2                	mov    esi,edx
  718fbb:	83 c3 10             	add    ebx,0x10
  718fbe:	89 5d f4             	mov    DWORD PTR [ebp-0xc],ebx
  718fc1:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fc2:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fc3:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fc4:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fc5:	8d 75 98             	lea    esi,[ebp-0x68]
  718fc8:	8b fa                	mov    edi,edx
  718fca:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fcb:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fcc:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fcd:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fce:	3b 45 ec             	cmp    eax,DWORD PTR [ebp-0x14]
  718fd1:	73 3c                	jae    0x71900f
  718fd3:	8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]
  718fd6:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
  718fd9:	8b 5d ec             	mov    ebx,DWORD PTR [ebp-0x14]
  718fdc:	8b f2                	mov    esi,edx
  718fde:	8d 7d 88             	lea    edi,[ebp-0x78]
  718fe1:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fe2:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fe3:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fe4:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fe5:	8b f1                	mov    esi,ecx
  718fe7:	8b fa                	mov    edi,edx
  718fe9:	83 c2 10             	add    edx,0x10
  718fec:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fed:	8d 42 10             	lea    eax,[edx+0x10]
  718ff0:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ff1:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ff2:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ff3:	8b f9                	mov    edi,ecx
  718ff5:	8d 75 88             	lea    esi,[ebp-0x78]
  718ff8:	83 e9 10             	sub    ecx,0x10
  718ffb:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ffc:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ffd:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718ffe:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  718fff:	3b c3                	cmp    eax,ebx
  719001:	72 d9                	jb     0x718fdc
  719003:	8b 5d f4             	mov    ebx,DWORD PTR [ebp-0xc]
  719006:	8b 55 f8             	mov    edx,DWORD PTR [ebp-0x8]
  719009:	89 4d fc             	mov    DWORD PTR [ebp-0x4],ecx
  71900c:	8b 4d 08             	mov    ecx,DWORD PTR [ebp+0x8]
  71900f:	8b 45 e8             	mov    eax,DWORD PTR [ebp-0x18]
  719012:	83 c2 f0             	add    edx,0xfffffff0
  719015:	eb 26                	jmp    0x71903d
  719017:	8b f3                	mov    esi,ebx
  719019:	8d bd 78 ff ff ff    	lea    edi,[ebp-0x88]
  71901f:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  719020:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  719021:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  719022:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  719023:	8b f2                	mov    esi,edx
  719025:	8b fb                	mov    edi,ebx
  719027:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  719028:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  719029:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71902a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71902b:	8b fa                	mov    edi,edx
  71902d:	8d b5 78 ff ff ff    	lea    esi,[ebp-0x88]
  719033:	83 ea 10             	sub    edx,0x10
  719036:	83 c3 10             	add    ebx,0x10
  719039:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71903a:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71903b:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71903c:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  71903d:	3b d0                	cmp    edx,eax
  71903f:	77 d6                	ja     0x719017
  719041:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  719044:	8b 45 10             	mov    eax,DWORD PTR [ebp+0x10]
  719047:	d1 f8                	sar    eax,1
  719049:	50                   	push   eax
  71904a:	89 45 10             	mov    DWORD PTR [ebp+0x10],eax
  71904d:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  719050:	83 c0 10             	add    eax,0x10
  719053:	50                   	push   eax
  719054:	51                   	push   ecx
  719055:	e8 72 fd ff ff       	call   0x718dcc
  71905a:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
  71905d:	8b cb                	mov    ecx,ebx
  71905f:	8b c2                	mov    eax,edx
  719061:	89 4d 08             	mov    DWORD PTR [ebp+0x8],ecx
  719064:	83 c4 10             	add    esp,0x10
  719067:	2b c3                	sub    eax,ebx
  719069:	bb 00 02 00 00       	mov    ebx,0x200
  71906e:	83 e0 f0             	and    eax,0xfffffff0
  719071:	3b c3                	cmp    eax,ebx
  719073:	0f 8f 6e fd ff ff    	jg     0x718de7
  719079:	8b c2                	mov    eax,edx
  71907b:	2b c1                	sub    eax,ecx
  71907d:	83 e0 f0             	and    eax,0xfffffff0
  719080:	3b c3                	cmp    eax,ebx
  719082:	7e 0f                	jle    0x719093
  719084:	ff 75 14             	push   DWORD PTR [ebp+0x14]
  719087:	52                   	push   edx
  719088:	51                   	push   ecx
  719089:	e8 7e 01 00 00       	call   0x71920c
  71908e:	83 c4 0c             	add    esp,0xc
  719091:	eb 55                	jmp    0x7190e8
  719093:	3b d1                	cmp    edx,ecx
  719095:	76 51                	jbe    0x7190e8
  719097:	8d 41 10             	lea    eax,[ecx+0x10]
  71909a:	eb 45                	jmp    0x7190e1
  71909c:	8d 7d d8             	lea    edi,[ebp-0x28]
  71909f:	8b f0                	mov    esi,eax
  7190a1:	8b d8                	mov    ebx,eax
  7190a3:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190a4:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190a5:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190a6:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190a7:	3b c1                	cmp    eax,ecx
  7190a9:	74 2a                	je     0x7190d5
  7190ab:	8b 55 dc             	mov    edx,DWORD PTR [ebp-0x24]
  7190ae:	8b 45 d8             	mov    eax,DWORD PTR [ebp-0x28]
  7190b1:	8d 73 f0             	lea    esi,[ebx-0x10]
  7190b4:	89 75 f0             	mov    DWORD PTR [ebp-0x10],esi
  7190b7:	3b 56 04             	cmp    edx,DWORD PTR [esi+0x4]
  7190ba:	77 13                	ja     0x7190cf
  7190bc:	72 04                	jb     0x7190c2
  7190be:	3b 06                	cmp    eax,DWORD PTR [esi]
  7190c0:	73 0d                	jae    0x7190cf
  7190c2:	8b fb                	mov    edi,ebx
  7190c4:	8b 5d f0             	mov    ebx,DWORD PTR [ebp-0x10]
  7190c7:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190c8:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190c9:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190ca:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190cb:	3b d9                	cmp    ebx,ecx
  7190cd:	75 e2                	jne    0x7190b1
  7190cf:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
  7190d2:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
  7190d5:	8b fb                	mov    edi,ebx
  7190d7:	8d 75 d8             	lea    esi,[ebp-0x28]
  7190da:	83 c0 10             	add    eax,0x10
  7190dd:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190de:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190df:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190e0:	a5                   	movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
  7190e1:	89 45 08             	mov    DWORD PTR [ebp+0x8],eax
  7190e4:	3b c2                	cmp    eax,edx
  7190e6:	75 b4                	jne    0x71909c
  7190e8:	5f                   	pop    edi
  7190e9:	5e                   	pop    esi
  7190ea:	5b                   	pop    ebx
  7190eb:	c9                   	leave
  7190ec:	c3                   	ret
