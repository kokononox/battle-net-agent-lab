; CONDITIONAL STATIC FRAGMENT prefix; not a continuous runtime trace; see snapshot/assumptions
00683780 4157                             push r15
00683782 4156                             push r14
00683784 4155                             push r13
00683786 4154                             push r12
00683788 56                               push rsi
00683789 57                               push rdi
0068378a 55                               push rbp
0068378b 53                               push rbx
0068378c 4881ecc8000000                   sub rsp, 0xc8
00683793 4c89c7                           mov rdi, r8
00683796 4889542450                       mov qword ptr [rsp + 0x50], rdx
0068379b 488b842448010000                 mov rax, qword ptr [rsp + 0x148]
006837a3 4c8bac2438010000                 mov r13, qword ptr [rsp + 0x138]
006837ab 488b9c2430010000                 mov rbx, qword ptr [rsp + 0x130]
006837b3 488b0d06caa401                   mov rcx, qword ptr [rip + 0x1a4ca06]
006837ba 4831e1                           xor rcx, rsp
006837bd 48898c24c0000000                 mov qword ptr [rsp + 0xc0], rcx
006837c5 8b0d052caa01                     mov ecx, dword ptr [rip + 0x1aa2c05]
006837cb 8d9174f9bc43                     lea edx, [rcx + 0x43bcf974]
006837d1 81f2f01a6d84                     xor edx, 0x846d1af0
006837d7 01ca                             add edx, ecx
006837d9 01d1                             add ecx, edx
006837db 81c1e02dade3                     add ecx, 0xe3ad2de0
006837e1 894c2434                         mov dword ptr [rsp + 0x34], ecx
006837e5 4889dd                           mov rbp, rbx
006837e8 48f7d5                           not rbp
006837eb 498d744500                       lea rsi, [r13 + rax*2]
006837f0 4c8db424b0000000                 lea r14, [rsp + 0xb0]
006837f8 4c8dbb00010000                   lea r15, [rbx + 0x100]
006837ff 4c8da424a0000000                 lea r12, [rsp + 0xa0]
00683807 eb67                             jmp 0x683870
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
00683910 3dce38c33c                       cmp eax, 0x3cc338ce
00683915 7f49                             jg 0x683960
00683917 3d72459800                       cmp eax, 0x984572
0068391c 0f84ad010000                     je 0x683acf
00683922 3d310ab405                       cmp eax, 0x5b40a31
00683927 0f85a3030000                     jne 0x683cd0
0068392d 4889742458                       mov qword ptr [rsp + 0x58], rsi
00683932 8b059c2aaa01                     mov eax, dword ptr [rip + 0x1aa2a9c]
00683938 8d88d42fe914                     lea ecx, [rax + 0x14e92fd4]
0068393e 89c2                             mov edx, eax
00683940 29ca                             sub edx, ecx
00683942 29ca                             sub edx, ecx
00683944 29c2                             sub edx, eax
00683946 81c20e333691                     add edx, 0x9136330e
0068394c 89542434                         mov dword ptr [rsp + 0x34], edx
00683950 e91bffffff                       jmp 0x683870
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
00683910 3dce38c33c                       cmp eax, 0x3cc338ce
00683915 7f49                             jg 0x683960
00683960 3dcf38c33c                       cmp eax, 0x3cc338cf
00683965 0f85c0000000                     jne 0x683a2b
00683a2b 80e2ff                           and dl, 0xff
00683a2e c0e300                           shl bl, 0
00683a31 7337                             jae 0x683a6a
00683a6a 488b4c2458                       mov rcx, qword ptr [rsp + 0x58]
00683a6f 4c89742428                       mov qword ptr [rsp + 0x28], r14
00683a74 4c896c2420                       mov qword ptr [rsp + 0x20], r13
00683a79 ba4b000000                       mov edx, 0x4b
00683a7e 41b823000000                     mov r8d, 0x23
00683a84 41b943000000                     mov r9d, 0x43
00683a8a e8e1fa7f00                       call 0xe83570
00e83570 56                               push rsi
00e83571 4883ec10                         sub rsp, 0x10
00e83575 488b442440                       mov rax, qword ptr [rsp + 0x40]
00e8357a 488b542448                       mov rdx, qword ptr [rsp + 0x48]
00e8357f 448b05c6472c01                   mov r8d, dword ptr [rip + 0x12c47c6]
00e83586 458d88a8a4afb0                   lea r9d, [r8 - 0x4f505b58]
00e8358d 458d90c9da5e79                   lea r10d, [r8 + 0x795edac9]
00e83594 458d98108ac617                   lea r11d, [r8 + 0x17c68a10]
00e8359b 4489de                           mov esi, r11d
00e8359e 81f6ddf11a4d                     xor esi, 0x4d1af1dd
00e835a4 4181f3220c2a1b                   xor r11d, 0x1b2a0c22
00e835ab 41f7db                           neg r11d
00e835ae 4501c3                           add r11d, r8d
00e835b1 4181c3108ac617                   add r11d, 0x17c68a10
00e835b8 4101f3                           add r11d, esi
00e835bb 4181c38896e329                   add r11d, 0x29e39688
00e835c2 4531c2                           xor r10d, r8d
00e835c5 4531ca                           xor r10d, r9d
00e835c8 4531da                           xor r10d, r11d
00e835cb 448954240c                       mov dword ptr [rsp + 0xc], r10d
00e835d0 7743                             ja 0xe83615
00e83615 488902                           mov qword ptr [rdx], rax
00e83618 48894a08                         mov qword ptr [rdx + 8], rcx
00e8361c 4883c410                         add rsp, 0x10
00e83620 5e                               pop rsi
00e83621 c3                               ret 
00683a8f 8b053729aa01                     mov eax, dword ptr [rip + 0x1aa2937]
00683a95 8d88ac84a04e                     lea ecx, [rax + 0x4ea084ac]
00683a9b 8d9040dd4383                     lea edx, [rax - 0x7cbc22c0]
00683aa1 81f21d1eb36e                     xor edx, 0x6eb31e1d
00683aa7 448d0402                         lea r8d, [rdx + rax]
00683aab 4101c0                           add r8d, eax
00683aae 4181c0d20a20eb                   add r8d, 0xeb200ad2
00683ab5 4131d0                           xor r8d, edx
00683ab8 4129c0                           sub r8d, eax
00683abb 4129c8                           sub r8d, ecx
00683abe 4181c0ebab7e55                   add r8d, 0x557eabeb
00683ac5 4489442434                       mov dword ptr [rsp + 0x34], r8d
00683aca e9a1fdffff                       jmp 0x683870
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
0068387f 3de2bf8b5a                       cmp eax, 0x5a8bbfe2
00683884 0f8e76010000                     jle 0x683a00
00683a00 3d55128243                       cmp eax, 0x43821255
00683a05 0f8553020000                     jne 0x683c5e
00683a0b 8b05cb29aa01                     mov eax, dword ptr [rip + 0x1aa29cb]
00683a11 8d88b89f77e9                     lea ecx, [rax - 0x16886048]
00683a17 81f15cda85bc                     xor ecx, 0xbc85da5c
00683a1d 01c8                             add eax, ecx
00683a1f 01c8                             add eax, ecx
00683a21 0549e92e52                       add eax, 0x522ee949
00683a26 e941feffff                       jmp 0x68386c
0068386c 89442434                         mov dword ptr [rsp + 0x34], eax
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
00683910 3dce38c33c                       cmp eax, 0x3cc338ce
00683915 7f49                             jg 0x683960
00683960 3dcf38c33c                       cmp eax, 0x3cc338cf
00683965 0f85c0000000                     jne 0x683a2b
0068396b 7267                             jb 0x6839d4
0068396d 86db                             xchg bl, bl
0068396f 7363                             jae 0x6839d4
006839d4 8b05fe29aa01                     mov eax, dword ptr [rip + 0x1aa29fe]
006839da 89c1                             mov ecx, eax
006839dc 81f1a1e23c37                     xor ecx, 0x373ce2a1
006839e2 359604f1ff                       xor eax, 0xfff10496
006839e7 29c1                             sub ecx, eax
006839e9 29c1                             sub ecx, eax
006839eb 81c110d0fc55                     add ecx, 0x55fcd010
006839f1 894c2434                         mov dword ptr [rsp + 0x34], ecx
006839f5 e976feffff                       jmp 0x683870
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
0068387f 3de2bf8b5a                       cmp eax, 0x5a8bbfe2
00683884 0f8e76010000                     jle 0x683a00
00683a00 3d55128243                       cmp eax, 0x43821255
00683a05 0f8553020000                     jne 0x683c5e
00683c5e 48c74424280d000000               mov qword ptr [rsp + 0x28], 0xd
00683c67 48c744242046000000               mov qword ptr [rsp + 0x20], 0x46
00683c70 41b91b000000                     mov r9d, 0x1b
00683c76 4c89f9                           mov rcx, r15
00683c79 4889da                           mov rdx, rbx
00683c7c 4d89e0                           mov r8, r12
00683c7f e80c442c01                       call 0x1948090
01948090 56                               push rsi
01948091 57                               push rdi
01948092 4883ec18                         sub rsp, 0x18
01948096 b893207ff8                       mov eax, 0xf87f2093
0194809b 33054b068300                     xor eax, dword ptr [rip + 0x83064b]
019480a1 448d88b7d6b413                   lea r9d, [rax + 0x13b4d6b7]
019480a8 4181f1b4741505                   xor r9d, 0x51574b4
019480af 468d1408                         lea r10d, [rax + r9]
019480b3 4181c209a80968                   add r10d, 0x6809a809
019480ba 4131c2                           xor r10d, eax
019480bd 438d040a                         lea eax, [r10 + r9]
019480c1 0529506e8c                       add eax, 0x8c6e5029
019480c6 4401c8                           add eax, r9d
019480c9 055e990b89                       add eax, 0x890b995e
019480ce 8944240c                         mov dword ptr [rsp + 0xc], eax
019480d2 498d4008                         lea rax, [r8 + 8]
019480d6 817c240c166b7245                 cmp dword ptr [rsp + 0xc], 0x45726b16
019480de 7565                             jne 0x1948145
019480e0 498910                           mov qword ptr [r8], rdx
019480e3 4889442410                       mov qword ptr [rsp + 0x10], rax
019480e8 448b0d01068300                   mov r9d, dword ptr [rip + 0x830601]
019480ef 458d910ba2bb4b                   lea r10d, [r9 + 0x4bbba20b]
019480f6 458d998b156a9d                   lea r11d, [r9 - 0x6295ea75]
019480fd 4531d3                           xor r11d, r10d
01948100 4181f2afc49b16                   xor r10d, 0x169bc4af
01948107 4181c215151421                   add r10d, 0x21141515
0194810e 4489d6                           mov esi, r10d
01948111 81f63bcd04a6                     xor esi, 0xa604cd3b
01948117 8dbe675a06c7                     lea edi, [rsi - 0x38f9a599]
0194811d 4431df                           xor edi, r11d
01948120 81f731d2a6fa                     xor edi, 0xfaa6d231
01948126 4429d7                           sub edi, r10d
01948129 4101f9                           add r9d, edi
0194812c 4181c10ba2bb4b                   add r9d, 0x4bbba20b
01948133 4131f1                           xor r9d, esi
01948136 44894c240c                       mov dword ptr [rsp + 0xc], r9d
0194813b 817c240c166b7245                 cmp dword ptr [rsp + 0xc], 0x45726b16
01948143 749b                             je 0x19480e0
01948145 743f                             je 0x1948186
01948147 86f6                             xchg dh, dh
01948149 86c9                             xchg cl, cl
0194814b 7539                             jne 0x1948186
01948186 488b442410                       mov rax, qword ptr [rsp + 0x10]
0194818b 488908                           mov qword ptr [rax], rcx
0194818e 4883c418                         add rsp, 0x18
01948192 5f                               pop rdi
01948193 5e                               pop rsi
01948194 c3                               ret 
00683c84 48897c2420                       mov qword ptr [rsp + 0x20], rdi
00683c89 48c74424280a000000               mov qword ptr [rsp + 0x28], 0xa
00683c92 b963000000                       mov ecx, 0x63
00683c97 41b963000000                     mov r9d, 0x63
00683c9d 4c89e2                           mov rdx, r12
00683ca0 4d89f0                           mov r8, r14
00683ca3 e828590100                       call 0x6995d0
