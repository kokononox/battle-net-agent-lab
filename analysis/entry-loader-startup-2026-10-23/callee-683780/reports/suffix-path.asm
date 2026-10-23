; CONDITIONAL STATIC FRAGMENT suffix; not a continuous runtime trace; see snapshot/assumptions
00683ca8 8944244c                         mov dword ptr [rsp + 0x4c], eax
00683cac 488b8424a0000000                 mov rax, qword ptr [rsp + 0xa0]
00683cb4 4889442438                       mov qword ptr [rsp + 0x38], rax
00683cb9 8b052127aa01                     mov eax, dword ptr [rip + 0x1aa2721]
00683cbf 8d0c00                           lea ecx, [rax + rax]
00683cc2 01c1                             add ecx, eax
00683cc4 b8ff7c65c5                       mov eax, 0xc5657cff
00683cc9 29c8                             sub eax, ecx
00683ccb e99cfbffff                       jmp 0x68386c
0068386c 89442434                         mov dword ptr [rsp + 0x34], eax
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
00683910 3dce38c33c                       cmp eax, 0x3cc338ce
00683915 7f49                             jg 0x683960
00683917 3d72459800                       cmp eax, 0x984572
0068391c 0f84ad010000                     je 0x683acf
00683acf 48895c2440                       mov qword ptr [rsp + 0x40], rbx
00683ad4 488b442438                       mov rax, qword ptr [rsp + 0x38]
00683ad9 4809e8                           or rax, rbp
00683adc 84f4                             test ah, dh
00683ade 7342                             jae 0x683b22
00683b22 48f7d0                           not rax
00683b25 488d0c80                         lea rcx, [rax + rax*4]
00683b29 488d0448                         lea rax, [rax + rcx*2]
00683b2d 4889442460                       mov qword ptr [rsp + 0x60], rax
00683b32 488b442438                       mov rax, qword ptr [rsp + 0x38]
00683b37 488b4c2440                       mov rcx, qword ptr [rsp + 0x40]
00683b3c 4889c2                           mov rdx, rax
00683b3f 4809ca                           or rdx, rcx
00683b42 4c8d0492                         lea r8, [rdx + rdx*4]
00683b46 4a8d1442                         lea rdx, [rdx + r8*2]
00683b4a 4889542468                       mov qword ptr [rsp + 0x68], rdx
00683b4f 4831c8                           xor rax, rcx
00683b52 4889442470                       mov qword ptr [rsp + 0x70], rax
00683b57 8b058728aa01                     mov eax, dword ptr [rip + 0x1aa2887]
00683b5d 8d88a8cb249b                     lea ecx, [rax - 0x64db3458]
00683b63 89ca                             mov edx, ecx
00683b65 81f20e09b5a7                     xor edx, 0xa7b5090e
00683b6b 448d8217fe59a7                   lea r8d, [rdx - 0x58a601e9]
00683b72 448d8a21dbce7c                   lea r9d, [rdx + 0x7ccedb21]
00683b79 448d927d4000fd                   lea r10d, [rdx - 0x2ffbf83]
00683b80 4531ca                           xor r10d, r9d
00683b83 4181f230be8dce                   xor r10d, 0xce8dbe30
00683b8a 4129d2                           sub r10d, edx
00683b8d 4531c2                           xor r10d, r8d
00683b90 4129ca                           sub r10d, ecx
00683b93 4101c2                           add r10d, eax
00683b96 4489542434                       mov dword ptr [rsp + 0x34], r10d
00683b9b e9d0fcffff                       jmp 0x683870
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
0068387f 3de2bf8b5a                       cmp eax, 0x5a8bbfe2
00683884 0f8e76010000                     jle 0x683a00
0068388a 3de3bf8b5a                       cmp eax, 0x5a8bbfe3
0068388f 0f8474ffffff                     je 0x683809
00683809 488b442470                       mov rax, qword ptr [rsp + 0x70]
0068380e 4889442478                       mov qword ptr [rsp + 0x78], rax
00683813 488b442440                       mov rax, qword ptr [rsp + 0x40]
00683818 48f7d0                           not rax
0068381b 4823442438                       and rax, qword ptr [rsp + 0x38]
00683820 4889842480000000                 mov qword ptr [rsp + 0x80], rax
00683828 8b059a2baa01                     mov eax, dword ptr [rip + 0x1aa2b9a]
0068382e 8d88c8df24b6                     lea ecx, [rax - 0x49db2038]
00683834 8d90fb777cca                     lea edx, [rax - 0x35838805]
0068383a 81f2f187f5ae                     xor edx, 0xaef587f1
00683840 81c2fe1dcc09                     add edx, 0x9cc1dfe
00683846 4189d0                           mov r8d, edx
00683849 4181f0f9023b0f                   xor r8d, 0xf3b02f9
00683850 31c1                             xor ecx, eax
00683852 81f1054a36f1                     xor ecx, 0xf1364a05
00683858 29d1                             sub ecx, edx
0068385a 4401c1                           add ecx, r8d
0068385d 31d1                             xor ecx, edx
0068385f 81f13a572489                     xor ecx, 0x8924573a
00683865 01c8                             add eax, ecx
00683867 05fb777cca                       add eax, 0xca7c77fb
0068386c 89442434                         mov dword ptr [rsp + 0x34], eax
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
0068387f 3de2bf8b5a                       cmp eax, 0x5a8bbfe2
00683884 0f8e76010000                     jle 0x683a00
0068388a 3de3bf8b5a                       cmp eax, 0x5a8bbfe3
0068388f 0f8474ffffff                     je 0x683809
00683895 3dd0939e65                       cmp eax, 0x659e93d0
0068389a 0f8500030000                     jne 0x683ba0
00683ba0 488b842480000000                 mov rax, qword ptr [rsp + 0x80]
00683ba8 488d04c0                         lea rax, [rax + rax*8]
00683bac 4889842488000000                 mov qword ptr [rsp + 0x88], rax
00683bb4 7e67                             jle 0x683c1d
00683bb6 86c0                             xchg al, al
00683bb8 7f63                             jg 0x683c1d
00683c1d 488b442438                       mov rax, qword ptr [rsp + 0x38]
00683c22 4823442440                       and rax, qword ptr [rsp + 0x40]
00683c27 4889842490000000                 mov qword ptr [rsp + 0x90], rax
00683c2f 8b05b327aa01                     mov eax, dword ptr [rip + 0x1aa27b3]
00683c35 8d881eda3655                     lea ecx, [rax + 0x5536da1e]
00683c3b 89ca                             mov edx, ecx
00683c3d 81f2f928fed0                     xor edx, 0xd0fe28f9
00683c43 81c2993f0085                     add edx, 0x85003f99
00683c49 31c1                             xor ecx, eax
00683c4b 31d1                             xor ecx, edx
00683c4d 29c1                             sub ecx, eax
00683c4f 81c1307cbc36                     add ecx, 0x36bc7c30
00683c55 894c2434                         mov dword ptr [rsp + 0x34], ecx
00683c59 e912fcffff                       jmp 0x683870
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
0068387f 3de2bf8b5a                       cmp eax, 0x5a8bbfe2
00683884 0f8e76010000                     jle 0x683a00
0068388a 3de3bf8b5a                       cmp eax, 0x5a8bbfe3
0068388f 0f8474ffffff                     je 0x683809
00683895 3dd0939e65                       cmp eax, 0x659e93d0
0068389a 0f8500030000                     jne 0x683ba0
006838a0 486b842490000000f5               imul rax, qword ptr [rsp + 0x90], -0xb
006838a9 482b842488000000                 sub rax, qword ptr [rsp + 0x88]
006838b1 482b442478                       sub rax, qword ptr [rsp + 0x78]
006838b6 4803442468                       add rax, qword ptr [rsp + 0x68]
006838bb 482b442460                       sub rax, qword ptr [rsp + 0x60]
006838c0 4889842498000000                 mov qword ptr [rsp + 0x98], rax
006838c8 8b051e2baa01                     mov eax, dword ptr [rip + 0x1aa2b1e]
006838ce 8d8816fd040c                     lea ecx, [rax + 0xc04fd16]
006838d4 89ca                             mov edx, ecx
006838d6 81f252e76e11                     xor edx, 0x116ee752
006838dc 448d820b88e97d                   lea r8d, [rdx + 0x7de9880b]
006838e3 4181f0d78e79bc                   xor r8d, 0xbc798ed7
006838ea 41b9669111cb                     mov r9d, 0xcb119166
006838f0 4129d1                           sub r9d, edx
006838f3 4131d1                           xor r9d, edx
006838f6 438d1401                         lea edx, [r9 + r8]
006838fa 81c2bde1a09e                     add edx, 0x9ea0e1bd
00683900 31ca                             xor edx, ecx
00683902 01c2                             add edx, eax
00683904 89542434                         mov dword ptr [rsp + 0x34], edx
00683908 e963ffffff                       jmp 0x683870
00683870 8b442434                         mov eax, dword ptr [rsp + 0x34]
00683874 3d54128243                       cmp eax, 0x43821254
00683879 0f8e91000000                     jle 0x683910
00683910 3dce38c33c                       cmp eax, 0x3cc338ce
00683915 7f49                             jg 0x683960
00683917 3d72459800                       cmp eax, 0x984572
0068391c 0f84ad010000                     je 0x683acf
00683922 3d310ab405                       cmp eax, 0x5b40a31
00683927 0f85a3030000                     jne 0x683cd0
00683cd0 488b842498000000                 mov rax, qword ptr [rsp + 0x98]
00683cd8 488b4c2450                       mov rcx, qword ptr [rsp + 0x50]
00683cdd 488901                           mov qword ptr [rcx], rax
00683ce0 8b44244c                         mov eax, dword ptr [rsp + 0x4c]
00683ce4 488b8c24c0000000                 mov rcx, qword ptr [rsp + 0xc0]
00683cec 4831e1                           xor rcx, rsp
00683cef 483b0dcac4a401                   cmp rcx, qword ptr [rip + 0x1a4c4ca]
00683cf6 7514                             jne 0x683d0c
00683cf8 4881c4c8000000                   add rsp, 0xc8
00683cff 5b                               pop rbx
00683d00 5d                               pop rbp
00683d01 5f                               pop rdi
00683d02 5e                               pop rsi
00683d03 415c                             pop r12
00683d05 415d                             pop r13
00683d07 415e                             pop r14
00683d09 415f                             pop r15
00683d0b c3                               ret 
