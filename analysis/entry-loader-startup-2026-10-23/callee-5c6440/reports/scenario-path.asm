; CONDITIONAL STATIC PATH; see assumptions in scenario-proof.json; repeated dispatcher instructions retained
005c6440 4157                             push r15
005c6442 4156                             push r14
005c6444 4155                             push r13
005c6446 4154                             push r12
005c6448 56                               push rsi
005c6449 57                               push rdi
005c644a 55                               push rbp
005c644b 53                               push rbx
005c644c 4881ecd8000000                   sub rsp, 0xd8
005c6453 4c898c24c0000000                 mov qword ptr [rsp + 0xc0], r9
005c645b 48899424b0000000                 mov qword ptr [rsp + 0xb0], rdx
005c6463 48898c24b8000000                 mov qword ptr [rsp + 0xb8], rcx
005c646b 4c8b0d4e9db001                   mov r9, qword ptr [rip + 0x1b09d4e]
005c6472 4931e1                           xor r9, rsp
005c6475 4c898c24d0000000                 mov qword ptr [rsp + 0xd0], r9
005c647d 448b0de8cdb501                   mov r9d, dword ptr [rip + 0x1b5cde8]
005c6484 458d918ce90546                   lea r10d, [r9 + 0x4605e98c]
005c648b 4181f212c19e9d                   xor r10d, 0x9d9ec112
005c6492 4501c9                           add r9d, r9d
005c6495 4529ca                           sub r10d, r9d
005c6498 4181c243df0f90                   add r10d, 0x900fdf43
005c649f 4489542444                       mov dword ptr [rsp + 0x44], r10d
005c64a4 41ba135fa091                     mov r10d, 0x91a05f13
005c64aa 41bb620733c5                     mov r11d, 0xc5330762
005c64b0 bef1fe8a51                       mov esi, 0x518afef1
005c64b5 bfc12004f4                       mov edi, 0xf40420c1
005c64ba bb59e6fc50                       mov ebx, 0x50fce659
005c64bf bd48b89d79                       mov ebp, 0x799db848
005c64c4 41befae1feb9                     mov r14d, 0xb9fee1fa
005c64ca 41bfeca05f6e                     mov r15d, 0x6e5fa0ec
005c64d0 41bc1ad6dcd9                     mov r12d, 0xd9dcd61a
005c64d6 e989000000                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6600 4181fddc2f0d3e                   cmp r13d, 0x3e0d2fdc
005c6607 0f8f03010000                     jg 0x5c6710
005c6710 4181fd157af64d                   cmp r13d, 0x4df67a15
005c6717 0f8fb4020000                     jg 0x5c69d1
005c671d 4181fddd2f0d3e                   cmp r13d, 0x3e0d2fdd
005c6724 0f8582050000                     jne 0x5c6cac
005c6cac 7e43                             jle 0x5c6cf1
005c6cae c0ff00                           sar bh, 0
005c6cb1 7f3e                             jg 0x5c6cf1
005c6cf1 8b0561a1b101                     mov eax, dword ptr [rip + 0x1b1a161]
005c6cf7 8944244c                         mov dword ptr [rsp + 0x4c], eax
005c6cfb 8b0567c5b501                     mov eax, dword ptr [rip + 0x1b5c567]
005c6d01 448d80a9c99d4e                   lea r8d, [rax + 0x4e9dc9a9]
005c6d08 4589c1                           mov r9d, r8d
005c6d0b 4181f13ac6f03b                   xor r9d, 0x3bf0c63a
005c6d12 4589c5                           mov r13d, r8d
005c6d15 4181f5d91e7703                   xor r13d, 0x3771ed9
005c6d1c 418d8d878aae41                   lea ecx, [r13 + 0x41ae8a87]
005c6d23 81f19af88d2b                     xor ecx, 0x2b8df89a
005c6d29 4429c1                           sub ecx, r8d
005c6d2c 4429e9                           sub ecx, r13d
005c6d2f 29c1                             sub ecx, eax
005c6d31 4429c9                           sub ecx, r9d
005c6d34 81c10d6f24d7                     add ecx, 0xd7246f0d
005c6d3a 4431c1                           xor ecx, r8d
005c6d3d 81f1ca417855                     xor ecx, 0x557841ca
005c6d43 428d0429                         lea eax, [rcx + r13]
005c6d47 05878aae41                       add eax, 0x41ae8a87
005c6d4c e90ff8ffff                       jmp 0x5c6560
005c6560 89442444                         mov dword ptr [rsp + 0x44], eax
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6583 4181fdba87c879                   cmp r13d, 0x79c887ba
005c658a 0f8e66020000                     jle 0x5c67f6
005c67f6 4181fd2676e475                   cmp r13d, 0x75e47626
005c67fd 0f84d8fcffff                     je 0x5c64db
005c6803 8b44244c                         mov eax, dword ptr [rsp + 0x4c]
005c6807 f7d0                             not eax
005c6809 89442460                         mov dword ptr [rsp + 0x60], eax
005c680d 25135fa091                       and eax, 0x91a05f13
005c6812 89442464                         mov dword ptr [rsp + 0x64], eax
005c6816 8b0558cab501                     mov eax, dword ptr [rip + 0x1b5ca58]
005c681c 8d8863e0110f                     lea ecx, [rax + 0xf11e063]
005c6822 8d1400                           lea edx, [rax + rax]
005c6825 01c2                             add edx, eax
005c6827 81c282e19abd                     add edx, 0xbd9ae182
005c682d 31ca                             xor edx, ecx
005c682f 29c2                             sub edx, eax
005c6831 81c241c0fa3a                     add edx, 0x3afac041
005c6837 89542444                         mov dword ptr [rsp + 0x44], edx
005c683b e924fdffff                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6600 4181fddc2f0d3e                   cmp r13d, 0x3e0d2fdc
005c6607 0f8f03010000                     jg 0x5c6710
005c660d 4181fde576b81a                   cmp r13d, 0x1ab876e5
005c6614 0f8f7c020000                     jg 0x5c6896
005c6896 4181fde676b81a                   cmp r13d, 0x1ab876e6
005c689d 0f85ae040000                     jne 0x5c6d51
005c6d51 8b442464                         mov eax, dword ptr [rsp + 0x64]
005c6d55 8d04c0                           lea eax, [rax + rax*8]
005c6d58 89442468                         mov dword ptr [rsp + 0x68], eax
005c6d5c 8b44244c                         mov eax, dword ptr [rsp + 0x4c]
005c6d60 f7d0                             not eax
005c6d62 25eca05f6e                       and eax, 0x6e5fa0ec
005c6d67 8944246c                         mov dword ptr [rsp + 0x6c], eax
005c6d6b 8b050bc5b501                     mov eax, dword ptr [rip + 0x1b5c50b]
005c6d71 8d88ac2ef550                     lea ecx, [rax + 0x50f52eac]
005c6d77 4189c8                           mov r8d, ecx
005c6d7a 4181f00d518bf2                   xor r8d, 0xf28b510d
005c6d81 4101c0                           add r8d, eax
005c6d84 4131c8                           xor r8d, ecx
005c6d87 81f1296c98a1                     xor ecx, 0xa1986c29
005c6d8d 448d89541ecc97                   lea r9d, [rcx - 0x6833e1ac]
005c6d94 4531c1                           xor r9d, r8d
005c6d97 4181f18d1fff21                   xor r9d, 0x21ff1f8d
005c6d9e 01c8                             add eax, ecx
005c6da0 05004dc1e8                       add eax, 0xe8c14d00
005c6da5 4129c1                           sub r9d, eax
005c6da8 4181c133a4d302                   add r9d, 0x2d3a433
005c6daf 44894c2444                       mov dword ptr [rsp + 0x44], r9d
005c6db4 e9abf7ffff                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6583 4181fdba87c879                   cmp r13d, 0x79c887ba
005c658a 0f8e66020000                     jle 0x5c67f6
005c6590 4181fdbb87c879                   cmp r13d, 0x79c887bb
005c6597 0f84ef040000                     je 0x5c6a8c
005c659d 4181fd274b707d                   cmp r13d, 0x7d704b27
005c65a4 0f85b8080000                     jne 0x5c6e62
005c65aa 8b44246c                         mov eax, dword ptr [rsp + 0x6c]
005c65ae 01c0                             add eax, eax
005c65b0 8d0480                           lea eax, [rax + rax*4]
005c65b3 89442470                         mov dword ptr [rsp + 0x70], eax
005c65b7 8b05bbccb501                     mov eax, dword ptr [rip + 0x1b5ccbb]
005c65bd 4431e0                           xor eax, r12d
005c65c0 448d808fb63197                   lea r8d, [rax - 0x68ce4971]
005c65c7 4589c1                           mov r9d, r8d
005c65ca 4181f1ed962b10                   xor r9d, 0x102b96ed
005c65d1 4589cd                           mov r13d, r9d
005c65d4 4529c5                           sub r13d, r8d
005c65d7 4181c5363e1a24                   add r13d, 0x241a3e36
005c65de 4531c5                           xor r13d, r8d
005c65e1 4181f5af6457ec                   xor r13d, 0xec5764af
005c65e8 4529cd                           sub r13d, r9d
005c65eb 4129c5                           sub r13d, eax
005c65ee 44896c2444                       mov dword ptr [rsp + 0x44], r13d
005c65f3 e96cffffff                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6583 4181fdba87c879                   cmp r13d, 0x79c887ba
005c658a 0f8e66020000                     jle 0x5c67f6
005c6590 4181fdbb87c879                   cmp r13d, 0x79c887bb
005c6597 0f84ef040000                     je 0x5c6a8c
005c6a8c 8b44244c                         mov eax, dword ptr [rsp + 0x4c]
005c6a90 4421f8                           and eax, r15d
005c6a93 89442478                         mov dword ptr [rsp + 0x78], eax
005c6a97 f7d0                             not eax
005c6a99 8d0c80                           lea ecx, [rax + rax*4]
005c6a9c 8d0448                           lea eax, [rax + rcx*2]
005c6a9f 89442474                         mov dword ptr [rsp + 0x74], eax
005c6aa3 8b05dbc7b501                     mov eax, dword ptr [rip + 0x1b5c7db]
005c6aa9 89c1                             mov ecx, eax
005c6aab 81f1e1f1df1c                     xor ecx, 0x1cdff1e1
005c6ab1 3515ad5301                       xor eax, 0x153ad15
005c6ab6 8d1400                           lea edx, [rax + rax]
005c6ab9 29ca                             sub edx, ecx
005c6abb 0541e1499b                       add eax, 0x9b49e141
005c6ac0 81c239fa4b8b                     add edx, 0x8b4bfa39
005c6ac6 31c2                             xor edx, eax
005c6ac8 29c2                             sub edx, eax
005c6aca 81c23a292377                     add edx, 0x7723293a
005c6ad0 89542444                         mov dword ptr [rsp + 0x44], edx
005c6ad4 e98bfaffff                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6600 4181fddc2f0d3e                   cmp r13d, 0x3e0d2fdc
005c6607 0f8f03010000                     jg 0x5c6710
005c6710 4181fd157af64d                   cmp r13d, 0x4df67a15
005c6717 0f8fb4020000                     jg 0x5c69d1
005c671d 4181fddd2f0d3e                   cmp r13d, 0x3e0d2fdd
005c6724 0f8582050000                     jne 0x5c6cac
005c672a 744b                             je 0x5c6777
005c6777 8b442478                         mov eax, dword ptr [rsp + 0x78]
005c677b 8944247c                         mov dword ptr [rsp + 0x7c], eax
005c677f 81fc00240000                     cmp esp, 0x2400
005c6785 7703                             ja 0x5c678a
005c678a 7408                             je 0x5c6794
005c678c 7506                             jne 0x5c6794
005c6794 50                               push rax
005c6795 ebff                             jmp 0x5c6796
005c6796 ffc0                             inc eax
005c6798 58                               pop rax
005c6799 730b                             jae 0x5c67a6
005c67a6 731b                             jae 0x5c67c3
005c67c3 8b44244c                         mov eax, dword ptr [rsp + 0x4c]
005c67c7 4421d0                           and eax, r10d
005c67ca 89842480000000                   mov dword ptr [rsp + 0x80], eax
005c67d1 8b05a9cab501                     mov eax, dword ptr [rip + 0x1b5caa9]
005c67d7 4189c0                           mov r8d, eax
005c67da 4181f07d5a10ad                   xor r8d, 0xad105a7d
005c67e1 4101c0                           add r8d, eax
005c67e4 35ec7ec630                       xor eax, 0x30c67eec
005c67e9 4429c0                           sub eax, r8d
005c67ec 05a53da061                       add eax, 0x61a03da5
005c67f1 e96afdffff                       jmp 0x5c6560
005c6560 89442444                         mov dword ptr [rsp + 0x44], eax
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6583 4181fdba87c879                   cmp r13d, 0x79c887ba
005c658a 0f8e66020000                     jle 0x5c67f6
005c67f6 4181fd2676e475                   cmp r13d, 0x75e47626
005c67fd 0f84d8fcffff                     je 0x5c64db
005c64db 80e7ff                           and bh, 0xff
005c64de 734b                             jae 0x5c652b
005c652b 8b842480000000                   mov eax, dword ptr [rsp + 0x80]
005c6532 8d0c80                           lea ecx, [rax + rax*4]
005c6535 8d0448                           lea eax, [rax + rcx*2]
005c6538 89842484000000                   mov dword ptr [rsp + 0x84], eax
005c653f 8b052bcdb501                     mov eax, dword ptr [rip + 0x1b5cd2b]
005c6545 89c1                             mov ecx, eax
005c6547 81f1be517474                     xor ecx, 0x747451be
005c654d 8d91079bae68                     lea edx, [rcx + 0x68ae9b07]
005c6553 0581baa2de                       add eax, 0xdea2ba81
005c6558 31d0                             xor eax, edx
005c655a 29c8                             sub eax, ecx
005c655c 0f1f4000                         nop dword ptr [rax]
005c6560 89442444                         mov dword ptr [rsp + 0x44], eax
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6600 4181fddc2f0d3e                   cmp r13d, 0x3e0d2fdc
005c6607 0f8f03010000                     jg 0x5c6710
005c660d 4181fde576b81a                   cmp r13d, 0x1ab876e5
005c6614 0f8f7c020000                     jg 0x5c6896
005c6896 4181fde676b81a                   cmp r13d, 0x1ab876e6
005c689d 0f85ae040000                     jne 0x5c6d51
005c68a3 8b842484000000                   mov eax, dword ptr [rsp + 0x84]
005c68aa 0344247c                         add eax, dword ptr [rsp + 0x7c]
005c68ae 2b442474                         sub eax, dword ptr [rsp + 0x74]
005c68b2 03442470                         add eax, dword ptr [rsp + 0x70]
005c68b6 03442468                         add eax, dword ptr [rsp + 0x68]
005c68ba 7b2f                             jnp 0x5c68eb
005c68eb 7b3c                             jnp 0x5c6929
005c6929 03442460                         add eax, dword ptr [rsp + 0x60]
005c692d 89442450                         mov dword ptr [rsp + 0x50], eax
005c6931 80e1ff                           and cl, 0xff
005c6934 86db                             xchg bl, bl
005c6936 7151                             jno 0x5c6989
005c6989 7100                             jno 0x5c698b
005c698b 8b442450                         mov eax, dword ptr [rsp + 0x50]
005c698f b9e0faed62                       mov ecx, 0x62edfae0
005c6994 01c8                             add eax, ecx
005c6996 89442454                         mov dword ptr [rsp + 0x54], eax
005c699a 8b05e8c8b501                     mov eax, dword ptr [rip + 0x1b5c8e8]
005c69a0 89c1                             mov ecx, eax
005c69a2 81f199cf3305                     xor ecx, 0x533cf99
005c69a8 8d916ccedf9b                     lea edx, [rcx - 0x64203194]
005c69ae 448d81c4ca44ea                   lea r8d, [rcx - 0x15bb353c]
005c69b5 448d89ed26fa90                   lea r9d, [rcx - 0x6f05d913]
005c69bc 4131d1                           xor r9d, edx
005c69bf 01c8                             add eax, ecx
005c69c1 05ea5154da                       add eax, 0xda5451ea
005c69c6 4431c0                           xor eax, r8d
005c69c9 4431c8                           xor eax, r9d
005c69cc e98ffbffff                       jmp 0x5c6560
005c6560 89442444                         mov dword ptr [rsp + 0x44], eax
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6690 4181fd926d156c                   cmp r13d, 0x6c156d92
005c6697 0f8fa3010000                     jg 0x5c6840
005c669d 4181fd54067658                   cmp r13d, 0x58760654
005c66a4 0f852f040000                     jne 0x5c6ad9
005c6ad9 8b442454                         mov eax, dword ptr [rsp + 0x54]
005c6add 01f8                             add eax, edi
005c6adf 89442448                         mov dword ptr [rsp + 0x48], eax
005c6ae3 f8                               clc 
005c6ae4 733d                             jae 0x5c6b23
005c6b23 8b442448                         mov eax, dword ptr [rsp + 0x48]
005c6b27 01d8                             add eax, ebx
005c6b29 89442458                         mov dword ptr [rsp + 0x58], eax
005c6b2d 715d                             jno 0x5c6b8c
005c6b8c 8b442458                         mov eax, dword ptr [rsp + 0x58]
005c6b90 448d809ea4c7fe                   lea r8d, [rax - 0x1385b62]
005c6b97 4489842488000000                 mov dword ptr [rsp + 0x88], r8d
005c6b9f 05057a4fc4                       add eax, 0xc44f7a05
005c6ba4 8944245c                         mov dword ptr [rsp + 0x5c], eax
005c6ba8 8b05dec6b501                     mov eax, dword ptr [rip + 0x1b5c6de]
005c6bae 41b8f5245438                     mov r8d, 0x385424f5
005c6bb4 4129c0                           sub r8d, eax
005c6bb7 058c302369                       add eax, 0x6923308c
005c6bbc 4131c0                           xor r8d, eax
005c6bbf 4181f07b66dc91                   xor r8d, 0x91dc667b
005c6bc6 4129c0                           sub r8d, eax
005c6bc9 4489442444                       mov dword ptr [rsp + 0x44], r8d
005c6bce e991f9ffff                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6690 4181fd926d156c                   cmp r13d, 0x6c156d92
005c6697 0f8fa3010000                     jg 0x5c6840
005c6840 4181fd936d156c                   cmp r13d, 0x6c156d93
005c6847 0f8586030000                     jne 0x5c6bd3
005c6bd3 8b44245c                         mov eax, dword ptr [rsp + 0x5c]
005c6bd7 4401f0                           add eax, r14d
005c6bda 8984248c000000                   mov dword ptr [rsp + 0x8c], eax
005c6be1 8b442448                         mov eax, dword ptr [rsp + 0x48]
005c6be5 89c1                             mov ecx, eax
005c6be7 81e10e0175ae                     and ecx, 0xae75010e
005c6bed 8d0cc9                           lea ecx, [rcx + rcx*8]
005c6bf0 898c2490000000                   mov dword ptr [rsp + 0x90], ecx
005c6bf7 f7d0                             not eax
005c6bf9 250e0175ae                       and eax, 0xae75010e
005c6bfe 89842494000000                   mov dword ptr [rsp + 0x94], eax
005c6c05 8b0585c6b501                     mov eax, dword ptr [rip + 0x1b5c685]
005c6c0b 89c1                             mov ecx, eax
005c6c0d 81f13fdf7203                     xor ecx, 0x372df3f
005c6c13 4189c0                           mov r8d, eax
005c6c16 4181f085d05ada                   xor r8d, 0xda5ad085
005c6c1d 4189c1                           mov r9d, eax
005c6c20 4181f1604a2185                   xor r9d, 0x85214a60
005c6c27 418d91a6018df7                   lea edx, [r9 - 0x872fe5a]
005c6c2e 4189d5                           mov r13d, edx
005c6c31 4181f5b314805a                   xor r13d, 0x5a8014b3
005c6c38 29c8                             sub eax, ecx
005c6c3a 4429e8                           sub eax, r13d
005c6c3d 053a11781e                       add eax, 0x1e78113a
005c6c42 31d0                             xor eax, edx
005c6c44 4429c8                           sub eax, r9d
005c6c47 4429c0                           sub eax, r8d
005c6c4a e911f9ffff                       jmp 0x5c6560
005c6560 89442444                         mov dword ptr [rsp + 0x44], eax
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6600 4181fddc2f0d3e                   cmp r13d, 0x3e0d2fdc
005c6607 0f8f03010000                     jg 0x5c6710
005c660d 4181fde576b81a                   cmp r13d, 0x1ab876e5
005c6614 0f8f7c020000                     jg 0x5c6896
005c661a 4181fdba0f5013                   cmp r13d, 0x13500fba
005c6621 0f8528060000                     jne 0x5c6c4f
005c6c4f 8b842494000000                   mov eax, dword ptr [rsp + 0x94]
005c6c56 01c0                             add eax, eax
005c6c58 8d0480                           lea eax, [rax + rax*4]
005c6c5b 89842498000000                   mov dword ptr [rsp + 0x98], eax
005c6c62 8b052cc6b501                     mov eax, dword ptr [rip + 0x1b5c62c]
005c6c68 8d885172ef59                     lea ecx, [rax + 0x59ef7251]
005c6c6e 81f127d8b095                     xor ecx, 0x95b0d827
005c6c74 8d9160cf80f4                     lea edx, [rcx - 0xb7f30a0]
005c6c7a 81f2c90d08f6                     xor edx, 0xf6080dc9
005c6c80 01d0                             add eax, edx
005c6c82 055172ef59                       add eax, 0x59ef7251
005c6c87 81c206c2a95a                     add edx, 0x5aa9c206
005c6c8d 01c8                             add eax, ecx
005c6c8f 0560cf80f4                       add eax, 0xf480cf60
005c6c94 01c8                             add eax, ecx
005c6c96 05c34d2087                       add eax, 0x87204dc3
005c6c9b 31d0                             xor eax, edx
005c6c9d 35021ad8c3                       xor eax, 0xc3d81a02
005c6ca2 05676c25c2                       add eax, 0xc2256c67
005c6ca7 e9b4f8ffff                       jmp 0x5c6560
005c6560 89442444                         mov dword ptr [rsp + 0x44], eax
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6690 4181fd926d156c                   cmp r13d, 0x6c156d92
005c6697 0f8fa3010000                     jg 0x5c6840
005c669d 4181fd54067658                   cmp r13d, 0x58760654
005c66a4 0f852f040000                     jne 0x5c6ad9
005c66aa 8b442448                         mov eax, dword ptr [rsp + 0x48]
005c66ae f7d0                             not eax
005c66b0 0d0e0175ae                       or eax, 0xae75010e
005c66b5 8d0440                           lea eax, [rax + rax*2]
005c66b8 8984249c000000                   mov dword ptr [rsp + 0x9c], eax
005c66bf 8b05d3cbb501                     mov eax, dword ptr [rip + 0x1b5cbd3]
005c66c5 89c1                             mov ecx, eax
005c66c7 81f147b552f9                     xor ecx, 0xf952b547
005c66cd 8d9116f9425c                     lea edx, [rcx + 0x5c42f916]
005c66d3 4189d0                           mov r8d, edx
005c66d6 4181f017938bcf                   xor r8d, 0xcf8b9317
005c66dd 4181c0a15aaf22                   add r8d, 0x22af5aa1
005c66e4 4131c8                           xor r8d, ecx
005c66e7 4401c1                           add ecx, r8d
005c66ea 81c116f9425c                     add ecx, 0x5c42f916
005c66f0 31d1                             xor ecx, edx
005c66f2 81f17048f037                     xor ecx, 0x37f04870
005c66f8 01c1                             add ecx, eax
005c66fa 894c2444                         mov dword ptr [rsp + 0x44], ecx
005c66fe e961feffff                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6600 4181fddc2f0d3e                   cmp r13d, 0x3e0d2fdc
005c6607 0f8f03010000                     jg 0x5c6710
005c660d 4181fde576b81a                   cmp r13d, 0x1ab876e5
005c6614 0f8f7c020000                     jg 0x5c6896
005c661a 4181fdba0f5013                   cmp r13d, 0x13500fba
005c6621 0f8528060000                     jne 0x5c6c4f
005c6627 448b6c2448                       mov r13d, dword ptr [rsp + 0x48]
005c662c 41f7d5                           not r13d
005c662f 4181e5f1fe8a51                   and r13d, 0x518afef1
005c6636 4501ed                           add r13d, r13d
005c6639 4489ac24a0000000                 mov dword ptr [rsp + 0xa0], r13d
005c6641 448b2d54ccb501                   mov r13d, dword ptr [rip + 0x1b5cc54]
005c6648 458d850b756f68                   lea r8d, [r13 + 0x686f750b]
005c664f 4181f0de4e050b                   xor r8d, 0xb054ede
005c6656 418d801543eaa7                   lea eax, [r8 - 0x5815bceb]
005c665d 4501c5                           add r13d, r8d
005c6660 4181c520b85910                   add r13d, 0x1059b820
005c6667 41b9b228be8d                     mov r9d, 0x8dbe28b2
005c666d 4529e9                           sub r9d, r13d
005c6670 4131c1                           xor r9d, eax
005c6673 4181f1ebc33f20                   xor r9d, 0x203fc3eb
005c667a 4529c1                           sub r9d, r8d
005c667d 44894c2444                       mov dword ptr [rsp + 0x44], r9d
005c6682 e9ddfeffff                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6600 4181fddc2f0d3e                   cmp r13d, 0x3e0d2fdc
005c6607 0f8f03010000                     jg 0x5c6710
005c6710 4181fd157af64d                   cmp r13d, 0x4df67a15
005c6717 0f8fb4020000                     jg 0x5c69d1
005c69d1 4181fd167af64d                   cmp r13d, 0x4df67a16
005c69d8 0f85db030000                     jne 0x5c6db9
005c6db9 f7c581da8f67                     test ebp, 0x678fda81
005c6dbf 7149                             jno 0x5c6e0a
005c6e0a 8b442448                         mov eax, dword ptr [rsp + 0x48]
005c6e0e 21f0                             and eax, esi
005c6e10 01c0                             add eax, eax
005c6e12 2b8424a0000000                   sub eax, dword ptr [rsp + 0xa0]
005c6e19 898424a4000000                   mov dword ptr [rsp + 0xa4], eax
005c6e20 8b057ac4b501                     mov eax, dword ptr [rip + 0x1b5c47a]
005c6e26 8d88f402c126                     lea ecx, [rax + 0x26c102f4]
005c6e2c 8d9041309ecb                     lea edx, [rax - 0x3461cfbf]
005c6e32 4189d0                           mov r8d, edx
005c6e35 4181f0799d72e0                   xor r8d, 0xe0729d79
005c6e3c 458d88fcc73e37                   lea r9d, [r8 + 0x373ec7fc]
005c6e43 41f7d9                           neg r9d
005c6e46 4401c8                           add eax, r9d
005c6e49 05e0ba3f91                       add eax, 0x913fbae0
005c6e4e 31c8                             xor eax, ecx
005c6e50 29d0                             sub eax, edx
005c6e52 4429c0                           sub eax, r8d
005c6e55 4401c0                           add eax, r8d
005c6e58 05fcc73e37                       add eax, 0x373ec7fc
005c6e5d e9fef6ffff                       jmp 0x5c6560
005c6560 89442444                         mov dword ptr [rsp + 0x44], eax
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6690 4181fd926d156c                   cmp r13d, 0x6c156d92
005c6697 0f8fa3010000                     jg 0x5c6840
005c6840 4181fd936d156c                   cmp r13d, 0x6c156d93
005c6847 0f8586030000                     jne 0x5c6bd3
005c684d 8b8424a4000000                   mov eax, dword ptr [rsp + 0xa4]
005c6854 0384249c000000                   add eax, dword ptr [rsp + 0x9c]
005c685b 2b842498000000                   sub eax, dword ptr [rsp + 0x98]
005c6862 2b842490000000                   sub eax, dword ptr [rsp + 0x90]
005c6869 898424a8000000                   mov dword ptr [rsp + 0xa8], eax
005c6870 8b052ecab501                     mov eax, dword ptr [rip + 0x1b5ca2e]
005c6876 31e8                             xor eax, ebp
005c6878 448d803b96e84a                   lea r8d, [rax + 0x4ae8963b]
005c687f 4181f0f4e94840                   xor r8d, 0x4048e9f4
005c6886 4101c0                           add r8d, eax
005c6889 b8cff1bca7                       mov eax, 0xa7bcf1cf
005c688e 4429c0                           sub eax, r8d
005c6891 e9cafcffff                       jmp 0x5c6560
005c6560 89442444                         mov dword ptr [rsp + 0x44], eax
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6600 4181fddc2f0d3e                   cmp r13d, 0x3e0d2fdc
005c6607 0f8f03010000                     jg 0x5c6710
005c6710 4181fd157af64d                   cmp r13d, 0x4df67a15
005c6717 0f8fb4020000                     jg 0x5c69d1
005c69d1 4181fd167af64d                   cmp r13d, 0x4df67a16
005c69d8 0f85db030000                     jne 0x5c6db9
005c69de 8b8424a8000000                   mov eax, dword ptr [rsp + 0xa8]
005c69e5 4401d8                           add eax, r11d
005c69e8 898424ac000000                   mov dword ptr [rsp + 0xac], eax
005c69ef f8                               clc 
005c69f0 8aed                             mov ch, ch
005c69f2 731d                             jae 0x5c6a11
005c6a11 734f                             jae 0x5c6a62
005c6a62 8b0540c8b501                     mov eax, dword ptr [rip + 0x1b5c840]
005c6a68 8d8841dd7c1f                     lea ecx, [rax + 0x1f7cdd41]
005c6a6e 81f15a3bf4b3                     xor ecx, 0xb3f43b5a
005c6a74 8d912dc2ccd4                     lea edx, [rcx - 0x2b333dd3]
005c6a7a 050badaf7f                       add eax, 0x7fafad0b
005c6a7f 31d0                             xor eax, edx
005c6a81 29c8                             sub eax, ecx
005c6a83 89442444                         mov dword ptr [rsp + 0x44], eax
005c6a87 e9d8faffff                       jmp 0x5c6564
005c6564 448b6c2444                       mov r13d, dword ptr [rsp + 0x44]
005c6569 4181fd53067658                   cmp r13d, 0x58760653
005c6570 0f8e8a000000                     jle 0x5c6600
005c6576 4181fd2576e475                   cmp r13d, 0x75e47625
005c657d 0f8e0d010000                     jle 0x5c6690
005c6583 4181fdba87c879                   cmp r13d, 0x79c887ba
005c658a 0f8e66020000                     jle 0x5c67f6
005c6590 4181fdbb87c879                   cmp r13d, 0x79c887bb
005c6597 0f84ef040000                     je 0x5c6a8c
005c659d 4181fd274b707d                   cmp r13d, 0x7d704b27
005c65a4 0f85b8080000                     jne 0x5c6e62
005c6e62 8b8424ac000000                   mov eax, dword ptr [rsp + 0xac]
005c6e69 33842488000000                   xor eax, dword ptr [rsp + 0x88]
005c6e70 03442454                         add eax, dword ptr [rsp + 0x54]
005c6e74 3384248c000000                   xor eax, dword ptr [rsp + 0x8c]
005c6e7b 2b442450                         sub eax, dword ptr [rsp + 0x50]
005c6e7f 2b442458                         sub eax, dword ptr [rsp + 0x58]
005c6e83 2b44245c                         sub eax, dword ptr [rsp + 0x5c]
005c6e87 898424cc000000                   mov dword ptr [rsp + 0xcc], eax
005c6e8e 488b842450010000                 mov rax, qword ptr [rsp + 0x150]
005c6e96 4889442438                       mov qword ptr [rsp + 0x38], rax
005c6e9b 488b8424b0000000                 mov rax, qword ptr [rsp + 0xb0]
005c6ea3 4889442428                       mov qword ptr [rsp + 0x28], rax
005c6ea8 488b8424b8000000                 mov rax, qword ptr [rsp + 0xb8]
005c6eb0 4889442420                       mov qword ptr [rsp + 0x20], rax
005c6eb5 48c74424302f000000               mov qword ptr [rsp + 0x30], 0x2f
005c6ebe 4c8d8424cc000000                 lea r8, [rsp + 0xcc]
005c6ec6 b917000000                       mov ecx, 0x17
005c6ecb 41b910000000                     mov r9d, 0x10
005c6ed1 488b9424c0000000                 mov rdx, qword ptr [rsp + 0xc0]
005c6ed9 e8a2c80b00                       call 0x683780
