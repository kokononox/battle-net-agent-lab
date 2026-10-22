; STATIC annotation only. reason=1; original bytes are unchanged.
; Stops conceptually at the call; post-call continuation requires return.
00df87c0 4883ec28                       sub rsp, 0x28
00df87c4 8b05decd3401                   mov eax, dword ptr [rip + 0x134cdde]
00df87ca 89c1                           mov ecx, eax
00df87cc 81f19d747a9a                   xor ecx, 0x9a7a749d
00df87d2 448d81517c946d                 lea r8d, [rcx + 0x6d947c51]
00df87d9 4431c1                         xor ecx, r8d
00df87dc 4181f0a24c72f3                 xor r8d, 0xf3724ca2
00df87e3 458d8896086521                 lea r9d, [r8 + 0x21650896]
00df87ea 4181f1cfd18178                 xor r9d, 0x7881d1cf
00df87f1 81f1ab35759a                   xor ecx, 0x9a7535ab
00df87f7 01c1                           add ecx, eax
00df87f9 4401c9                         add ecx, r9d
00df87fc 4401c1                         add ecx, r8d
00df87ff 418d0408                       lea eax, [r8 + rcx]
00df8803 05b56759d8                     add eax, 0xd85967b5
00df8808 89442424                       mov dword ptr [rsp + 0x24], eax
00df880c 817c2424befeb840               cmp dword ptr [rsp + 0x24], 0x40b8febe
00df8814 0f85a4000000                   jne 0xdf88be
00df881a 660f1f440000                   nop word ptr [rax + rax]
00df8820 24ff                           and al, 0xff
00df8822 7345                           jae 0xdf8869 ; AND AL clears CF; JAE is taken
00df8869 83fa01                         cmp edx, 1
00df886c 7565                           jne 0xdf88d3 ; Reason=DLL_PROCESS_ATTACH (EDX=1), preserved to CMP
00df886e 8b0530cd3401                   mov eax, dword ptr [rip + 0x134cd30]
00df8874 8d88dbb8874f                   lea ecx, [rax + 0x4f87b8db]
00df887a 81f198913e4d                   xor ecx, 0x4d3e9198
00df8880 448d81119d5772                 lea r8d, [rcx + 0x72579d11]
00df8887 4101c0                         add r8d, eax
00df888a 4181c0dbb8874f                 add r8d, 0x4f87b8db
00df8891 41f7d8                         neg r8d
00df8894 4101c8                         add r8d, ecx
00df8897 4181c0119d5772                 add r8d, 0x72579d11
00df889e 4101c0                         add r8d, eax
00df88a1 4401c1                         add ecx, r8d
00df88a4 81c18d597484                   add ecx, 0x8474598d
00df88aa 31c1                           xor ecx, eax
00df88ac 894c2424                       mov dword ptr [rsp + 0x24], ecx
00df88b0 817c2424befeb840               cmp dword ptr [rsp + 0x24], 0x40b8febe
00df88b8 0f8462ffffff                   je 0xdf8820 ; Second guard is odd for every DWORD; even magic cannot equal it
00df88be b962000000                     mov ecx, 0x62
00df88c3 ba1f000000                     mov edx, 0x1f
00df88c8 41b819000000                   mov r8d, 0x19
00df88ce e8ad386c00                     call 0x14bc180
00df88d3 90                             nop 
00df88d4 4883c428                       add rsp, 0x28
00df88d8 c3                             ret 
