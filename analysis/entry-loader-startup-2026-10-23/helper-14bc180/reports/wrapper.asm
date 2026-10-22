; STATIC ONLY: Conditional on reaching this wrapper; either CF after stack subtraction is allowed
015b40a0 4883ec38                         sub rsp, 0x38
015b40a4 4c89c0                           mov rax, r8
015b40a7 4c8b4c2468                       mov r9, qword ptr [rsp + 0x68]
015b40ac 733b                             jae 0x15b40e9
015b40ae 86ff                             xchg bh, bh
015b40b0 722b                             jb 0x15b40dd ; fallthrough of JAE implies CF=1; XCHG BH,BH preserves flags
015b40dd 720c                             jb 0x15b40eb ; JB taken, CF=1 unchanged
015b40e9 7300                             jae 0x15b40eb ; JAE taken, CF=0 unchanged
015b40eb 48894c2430                       mov qword ptr [rsp + 0x30], rcx
015b40f0 48c74424281c000000               mov qword ptr [rsp + 0x28], 0x1c
015b40f9 48c744242021000000               mov qword ptr [rsp + 0x20], 0x21
015b4102 41b846000000                     mov r8d, 0x46
015b4108 4889d1                           mov rcx, rdx
015b410b 4889c2                           mov rdx, rax
015b410e e82d2301ff                       call 0x5c6440
