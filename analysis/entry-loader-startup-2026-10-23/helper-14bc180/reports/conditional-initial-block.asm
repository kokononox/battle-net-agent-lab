; STATIC ONLY: Initial global equals its disk value; pointer comparison at 0x14C2242 is not equal; valid ordinary reads and unchanged code
014c224b 4889842490020000                 mov qword ptr [rsp + 0x290], rax
014c2253 488b842490020000                 mov rax, qword ptr [rsp + 0x290]
014c225b 4889842418010000                 mov qword ptr [rsp + 0x118], rax
014c2263 0f29b424d0080000                 movaps xmmword ptr [rsp + 0x8d0], xmm6
014c226b 0f29b424c0080000                 movaps xmmword ptr [rsp + 0x8c0], xmm6
014c2273 0f29b424b0080000                 movaps xmmword ptr [rsp + 0x8b0], xmm6
014c227b 0f29b424a0080000                 movaps xmmword ptr [rsp + 0x8a0], xmm6
014c2283 0f29b42490080000                 movaps xmmword ptr [rsp + 0x890], xmm6
014c228b 0f29b42480080000                 movaps xmmword ptr [rsp + 0x880], xmm6
014c2293 0f29b42470080000                 movaps xmmword ptr [rsp + 0x870], xmm6
014c229b 0f29b42460080000                 movaps xmmword ptr [rsp + 0x860], xmm6
014c22a3 0f29b42450080000                 movaps xmmword ptr [rsp + 0x850], xmm6
014c22ab 0f29b42440080000                 movaps xmmword ptr [rsp + 0x840], xmm6
014c22b3 0f29b42430080000                 movaps xmmword ptr [rsp + 0x830], xmm6
014c22bb 0f29b42420080000                 movaps xmmword ptr [rsp + 0x820], xmm6
014c22c3 0f29b42410080000                 movaps xmmword ptr [rsp + 0x810], xmm6
014c22cb 0f29b42400080000                 movaps xmmword ptr [rsp + 0x800], xmm6
014c22d3 0f29b424f0070000                 movaps xmmword ptr [rsp + 0x7f0], xmm6
014c22db 0f29b424e0070000                 movaps xmmword ptr [rsp + 0x7e0], xmm6
014c22e3 0fb74058                         movzx eax, word ptr [rax + 0x58]
014c22e7 0fb70daa78c300                   movzx ecx, word ptr [rip + 0xc378aa]
014c22ee 8d912af8ffff                     lea edx, [rcx - 0x7d6]
014c22f4 448d81bc110000                   lea r8d, [rcx + 0x11bc]
014c22fb 4131d0                           xor r8d, edx
014c22fe 89ca                             mov edx, ecx
014c2300 f7d2                             not edx
014c2302 4189d1                           mov r9d, edx
014c2305 4181c9962d0000                   or r9d, 0x2d96
014c230c 4189d2                           mov r10d, edx
014c230f 4181e269d2ffff                   and r10d, 0xffffd269
014c2316 4501ca                           add r10d, r9d
014c2319 81e1962d0000                     and ecx, 0x2d96
014c231f 01c9                             add ecx, ecx
014c2321 81f12c5b0000                     xor ecx, 0x5b2c
014c2327 4401d1                           add ecx, r10d
014c232a 29d1                             sub ecx, edx
014c232c ffc1                             inc ecx
014c232e 4431c1                           xor ecx, r8d
014c2331 0c00                             or al, 0
014c2333 8aed                             mov ch, ch
014c2335 713d                             jno 0x14c2374 ; OR AL,0 clears OF; MOV CH,CH preserves flags
014c2374 80f1d6                           xor cl, 0xd6
014c2377 48d3e8                           shr rax, cl
014c237a 7b36                             jnp 0x14c23b2
014c237c 7a4a                             jp 0x14c23c8 ; fallthrough of adjacent JNP: PF=1; JP is complementary
014c23b2 7b08                             jnp 0x14c23bc ; arrived through JNP; flags unchanged
014c23bc 7b16                             jnp 0x14c23d4 ; preceding JNP taken; flags unchanged
014c23c8 7a0a                             jp 0x14c23d4 ; arrived through JP; flags unchanged
014c23d4 a8e1                             test al, 0xe1
014c23d6 c0ff00                           sar bh, 0
014c23d9 7128                             jno 0x14c2403 ; TEST clears OF; SAR BH,0 preserves flags
014c2403 90                               nop 
014c2404 710e                             jno 0x14c2414 ; JNO taken; NOP preserves OF
014c2414 488b8c2418010000                 mov rcx, qword ptr [rsp + 0x118]
014c241c 4c8b4160                         mov r8, qword ptr [rcx + 0x60]
014c2420 488d8c24d8050000                 lea rcx, [rsp + 0x5d8]
014c2428 48894c2428                       mov qword ptr [rsp + 0x28], rcx
014c242d 48c74424305b000000               mov qword ptr [rsp + 0x30], 0x5b
014c2436 48c74424204d000000               mov qword ptr [rsp + 0x20], 0x4d
014c243f 41b944000000                     mov r9d, 0x44
014c2445 4889c1                           mov rcx, rax
014c2448 488d9424e0070000                 lea rdx, [rsp + 0x7e0]
014c2450 e84b1c0f00                       call 0x15b40a0
