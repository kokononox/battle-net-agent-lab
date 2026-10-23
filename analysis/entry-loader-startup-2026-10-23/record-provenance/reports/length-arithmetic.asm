; STATIC VALUE MODEL. N=half length requires G=0xF92D. No runtime values observed.
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
014c2374 80f1d6                           xor cl, 0xd6
014c2377 48d3e8                           shr rax, cl
