# Linux i386 harness. No PE loader, Windows API, network or filesystem calls.
# argv[1]=synthetic ASCII computer name, argv[2]=raw ASCII path to normalize.
# stdout=canonical bytes + NUL + MD5 seed16 + reserved keys256 (archive0/cap1024).
.section .driver,"ax"
.global _start
_start:
 cmpl $3,(%esp)
 jne bad
 mov 8(%esp),%esi
 mov %esi,host
 mov $15,%edx
 call checked_len
 test %eax,%eax
 jz bad
 mov %eax,hostlen
 mov 12(%esp),%esi
 mov %esi,path
 mov $775,%edx
 call checked_len
 test %eax,%eax
 jz bad
 push path
 push $780
 push $out
 call normalize
 add $12,%esp
 mov $out,%esi
 mov $779,%edx
 call checked_len
 mov %eax,pathlen
 mov $context,%ecx
 call md5init
 push hostlen
 push host
 mov $context,%ecx
 call md5update
 push pathlen
 push $out
 mov $context,%ecx
 call md5update
 push $seed
 mov $context,%ecx
 call md5final
 push $keys
 push $1024
 push $0
 push $seed
 call keygen
 add $16,%esp
 mov $out,%ecx
 mov pathlen,%edx
 inc %edx
 call emit
 mov $seed,%ecx
 mov $16,%edx
 call emit
 mov $keys,%ecx
 mov $256,%edx
 call emit
 mov $1,%eax
 xor %ebx,%ebx
 int $0x80
# checked nonempty ASCII C string, EDX=max bytes; no environment expansion.
checked_len:
 xor %eax,%eax
1:
 movzbl (%esi,%eax),%ecx
 test %ecx,%ecx
 jz 2f
 cmp $0x20,%ecx
 jb bad
 cmp $0x7e,%ecx
 ja bad
 inc %eax
 cmp %edx,%eax
 ja bad
 jmp 1b
2:
 ret
emit:
 push %ebx
3:
 mov $4,%eax
 mov $1,%ebx
 int $0x80
 test %eax,%eax
 jle bad
 add %eax,%ecx
 sub %eax,%edx
 jnz 3b
 pop %ebx
 ret
bad:
 mov $1,%eax
 mov $90,%ebx
 int $0x80
# libc-independent replacements only for known pure memcpy/memset targets.
.section .memcpy,"ax"
.global copy_stub
copy_stub:
 push %edi
 push %esi
 mov 12(%esp),%edi
 mov 16(%esp),%esi
 mov 20(%esp),%ecx
 mov %edi,%eax
 cld
 rep movsb
 pop %esi
 pop %edi
 ret
.section .memset,"ax"
.global zero_stub
zero_stub:
 push %edi
 mov 8(%esp),%edi
 mov 12(%esp),%eax
 mov 16(%esp),%ecx
 mov %edi,%edx
 cld
 rep stosb
 mov %edx,%eax
 pop %edi
 ret
.section .scratch,"aw",@nobits
host: .zero 4
hostlen: .zero 4
path: .zero 4
pathlen: .zero 4
out: .zero 780
seed: .zero 16
keys: .zero 256
context: .zero 104
.section .note.GNU-stack,"",@progbits
