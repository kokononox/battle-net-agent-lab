# Original 0x72d18f primitive with a Linux stdin/stdout driver; no Windows API.
.intel_syntax noprefix
.section .driver,"ax"
.global _start
_start:
 cld
 mov esi,offset input
 mov edi,33
read_loop:
 mov eax,3
 xor ebx,ebx
 mov ecx,esi
 mov edx,edi
 int 0x80
 test eax,eax
 js fail
 jz done_read
 add esi,eax
 sub edi,eax
 jnz read_loop
 jmp fail
done_read:
 cmp esi,offset input+32
 jne fail
 push offset output+4
 push offset input+16
 push offset input
 call value_range
 add esp,12
 movzx eax,al
 mov [output],eax
 cmp dword ptr [before],0x12345678
 jne fail
 cmp dword ptr [after],0x87654321
 jne fail
 mov eax,4
 mov ebx,1
 mov ecx,offset output
 mov edx,12
 int 0x80
 cmp eax,12
 jne fail
 mov eax,1
 xor ebx,ebx
 int 0x80
fail:
 mov eax,1
 mov ebx,111
 int 0x80
.section .scratch,"aw"
input: .space 33
.balign 4
before: .long 0x12345678
output: .space 12
after: .long 0x87654321
.section .note.GNU-stack,"",@progbits
