.intel_syntax noprefix
.section .driver,"ax"
.global _start
_start:
 cld
 mov esi,offset input
 mov edi,45
read_loop:
 mov eax,3
 xor ebx,ebx
 mov ecx,esi
 mov edx,edi
 int 0x80
 test eax,eax
 js fail
 jz read_done
 add esi,eax
 sub edi,eax
 jnz read_loop
 jmp fail
read_done:
 cmp esi,offset input+44
 jne fail
 # Input occupies its own pages; all parser inputs are read-only.
 mov eax,125
 mov ebx,offset input
 mov ecx,4096
 mov edx,1
 int 0x80
 test eax,eax
 jnz fail
 mov dword ptr [guard_before],0x11223344
 mov dword ptr [guard_after],0x55667788
 mov ebp,esp
 push offset parsed
 push dword ptr [input+4]
 push dword ptr [input]
 push dword ptr [input+8]
 push offset input+12
 call parse_span
 add esp,20
 and eax,255
 cmp esp,ebp
 jne fail
 mov [result],eax
 cmp eax,1
 jne done
 mov ecx,offset parsed
 call archive_number
 mov [archive],eax
 mov [archive+4],edx
 mov ecx,offset parsed
 call payload_offset
 mov [payload],eax
 mov [payload+4],edx
done:
 cmp dword ptr [guard_before],0x11223344
 jne fail
 cmp dword ptr [guard_after],0x55667788
 jne fail
 # Parser cannot modify input, and output object is exactly 40 bytes.
 mov esi,offset result
 mov edi,60
write_loop:
 mov eax,4
 mov ebx,1
 mov ecx,esi
 mov edx,edi
 int 0x80
 test eax,eax
 jle fail
 add esi,eax
 sub edi,eax
 jnz write_loop
 mov eax,1
 xor ebx,ebx
 int 0x80
fail:
 mov eax,1
 mov ebx,90
 int 0x80
.section .scratch,"aw",@nobits
.balign 4096
input: .skip 4096
.balign 16
guard_before: .skip 4
result: .skip 4
parsed: .skip 40
archive: .skip 8
payload: .skip 8
guard_after: .skip 4
.section .note.GNU-stack,"",@progbits
