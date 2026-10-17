.intel_syntax noprefix
.section .driver,"ax"
.global _start
_start:
 cld
 mov esi,offset input
 mov edi,29
1:
 mov eax,3
 xor ebx,ebx
 mov ecx,esi
 mov edx,edi
 int 0x80
 test eax,eax
 js fail
 jz 2f
 add esi,eax
 sub edi,eax
 jnz 1b
 jmp fail
2:
 cmp esi,offset input+28
 jne fail
 cmp dword ptr [input+8],4096
 ja fail
 cmp dword ptr [input+12],1
 ja fail
 mov eax,125
 mov ebx,offset input
 mov ecx,4096
 mov edx,1
 int 0x80
 test eax,eax
 jnz fail
 mov dword ptr [context+0x148],0x3fffffff
 mov byte ptr [context+0x150],30
 mov eax,[input+12]
 mov byte ptr [context+0x151],al
 mov eax,[input+24]
 mov [file_object+0x24],eax
 mov dword ptr [guard_before],0x12345678
 mov dword ptr [guard_after],0x87654321
 mov ebp,esp
 push offset result+4
 push dword ptr [input+8]
 push dword ptr [input+4]
 push dword ptr [input]
 push offset payload
 mov ecx,offset context
 call archive_read
 cmp esp,ebp
 jne fail
 mov [result],eax
 cmp dword ptr [guard_before],0x12345678
 jne fail
 cmp dword ptr [guard_after],0x87654321
 jne fail
 cmp dword ptr [result+4],4096
 ja fail
 mov esi,offset result
 mov edi,48
 call write_all
 mov esi,offset payload
 mov edi,[result+4]
 test edi,edi
 jz finish
 call write_all
finish:
 mov eax,1
 xor ebx,ebx
 int 0x80
write_all:
 mov eax,4
 mov ebx,1
 mov ecx,esi
 mov edx,edi
 int 0x80
 test eax,eax
 jle fail
 add esi,eax
 sub edi,eax
 jnz write_all
 ret
fail:
 mov eax,1
 mov ebx,90
 int 0x80
read_api:
 push ebp
 mov ebp,esp
 push ebx
 push esi
 push edi
 inc dword ptr [result+16]
 mov eax,[ebp+8]
 mov [result+40],eax
 mov eax,[ebp+16]
 mov [result+36],eax
 mov eax,[ebp+24]
 mov edx,[eax+8]
 mov [result+28],edx
 mov edx,[eax+12]
 mov [result+32],edx
 mov ecx,[ebp+20]
 mov dword ptr [ecx],0
 mov eax,[input+16]
 test eax,eax
 jnz read_error
 mov ebx,[ebp+8]
 mov ecx,[ebp+12]
 mov edx,[ebp+16]
 mov esi,[result+28]
 mov edi,[result+32]
 mov eax,180
 int 0x80
 test eax,eax
 js syscall_error
 mov ecx,[ebp+20]
 mov [ecx],eax
 mov eax,1
 jmp read_done
syscall_error:
 mov eax,5
read_error:
 mov [last_error],eax
 xor eax,eax
read_done:
 pop edi
 pop esi
 pop ebx
 leave
 ret 20
get_error:
 mov eax,[last_error]
 ret
.section .ownership,"ax"
.global ownership
ownership:
 inc dword ptr [result+20]
 ret
.section .error_text,"ax"
.global error_text
error_text:
 xor eax,eax
 ret
.section .membership_forbidden,"ax"
.global membership_forbidden
membership_forbidden:
 jmp fail
.section .alignment_forbidden,"ax"
.global alignment_forbidden
alignment_forbidden:
 jmp fail
.section .error_log,"ax"
.global error_log
error_log:
 inc dword ptr [result+44]
 ret
.section .open_adapter,"ax"
.global open_adapter
open_adapter:
 push ebp
 mov ebp,esp
 inc dword ptr [result+8]
 mov eax,[ebp+12]
 mov [result+12],eax
 mov eax,[ebp+24]
 mov [result+24],eax
 mov edx,[ebp+8]
 mov eax,[input+20]
 test eax,eax
 jnz open_error
 mov dword ptr [edx],offset file_object
 jmp open_done
open_error:
 mov dword ptr [edx],0
 mov edx,[ebp+28]
 mov [edx],eax
open_done:
 leave
 ret 36
.section .frame_start,"ax"
.global frame_start
frame_start:
 pop eax
 add esp,4
 push ebp
 mov ebp,esp
 sub esp,256
 mov [ebp-240],ebx
 mov [ebp-244],esi
 mov [ebp-248],edi
 push eax
 ret
.section .frame_end,"ax"
.global frame_end
frame_end:
 pop edx
 mov ebx,[ebp-240]
 mov esi,[ebp-244]
 mov edi,[ebp-248]
 mov esp,ebp
 pop ebp
 push edx
 ret
.section .log_adapter,"ax"
.global log_adapter
log_adapter:
 ret
.section .iat,"a"
.org 0x248
.long get_error
.org 0x2c8
.long read_api
.section .scratch,"aw",@nobits
.balign 4096
input: .skip 4096
context: .skip 512
file_object: .skip 64
last_error: .skip 4
result: .skip 48
# status, actualbytes, opens, archive, reads, releases, flags,
# offsetlo, offsethi, requested, fd, lower_error_logs
.balign 16
guard_before: .skip 4
payload: .skip 4096
guard_after: .skip 4
.section .note.GNU-stack,"",@progbits
