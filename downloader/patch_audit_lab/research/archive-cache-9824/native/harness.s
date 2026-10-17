.intel_syntax noprefix
.section .driver,"ax"
.global _start
_start:
 cld
 mov esi,offset input
 mov edi,49
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
 cmp esi,offset input+48
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
 call init_cache
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
 call collect_cache
 cmp dword ptr [guard_before],0x12345678
 jne fail
 cmp dword ptr [guard_after],0x87654321
 jne fail
 cmp dword ptr [result+4],4096
 ja fail
 mov esi,offset result
 mov edi,148
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
init_cache:
 # One-bucket, bounded two-entry collision fixture; original hash still runs.
 mov edi,offset context+0x154
 lea eax,[edi+8]
 mov [eax],eax
 mov [eax+4],eax
 mov dword ptr [edi+0x10],offset heads
 mov dword ptr [edi+0x14],offset entries
 mov dword ptr [edi+0x18],offset nexts
 mov dword ptr [edi+0x20],1
 mov dword ptr [heads],-1
 mov eax,[input+4]
 shl eax,2
 mov edx,[input]
 shr edx,30
 or eax,edx
 mov [result+12],eax
 mov [entries],eax
 mov [entries+24],eax
 mov dword ptr [entries+16],offset file_object
 mov dword ptr [entries+40],offset file_second
 mov dword ptr [nexts],-1
 mov dword ptr [nexts+4],-1
 mov dword ptr [file_object+4],1
 mov dword ptr [file_second+4],1
 mov dword ptr [file_new+4],2
 mov dword ptr [file_object],offset vtable_trap
 mov dword ptr [file_second],offset vtable_trap
 mov dword ptr [file_new],offset vtable_trap
 mov eax,[input+32]
 mov [file_object+0x24],eax
 mov eax,[input+36]
 mov [file_second+0x24],eax
 mov eax,[input+28]
 cmp eax,6
 ja fail
 test eax,eax
 jz cache_init_done
 mov dword ptr [heads],0
 lea eax,[edi+8]
 mov dword ptr [file_object+0x2c],eax
 mov dword ptr [file_object+0x30],eax
 mov dword ptr [eax],offset file_object+0x2c
 mov dword ptr [eax+4],offset file_object+0x2c
 mov eax,[input+28]
 cmp eax,2
 jne 3f
 inc dword ptr [entries]
3:
 cmp eax,3
 jne 4f
 mov byte ptr [entries+8],1
4:
 cmp eax,4
 jne 5f
 mov dword ptr [entries+4],1
5:
 cmp eax,5
 jb cache_init_done
 mov dword ptr [nexts],1
 lea edx,[edi+8]
 mov dword ptr [file_object+0x2c],offset file_second+0x2c
 mov dword ptr [file_second+0x30],offset file_object+0x2c
 mov [file_second+0x2c],edx
 mov dword ptr [edx+4],offset file_second+0x2c
 # Scenario 5: chain head has wrong high DWORD; second is the hit.
 cmp eax,5
 jne 6f
 mov dword ptr [entries+4],1
 jmp cache_init_done
6:
 # Scenario 6: first is hit, but not initially at the list tail.
 inc dword ptr [entries+24]
cache_init_done:
 mov ecx,offset entries
 push ecx
 call key_hash
 mov [result+100],eax
 ret
collect_cache:
 mov eax,[file_object+4]
 mov [result+84],eax
 mov eax,[file_second+4]
 mov [result+88],eax
 mov eax,[context+0x15c]
 mov edx,2
 cmp eax,offset file_object+0x2c
 jne 7f
 xor edx,edx
7:
 cmp eax,offset file_second+0x2c
 jne 8f
 mov edx,1
8:
 mov [result+92],edx
 mov eax,[file_new+4]
 mov [result+20],eax
 ret
create_api:
 push ebp
 mov ebp,esp
 push ebx
 push esi
 push edi
 inc dword ptr [result+64]
 mov eax,[ebp+12]
 mov [result+68],eax
 mov eax,[ebp+24]
 mov [result+72],eax
 mov eax,[ebp+16]
 mov [result+76],eax
 mov eax,[ebp+28]
 mov [result+80],eax
 # Never permit original write/create modes. Report denial; do not downgrade.
 cmp dword ptr [ebp+12],0x80000000
 jne create_denied
 cmp dword ptr [ebp+24],3
 jne create_denied
 mov eax,[input+20]
 test eax,eax
 jnz create_error
 mov esi,[ebp+8]
 mov edi,offset open_name
 xor ecx,ecx
create_convert:
 lodsw
 test ah,ah
 jnz fail
 stosb
 test al,al
 jz create_open
 inc ecx
 cmp ecx,31
 ja fail
 jmp create_convert
create_open:
 mov eax,295
 mov ebx,[input+24]
 mov ecx,offset open_name
 mov edx,0xa0000
 xor esi,esi
 int 0x80
 test eax,eax
 jns create_done
 neg eax
 cmp eax,2
 je create_error
 mov eax,5
 jmp create_error
create_denied:
 mov eax,5
create_error:
 mov [last_error],eax
 mov eax,-1
create_done:
 pop edi
 pop esi
 pop ebx
 leave
 ret 28
forbidden_api:
 jmp fail
frame_end_impl:
 pop edx
 mov ebx,[ebp-1200]
 mov esi,[ebp-1204]
 mov edi,[ebp-1208]
 mov esp,ebp
 pop ebp
 push edx
 ret
vtable_trap: .long fail,fail
read_api:
 push ebp
 mov ebp,esp
 push ebx
 push esi
 push edi
 inc dword ptr [result+16]
 mov eax,[file_object+4]
 mov [result+104],eax
 mov eax,[file_second+4]
 mov [result+108],eax
 mov eax,[file_new+4]
 mov [result+112],eax
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
.section .frame_start,"ax"
.global frame_start
frame_start:
 pop eax
 add esp,4
 push ebp
 mov ebp,esp
 sub esp,1280
 mov [ebp-1200],ebx
 mov [ebp-1204],esi
 mov [ebp-1208],edi
 push eax
 ret
.section .frame_end,"ax"
.global frame_end
frame_end:
 jmp frame_end_impl
.section .log_adapter,"ax"
.global log_adapter
log_adapter:
 ret
.section .iat,"a"
.org 0x248
.long get_error
.org 0x2b4
.long create_api
.org 0x2c8
.long read_api
.org 0x2d0
.long forbidden_api
.section .frame_start_cookie,"ax"
.global frame_start_cookie
frame_start_cookie:
 jmp frame_start
.section .frame_end_cookie,"ax"
.global frame_end_cookie
frame_end_cookie:
 jmp frame_end
.section .cookie_check,"ax"
.global cookie_check
cookie_check:
 ret
.section .lock_adapter,"ax"
.global lock_adapter
lock_adapter:
 inc dword ptr [result+8]
 inc dword ptr [result+48]
 ret
.section .unlock_adapter,"ax"
.global unlock_adapter
unlock_adapter:
 inc dword ptr [result+52]
 ret
.section .memset_adapter,"ax"
.global memset_adapter
memset_adapter:
 push ebp
 mov ebp,esp
 push edi
 mov edi,[ebp+8]
 mov eax,[ebp+12]
 mov ecx,[ebp+16]
 rep stosb
 mov eax,[ebp+8]
 pop edi
 leave
 ret
.section .printf_adapter,"ax"
.global printf_adapter
printf_adapter:
 push ebp
 mov ebp,esp
 push ebx
 push esi
 push edi
 inc dword ptr [result+60]
 # Controlled profile: original formatter selected the literal data.%03d.
 cmp dword ptr [ebp+16],offset filename_default
 jne fail
 mov edi,[ebp+8]
 cmp dword ptr [ebp+12],780
 jne fail
 mov esi,[ebp+20]
 mov eax,[esi]
 cmp eax,1022
 ja fail
 mov dword ptr [edi],0x61746164
 mov byte ptr [edi+4],'.'
 add edi,5
 xor ecx,ecx
 mov ebx,10
format_digits:
 xor edx,edx
 div ebx
 add edx,48
 push edx
 inc ecx
 test eax,eax
 jnz format_digits
format_padding:
 cmp ecx,3
 jae format_output
 push 48
 inc ecx
 jmp format_padding
format_output:
 pop eax
 stosb
 loop format_output
 mov byte ptr [edi],0
 mov esi,[ebp+8]
 mov ecx,32
 mov edi,offset filename_trace
 rep movsb
 mov eax,[input+40]
 test eax,eax
 jnz format_done
 mov eax,8
 cmp byte ptr [filename_trace+8],0
 je format_done
 inc eax
format_done:
 mov [result+96],eax
 pop edi
 pop esi
 pop ebx
 leave
 ret
.section .constructor_adapter,"ax"
.global constructor_adapter
constructor_adapter:
 push ebp
 mov ebp,esp
 push ebx
 inc dword ptr [result+56]
 mov eax,[ebp+24]
 mov [result+24],eax
 # Actual allocation/table insertion omitted; the OS handle route is ORIGINAL.
 movzx eax,byte ptr [input+44]
 push eax
 push dword ptr [ebp+28]
 push dword ptr [ebp+24]
 push dword ptr [ebp+20]
 push offset file_new+0x24
 call file_open_route
 add esp,20
 mov edx,[ebp+8]
 test eax,eax
 jnz constructor_error
 mov dword ptr [edx],offset file_new
 jmp constructor_done
constructor_error:
 mov ecx,[ebp+40]
 mov [ecx],eax
 mov dword ptr [edx],0
constructor_done:
 mov eax,edx
 pop ebx
 leave
 ret 36
.section .strlen_adapter,"ax"
.global strlen_adapter
strlen_adapter:
 mov edx,[esp+4]
 xor eax,eax
strlen_loop:
 cmp byte ptr [edx+eax],0
 je strlen_done
 inc eax
 cmp eax,31
 ja fail
 jmp strlen_loop
strlen_done:
 ret
.section .utf16_adapter,"ax"
.global utf16_adapter
utf16_adapter:
 push ebp
 mov ebp,esp
 push esi
 push edi
 mov edi,[ebp+8]
 mov esi,[ebp+16]
 xor ecx,ecx
utf_loop:
 lodsb
 movzx eax,al
 stosw
 test eax,eax
 jz utf_done
 inc ecx
 cmp ecx,31
 ja fail
 jmp utf_loop
utf_done:
 mov eax,ecx
 pop edi
 pop esi
 leave
 ret
.section .stack_alloc,"ax"
.global stack_alloc
stack_alloc:
 pop edx
 sub esp,eax
 push edx
 ret
.section .invalid_mode_forbidden,"ax"
.global invalid_mode_forbidden
invalid_mode_forbidden:
 jmp fail
.section .scratch,"aw",@nobits
.balign 4096
input: .skip 4096
context: .skip 512
heads: .skip 4
entries: .skip 48
nexts: .skip 8
file_second: .skip 64
file_new: .skip 64
open_name: .skip 32
file_object: .skip 64
last_error: .skip 4
result: .skip 116
filename_trace: .skip 32
# status, actualbytes, opens, archive, reads, releases, flags,
# offsetlo, offsethi, requested, fd, lower_error_logs
.balign 16
guard_before: .skip 4
payload: .skip 4096
guard_after: .skip 4
.section .note.GNU-stack,"",@progbits
