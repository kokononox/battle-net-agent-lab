.intel_syntax noprefix
.section .driver,"ax"
.global _start
_start:
 cld
 mov esi,offset input
 mov edi,89
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
 cmp esi,offset input+88
 jne fail
 cmp dword ptr [input+8],4096
 ja fail
 cmp dword ptr [input+12],1
 ja fail
 mov eax,125
 mov ebx,offset input
 mov ecx,4096
 mov edx,3
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
 mov dword ptr [read_iteration],0
read_loop:
 mov dword ptr [result+4],0
 mov dword ptr [current_object],0
 mov dword ptr [result+112],0
 mov dword ptr [result+40],0
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
 jz next_read
 call write_all
next_read:
 inc dword ptr [read_iteration]
 mov eax,[read_iteration]
 cmp eax,[input+28]
 jae finish
 mov ecx,[read_iteration]
 dec ecx
 mov eax,[input+64+ecx*8]
 mov edx,[input+68+ecx*8]
 mov [input],eax
 mov [input+4],edx
 jmp read_loop
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
 cmp dword ptr [input+28],1
 jb fail
 cmp dword ptr [input+28],4
 ja fail
 mov edi,offset context+0x154
 mov dword ptr [edi+4],8
 lea eax,[edi+8]
 mov [eax],eax
 mov [eax+4],eax
 mov dword ptr [edi+0x10],offset heads
 mov dword ptr [edi+0x14],offset entries
 mov dword ptr [edi+0x18],offset nexts
 mov dword ptr [edi+0x1c],offset allocator
 mov dword ptr [edi+0x20],8
 mov dword ptr [edi+0x24],0
 mov dword ptr [edi+0x28],8
 mov eax,[input+44]
 mov [edi+0x2c],al
 mov edi,offset heads
 mov eax,-1
 mov ecx,8
 rep stosd
 ret
collect_cache:
 mov eax,[context+0x178]
 mov [result+84],eax
 mov eax,[current_object]
 mov dword ptr [result+20],0
 test eax,eax
 jz collect_empty
 mov edx,[eax+4]
 mov [result+20],edx
 mov edx,[eax+0x24]
 mov [result+88],edx
collect_empty:
 mov eax,[alloc_count]
 mov [result+56],eax
 mov eax,[close_count]
 mov [result+100],eax
 mov eax,[context+0x15c]
 cmp eax,offset context+0x15c
 je list_empty
 sub eax,offset arena+0x2c
 shr eax,6
 jmp list_store
list_empty:
 mov eax,-1
list_store:
 mov [result+92],eax
 mov eax,[read_iteration]
 mov [result+24],eax
 ret
allocate_bounded:
 # thiscall vtable allocation(56,8), separate from original object initializer.
 cmp dword ptr [esp+4],0x38
 jne fail
 cmp dword ptr [esp+8],8
 jne fail
 inc dword ptr [alloc_count]
 mov eax,[alloc_count]
 cmp eax,[input+56]
 je fail
 cmp eax,4
 ja fail
 dec eax
 shl eax,6
 add eax,offset arena
 mov [last_object],eax
 ret 8
allocator: .long allocator_vtable
allocator_vtable: .long fail,fail,fail,allocate_bounded
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
 jz no_open_injection
 mov edx,[input+52]
 test edx,edx
 jz create_error
 cmp edx,[result+64]
 je create_error
no_open_injection:
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
 mov eax,[ebp+8]
 mov edx,offset arena
 xor ecx,ecx
read_find_object:
 cmp ecx,[alloc_count]
 jae fail
 cmp [edx+0x24],eax
 je read_found_object
 add edx,64
 inc ecx
 jmp read_find_object
read_found_object:
 mov [current_object],edx
 mov [result+104],ecx
 mov eax,[edx+4]
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
 jz no_read_injection
 mov edx,[input+48]
 test edx,edx
 jz read_error
 cmp edx,[result+16]
 je read_error
no_read_injection:
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
.section .transfer_nonempty_forbidden,"ax"
transfer_nonempty_forbidden: jmp fail
.section .mapping_forbidden,"ax"
mapping_forbidden: jmp fail
.section .evict_forbidden,"ax"
evict_forbidden: jmp fail
.section .remove_forbidden,"ax"
remove_forbidden: jmp fail
.section .grow_hash_forbidden,"ax"
grow_hash_forbidden: jmp fail
.section .grow_entries_forbidden,"ax"
grow_entries_forbidden: jmp fail
.section .mapping_transfer_adapter,"ax"
mapping_transfer_adapter:
 mov eax,[esp+4]
 cmp dword ptr [eax],-1
 jne fail
 cmp dword ptr [ecx],-1
 jne fail
 mov eax,ecx
 ret 4
.section .mapping_cleanup_adapter,"ax"
mapping_cleanup_adapter:
 cmp dword ptr [ecx],-1
 jne fail
 ret
.section .handle_cleanup_adapter,"ax"
handle_cleanup_adapter:
 cmp dword ptr [ecx],-1
 je cleanup_done
 push ebx
 push ecx
 mov ebx,[ecx]
 mov eax,6
 int 0x80
 test eax,eax
 jnz fail
 pop ecx
 pop ebx
 mov dword ptr [ecx],-1
 inc dword ptr [close_count]
cleanup_done:
 ret
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
heads: .skip 32
entries: .skip 192
nexts: .skip 32
read_iteration: .skip 4
alloc_count: .skip 4
last_object: .skip 4
current_object: .skip 4
close_count: .skip 4
arena: .skip 256
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
