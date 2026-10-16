# Bounded Linux driver. Nonempty mode 1 only; Windows mapping/logging are mocks.
.intel_syntax noprefix
.section .driver,"ax"
.global _start
_start:
 cld
 mov esi,offset input
 mov edi,1048625
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
 sub esi,offset input
 cmp esi,48
 jb fail
 mov eax,[input]
 test eax,eax
 jz fail
 cmp eax,1048576
 ja fail
 add eax,48
 cmp eax,esi
 jne fail
 cmp dword ptr [input+4],15
 ja fail
 cmp dword ptr [input+12],1
 ja fail
 # Validate dangerous size additions in the driver, not in Agent.
 mov eax,[input]
 cmp eax,8
 jb safe_lengths
 mov edx,[blob]
 cmp edx,1048576
 ja fail
 add edx,23
 and edx,-16
 cmp edx,eax
 jae safe_lengths
 sub eax,edx
 cmp eax,4
 jb safe_lengths
 mov eax,[blob+edx]
 cmp eax,1048576
 ja fail
safe_lengths:
 mov dword ptr [obj-4],0x11223344
 mov dword ptr [obj+80],0x55667788
 # Protect the entire supplied byte buffer (including trailing zeros) read-only.
 mov eax,125
 mov ebx,offset blob
 mov ecx,1048576
 mov edx,1
 int 0x80
 test eax,eax
 jnz fail
 mov ebp,esp
 push 0
 push 0
 push dword ptr [input+4]
 push 1
 push 42
 mov ecx,offset obj
 call bind_inner
 cmp esp,ebp
 jne fail
 mov [result],eax
 mov eax,[obj+68]
 mov [result+4],eax
 mov eax,[obj+76]
 mov [result+8],eax
 mov eax,[obj+48]
 mov [result+12],eax
 mov eax,[obj+52]
 mov [result+16],eax
 cmp dword ptr [result],0
 jne after_search
 cmp dword ptr [input+12],0
 je after_search
 push offset found_end
 push offset found_begin
 push dword ptr [obj+68]
 push dword ptr [obj+64]
 push offset input+16
 call search
 add esp,20
 mov eax,[found_begin]
 mov [result+20],eax
 mov edx,[found_end]
 mov [result+24],edx
 cmp eax,edx
 jae after_search
 shl eax,5
 add eax,[obj+64]
 mov esi,eax
 mov edi,offset result+64
 mov ecx,8
 rep movsd
after_search:
 cmp dword ptr [result],0
 jne after_lookup
 cmp dword ptr [input+12],1
 jne after_lookup
 mov ebp,esp
 push offset result+116
 push offset result+100
 push offset input+32
 push offset input+16
 mov ecx,offset obj
 call lookup
 cmp esp,ebp
 jne fail
 mov [result+96],eax
after_lookup:
 mov ecx,offset obj
 call cleanup
 mov ecx,8
 mov esi,offset obj+48
 xor eax,eax
cleanup_check:
 or eax,[esi]
 add esi,4
 loop cleanup_check
 test eax,eax
 jnz fail
 cmp dword ptr [obj-4],0x11223344
 jne fail
 cmp dword ptr [obj+80],0x55667788
 jne fail
 mov dword ptr [result+28],1
 mov eax,[map_count]
 mov [result+32],eax
 mov eax,[unmap_count]
 mov [result+36],eax
 mov eax,[log_count]
 mov [result+40],eax
 mov eax,[length_count]
 mov [result+44],eax
 mov eax,4
 mov ebx,1
 mov ecx,offset result
 mov edx,144
 int 0x80
 cmp eax,144
 jne fail
 mov eax,1
 xor ebx,ebx
 int 0x80
fail:
 mov eax,1
 mov ebx,111
 int 0x80
.section .file_length,"ax"
 inc dword ptr [length_count]
 mov eax,[input]
 xor edx,edx
 ret
.section .map_file,"ax"
 inc dword ptr [map_count]
 mov eax,[input+8]
 test eax,eax
 jnz map_return
 mov edx,[esp+4]
 mov dword ptr [edx],offset blob
 mov ecx,[input]
 mov [edx+8],ecx
map_return:
 ret
.section .unmap_file,"ax"
 inc dword ptr [unmap_count]
 mov eax,[esp+4]
 mov dword ptr [eax],0
 mov dword ptr [eax+8],0
 ret
.section .logger,"ax"
 inc dword ptr [log_count]
 xor eax,eax
 ret
.section .convert_error,"ax"
 mov eax,[esp+4]
 ret
.section .mode2_forbidden,"ax"
 jmp fail
.section .initialize_forbidden,"ax"
 jmp fail
.section .memcmp,"ax"
 push esi
 push edi
 mov esi,[esp+12]
 mov edi,[esp+16]
 mov ecx,[esp+20]
 xor eax,eax
 test ecx,ecx
 jz mem_done
mem_loop:
 movzx eax,byte ptr [esi]
 movzx edx,byte ptr [edi]
 sub eax,edx
 jnz mem_done
 inc esi
 inc edi
 loop mem_loop
mem_done:
 pop edi
 pop esi
 ret
.section .scratch,"aw",@nobits
.balign 4096
.skip 4048
input: .skip 48
.balign 4096
blob: .skip 1048576
.skip 4096
.space 4
obj: .skip 80
.space 4
result: .skip 144
found_begin: .skip 4
found_end: .skip 4
map_count: .skip 4
unmap_count: .skip 4
log_count: .skip 4
length_count: .skip 4
.section .note.GNU-stack,"",@progbits

# Custom normal-path frame only, NOT Windows SEH dispatch or unwinding.
.section .prolog,"ax"
 pop edx
 pop eax
 push ebp
 mov ebp,esp
 sub esp,0x520
 mov [ebp-0x510],ebx
 mov [ebp-0x514],esi
 mov [ebp-0x518],edi
 jmp edx
.section .epilog,"ax"
 pop edx
 mov ebx,[ebp-0x510]
 mov esi,[ebp-0x514]
 mov edi,[ebp-0x518]
 mov esp,ebp
 pop ebp
 jmp edx
.section .vector_destroy,"ax"
 cmp dword ptr [ecx+12],0x80000020
 jne fail
 cmp dword ptr [ecx+8],32
 ja fail
 lea eax,[ecx+16]
 cmp [ecx+4],eax
 jne fail
 inc dword ptr [result+132]
 ret
.section .iterator_destroy,"ax"
 lea eax,[ecx+32]
 cmp [ecx+0x120],eax
 jne fail
 cmp dword ptr [ecx+0x124],16
 ja fail
 inc dword ptr [result+136]
 ret
.section .warning,"ax"
 inc dword ptr [result+140]
 xor eax,eax
 ret 20
.section .vector_grow_forbidden,"ax"
 jmp fail
.section .events_grow_forbidden,"ax"
 jmp fail
.section .sort_large1_forbidden,"ax"
 jmp fail
.section .sort_large2_forbidden,"ax"
 jmp fail
.section .sort_large3_forbidden,"ax"
 jmp fail
