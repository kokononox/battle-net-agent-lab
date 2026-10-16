# Nonthrowing mocked-I/O experiment. Four original Agent functions run intact.
# No PE loader/Windows APIs. stdin exactly 12 u32; stdout exactly 64 u32.
# External helpers, including SEH frame setup, are researcher stubs, NOT Agent I/O.
.macro event id
 pushfl
 pushal
 mov output+48,%eax
 cmp $32,%eax
 jae bad
 movl $\id,output+64(,%eax,4)
 incl output+48
 popal
 popfl
.endm
.section .driver,"ax"
.global _start
_start:
 cld
 mov $config,%ecx
 mov $48,%edx
read_more:
 mov $3,%eax
 xor %ebx,%ebx
 int $0x80
 test %eax,%eax
 jle bad
 add %eax,%ecx
 sub %eax,%edx
 jnz read_more
 mov $3,%eax
 xor %ebx,%ebx
 mov $extra,%ecx
 mov $1,%edx
 int $0x80
 test %eax,%eax
 jnz bad
 cmpl $2,config
 ja bad
 cmpl $5,config+4
 ja bad
 cmpl $15,config+8
 ja bad
 cmpl $1,config+44
 ja bad
 # Initialize canaries and only the required object/control fields.
 mov $object,%edi
 mov $0xa5a5a5a5,%eax
 mov $1024,%ecx
 rep stosl
 mov $control,%edi
 mov $0x5a5a5a5a,%eax
 mov $1024,%ecx
 rep stosl
 mov config+4,%eax
 mov %eax,object+0x2c
 movl $control,object+0x38
 movl $1,object+0x9c
 mov config+8,%eax
 lea object+0xa0(,%eax,8),%edi
 mov %edi,cacheptr
 mov config+16,%edx
 mov %edx,(%edi)
 lea control+0x110(,%eax,4),%edi
 mov %edi,headerptr
 mov config+12,%edx
 mov %edx,(%edi)
 mov $object,%esi
 mov $before,%edi
 mov $2048,%ecx
 rep movsl
 movl $-1,output+24
 movl $-1,output+28
 movl $-1,output+32
 movl $-1,output+36
 movl $-1,output+40
 movl $-1,output+44
 movl $-1,output+56
 cmpl $0,config
 jne read_once
 push config+44
 push $0
 push config+8
 mov $object,%ecx
 call header_publish
 jmp finished
read_once:
 push config+8
 mov $object,%ecx
 call header_reader
 mov %eax,output+56
 cmpl $2,config
 jne finished
 push config+8
 mov $object,%ecx
 call header_reader
finished:
 mov %eax,output
 mov headerptr,%edx
 mov (%edx),%eax
 mov %eax,output+4
 mov cacheptr,%edx
 mov (%edx),%eax
 mov %eax,output+8
 # Guard every object/control byte except selected DWORDs. Stack scratch is separate.
 mov $object,%esi
 mov $before,%edi
 mov $8192,%ecx
check_bytes:
 mov cacheptr,%eax
 cmp %eax,%esi
 jb check_header
 add $4,%eax
 cmp %eax,%esi
 jb skip_byte
check_header:
 mov headerptr,%eax
 cmp %eax,%esi
 jb compare_byte
 add $4,%eax
 cmp %eax,%esi
 jb skip_byte
compare_byte:
 movb (%esi),%al
 cmpb (%edi),%al
 jne bad
skip_byte:
 inc %esi
 inc %edi
 loop check_bytes
 movl $1,output+52
 mov $output,%ecx
 mov $256,%edx
emit:
 mov $4,%eax
 mov $1,%ebx
 int $0x80
 test %eax,%eax
 jle bad
 add %eax,%ecx
 sub %eax,%edx
 jnz emit
 mov $1,%eax
 xor %ebx,%ebx
 int $0x80
bad:
 mov $1,%eax
 mov $90,%ebx
 int $0x80
# Custom frame compatible with the fields touched by these bounded functions.
# It does NOT implement SEH, TLS/FS registration, exception dispatch or unwinding.
.section .prolog,"ax"
 pop %edx
 pop %eax
 push %ebp
 mov %esp,%ebp
 sub $0x360,%esp
 mov %ebx,-0x350(%ebp)
 mov %esi,-0x354(%ebp)
 mov %edi,-0x358(%ebp)
 jmp *%edx
.section .epilog,"ax"
 pop %edx
 mov -0x350(%ebp),%ebx
 mov -0x354(%ebp),%esi
 mov -0x358(%ebp),%edi
 mov %ebp,%esp
 pop %ebp
 jmp *%edx
.section .constructor,"ax"
 mov %ecx,%eax
 ret
.section .tempname,"ax"
 event 1
 mov config+24,%eax
 ret
.section .serialize_full,"ax"
 event 2
 mov config+28,%eax
 ret $4
.section .serialize_some,"ax"
 event 2
 mov config+28,%eax
 ret $12
.section .flush,"ax"
 event 3
 incl output+20
 mov 12(%esp),%eax
 mov %eax,output+32
 mov config+32,%eax
 test %eax,%eax
 jnz flush_return
 mov 24(%esp),%edx
 mov config+20,%eax
 mov %eax,(%edx)
 xor %eax,%eax
flush_return:
 ret
.section .move,"ax"
 event 4
 ret $4
.section .bind,"ax"
 event 5
 incl output+12
 mov cacheptr,%edx
 mov (%edx),%eax
 mov %eax,output+36
 mov headerptr,%edx
 mov (%edx),%eax
 mov %eax,output+40
 mov 12(%esp),%eax
 mov %eax,output+44
 mov config+36,%eax
 ret $20
.section .destroy,"ax"
 event 6
 ret
.section .filename,"ax"
 event 7
 mov 16(%esp),%eax
 mov %eax,output+24
 mov 12(%esp),%eax
 mov %eax,output+28
 ret
.section .join,"ax"
 event 8
 ret
.section .open,"ax"
 event 9
 incl output+16
 mov 12(%esp),%eax
 mov %eax,output+60
 mov config+40,%eax
 ret
.section .errorpath,"ax"
 event 12
 ret
.section .convert_error,"ax"
 event 10
 mov config+40,%eax
 ret
.section .error_string,"ax"
 event 13
 xor %eax,%eax
 ret
.section .logger,"ax"
 event 11
 xor %eax,%eax
 ret
.section .scratch,"aw",@nobits
config: .zero 48
extra: .zero 4
output: .zero 256
cacheptr: .zero 4
headerptr: .zero 4
.balign 16
object: .zero 4096
control: .zero 4096
before: .zero 8192
.section .note.GNU-stack,"",@progbits
