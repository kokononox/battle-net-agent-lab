#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
/* An owned 7-byte real-mode guest: output fixed synthetic marker then halt.
   No disk, network, guest OS, firmware image or third-party executable. */
int main(void){
 int k=-1,v=-1,c=-1,api=0,created=0,mapped=0,cpu=0,marker=0,halted=0,failed=0;size_t run_size=0;
 void *memory=MAP_FAILED;struct kvm_run *run=MAP_FAILED;
 alarm(6);
 k=open("/dev/kvm",O_RDWR|O_CLOEXEC);if(k<0){failed=1;goto done;}
 api=ioctl(k,KVM_GET_API_VERSION,0);if(api!=12){failed=2;goto done;}
 v=ioctl(k,KVM_CREATE_VM,0);if(v<0){failed=3;goto done;}created=1;
 memory=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(memory==MAP_FAILED){failed=4;goto done;}
 const unsigned char code[]={0xba,0xe9,0x00,0xb0,0x42,0xee,0xf4};memcpy(memory,code,sizeof code);
 struct kvm_userspace_memory_region region={.slot=0,.flags=0,.guest_phys_addr=0x1000,.memory_size=4096,.userspace_addr=(uintptr_t)memory};
 if(ioctl(v,KVM_SET_USER_MEMORY_REGION,&region)<0){failed=5;goto done;}mapped=1;
 c=ioctl(v,KVM_CREATE_VCPU,0);if(c<0){failed=6;goto done;}cpu=1;
 int n=ioctl(k,KVM_GET_VCPU_MMAP_SIZE,0);if(n<(int)sizeof(struct kvm_run)){failed=7;goto done;}run_size=(size_t)n;
 run=mmap(NULL,run_size,PROT_READ|PROT_WRITE,MAP_SHARED,c,0);if(run==MAP_FAILED){failed=8;goto done;}
 struct kvm_sregs sregs;if(ioctl(c,KVM_GET_SREGS,&sregs)<0){failed=9;goto done;}
 sregs.cs.base=0;sregs.cs.selector=0;if(ioctl(c,KVM_SET_SREGS,&sregs)<0){failed=10;goto done;}
 struct kvm_regs regs={.rip=0x1000,.rflags=2,.rsp=0x2000};if(ioctl(c,KVM_SET_REGS,&regs)<0){failed=11;goto done;}
 for(int i=0;i<4;i++){
  if(ioctl(c,KVM_RUN,0)<0){failed=12;break;}
  if(run->exit_reason==KVM_EXIT_IO){
   uint64_t off=run->io.data_offset;
   if(run->io.direction==KVM_EXIT_IO_OUT&&run->io.port==0xe9&&run->io.size==1&&run->io.count==1&&off<run_size&&*((unsigned char*)run+off)==0x42){marker=1;continue;}
   failed=13;break;
  }
  if(run->exit_reason==KVM_EXIT_HLT){halted=1;break;}
  failed=14;break;
 }
 done:
 if(run!=MAP_FAILED)munmap(run,run_size);
 if(c>=0)close(c);
 if(v>=0)close(v);
 if(memory!=MAP_FAILED)munmap(memory,4096);
 if(k>=0)close(k);
 printf("{\"schema\":\"owned-kvm-guest-1\",\"api_version\":%d,\"vm_created\":%s,\"memory_registered\":%s,\"vcpu_created\":%s,\"synthetic_marker_received\":%s,\"halt_exit_received\":%s,\"failure_stage\":%d,\"guest_os_booted\":false,\"guest_reboot_tested\":false,\"target_launched\":false}\n",api,created?"true":"false",mapped?"true":"false",cpu?"true":"false",marker?"true":"false",halted?"true":"false",failed);
 return 0;
}
