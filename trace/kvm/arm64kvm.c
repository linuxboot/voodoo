#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/stddef.h>
#include <linux/kvm.h>
#include <strings.h>
#include <stddef.h>

//#include <register.h>
// Stuff we added.
#define ENTRY_POINT 0
#define ENTRY_OFFSET 0
#define RAM_SIZE 0x20000
#define RAM_START 0x80000000
#define EXIT_REG 0

#define KVM_DEV		"/dev/kvm"
#define GUEST_BIN	"./guest.bin"
#define AARCH64_CORE_REG(x)		(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))
#define KVM_REG_ARM_CORE_REG(name)    (offsetof(struct kvm_regs, name) / sizeof(__u32))

int main(int argc, const char *argv[])
{
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	int guest_fd;
	int ret;
	int mmap_size;

	struct kvm_userspace_memory_region mem;
	struct kvm_run *kvm_run;
	struct kvm_one_reg reg;
	struct kvm_vcpu_init init;
	void *userspace_addr;
	__u64 guest_entry = ENTRY_POINT;
	__u64 guest_pstate;

	// 打开kvm模块
	kvm_fd = open(KVM_DEV, O_RDWR);
	assert(kvm_fd > 0);

	// 创建一个虚拟机
	vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	assert(vm_fd > 0);

	// 创建一个VCPU
	vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
	assert(vcpu_fd > 0);

	// 获取共享数据空间的大小
	mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	assert(mmap_size > 0);

	// 将共享数据空间映射到用户空间
	kvm_run = (struct kvm_run *)mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
	assert(kvm_run >= 0);

	// 打开客户机镜像
	if (0) {
		guest_fd = open(GUEST_BIN, O_RDONLY);
		assert(guest_fd > 0);
	}

	// 分配一段匿名共享内存，下面会将这段共享内存映射到客户机中，作为客户机看到的物理地址
	userspace_addr = mmap(NULL, RAM_SIZE, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	assert(userspace_addr > 0);

	// 将客户机镜像装载到共享内存中
	if (0) {
		ret = read(guest_fd, userspace_addr + ENTRY_OFFSET, RAM_SIZE);
		assert(ret > 0);
	}
	for(int i = 0; i < RAM_SIZE; i += 4) {
		*(u_int32_t *)(userspace_addr+ENTRY_OFFSET+i) = 0xf7f0a000;
	}

	// 将上面分配的共享内存(HVA)到客户机的0x100000物理地址(GPA)的映射注册到KVM中
	// 
	// 当客户机使用GPA(IPA)访问这段内存时，会发生缺页异常，陷入EL2
	// EL2会在异常处理函数中根据截获的GPA查找上面提前注册的映射信息得到HVA
	// 然后根据HVA找到HPA，最后创建一个将GPA到HPA的映射，并将映射信息填写到
	// VTTBR_EL2指向的stage2页表中，这个跟intel架构下的EPT技术类似
	mem.slot = 0;
	mem.flags = 0;
	mem.guest_phys_addr = (__u64)RAM_START;
	mem.userspace_addr = (__u64)userspace_addr;
	mem.memory_size = (__u64)RAM_SIZE;
	ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &mem);
	assert(ret >= 0);

	// 设置cpu的初始信息，因为host使用qemu模拟的cortex-a57，所以这里要
	// 将target设置为KVM_ARM_TARGET_CORTEX_A57
	bzero(&init, sizeof(init));
	init.target = KVM_ARM_TARGET_CORTEX_A57;
	init.target = 5;
	
	ret = ioctl(vcpu_fd, KVM_ARM_VCPU_INIT, &init);
	assert(ret >= 0);

	// 设置从host进入虚拟机后cpu第一条指令的地址，也就是上面的0x100000
	reg.id = AARCH64_CORE_REG(regs.pc);
	reg.addr = (__u64)&guest_entry;
	ret = ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg);
	assert(ret >= 0);

	// 设置guest的运行状态
	guest_pstate = PSR_MODE_EL1h | PSR_F_BIT | PSR_I_BIT;
	reg.id = AARCH64_CORE_REG(regs.pstate);
	reg.addr = (__u64)&guest_pstate;
	ret = ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg);
	assert(ret >= 0);

	while(1) {
		// 启动虚拟机
		ret = ioctl(vcpu_fd, KVM_RUN, NULL);
		assert(ret >= 0);

		// 根据虚拟机退出的原因完成相应的操作
		switch (kvm_run->exit_reason) {
		case KVM_EXIT_MMIO:
			printf("sod this\n");
#if 0 // sod this
			if (kvm_run->mmio.is_write && kvm_run->mmio.len == 1) {
				if (kvm_run->mmio.phys_addr == OUT_PORT) {
					// 输出guest写入到OUT_PORT中的信息
					printf("%c", kvm_run->mmio.data[0]);
				} else if (kvm_run->mmio.phys_addr == EXIT_REG){
					// Guest退出
					printf("<Guest Exit!>\n");
					close(kvm_fd);
					close(guest_fd);
					goto exit_virt;
				}
			} else if (!kvm_run->mmio.is_write && kvm_run->mmio.len == 1) {
				if (kvm_run->mmio.phys_addr == IN_PORT) {
					// 客户机从IN_PORT发起读请求
					kvm_run->mmio.data[0] = 'G';
				}
			}

			break;
#endif
		default:
			printf("Unknow exit reason: %d\n", kvm_run->exit_reason);
			goto exit_virt;
		}
	}

exit_virt:
	return 0;
}
// aarch64-linux-gnu-gcc -o arm64kvm -static arm64kvm.c
