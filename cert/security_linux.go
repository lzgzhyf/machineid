//go:build linux
// +build linux

package cert

import (
	"crypto/md5"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// detectPlatformDebugger Linux调试器检测
func detectPlatformDebugger(debuggerNames []string) bool {
	// 检查/proc/self/status中的TracerPid
	if checkLinuxTracerPid() {
		return true
	}

	// 检查ptrace
	if checkPtraceUsage() {
		return true
	}

	return false
}

// checkLinuxTracerPid 检查/proc/self/status中的TracerPid
func checkLinuxTracerPid() bool {
	// 使用已有的平台特定实现
	return checkDebugger()
}

// checkPtraceUsage 检查ptrace使用情况
func checkPtraceUsage() bool {
	// 检查ptrace系统调用的使用情况
	// 通过尝试ptrace自身来检测是否已被调试
	// 如果进程已经被ptrace，再次ptrace会失败

	// 这里使用更安全的方法：检查/proc/self/status
	// 以及检查父进程是否可疑
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	// 检查是否有tracer
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
		}
	}

	return false
}

// checkPlatformDebugAPI 检查平台调试API
func checkPlatformDebugAPI() bool {
	// Linux下主要通过ptrace检测
	return checkPtraceUsage()
}

// checkPlatformVirtualBox VirtualBox平台特定检测
func checkPlatformVirtualBox() bool {
	// Linux特定检查
	// 检查/proc/cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "vbox") {
			return true
		}
	}

	// 检查/proc/modules
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "vbox") {
			return true
		}
	}

	// 检查/sys/class/dmi/id/product_name
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.ToLower(strings.TrimSpace(string(data)))
		if strings.Contains(product, "virtualbox") {
			return true
		}
	}

	return false
}

// checkPlatformHyperV Hyper-V平台特定检测
func checkPlatformHyperV() bool {
	// Linux下检查虚拟化标志
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		cpuinfo := strings.ToLower(string(data))
		if strings.Contains(cpuinfo, "hypervisor") ||
			strings.Contains(cpuinfo, "microsoft") {
			return true
		}
	}

	// 检查DMI信息
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor := strings.ToLower(strings.TrimSpace(string(data)))
		if strings.Contains(vendor, "microsoft") {
			return true
		}
	}

	return false
}

// checkPlatformQEMU QEMU平台特定检测
func checkPlatformQEMU() bool {
	// Linux特定检查
	// 检查/proc/cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		cpuinfo := strings.ToLower(string(data))
		qemuIndicators := []string{"qemu", "bochs"}
		for _, indicator := range qemuIndicators {
			if strings.Contains(cpuinfo, indicator) {
				return true
			}
		}
	}

	// 检查设备管理器
	if data, err := os.ReadFile("/proc/scsi/scsi"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "qemu") {
			return true
		}
	}

	// 检查DMI信息
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.ToLower(strings.TrimSpace(string(data)))
		if strings.Contains(product, "qemu") || strings.Contains(product, "bochs") {
			return true
		}
	}

	return false
}

// checkPlatformCuckoo Cuckoo Sandbox平台特定检测
func checkPlatformCuckoo() bool {
	// Linux下Cuckoo检测
	// 检查特定的进程或文件
	cuckooArtifacts := []string{
		"/home/cuckoo",
		"/opt/cuckoo",
	}

	for _, artifact := range cuckooArtifacts {
		if _, err := os.Stat(artifact); err == nil {
			return true
		}
	}

	return false
}

// checkPlatformJoeSandbox Joe Sandbox平台特定检测
func checkPlatformJoeSandbox() bool {
	// Linux下Joe Sandbox检测
	// 简化实现
	return false
}

// checkPlatformAnubis Anubis平台特定检测
func checkPlatformAnubis() bool {
	// 检查系统特征
	// Anubis通常运行在Linux环境中
	// 检查进程列表中是否有可疑进程
	if data, err := os.ReadFile("/proc/version"); err == nil {
		version := strings.ToLower(string(data))
		anubisIndicators := []string{"anubis", "sandbox", "malware", "sample"}
		for _, indicator := range anubisIndicators {
			if strings.Contains(version, indicator) {
				return true
			}
		}
	}

	return false
}

// checkPlatformDLLInjection DLL注入平台特定检测
func checkPlatformDLLInjection() bool {
	// Linux下没有DLL的概念，检查SO注入
	// 简化实现：总是返回false
	return false
}

// encryptMemoryPlatform 平台特定内存加密
func encryptMemoryPlatform(memProtect []byte) {
	// Linux特定的内存加密
	key := md5.Sum([]byte("cert-security-key-linux"))
	for i := range memProtect {
		memProtect[i] ^= key[i%len(key)]
	}
}

// setMemoryPermissionsPlatform 平台特定内存保护
func setMemoryPermissionsPlatform(memProtect []byte) error {
	// Linux mprotect调用
	if len(memProtect) == 0 {
		return nil
	}

	ptr := uintptr(unsafe.Pointer(&memProtect[0]))
	size := uintptr(len(memProtect))

	return mprotectLinux(ptr, size)
}

// mprotectLinux Linux内存保护
func mprotectLinux(ptr uintptr, size uintptr) error {
	// 设置为只读
	_, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, ptr, size, syscall.PROT_READ)
	if errno != 0 {
		return errno
	}
	return nil
}
