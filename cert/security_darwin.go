//go:build darwin
// +build darwin

package cert

import (
	"crypto/md5"
	"os"
	"strings"
)

// detectPlatformDebugger macOS调试器检测
func detectPlatformDebugger(debuggerNames []string) bool {
	// macOS调试检测
	// 使用已有的平台特定实现
	return checkMacOSDebugging()
}

// checkMacOSDebugging macOS调试检测
func checkMacOSDebugging() bool {
	// 使用已有的平台特定实现
	return checkDebugger()
}

// checkPlatformDebugAPI 检查平台调试API
func checkPlatformDebugAPI() bool {
	// macOS下主要通过sysctl检测
	return checkMacOSDebugging()
}

// checkPlatformVirtualBox VirtualBox平台特定检测
func checkPlatformVirtualBox() bool {
	// macOS特定检查
	// 检查系统信息
	if data, err := os.ReadFile("/usr/sbin/system_profiler SPHardwareDataType"); err == nil {
		hardware := strings.ToLower(string(data))
		if strings.Contains(hardware, "virtualbox") ||
			strings.Contains(hardware, "vbox") {
			return true
		}
	}

	// 检查IOKit注册表
	// 简化实现：检查常见路径
	vboxPaths := []string{
		"/Library/Extensions/VBoxGuest.kext",
		"/System/Library/Extensions/VBoxGuest.kext",
	}

	for _, path := range vboxPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

// checkPlatformHyperV Hyper-V平台特定检测
func checkPlatformHyperV() bool {
	// macOS不运行在Hyper-V上
	return false
}

// checkPlatformQEMU QEMU平台特定检测
func checkPlatformQEMU() bool {
	// macOS下QEMU检测
	// 检查系统信息中是否有QEMU特征
	// 简化实现
	return false
}

// checkPlatformCuckoo Cuckoo Sandbox平台特定检测
func checkPlatformCuckoo() bool {
	// macOS下Cuckoo检测
	cuckooArtifacts := []string{
		"/Users/cuckoo",
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
	// macOS下Joe Sandbox检测
	// 简化实现
	return false
}

// checkPlatformAnubis Anubis平台特定检测
func checkPlatformAnubis() bool {
	// macOS下Anubis检测
	// Anubis主要在Linux环境，macOS下简化实现
	return false
}

// checkPlatformDLLInjection DLL注入平台特定检测
func checkPlatformDLLInjection() bool {
	// macOS下没有DLL的概念，检查dylib注入
	// 简化实现：总是返回false
	return false
}

// encryptMemoryPlatform 平台特定内存加密
func encryptMemoryPlatform(memProtect []byte) {
	// macOS特定的内存加密
	key := md5.Sum([]byte("cert-security-key-darwin"))
	for i := range memProtect {
		memProtect[i] ^= key[i%len(key)]
	}
}

// setMemoryPermissionsPlatform 平台特定内存保护
func setMemoryPermissionsPlatform(memProtect []byte) error {
	// macOS内存保护
	// 这需要使用mprotect系统调用
	// 简化实现：不执行实际的保护
	return nil
}
