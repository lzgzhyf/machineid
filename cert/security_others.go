//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package cert

import (
	"crypto/md5"
)

// detectPlatformDebugger 其他平台调试器检测（空实现）
func detectPlatformDebugger(debuggerNames []string) bool {
	// 不支持的平台，返回false
	return false
}

// checkPlatformDebugAPI 检查平台调试API（空实现）
func checkPlatformDebugAPI() bool {
	// 不支持的平台，返回false
	return false
}

// checkPlatformVirtualBox VirtualBox平台特定检测（空实现）
func checkPlatformVirtualBox() bool {
	// 不支持的平台，返回false
	return false
}

// checkPlatformHyperV Hyper-V平台特定检测（空实现）
func checkPlatformHyperV() bool {
	// 不支持的平台，返回false
	return false
}

// checkPlatformQEMU QEMU平台特定检测（空实现）
func checkPlatformQEMU() bool {
	// 不支持的平台，返回false
	return false
}

// checkPlatformCuckoo Cuckoo Sandbox平台特定检测（空实现）
func checkPlatformCuckoo() bool {
	// 不支持的平台，返回false
	return false
}

// checkPlatformJoeSandbox Joe Sandbox平台特定检测（空实现）
func checkPlatformJoeSandbox() bool {
	// 不支持的平台，返回false
	return false
}

// checkPlatformAnubis Anubis平台特定检测（空实现）
func checkPlatformAnubis() bool {
	// 不支持的平台，返回false
	return false
}

// checkPlatformDLLInjection DLL注入平台特定检测（空实现）
func checkPlatformDLLInjection() bool {
	// 不支持的平台，返回false
	return false
}

// encryptMemoryPlatform 平台特定内存加密（简单实现）
func encryptMemoryPlatform(memProtect []byte) {
	// 其他平台的简单加密
	key := md5.Sum([]byte("cert-security-key-default"))
	for i := range memProtect {
		memProtect[i] ^= key[i%len(key)]
	}
}

// setMemoryPermissionsPlatform 平台特定内存保护（空实现）
func setMemoryPermissionsPlatform(memProtect []byte) error {
	// 不支持的平台，不执行任何操作
	return nil
}
