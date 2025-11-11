package cert

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// SecurityLevel 安全防护级别
const (
	SecurityLevelDisabled = 0 // 完全禁用（默认）
	SecurityLevelBasic    = 1 // 基础防护（仅基本调试器检测）
	SecurityLevelAdvanced = 2 // 高级防护（完整反逆向保护）
	SecurityLevelCritical = 3 // 关键防护（最高级别保护）
)

// SecurityManager 安全管理器
type SecurityManager struct {
	level           int
	checksum        []byte
	lastCheckTime   time.Time
	debuggerCount   int
	mu              sync.RWMutex
	antiDebugActive bool
	memProtect      []byte
}

// NewSecurityManager 创建安全管理器
func NewSecurityManager(level int) *SecurityManager {
	sm := &SecurityManager{
		level:           level,
		checksum:        make([]byte, 32),
		lastCheckTime:   time.Now(),
		antiDebugActive: true,
		memProtect:      make([]byte, 4096),
	}

	// 初始化内存保护区域
	for i := range sm.memProtect {
		sm.memProtect[i] = byte(i % 256)
	}

	// 计算初始校验和
	sm.calculateChecksum()

	// 启动后台安全检查
	go sm.backgroundSecurityCheck()

	return sm
}

// === 反调试功能 ===

// checkAdvancedDebugger 检测调试器（增强版）
func checkAdvancedDebugger() bool {
	// 首先使用平台特定的基础检测
	if checkDebugger() {
		return true
	}

	// 方法1: 时间差攻击检测
	if detectTimeBasedDebugging() {
		return true
	}

	// 方法2: 调试器进程检测
	if detectDebuggerProcess() {
		return true
	}

	// 方法3: 系统调用检测
	if detectSystemCallTracing() {
		return true
	}

	// 方法4: 内存布局检测
	if detectMemoryDebugging() {
		return true
	}

	// 方法5: 调试器API检测
	if detectDebuggerAPI() {
		return true
	}

	return false
}

// detectTimeBasedDebugging 时间差攻击检测
func detectTimeBasedDebugging() bool {
	// 记录开始时间
	start := time.Now()

	// 执行一些快速操作
	sum := 0
	for i := 0; i < 1000; i++ {
		sum += i
	}

	// 检查执行时间
	duration := time.Since(start)

	// 如果执行时间异常长，可能正在被调试
	return duration > time.Millisecond*10
}

// detectDebuggerProcess 检测调试器进程
func detectDebuggerProcess() bool {
	debuggerNames := []string{
		"gdb", "lldb", "dbg", "windbg", "x32dbg", "x64dbg",
		"ida", "ida64", "ollydbg", "immunity", "cheat engine",
		"process hacker", "process monitor", "wireshark",
		"fiddler", "burp", "charles", "mitmproxy",
	}

	// 调用平台特定的检测函数
	return detectPlatformDebugger(debuggerNames)
}

// detectSystemCallTracing 系统调用跟踪检测
func detectSystemCallTracing() bool {
	// 通过异常处理和系统调用监测调试器
	return checkSyscallInterception()
}

// detectMemoryDebugging 内存调试检测
func detectMemoryDebugging() bool {
	// 检查内存布局异常
	return checkMemoryLayout()
}

// detectDebuggerAPI 调试器API检测
func detectDebuggerAPI() bool {
	// 调用平台特定的检测函数
	return checkPlatformDebugAPI()
}

// === 防篡改功能 ===

// calculateChecksum 计算校验和
func (sm *SecurityManager) calculateChecksum() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 获取当前程序的内存映像
	data := sm.getCriticalMemoryRegions()
	hash := sha256.Sum256(data)
	copy(sm.checksum, hash[:])
	sm.lastCheckTime = time.Now()
}

// VerifyIntegrity 验证完整性
func (sm *SecurityManager) VerifyIntegrity() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// 计算当前校验和
	data := sm.getCriticalMemoryRegions()
	hash := sha256.Sum256(data)

	// 比较校验和
	for i, b := range hash {
		if i >= len(sm.checksum) || sm.checksum[i] != b {
			return NewSecurityError(ErrUnauthorizedAccess,
				"code integrity check failed - possible tampering detected", nil).
				WithDetail("expected_hash", fmt.Sprintf("%x", sm.checksum)).
				WithDetail("actual_hash", fmt.Sprintf("%x", hash)).
				WithSuggestion("程序可能被篡改，请重新安装原始版本")
		}
	}

	return nil
}

// getCriticalMemoryRegions 获取关键内存区域
func (sm *SecurityManager) getCriticalMemoryRegions() []byte {
	// 这里应该获取程序的关键部分
	// 为了演示，我们使用一些固定数据
	data := make([]byte, 0, 1024)

	// 添加当前函数的一些信息
	data = append(data, []byte("cert-security-check")...)
	data = append(data, sm.memProtect...)

	// 添加一些运行时信息
	runtime_info := fmt.Sprintf("%s-%s-%d",
		runtime.GOOS, runtime.GOARCH, runtime.NumGoroutine())
	data = append(data, []byte(runtime_info)...)

	return data
}

// === 环境检测 ===

// DetectVirtualMachine 检测虚拟机环境
func (sm *SecurityManager) DetectVirtualMachine() bool {
	// 检测VMware
	if sm.detectVMware() {
		return true
	}

	// 检测VirtualBox
	if sm.detectVirtualBox() {
		return true
	}

	// 检测Hyper-V
	if sm.detectHyperV() {
		return true
	}

	// 检测QEMU
	if sm.detectQEMU() {
		return true
	}

	return false
}

// detectVMware 检测VMware
func (sm *SecurityManager) detectVMware() bool {
	// 检查VMware特有的设备和注册表项
	vmwareIndicators := []string{
		"VMware",
		"vmware",
		"VBOX",
		"QEMU",
	}

	hostname, _ := os.Hostname()
	for _, indicator := range vmwareIndicators {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// detectVirtualBox 检测VirtualBox
func (sm *SecurityManager) detectVirtualBox() bool {
	// VirtualBox检测逻辑
	return sm.checkVirtualBoxArtifacts()
}

// detectHyperV 检测Hyper-V
func (sm *SecurityManager) detectHyperV() bool {
	// Hyper-V检测逻辑
	return sm.checkHyperVArtifacts()
}

// detectQEMU 检测QEMU
func (sm *SecurityManager) detectQEMU() bool {
	// QEMU检测逻辑
	return sm.checkQEMUArtifacts()
}

// DetectSandbox 检测沙箱环境
func (sm *SecurityManager) DetectSandbox() bool {
	// 检测各种沙箱特征
	if sm.detectCuckooSandbox() {
		return true
	}

	if sm.detectJoeSandbox() {
		return true
	}

	if sm.detectAnubis() {
		return true
	}

	return false
}

// === 进程保护 ===

// ProtectProcess 进程保护
func (sm *SecurityManager) ProtectProcess() error {
	if sm.level >= SecurityLevelAdvanced {
		// 启用反注入保护
		if err := sm.enableAntiInjection(); err != nil {
			return err
		}

		// 启用内存保护
		if err := sm.enableMemoryProtection(); err != nil {
			return err
		}
	}

	if sm.level >= SecurityLevelCritical {
		// 启用关键数据加密
		if err := sm.enableDataEncryption(); err != nil {
			return err
		}
	}

	return nil
}

// enableAntiInjection 启用反注入保护
func (sm *SecurityManager) enableAntiInjection() error {
	// DLL注入检测
	if sm.detectDLLInjection() {
		return NewSecurityError(ErrUnauthorizedAccess,
			"DLL injection detected", nil)
	}

	// 代码注入检测
	if sm.detectCodeInjection() {
		return NewSecurityError(ErrUnauthorizedAccess,
			"code injection detected", nil)
	}

	return nil
}

// enableMemoryProtection 启用内存保护
func (sm *SecurityManager) enableMemoryProtection() error {
	// 关键内存区域加密
	sm.encryptCriticalMemory()

	// 设置内存访问权限
	return sm.setMemoryPermissions()
}

// enableDataEncryption 启用数据加密
func (sm *SecurityManager) enableDataEncryption() error {
	// 生成加密密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}

	// 加密关键数据
	return sm.encryptSensitiveData(key)
}

// === 后台安全检查 ===

// backgroundSecurityCheck 后台安全检查
func (sm *SecurityManager) backgroundSecurityCheck() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for range ticker.C {
		if !sm.antiDebugActive {
			break
		}

		// 执行各种安全检查
		sm.performSecurityChecks()
	}
}

// performSecurityChecks 执行安全检查
func (sm *SecurityManager) performSecurityChecks() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 检测调试器
	if checkAdvancedDebugger() {
		sm.debuggerCount++
		if sm.debuggerCount > 3 {
			// 多次检测到调试器，执行防御措施
			sm.executeDefenseMeasures()
		}
	} else {
		// 重置计数器
		if sm.debuggerCount > 0 {
			sm.debuggerCount--
		}
	}

	// 验证完整性
	if time.Since(sm.lastCheckTime) > time.Minute*5 {
		if err := sm.VerifyIntegrity(); err != nil {
			sm.executeDefenseMeasures()
		}
	}

	// 检测虚拟机和沙箱
	if sm.level >= SecurityLevelAdvanced {
		if sm.DetectVirtualMachine() || sm.DetectSandbox() {
			// 在虚拟环境中运行，可以选择性地限制功能
			sm.handleVirtualEnvironment()
		}
	}
}

// executeDefenseMeasures 执行防御措施
func (sm *SecurityManager) executeDefenseMeasures() {
	// 可以选择不同的防御策略：
	// 1. 优雅退出
	// 2. 混淆输出
	// 3. 自毁功能
	// 4. 发送警报

	// 这里我们选择优雅退出并记录事件
	sm.logSecurityEvent("Defense measures activated - potential security threat detected")

	// 清理敏感数据
	sm.clearSensitiveData()

	// 可选择退出程序
	if sm.level >= SecurityLevelCritical {
		os.Exit(1)
	}
}

// handleVirtualEnvironment 处理虚拟环境
func (sm *SecurityManager) handleVirtualEnvironment() {
	// 在虚拟环境中的处理逻辑
	// 可以限制某些功能或提供模拟数据
	sm.logSecurityEvent("Virtual environment detected")
}

// logSecurityEvent 记录安全事件
func (sm *SecurityManager) logSecurityEvent(event string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[SECURITY] %s: %s\n", timestamp, event)
}

// clearSensitiveData 清理敏感数据
func (sm *SecurityManager) clearSensitiveData() {
	// 清零敏感内存区域
	for i := range sm.memProtect {
		sm.memProtect[i] = 0
	}
	for i := range sm.checksum {
		sm.checksum[i] = 0
	}
}

// StopSecurityChecks 停止安全检查
func (sm *SecurityManager) StopSecurityChecks() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.antiDebugActive = false
}

// === 通用实现 ===

// checkSyscallInterception 系统调用拦截检测
func checkSyscallInterception() bool {
	// 系统调用拦截检测
	// 检查系统调用是否被拦截或监控

	// 方法：测量系统调用执行时间
	start := time.Now()

	// 执行一个简单的系统调用
	_ = os.Getpid()

	duration := time.Since(start)

	// 如果系统调用执行时间异常长，可能被拦截
	return duration > time.Microsecond*50
}

// checkMemoryLayout 内存布局检测
func checkMemoryLayout() bool {
	// 内存布局检测
	// 检查内存布局是否异常（可能表示在虚拟或调试环境中）

	// 创建一些变量检查它们的内存地址
	a := 1
	b := 2
	c := 3

	addr_a := uintptr(unsafe.Pointer(&a))
	addr_b := uintptr(unsafe.Pointer(&b))
	addr_c := uintptr(unsafe.Pointer(&c))

	// 检查地址间距是否异常
	// 正常情况下，连续声明的变量地址应该相对接近
	diff1 := addr_b - addr_a
	diff2 := addr_c - addr_b

	if diff1 < 0 {
		diff1 = -diff1
	}
	if diff2 < 0 {
		diff2 = -diff2
	}

	// 如果地址间距异常大，可能在特殊环境中
	return diff1 > 1024 || diff2 > 1024
}

// === 虚拟机检测辅助函数 ===

// checkVirtualBoxArtifacts 检测VirtualBox特征
func (sm *SecurityManager) checkVirtualBoxArtifacts() bool {
	// VirtualBox检测特征
	vboxIndicators := []string{
		"VirtualBox",
		"VBOX",
		"vbox",
		"Oracle",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range vboxIndicators {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(indicator)) {
			return true
		}
	}

	// 检查环境变量
	envVars := []string{
		"VBOX_MSI_INSTALL_PATH",
		"VBOX_INSTALL_PATH",
	}

	for _, envVar := range envVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	// 调用平台特定的检测
	return checkPlatformVirtualBox()
}

// checkHyperVArtifacts 检测Hyper-V特征
func (sm *SecurityManager) checkHyperVArtifacts() bool {
	// Hyper-V检测特征
	hypervIndicators := []string{
		"Microsoft Corporation",
		"Hyper-V",
		"Virtual Machine",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range hypervIndicators {
		if strings.Contains(hostname, indicator) {
			return true
		}
	}

	// 调用平台特定的检测
	return checkPlatformHyperV()
}

// checkQEMUArtifacts 检测QEMU特征
func (sm *SecurityManager) checkQEMUArtifacts() bool {
	// QEMU检测特征
	qemuIndicators := []string{
		"QEMU",
		"qemu",
		"Bochs",
		"bochs",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range qemuIndicators {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(indicator)) {
			return true
		}
	}

	// 调用平台特定的检测
	return checkPlatformQEMU()
}

// === 沙箱检测辅助函数 ===

// detectCuckooSandbox 检测Cuckoo Sandbox
func (sm *SecurityManager) detectCuckooSandbox() bool {
	// Cuckoo Sandbox检测特征
	cuckooIndicators := []string{
		"cuckoo",
		"sandbox",
		"malware",
		"analysis",
		"sample",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range cuckooIndicators {
		if strings.Contains(strings.ToLower(hostname), indicator) {
			return true
		}
	}

	// 检查用户名
	if user := os.Getenv("USER"); user != "" {
		for _, indicator := range cuckooIndicators {
			if strings.Contains(strings.ToLower(user), indicator) {
				return true
			}
		}
	}

	// 调用平台特定的检测
	return checkPlatformCuckoo()
}

// detectJoeSandbox 检测Joe Sandbox
func (sm *SecurityManager) detectJoeSandbox() bool {
	// Joe Sandbox检测特征
	joeIndicators := []string{
		"joe",
		"joesandbox",
		"analysis",
		"sample",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range joeIndicators {
		if strings.Contains(strings.ToLower(hostname), indicator) {
			return true
		}
	}

	// 检查环境变量
	envVars := []string{
		"JOE_SANDBOX",
		"ANALYSIS",
	}

	for _, envVar := range envVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	// 调用平台特定的检测
	return checkPlatformJoeSandbox()
}

// detectAnubis 检测Anubis沙箱
func (sm *SecurityManager) detectAnubis() bool {
	// Anubis沙箱检测特征
	anubisIndicators := []string{
		"anubis",
		"sandbox",
		"malware",
		"sample",
	}

	// 检查主机名
	hostname, _ := os.Hostname()
	for _, indicator := range anubisIndicators {
		if strings.Contains(strings.ToLower(hostname), indicator) {
			return true
		}
	}

	// 检查用户名和环境
	if user := os.Getenv("USER"); user != "" {
		for _, indicator := range anubisIndicators {
			if strings.Contains(strings.ToLower(user), indicator) {
				return true
			}
		}
	}

	// 调用平台特定的检测
	return checkPlatformAnubis()
}

// === 注入检测辅助函数 ===

// detectDLLInjection DLL注入检测
func (sm *SecurityManager) detectDLLInjection() bool {
	// 调用平台特定的检测
	return checkPlatformDLLInjection()
}

// detectCodeInjection 代码注入检测
func (sm *SecurityManager) detectCodeInjection() bool {
	// 代码注入检测
	// 检查进程内存中是否有异常的可执行区域

	// 方法：检查堆栈和堆的状态
	// 代码注入通常会改变这些区域的特性

	// 简化实现：检查goroutine数量是否异常
	numGoroutines := runtime.NumGoroutine()

	// 对于证书管理系统，正常情况下不应该有太多 goroutine
	// 如果数量异常多，可能有恶意代码注入
	return numGoroutines > 100
}

// === 内存保护辅助函数 ===

// encryptCriticalMemory 加密关键内存区域
func (sm *SecurityManager) encryptCriticalMemory() {
	// 使用平台特定的加密方法
	encryptMemoryPlatform(sm.memProtect)
}

// setMemoryPermissions 设置内存页面权限
func (sm *SecurityManager) setMemoryPermissions() error {
	// 调用平台特定的内存保护
	return setMemoryPermissionsPlatform(sm.memProtect)
}

// encryptSensitiveData 加密敏感数据
func (sm *SecurityManager) encryptSensitiveData(key []byte) error {
	if len(key) < 32 {
		return fmt.Errorf("encryption key must be at least 32 bytes")
	}

	// 加密关键内存区域
	for i := range sm.memProtect {
		sm.memProtect[i] ^= key[i%len(key)]
	}

	// 加密校验和
	for i := range sm.checksum {
		sm.checksum[i] ^= key[(i+16)%len(key)]
	}

	return nil
}

// === 集成函数 ===

// InitSecurityManager 初始化安全管理器并集成到授权管理器
func (a *Authorizer) InitSecurityManager() *SecurityManager {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 根据配置确定安全级别
	level := SecurityLevelBasic
	if a.config.Security.EnableAntiDebug {
		level = SecurityLevelAdvanced
	}
	if a.config.Security.RequireHardwareBinding {
		level = SecurityLevelCritical
	}

	// 创建安全管理器
	sm := NewSecurityManager(level)

	return sm
}

// PerformSecurityCheck 执行安全检查（集成到证书验证流程）
func (a *Authorizer) PerformSecurityCheck() error {
	if !a.config.Security.EnableAntiDebug {
		return nil // 如果没有启用安全检查，直接返回
	}

	// 根据配置确定安全检查级别
	level := a.getSecurityLevel()
	if level == SecurityLevelDisabled {
		return nil // 安全检查被完全禁用
	}

	// 创建临时安全管理器进行检查
	sm := NewSecurityManager(level)
	defer sm.StopSecurityChecks()

	// 根据安全级别执行不同程度的检查
	switch level {
	case SecurityLevelBasic:
		// 基础级别：只检查简单调试器
		if checkDebugger() {
			return NewSecurityError(ErrDebuggerDetected,
				"debugging environment detected", nil).
				WithSuggestion("请在非调试环境下运行程序")
		}

	case SecurityLevelAdvanced:
		// 高级级别：完整反逆向检测
		if checkAdvancedDebugger() {
			return NewSecurityError(ErrDebuggerDetected,
				"advanced debugging environment detected", nil).
				WithSuggestion("请在非调试环境下运行程序")
		}

		// 检查虚拟机环境
		if sm.DetectVirtualMachine() {
			sm.logSecurityEvent("Virtual machine environment detected")
		}

		// 检查沙箱环境
		if sm.DetectSandbox() {
			return NewSecurityError(ErrUnauthorizedAccess,
				"sandbox environment detected", nil).
				WithSuggestion("程序不允许在沙箱环境中运行")
		}

	case SecurityLevelCritical:
		// 关键级别：最严格的检查
		if checkAdvancedDebugger() {
			return NewSecurityError(ErrDebuggerDetected,
				"critical security violation - debugging detected", nil).
				WithSuggestion("程序在关键模式下不允许调试")
		}

		if sm.DetectVirtualMachine() || sm.DetectSandbox() {
			return NewSecurityError(ErrUnauthorizedAccess,
				"critical security violation - virtual environment detected", nil).
				WithSuggestion("程序在关键模式下只能在物理机运行")
		}

		// 执行进程保护检查
		if err := sm.ProtectProcess(); err != nil {
			return err
		}
	}

	return nil
}

// getSecurityLevel 根据配置获取安全级别
func (a *Authorizer) getSecurityLevel() int {
	// 如果明确设置了安全级别，直接使用
	if level, ok := a.config.Security.GetSecurityLevel(); ok {
		return level
	}

	// 否则根据配置推断
	if !a.config.Security.EnableAntiDebug {
		return SecurityLevelDisabled
	}

	// 根据配置组合推断级别
	if a.config.Security.RequireHardwareBinding {
		return SecurityLevelCritical
	}

	if a.config.Security.EnableTimeValidation {
		return SecurityLevelAdvanced
	}

	return SecurityLevelBasic
}

// ValidateWithSecurity 带安全检查的证书验证
func (a *Authorizer) ValidateWithSecurity(certPEM []byte, machineID string) error {
	// 首先执行安全检查
	if err := a.PerformSecurityCheck(); err != nil {
		return err
	}

	// 然后执行正常的证书验证
	return a.ValidateCert(certPEM, machineID)
}
