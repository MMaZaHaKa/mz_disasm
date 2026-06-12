#pragma once
// disasm by MaZaHaKa
#define UNICORN //  .\vcpkg install unicorn:x86-windows unicorn:x64-windows  // .\vcpkg integrate install
//#define CAPSTONE
#define ZYDIS //  .\vcpkg install zydis:x86-windows zydis:x64-windows  // .\vcpkg integrate install

#ifdef UNICORN // эмулятор
#include <unicorn/unicorn.h>
#endif
#ifdef CAPSTONE // дизасемблер (не работает)
#include <capstone/capstone.h>
#pragma comment(lib, "capstone.lib")
#endif
#ifdef ZYDIS // дизасемблер
#include <Zydis/Zydis.h>
#endif

#define AR_SNAME ("AsmRunner")
//#define AR_SYSCALL_JUMP_CB
//#define AR_DEBUG
#define AR_IDA_WS
//#define AR_HALT_JMPCB // allow jmp cb notify jmp to halt
#define AR_HALT_ADDR_ONLY // fast + correct halt shutdown log, the rest is neat (unmapped execute)

#ifdef CopyMemory
#undef CopyMemory
#endif

// TODO: normal seh, tls UC_X86_REG_FS_BASE in SetTebBase, breakpoint condition cb, cb UC_HOOK_INSN, UC_HOOK_INTR, cb on register change?, trace deadzone?
// UC bugs: 1 can't set fs: but res ok, 2 update pc + emu_stop() can't stop emu

#include <vector>
#include <map>
#include <functional>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <unordered_map>

#define ARP(p) ((uintptr_t)p)
#define ARV(p) ((void*)p)

#define GET_REG(reg, varname) \
    uint32_t varname; \
    __asm { mov varname, reg }

#define SET_REG(reg, value) \
    __asm { mov reg, value }

#define BIT(num) (1<<(num))
#define GET_BITS(value, mask, shift) (((value) & (mask)) >> (shift))
#define GET_BIT(num, n) (((num) >> (n)) & 1)
#define SET_BIT(num, n, val) ((num) = ((num) & ~BIT(n)) | ((val) << (n)))
#define GET_BYTE(num, n) ((num >> (8 * n)) & 0xFF)
#define SET_BYTE(num, n, val) ((num) = ((num) & ~(0xFF << (8 * (n)))) | ((val) << (8 * (n))))
#define SWAP_BIT(num, n) SET_BIT(num, n, !GET_BIT(num, n))
#define SWAP_ENDIAN(x) ((((uint32_t)(x)&0x000000ff)<<24)|(((uint32_t)(x)&0x0000ff00)<<8)|(((uint32_t)(x)&0x00ff0000)>>8)|(((uint32_t)(x)&0xff000000) >> 24))
#define OFFSET(base, off, type) ((type)&(((uint8_t*)base)[off]) )
#define ALIGN4BYTES(s) ((((uint32_t)s) + 3) & 0xFFFFFFFC)
#define MASK(p, s) (((1 << (s)) - 1) << (p))

enum eFlags : uint32_t
{
	CARRY_FLAG                = BIT(0),  // CF - Carry Flag
	BIT_1_RESERVED            = BIT(1),  // Reserved (always 1)
	PARITY_FLAG               = BIT(2),  // PF - Parity Flag
	BIT_3_RESERVED            = BIT(3),  // Reserved
	AUXILIARY_FLAG            = BIT(4),  // AF - Auxiliary Carry Flag
	BIT_5_RESERVED            = BIT(5),  // Reserved
	ZERO_FLAG                 = BIT(6),  // ZF - Zero Flag
	SIGN_FLAG                 = BIT(7),  // SF - Sign Flag
	TRAP_FLAG                 = BIT(8),  // TF - Trap Flag
	INTERRUPT_FLAG            = BIT(9),  // IF - Interrupt Enable Flag
	DIRECTION_FLAG            = BIT(10), // DF - Direction Flag
	OVERFLOW_FLAG             = BIT(11), // OF - Overflow Flag
	IOPL_FLAG                 = BIT(12) | BIT(13), // IOPL - I/O Privilege Level
	NESTED_TASK               = BIT(14), // NT - Nested Task
	BIT_15_RESERVED           = BIT(15), // Reserved
	RESUME_FLAG               = BIT(16), // RF - Resume Flag
	VIRTUAL_8086              = BIT(17), // VM - Virtual-8086 Mode
	ALIGNMENT_CHECK           = BIT(18), // AC - Alignment Check
	VIRTUAL_INTERRUPT         = BIT(19), // VIF - Virtual Interrupt Flag
	VIRTUAL_INTERRUPT_PENDING = BIT(20), // VIP - Virtual Interrupt Pending
	ID_FLAG                   = BIT(21), // ID - ID Flag
};

enum eIoplLevel : uint32_t
{
	LEVEL_0 = 0 << 12,
	LEVEL_1 = 1 << 12,
	LEVEL_2 = 2 << 12,
	LEVEL_3 = 3 << 12,
};

struct tFuncNode //tmp, use tIEFuncNode
{
	uintptr_t rva = 0;
	size_t size = 0;
	std::string name;
};

struct tIEFuncNode
{
	std::string moduleName;
	std::string funcName;
	uintptr_t moduleBase;
	uintptr_t funcRva;

	inline uintptr_t GetAbsolute() { return moduleBase + funcRva; }
	inline std::string GetAbsoluteName() { return funcName + " " + moduleName; }
};

enum eBpType : uint32_t
{
	BP_CODE = 0,  // инструкция (UC_HOOK_CODE)
	BP_MEM_READ = 1,  // чтение памяти
	BP_MEM_WRITE = 2,  // запись памяти
	BP_MEM_RW = 3   // чтение или запись
};


class AsmRunner // x86 x64 with macro
{
public:
	// Тип колбэка для опкода: вызывается перед выполнением инструкции
	// ctx - контекст Unicorn, address - адрес инструкции, size - размер инструкции, user_data - пользовательские данные
	using OnOpcodeCb = std::function<bool(uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data)>;

	// Тип колбэка для памяти: вызывается при чтении/записи памяти
	// type - UC_MEM_READ/UC_MEM_WRITE, address - адрес доступа, size - размер, value - значение (для записи)
	using OnMemCb = std::function<bool(uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data)>;

	// Тип колбэка для перехода: вызывается при jmp/call/ret // Pre - Jump transfer callback
	using OnJmpCb = std::function<bool(uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, void* user_data)>;

	// Тип колбэка для брейкпоинта
	using OnBreakpointCb = std::function<bool(uc_engine* uc, uintptr_t address, void* user_data)>;

	// Тип колбэка для трассировки: возвращает true для остановки трассировки
	using TraceCb = std::function<bool(uc_engine* uc, uintptr_t address, uint32_t instruction_count, void* user_data)>;

	using HookNotifyCb = std::function<void(tIEFuncNode* pNode)>;

	AsmRunner(bool bX64 = false);
	~AsmRunner();

	void SetLogging(bool enabled) { m_bLogEnabled = enabled; }
	bool IsLogging() const { return m_bLogEnabled; }
	void SetDisasmAfterCB(bool enabled) { m_bDisasmAfterCB = enabled; }
	bool IsDisasmAfterCB() const { return m_bDisasmAfterCB; }
	void SetDisasmRVA(bool enabled, uintptr_t disasmCustomASLR = 0) { m_bDisasmRVA = enabled; m_DisasmCustomASLR = disasmCustomASLR; }
	bool IsDisasmRVA() const { return m_bDisasmRVA; }
	uintptr_t GetDisasmCASLR() const { return m_DisasmCustomASLR; }
	uintptr_t CalcWithCASLR(uintptr_t p) const { return p - GetModStart() + GetDisasmCASLR(); }
	void SetLogDisasm(bool enabled) { m_bLogDisasm = enabled; }
	bool IsLogDisasm() const { return m_bLogDisasm; }
	void SetLogDisasmICNotice(uintptr_t disasmICNotice) { m_DisasmICNotice = disasmICNotice; }
	void SetLogMemRW(bool enabled) { m_bLogMemRW = enabled; }
	bool IsLogMemRW() const { return m_bLogMemRW; }
	void SetLogAnyJmp(bool enabled) { m_bLogAnyJmp = enabled; }
	bool IsLogAnyJmp() const { return m_bLogAnyJmp; }
	void SetLogRunner(bool enabled) { m_bLogRunner = enabled; }
	bool IsLogRunner() const { return m_bLogRunner; }
	void SetX64(bool isX64) { m_bX64 = isX64; }
	bool IsX64() const { return m_bX64; }
	void SetSkipCBCallsWithNewPC(bool bSkipCBCallsWithNewPC) { m_bSkipCBCallsWithNewPC = bSkipCBCallsWithNewPC; }
	bool IsSkipCBCallsWithNewPC() const { return m_bSkipCBCallsWithNewPC; }
	void SetRWHistory(bool enabled) { m_bRWHistory = enabled; }
	bool IsRWHistory() const { return m_bRWHistory; }
	bool IsSymMapInitialised() const { return m_sym.size() != 0; }
	uintptr_t GetModStart() const { return m_modStart; }
	uintptr_t GetModEnd() const { return m_modEnd; }

	// core lifecycle
	void Initialise(bool bLogDisasm, bool bLogMemRW, bool bLogAnyJmp, bool bLogRunner, bool bInitUC = true); // set log, init unicorn, init disasms, alloc stack, alloc seh(:fs)
	void Shutdown();
	void ShutdownByCallback(uc_engine* uc);
	void ShutdownByHalt(uc_engine* uc);
	uc_engine* GetCTX();
	uintptr_t GetInstructionCount() const { return m_instrCount; }

	// tools
	static inline uintptr_t AlignUp(uintptr_t x, uintptr_t a) { return (x + a - 1) & ~(a - 1); }
	static inline uintptr_t AlignDown(uintptr_t v, uintptr_t a) { return v & ~(a - 1); }
	static inline uintptr_t AlignDownPage(uintptr_t v) { return v & ~static_cast<uintptr_t>(0xFFF); }
	static inline bool IsPrintableAscii(uint8_t c) { return c >= 0x20 && c <= 0x7e; }
	static std::chrono::steady_clock::time_point CaptureTime();
	static void DumpTime(std::chrono::steady_clock::time_point start, const char* label = nullptr);
	static void DumpDeltaTime(std::chrono::steady_clock::time_point a, std::chrono::steady_clock::time_point b, const char* label = nullptr);
	static std::string PrintPtrAsciiTag(uintptr_t v, size_t width, bool bDec = false, bool bDecBracket = true);
	static std::string PrintHexOnly(uintptr_t v, bool bDec = false);

	uintptr_t GetMappedModuleSizeByName(LPCSTR moduleName);
	bool GetMappedModuleBounds(LPCSTR moduleName, uintptr_t& pOutStart, uintptr_t& pOutEnd, uintptr_t& nOutSize);
	std::string GetProcessName();
	std::string GetModuleName(HMODULE hMod);
	void AddExportsFromModule(HMODULE hMod, std::unordered_map<uintptr_t, tIEFuncNode>& addrToInfo);
	void CollectAllExports(std::unordered_map<uintptr_t, tIEFuncNode>& addrToInfo);
	static void DataToHexString(int indent, uintptr_t startAddr, const uint8_t* data, size_t size, std::string* output);
	static void DataToHexString(int indent, uintptr_t startAddr, const uint8_t* data, size_t size, const uint16_t* byteColors, const uint16_t* asciiColors);
	static void SetConsoleColor(int32_t mode);
	static HANDLE InitConsole();
	static void CopyToClipboard(const char* text);
	static void MboxSTD(std::string msg, std::string title);
	static void EXIT_F();
	static void EXIT_S();
	static uintptr_t RestorePointer(uintptr_t op_addr, uintptr_t offset);
	static uintptr_t CalculateOffset(uintptr_t op_addr, uintptr_t dst);
	static void* SearchPointerByPattern(void* ptrStart, int block_size, std::string pattern);
	struct tMemoryRegion
	{
		void* baseAddress;
		SIZE_T size;
	};
	// std::vector<AsmRunner::tMemoryRegion> regions = FindRegions(0x17000, MEM_PRIVATE, PAGE_READWRITE, MEM_COMMIT);
	static std::vector<tMemoryRegion> FindRegions(SIZE_T targetSize = 0, DWORD targetType = 0, DWORD targetProtect = 0, DWORD targetState = MEM_COMMIT);
	static void CompareRegionsSnapshots(const std::vector<tMemoryRegion>& oldRegions, const std::vector<tMemoryRegion>& newRegions, bool bExtra = true);
	static bool IsNTMemoryReadable(uintptr_t address, uintptr_t size = 1);

	// Mem
	uintptr_t AddMemory(uintptr_t nSize, uint32_t nType/* = UC_PROT_ALL*/);
	uintptr_t AddMemory(uintptr_t pFrom, uintptr_t nSize, uint32_t nType/* = UC_PROT_ALL*/);
	bool AddMemoryTo(uintptr_t pVTo, uintptr_t nSize, uint32_t nType = UC_PROT_ALL);
	bool AddMemoryFromBuff(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize, uint32_t nType = UC_PROT_ALL);
	void CopyMemory(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize); // memcpy
	bool FreeMemory(uintptr_t pVTo);
	bool ChangeMemoryType(uintptr_t pVTo, uint32_t nType = UC_PROT_ALL);
	void DumpMemory(const char* szFileOutPath, uintptr_t pStart, uintptr_t nSize); // file
	void DumpMemory(uintptr_t pStart, uintptr_t nSize); // to console DataToHexString
	void DumpMemory(uintptr_t pNativeStart, uintptr_t pVTStart, uintptr_t nSize);
	uintptr_t DumpMemoryNTAlloc(uintptr_t pStart, uintptr_t nSize);
	uintptr_t DumpMemoryAlloc(uintptr_t pStart, uintptr_t nSize); // ?
	bool IsModuleAddr(uintptr_t pAddr);
	bool IsHaltAddr(uintptr_t pAddr);
	bool InExtraRegion(uintptr_t pAddr);
	bool IsPCNormal(uintptr_t pAddr, bool bSkipHalt = false);
	void UpdatePC(uintptr_t pAddr, bool bSkipCBCallsWithNewPC = true); // false - вызвать все cb для hook уже с изменённым pc
	void CapturePC();
	bool IsPCChanged();
	bool ShouldStopCB(bool bReset);
	static bool IsInAddr(uintptr_t pAddr, uintptr_t pStart, uintptr_t pEnd);

	// asm / registers / stack
	uint32_t PcReg() const { return m_bX64 ? UC_X86_REG_RIP : UC_X86_REG_EIP; }
	uint32_t SpReg() const { return m_bX64 ? UC_X86_REG_RSP : UC_X86_REG_ESP; }
	uint32_t FpReg() const { return m_bX64 ? UC_X86_REG_RBP : UC_X86_REG_EBP; }
	uint32_t AxReg() const { return m_bX64 ? UC_X86_REG_RAX : UC_X86_REG_EAX; }
	uint32_t BxReg() const { return m_bX64 ? UC_X86_REG_RBX : UC_X86_REG_EBX; }
	uint32_t CxReg() const { return m_bX64 ? UC_X86_REG_RCX : UC_X86_REG_ECX; }
	uint32_t DxReg() const { return m_bX64 ? UC_X86_REG_RDX : UC_X86_REG_EDX; }
	uint32_t SiReg() const { return m_bX64 ? UC_X86_REG_RSI : UC_X86_REG_ESI; }
	uint32_t DiReg() const { return m_bX64 ? UC_X86_REG_RDI : UC_X86_REG_EDI; }
	uint32_t FlagsReg() const { return UC_X86_REG_EFLAGS; }
	uint32_t R8Reg() const { return m_bX64 ? UC_X86_REG_R8 : UC_X86_REG_R8D; }
	uint32_t R9Reg() const { return m_bX64 ? UC_X86_REG_R9 : UC_X86_REG_R9D; }
	uint32_t R10Reg() const { return m_bX64 ? UC_X86_REG_R10 : UC_X86_REG_R10D; }
	uint32_t R11Reg() const { return m_bX64 ? UC_X86_REG_R11 : UC_X86_REG_R11D; }
	uint32_t R12Reg() const { return m_bX64 ? UC_X86_REG_R12 : UC_X86_REG_R12D; }
	uint32_t R13Reg() const { return m_bX64 ? UC_X86_REG_R13 : UC_X86_REG_R13D; }
	uint32_t R14Reg() const { return m_bX64 ? UC_X86_REG_R14 : UC_X86_REG_R14D; }
	uint32_t R15Reg() const { return m_bX64 ? UC_X86_REG_R15 : UC_X86_REG_R15D; }
	uint32_t PointerSize() const { return m_bX64 ? 8 : 4; }
	uintptr_t CurrentPc(uc_engine* uc) const;
	uintptr_t CurrentSp(uc_engine* uc) const;

	void SetEntryPointStackArg(uint32_t nArgIdx, uintptr_t arg); // bLogRunner log st ptr // default // 0=ebp+4?
	void SetStackArgEbpIndex(uint32_t nArgIdx, uintptr_t arg); // ebp+4 +8 +C ...  // bLogRunner log st ptr // custom stack arg // 4=ebpdefault 0arg?
	void SetRegister(uint32_t nRegister, uintptr_t arg); // todo unicorn types?
	uintptr_t GetRegister(uint32_t nRegister);
	void SetStack(uintptr_t pStack, uintptr_t nSize); // if bLogRunner log stack
	void CopyNTStack(uintptr_t pStack = 0, uintptr_t nSize = 0);
	void SetStack(); // if bLogRunner log stack
	uintptr_t GetStack(uint32_t nIdx);
	bool StackPush(uintptr_t v);
	bool StackPop(uintptr_t& v);
	uintptr_t StackPop();
	bool StackPeek(uintptr_t& v, uint32_t nIdx = 0);
	uintptr_t StackPeek(uint32_t nIdx = 0);
	bool StackPeekBP(uintptr_t& v, int32_t nIdx = 0); // warn!! before prologue ebp from prev frame!
	uintptr_t StackPeekBP(int32_t nIdx = 0);
	uintptr_t StackAt(bool bEsp = true, int32_t nIdx = 0);
	bool StackSetValue(uintptr_t v, bool bEsp = true, int32_t nIdx = 0);
	bool StackGetArg(uintptr_t& v, uint32_t idx, bool bShouldPopArgs_NoCdecl); // true=stdcall pop like, false=cdecl peek
	uintptr_t ExtractAnyIpTransferReturn(ZydisMnemonic mn, uintptr_t from, uint32_t size);
	void SetFakeSehTid(uintptr_t pAddr = 0, uintptr_t nSize = 0);
	void CopyNTSeh(uintptr_t pAddr = 0, uintptr_t nSize = 0);
	bool SetTebBase(uintptr_t base);
	uintptr_t GetTebBase() const;
	bool WriteTebValue(uint32_t offset, uintptr_t value);
	uintptr_t ReadTebValue(uint32_t offset) const;
	void SetTebLastError(uint32_t error);
	uint32_t GetTebLastError() const;

	// callbacks / execution
	void SetAnyJmpHook(uintptr_t pAddr, OnJmpCb cb, void* data = nullptr, bool callBefore = false, bool moduleHook = false); // !moduleHook for new dummy region
	void SetIAT(uintptr_t pStart, uintptr_t pEnd, bool bTryResolveInModule = true, bool bRIMEscapeHook = true, bool bSaveRIM = false);
	void SetIATCallCB(OnOpcodeCb cb = nullptr, void* data = nullptr);
	void SetSysCallCB(OnOpcodeCb cb = nullptr, void* data = nullptr);
	tIEFuncNode* FindIATNode(uintptr_t pAddr, bool bRVA = false);
	tIEFuncNode* FindIATNode(std::string funcName, std::string moduleName = "", bool bLowerCmp = true, bool bContains = false);
	void SetCallbacks(OnOpcodeCb opcode_cb = nullptr, void* opcode_data = nullptr,
		OnMemCb mem_cb = nullptr, void* mem_data = nullptr,
		OnJmpCb jmp_cb = nullptr, void* jmp_data = nullptr); // default AsmRunner hooks with disasm bDisasm, after user cb call // +other cbs
	void SetICCallback(uintptr_t nIC, OnOpcodeCb opcode_cb, void* opcode_data);
	uintptr_t CopyModule(const char* szModule, uintptr_t nSize = 0); // if nSize 0 GetMappedModuleBounds, after CopyModuleToUnicorn(rename)
	void CopyModule(uintptr_t pFrom, uintptr_t nSize = 0); // if nSize 0 GetMappedModuleBounds, after CopyModuleToUnicorn(rename), 
	void LoadModule(const char* szModule); // mz pe? (exe+dll)
	void ResolveIATModule();
	void AddExecRegion(uintptr_t pStart, uintptr_t pEnd);
	std::vector<tFuncNode> GetModuleExports();
	tFuncNode GetModuleExport(const char* szModule, const char* szExportName);
	void SetPCTrace(const char* szPCTraceFileOutPath, bool bRVA = true, uintptr_t pASLR = 0, uintptr_t nICOffset = 0);
	void ComparePCTrace(const char* szPCTraceA, const char* szPCTraceB, bool bAll, const char* szOutFileCompare = nullptr);
	void Run(uintptr_t pEntry, uintptr_t nStepsDeep);
	void Pause();
	void Resume();
	void Stop();
	void B(intptr_t nOps); // -2 +2 b branch like mips, update eip, manual jmp // pause, eip, Resume?
	void DumpRegisters(bool bFull = true); // and flags
	void DumpSegmentRegisters();
	void DumpFlags();
	bool GetFlag(eFlags flag);
	void SetFlag(eFlags flag, bool value);
	void DumpStack(intptr_t nCount = -1, bool bValNotice = true);
	void DumpRWHistory(uintptr_t nLimSize = 0, bool bStartLim = false, bool bRead = true, bool bWrite = true, bool bValNotice = true, bool bRVA = true, bool bSym = true, bool bShortFmt = false);
	void DumpRWHistoryFile(std::string fName, uintptr_t nLimSize = 0, bool bStartLim = false, bool bRead = true, bool bWrite = true, bool bValNotice = true, bool bRVA = true, bool bSym = true, bool bShortFmt = false);
	void ClearRWHistory();
	void AddDeadzoneIC(uintptr_t startIC, uintptr_t endIC, bool checkPC = true, bool skipAll = true, bool skipJmps = true, bool skipMem = true, bool skipOpcode = true);
	void InstallDefaultHooks(HookNotifyCb cb);

	// Disasm (Capstone, Zydis) // if not InitialiseSymMap default disasm, else macro
	void InitialiseSymMap(const char* szPath, uintptr_t nSymASLR = 0); // ppsspp sym map like // fmt: 0xptr NAME // example [0x60F2F0DA] 0x126FDF68: call 0x1288231E  [0x60F2F0DA] 0x126FDF68: call FUNC_23
	const tFuncNode* FindSymbolByRuntime(uintptr_t rtAddr) const;
	tFuncNode GetSymByName(const char* szName);
	tFuncNode GetSymByAddr(uintptr_t pAddr);
	void DisassembleWithZydis();
	void DisassembleWithCapstone();

	void SetBreakpoint(uintptr_t pAddr, eBpType type = BP_CODE, uint32_t size = 1, OnBreakpointCb cb = nullptr, void* data = nullptr);
	void RemoveBreakpoint(uintptr_t pAddr);
	// TODO: AddTraceInstructionPoint // точка с которой начинается логирование в обчном Run
	void TraceInstruction(const char* szTraceFileOutPath, uintptr_t pStart, uint32_t nMaxCount = 0, TraceCb cb = nullptr, bool bPCArray = false); // 0 until end, cb can null autofalse

	// IDA 7.6 IDC // https://docs.hex-rays.com/9.0/developer-guide/idc/idc-api-reference/alphabetical-list-of-idc-functions/686
	std::string SanitizeIdaName(const std::string& in);
	std::string ClearStr(std::string input, std::string charsToRemove);
	std::string SetName(uintptr_t pAddr, std::string name, bool snt = true);
	std::string SetComment(uintptr_t pAddr, std::string comment, uint32_t nType = 0);
	std::string MakeArray(uintptr_t pAddr, uint32_t nArraySize);
	std::string SetType(uintptr_t pAddr, std::string type);
	std::string SetColor(uintptr_t pAddr, uint8_t r = 0x28, uint8_t g = 0x53, uint8_t b = 0x68);
	std::string CreateSegment(uintptr_t pStart, uintptr_t pEnd, std::string name, bool snt = true);
	std::string PatchByte(uintptr_t pAddr, uint8_t val);
	std::string AddFunc(uintptr_t pAddr);
	std::string MakeCode(uintptr_t pAddr);
	std::string Message(std::string message);
	std::string DelItems(uintptr_t pAddr, uintptr_t nSize);
	std::string get_type(uintptr_t pAddr);
	std::string GetType(uintptr_t pAddr);
	std::string Name(uintptr_t pAddr);
	std::string isCode(uintptr_t pAddr);
	std::string isData(uintptr_t pAddr);
	std::string isASCII(uintptr_t pAddr);
	std::string get_func_name(uintptr_t pAddr);
#ifdef AR_IDA_WS
	bool InitIDAWS(const std::string& host = "127.0.0.1", uint16_t port = 27310);
	bool IsIDAWSConnected() const;
	void WaitIDAWSConnection() const;
	bool SendIDAAddr(uintptr_t addr);
	bool SendIDAIdcBuff(const std::string& idcBuff);
	void CloseIDAWS();
#endif

	//MakeCode-AddFunc-SetName

	// Проверка допустимых режимов:
	// "r"  - чтение (файл должен существовать)
	// "w"  - запись (создает новый или перезаписывает)
	// "a"  - добавление (в конец файла)
	// "r+" - чтение и запись (файл должен существовать)
	// "w+" - чтение и запись (создает новый или перезаписывает)
	// "a+" - чтение и добавление (создает новый, если не существует)
	FILE* FileOpen(const char* filename, const char* mode = "w");
	size_t FileSize(FILE* file);
	size_t FileRead(FILE* file, void* pb, size_t sz);
	void FileAdd(FILE* file, const char* fmt, ...);
	void FileClose(FILE* file);

	// Snapshot
	struct tMemSnapshot
	{
		uintptr_t pStart = 0;
		size_t size = 0;
		std::vector<uint8_t> data;
	};
	tMemSnapshot MakeSnapshot(uintptr_t pStart, uintptr_t pEnd);
	tMemSnapshot MakeSnapshotS(uintptr_t pStart, uintptr_t nSize);
	void CompareSnapshots(const tMemSnapshot& a, const tMemSnapshot& b, bool bDiffOnly = true);

	template <typename T>
	bool WriteMemory(uintptr_t pAddr, const T& val, bool bCreateRegion = false)
	{
		static_assert(std::is_trivially_copyable_v<T>,
			"WriteMemory<T> requires trivially copyable T");

		if (!m_uc || !pAddr)
			return false;

		const auto tryWrite = [&]() -> bool
		{
			return uc_mem_write(m_uc, pAddr, &val, sizeof(T)) == UC_ERR_OK;
		};

		if (tryWrite())
			return true;

		if (!bCreateRegion)
		{
			if (m_bLogRunner)
				Log("WriteMemory: write failed at 0x%p, size=%zu", (void*)pAddr, sizeof(T));
			return false;
		}

		const uintptr_t pageSize = 0x1000;
		const uintptr_t base = AlignDownPage(pAddr);
		const uintptr_t end = AlignUp(pAddr + sizeof(T), pageSize);
		const uintptr_t mapSize = end - base;

		if (!AddMemoryTo(base, mapSize, UC_PROT_READ | UC_PROT_WRITE))
		{
			if (m_bLogRunner)
				Log("WriteMemory: failed to map region at 0x%p, size=0x%zx", (void*)base, (size_t)mapSize);
			return false;
		}

		if (tryWrite())
			return true;

		if (m_bLogRunner)
			Log("WriteMemory: write still failed after mapping at 0x%p, size=%zu", (void*)pAddr, sizeof(T));

		return false;
	}

private:
	// точки останова: addr info
	struct tBpInfo
	{
		uint32_t size = 1;
		eBpType type = BP_CODE;
		OnBreakpointCb cb;
		void* data = nullptr;
		uc_hook hook = 0;
	};

	// состояние трасировки Tenet
	struct tTraceState
	{
		std::ofstream file;
		uint32_t count = 0;
		uint32_t maxCount = 0;
		TraceCb cbStop;
		bool active = false;
		std::map<int, uint64_t> prevRegs;  // предыдущие значения регистров для delta
		uintptr_t lastMemAddr = 0;
		uint32_t lastMemSize = 0;
		bool lastMemWrite = false;
		bool PCArray = false;
		std::vector<uint8_t> lastMemData;
	};

	struct tAnyJmpHookNode
	{
		uintptr_t pAddr = 0;
		OnJmpCb cb = nullptr;
		void* data = nullptr;
		bool before = false; // true - call when next op our pAddr, false when pc == pAddr (avoid ExtractAnyIpTransferReturn)
		struct tJmpCBArgs
		{
			uintptr_t from = 0;
			uintptr_t to = 0;
			uint32_t size = 0;
			ZydisMnemonic mnemonic = ZYDIS_MNEMONIC_INVALID;
			bool valid = false;
		} bfArgs; // delayed before OnJmpCb args
	};

	struct tExecRegion
	{
		uintptr_t pStart = 0;
		uintptr_t pEnd = 0;
	};

	struct tRTTrace
	{
		std::ofstream file;
		uintptr_t aslr;
		uintptr_t icoffset;
		bool rva;
		bool inited;
	};

	struct tICNode
	{
		uintptr_t nIC;
		OnOpcodeCb cb;
		void* data = nullptr;
	};

	struct tDeadzoneIC
	{
		uintptr_t startIC;     // Начальный счётчик инструкций
		uintptr_t endIC;       // Конечный счётчик инструкций
		bool checkPC;          // Проверять границы
		bool skipJmps;         // Пропускать JMP колбэки
		bool skipMem;          // Пропускать MEM колбэки
		bool skipOpcode;       // Пропускать Opcode колбэки
		bool skipAll;          // Пропустить всё
		bool active;           // Активен ли сейчас
	};

	struct tIdaWsBridge
	{
		std::string bind_addr;
		int32_t port;
		uintptr_t listen_sock; // sock_t
		uintptr_t client_sock; // sock_t
		std::thread accept_thread;
		std::mutex client_mutex;
		std::atomic<bool> running;
		bool wsa_started;
	};

	struct tRWHistory
	{
		uintptr_t pc; // who
		uintptr_t addr; // when
		uintptr_t value; // res
		uintptr_t size;
		uintptr_t ic;
		bool bRead;
	};

	uc_engine* m_uc = nullptr;
	bool m_bInitialised = false;
	bool m_bLogEnabled = true;
	bool m_bLogDisasm = false;
	bool m_bLogMemRW = false;
	bool m_bLogAnyJmp = false;
	bool m_bLogRunner = false;
	bool m_bInitedStack = false;
	bool m_bInitedSehFS = false; // 0x0 0x7FFDF000 fs TEB Thread Environment Block FS:[0]
	bool m_bX64 = false;
	bool m_bDisasmAfterCB = false;
	bool m_bDisasmRVA = false;
	uintptr_t m_DisasmCustomASLR = 0;
	uintptr_t m_DisasmICNotice = 0;
	bool m_bInitIAT = false;
	bool m_bSkipCBCallsWithNewPC = false;

	std::vector<tFuncNode> m_sym;
	std::vector<tAnyJmpHookNode> m_anyJmpHooks; // when any call smth from here
	std::vector<tIEFuncNode> m_iat;
	std::vector<tExecRegion> m_execRegions; // extra allowed no halt regions for execute
	std::unordered_map<uintptr_t, tIEFuncNode> exportsENV;
	std::vector<tICNode> m_icHooks;
	std::vector<tDeadzoneIC> m_deadzonesIC;
	bool m_bInDeadzoneIC = false;
	int32_t m_currentDeadzoneICIndex = -1;
	std::vector<tRWHistory> m_RWHistory;
	bool m_bRWHistory = false;

	uintptr_t m_iatStart = 0;
	uintptr_t m_iatEnd = 0;
	OnOpcodeCb m_cbIATCall; // when any call smth from m_iat
	void* m_cbIATCallData = nullptr;
	OnOpcodeCb m_cbSysCall; // syscall, int, ud2, etc
	void* m_cbSysCallData = nullptr;

	uintptr_t m_modStart = 0;
	uintptr_t m_modEnd = 0;

	uintptr_t m_stackBase = 0x00100000; // max esp
	uintptr_t m_stackSize = 0x00100000; // real base ebp (m_stackBase+m_stackSize)
	uintptr_t m_stackEPSize = 0x100; // m_bX64 ? 0x20 : 8
	uintptr_t m_allocBase = 0x20000000;
	uintptr_t m_allocCursor = 0x20000000;
	uintptr_t m_fsBase = 0;
	uintptr_t m_fsSize = 0;
	uintptr_t m_halt = 0x0; // 0x0 0x13371337 0xDEADBEEF
	uintptr_t m_lastPC = 0;

	uintptr_t m_instrCount = 0;
	uc_hook m_hkCode = 0;
	uc_hook m_hkMem = 0;

	OnOpcodeCb m_cbOpcode;
	void* m_cbOpcodeData = nullptr;
	OnMemCb m_cbMem;
	void* m_cbMemData = nullptr;
	OnJmpCb m_cbJmp;
	void* m_cbJmpData = nullptr;
	OnBreakpointCb m_cbBreak;
	void* m_cbBreakData = nullptr;

	// флаги управления эмуляцией
	bool m_bPaused = false;
	bool m_bStopped = false;

	std::map<uintptr_t, tBpInfo> m_breakpoints;
	tTraceState m_trace; // separate run
	tRTTrace m_rttrace; // default

#ifdef AR_IDA_WS
	tIdaWsBridge m_ws;
#endif

#ifdef ZYDIS
	ZydisDecoder m_decoder{};
	ZydisFormatter m_formatter{};
#endif
#ifdef CAPSTONE
	csh m_csHandle = 0;
#endif

private:
	void Log(const char* fmt, ...) const;

	static void HookCodeTrampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static bool HookMemTrampoline(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
	static bool IsAnyIpTransfer(ZydisMnemonic mn);
	bool TryResolveIpTransfer(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t curPc, uintptr_t& outTarget);
	bool ReadZydisRegisterValue(uc_engine* uc, ZydisRegister reg, uintptr_t& out) const;
	bool ResolveMemoryOperandAddress(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand& op, uintptr_t insnAddr, uintptr_t& outAddr) const;
	bool ResolveDirectBranchTarget(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t insnAddr, uintptr_t& outTarget) const;
	bool CopyModuleUC(uintptr_t real_base, uintptr_t emu_base, uintptr_t size);
	void UpdateDeadzoneIC(uintptr_t currentIC);
	tDeadzoneIC* GetCurrentDeadzoneIC();

	// внутренние колбэки Unicorn (static, this передаётся через user_data)
	void _OnInstructionStep(uc_engine* uc, uint64_t address, uint32_t size, void* user_data); // дизасм + user cb + брейкпоинты + трасировка
	bool _OnMemory(uc_engine* uc, uc_mem_type type, uint64_t address, uint32_t size, int64_t value, void* user_data); // лог rw + user cb + трасировка mem
	bool _OnAnyJmp(uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic);        // jmp/call/ret детектируется в _OnInstructionStep
	void _OnBreakpoint(uc_engine* uc, uintptr_t address);             // срабатывание точки останова
	void _OnTraceStep(uc_engine* uc, uintptr_t address, uint32_t sz); // запись шага трасировки в Tenet-файл

	// symbol helpers
	std::string FormatRuntimeAddress(uintptr_t rtAddr) const;
	std::string FormatRuntimeAddressWithSymbol(uintptr_t rtAddr) const;
	std::string FormatCurrentSymbolSuffix(uintptr_t rtAddr) const;

	// more helpers
	bool ReadBytes(uc_engine* uc, uint64_t address, uint32_t size, std::vector<uint8_t>& out) const;
	std::string RegName(uint32_t reg) const;
	bool IsInModule(uintptr_t addr) const;
	void TraceWriteLine(const std::string& s);
	std::string MakeDisasmLine(const uint8_t* bytes, size_t size, uintptr_t runtimeAddress, ZydisDecodedInstruction* instr, ZydisDecodedOperand* operands, bool& bResOK);

	// exports / PE helpers
	static void TrimInPlace(std::string& s);
	static bool ParseHexPtr(const std::string& s, uintptr_t& out);
	bool LoadExportsFromBase(uintptr_t base, std::vector<tFuncNode>& out) const;
};

class MemoryPatcher
{
public:
	uintptr_t address;
	std::vector<uint8_t> originalBytes;
	std::vector<uint8_t> patchBytes;
	int size;
	bool isPatched;
	bool IsValidPointer(void* ptr)
	{
		if (!ptr) { return false; }
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) { return false; }
		return (mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_NOACCESS);
	}
	void inline PerformWrite(uintptr_t pto, uintptr_t pfrom, uint32_t size)
	{
		DWORD vp[2];
		if (!pto || !pfrom || !size) { printf("err patch\n"); return; }
		VirtualProtect((void*)pto, size, PAGE_EXECUTE_READWRITE, &vp[0]);
		memcpy((void*)pto, (void*)pfrom, size);
		VirtualProtect((void*)pto, size, vp[0], &vp[1]);
	}
	MemoryPatcher() {}
	MemoryPatcher(uintptr_t addr, uint8_t val, uint32_t cnt) : isPatched(false)//, address(addr), size(cnt)
	{
		if (!addr || !cnt || !IsValidPointer((void*)addr)) { return; }
		address = addr; // 0 if !valid
		size = cnt;
		for (size_t i = 0; i < size; i++) { patchBytes.push_back(val); }
	}
	MemoryPatcher(uintptr_t addr, std::vector<uint8_t> patchData) : isPatched(false)//, address(addr)
	{
		if (!addr || !patchData.size() || !IsValidPointer((void*)addr)) { return; }
		address = addr; // 0 if !valid
		patchBytes = patchData;
		size = patchBytes.size();
	}
	bool ReadBytes()
	{
		if (!address || !size || !IsValidPointer((void*)address)) { return false; }
		originalBytes.clear();
		originalBytes.reserve(size);
		for (uint32_t i = 0; i < size; ++i)
			originalBytes.push_back(((uint8_t*)address)[i]);
		return true;
	}
	void inline ApplyPatch()
	{
		if (!originalBytes.size()) { for (int i = 0; i < size; i++) { originalBytes.push_back(((uint8_t*)address)[i]); } }
		if (size && !isPatched) { PerformWrite(address, (uintptr_t)patchBytes.data(), patchBytes.size()); isPatched = true; printf("[0x%p/%d]: Ena\n", address, size); }
	}
	void inline RemovePatch() { if (size && isPatched) { PerformWrite(address, (uintptr_t)originalBytes.data(), originalBytes.size()); isPatched = false; printf("[0x%p/%d]: Disa\n", address, size); } }
};

//TraceInstruction format like Tenet ida plugin
//ax = 0xf4, eip = 0x502612, mr = 0x4ccbdf:f4
//	edx = 0x502608, eip = 0x502615
//	eax = 0xc2, eip = 0x502617
//	esp = 0x2f1f518, eip = 0x502618, mw = 0x2f1f518 : 82020000
//	esp = 0x2f1f514, eip = 0x50261d, mw = 0x2f1f514 : a2a1d06c
//	eip = 0x503a1b
//	esi = 0x4ccbe0, eip = 0x503a1c
//	edx = 0x5000c2, eip = 0x503a20
//	edx = 0x500000, eip = 0x503a23
//	eax = 0xc3, eip = 0x503a25
//	eip = 0x503a26
//	eax = 0x3d, eip = 0x503a28
//	edx = 0x5000ff, eip = 0x503a2a
//	esp = 0x2f1f510, eip = 0x503a2e, mr = 0x2f1f518:82020000, mw = 0x2f1f510 : 82020000
//	esp = 0x2f1f4f0, eip = 0x503a2f, mw = 0x2f1f4f0 : 1cf5f102e0cb4c00e0f5f10210f5f10236fe7f08ff0050002ac44c003d000000
//	edx = 0x5000fe, eip = 0x503a31
//	eax = 0x3c, eip = 0x503a33
//	edx = 0x50c4fe, eip = 0x503a35
//	esp = 0x2f1f4ec, eip = 0x5030c5, mw = 0x2f1f4ec : 3a3a5000
//	edx = 0x5031fe, eip = 0x5030c7
//	edx = 0x500001, eip = 0x5030cb

// note: копируем модуль по тем же адресам в uc, грузим карту sym, если nSymASLR!=0 отнимаем у адреса каждой функции nSymASLR получаем rva, я бы написал -= nSymASLR всегда
// my usage
// Initialise with logeip, logmem // autoinit unicorn stack seh, disasm, etc
// CopyModule(pNativeModule, size)
// InitialiseSymMap("funcs.sym", 0x6700000(pidb)) // pmap - pidb = rva // pidb can be with aslr from idb, sub to rva
// SetCallbacks(myop, mymem, myanyjmp) // separate install uninstall?
// pVMem = AddMemory(pNative, sz)
// pVMemObj = AddMemory(pNative, sz)
// SetEntryPointStackArg(0, pVMem) // call entrypoint stdcall arg (pBuff[in stack]) // 
// SetRegister(ecx, pVMemObj) // + thiscall ctx
// Run(0x12345678, 60) // 
// Shutdown()


// sym map example
//60F01000 VT_Adapters::CSteamAppDisableUpdate001_sub_60F01000, 001d
//60F01020 sub_60F01020, 001d
//60F01040 VT_Adapters::CSteamAppTicket001_TICKET_sub_60F01040, 010d
//60F01150 sub_60F01150, 001a


// Stack hint
// STACK: 0x00 (stack max)
//	lvars int b;
//	lvars int a;
//	prev frame EBP (saved EBP); // pushed by prologue current function
//  return addr; // pc after call, pushed by cpu call
//  arg1 5; // pushed caller before call, 3d push
//  arg2 6; // pushed caller before call, 2th push
//  arg3 7; // pushed caller before call, 1st push
//  0x0000 halt
// STACK: 0xFF (stack base)

//0x7FFDF000 fs TEB Thread Environment Block FS:[0]

// links
//https://github.com/colby57/VMP-Imports-Deobfuscator/tree/3d9817024ea58d806a52a2bd85dde5b1c697dc75
//https://github.com/KuNgia09/vmp3-import-fix
//https://github.com/pulpgit/Themida-Imports-Deobfuscator-main/tree/84e8edf96a2b8a9134bf40c97ad94e8cb558ff16
//https://github.com/MMaZaHaKa/awesome_anti_virus_engine
//https://github.com/gmh5225/awesome-game-security/tree/1f857416ca85858759eb44da277bf070046498b0
//https://github.com/samshine/VoyagerWithEPT
//
//https://github.com/unicorn-engine/unicorn
//https://github.com/DarthTon/Blackbone
//https://github.com/archercreat/vmpfix
//https://github.com/NtQuery/Scylla
//https://github.com/zyantific/zydis
//https://github.com/gabime/spdlog