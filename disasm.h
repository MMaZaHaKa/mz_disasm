#pragma once
// disasm by MaZaHaKa
#define UNICORN //  .\vcpkg install unicorn:x86-windows unicorn:x64-windows  // .\vcpkg integrate install
//#define CAPSTONE
#define ZYDIS //  .\vcpkg install zydis:x86-windows zydis:x64-windows  // .\vcpkg integrate install
//vcpkg install unicorn:x64-windows-static zydis:x64-windows-static
//vcpkg install unicorn:x86-windows-static zydis:x86-windows-static

#if 0
#define ZYDIS_STATIC_BUILD

#ifdef _DEBUG // (/MTd)
#pragma comment(linker, "/NODEFAULTLIB:msvcrt.lib")
#pragma comment(linker, "/NODEFAULTLIB:msvcrtd.lib")
#pragma comment(linker, "/NODEFAULTLIB:msvcp140.lib")
#pragma comment(linker, "/NODEFAULTLIB:vcruntime.lib")
#pragma comment(linker, "/NODEFAULTLIB:ucrt.lib")

#pragma comment(linker, "/DEFAULTLIB:libcmtd.lib")
#pragma comment(linker, "/DEFAULTLIB:libvcruntimed.lib")
#pragma comment(linker, "/DEFAULTLIB:libucrtd.lib")

#pragma comment(lib, "zycore.lib")
#pragma comment(lib, "zydis.lib")
#pragma comment(lib, "unicorn.lib")
#else
#pragma comment(linker, "/NODEFAULTLIB:msvcrt.lib")
#pragma comment(linker, "/NODEFAULTLIB:msvcrtd.lib")
#pragma comment(linker, "/NODEFAULTLIB:msvcp140.lib")
#pragma comment(linker, "/NODEFAULTLIB:vcruntime.lib")
#pragma comment(linker, "/NODEFAULTLIB:ucrt.lib")

#pragma comment(linker, "/DEFAULTLIB:libcmt.lib")
#pragma comment(linker, "/DEFAULTLIB:libvcruntime.lib")
#pragma comment(linker, "/DEFAULTLIB:libucrt.lib")

#pragma comment(lib, "zycore.lib")
#pragma comment(lib, "zydis.lib")
#pragma comment(lib, "unicorn.lib")
#endif
#pragma comment(linker, "/IGNORE:2038")
#pragma comment(linker, "/IGNORE:4099")
#pragma comment(linker, "/IGNORE:4217")
#pragma comment(linker, "/IGNORE:4049")
#pragma comment(linker, "/FORCE:MULTIPLE")
#endif

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
#define AR_MAX_FSIZE (0xF0'00)
//#define AR_SYSCALL_JUMP_CB
//#define AR_DEBUG
#define AR_IDA_WS
//#define AR_HALT_JMPCB // allow jmp cb notify jmp to halt
#define AR_HALT_ADDR_ONLY // fast + correct halt shutdown log, the rest is neat (unmapped execute)
//#define AR_BP_AFTER_DZ // faster dz
//#define AR_BP_RANGE // size or range
#define AR_DFT // BPF verifier per-register parent pointers bpf_reg_state // Data Flow Tracing, Taint Tracking Data Tracking
#define AR_NTCORE_PATCH // SMC crash fix
//#define AR_STATE_SEG // не включать, ломает уебанские нерабочие сегменты, size не тот и тд

// windows header hell kek
#undef CopyMemory
#undef min
#undef max

// TODO: normal seh+frame unwind MSR_FS_BASE, tls UC_X86_REG_FS_BASE in SetTebBase, breakpoint condition cb, cb UC_HOOK_INSN, UC_HOOK_INTR, cb on register change?, trace deadzone?
// символьное исполнение LLVM Guided Symbolic Evaluation + BPF verifier per-register parent pointers bpf_reg_state // Data Flow Tracing, Taint Tracking Data Tracking
// todo FreeMemory alloc map + size
// UC bugs: 1 can't set fs: but res ok, 2 update pc + emu_stop() can't stop emu
// все хуки в Unicorn по умолчанию являются pre-hooks, Разработчики обсуждали добавление пост-хуков, но столкнулись с техническими сложностями из-за JIT-компиляции (особенно с повторяющимися инструкциями вроде REP STOS) .
// Поэтому официально реализованы только pre-hooks.
// сшивания TCG Translation Blocks tb_add_jump chaining translation blocks (TB chaining)  краш на SMC коде
// 
//#define AR_TRY_FIX_TCG // self-modifying SMC

#include <vector>
#include <map> // X_bound
#include <unordered_map> // unsorted
#include <functional>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <initializer_list>
#include <chrono>
#include <thread>
#include <mutex>
#include <set>
#include <memory>

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

struct tFuncNode
{
	std::string moduleName;
	std::string funcName;
	uintptr_t moduleBase;
	uintptr_t funcRva;
	uintptr_t funcSize;

	inline uintptr_t GetAbsolute() { return moduleBase + funcRva; }
	inline std::string GetAbsoluteName() { return funcName + " " + moduleName; }
};

struct tRange
{
	uintptr_t start;
	uintptr_t end;
	bool sExcl;
	bool eExcl;
	tRange() { start = 0; end = 0; sExcl = false; eExcl = true; }
	tRange(uintptr_t Start, uintptr_t End) { start = Start; end = End; sExcl = false; eExcl = true; }
};

enum eBpType : uint32_t
{
	BP_CODE = 0,  // инструкция (UC_HOOK_CODE)
	BP_MEM_READ = 1,  // чтение памяти
	BP_MEM_WRITE = 2,  // запись памяти
	BP_MEM_RW = 3   // чтение или запись // access
};

static constexpr uint32_t kArMagic = 0x41535452u; // 'ASTR'
static constexpr uint32_t kArVersion = 1u;

static constexpr uint32_t kChunkREGS = 0x53474552u; // 'REGS'
static constexpr uint32_t kChunkMEMS = 0x534D454Du; // 'MEMS'
static constexpr uint32_t kChunkEND = 0x444E4524u; // '$END'

#pragma pack(push, 1)
struct ArFileHdr
{
	uint32_t magic;
	uint32_t version;
	uint8_t  bis64;
	uint8_t  bHasModuleData;
	uint8_t  reserved[2];
	uint64_t iccount;
	uint64_t stepsDeep;
	uint64_t modStart;
	uint64_t modEnd;
	char     modName[256];
	uint64_t stackBase;
	uint64_t stackSize;
	uint64_t fsBase;
	uint64_t fsSize;
	uint64_t fsLastError;
	uint64_t allocBase;
	uint64_t allocCursor;
	uint64_t savedPC;
};

struct ArRegsBlob
{
	uint64_t ax, bx, cx, dx, si, di, bp, sp, ip;
	uint64_t flags;
	uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
	uint64_t fs_base, gs_base;
	uint16_t cs, ds, es, fs_sel, gs_sel, ss;
	uint8_t  _pad[4];
};

struct ArMemEntry
{
	uint64_t addr;
	uint64_t mapSize;
	uint32_t prot;
	uint8_t  regionType; // 0=generic 1=stack 2=teb 3=module
	uint8_t  hasData;
	uint8_t  _pad[2];
	// followed by mapSize bytes if hasData==1
};

struct ArChunkHdr
{
	uint32_t tag;
	uint32_t size;
};
#pragma pack(pop)


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
	using OnJmpCb = std::function<bool(uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data)>;

	// Тип колбэка для трассировки: возвращает true для остановки трассировки
	using TraceCb = std::function<bool(uc_engine* uc, uintptr_t address, uint32_t instruction_count, void* user_data)>;

	// UC_HOOK_INSN - UC_X86_INS_CPUID
	using OnInsnCb = std::function<bool(uc_engine* uc, uintptr_t address, uint32_t size, uintptr_t nUcInsn, ZydisMnemonic mnemonic, void* user_data)>;

	using HookNotifyCb = std::function<void(tFuncNode* pNode)>;


	AsmRunner(bool bX64 = false);
	~AsmRunner();

	void SetLogging(bool enabled) { m_bLogEnabled = enabled; }
	bool IsLogging() const { return m_bLogEnabled; }
	void SetDisasmAfterCB(bool enabled) { m_bDisasmAfterCB = enabled; }
	bool IsDisasmAfterCB() const { return m_bDisasmAfterCB; }
	void SetDisasmRVA(bool enabled, uintptr_t disasmCustomASLR = 0) { m_bDisasmRVA = enabled; m_DisasmCustomASLR = disasmCustomASLR; }
	bool IsDisasmRVA() const { return m_bDisasmRVA; }
	uintptr_t GetDisasmCASLR() const { return m_DisasmCustomASLR; }
	void SetDisasmSepGroup(uintptr_t disasmSepGroup) { m_DisasmSepGroup = disasmSepGroup; }
	bool IsDisasmSepGroup() const { return m_DisasmSepGroup; }
	uintptr_t CalcWithCASLR(uintptr_t p) const { return p - GetModStart() + GetDisasmCASLR(); }
	void SetLogDisasm(bool enabled) { m_bLogDisasm = enabled; }
	bool IsLogDisasm() const { return m_bLogDisasm; }
	void SetLogDisasmRawBytes(bool enabled) { m_bLogDisasmRawBytes = enabled; }
	bool IsLogDisasmRawBytes() const { return m_bLogDisasmRawBytes; }
	void SetLogDisasmSection(bool enabled) { m_bLogDisasmSection = enabled; }
	bool IsLogDisasmSection() const { return m_bLogDisasmSection; }
	void SetLogDisasmICNotice(uintptr_t disasmICNotice) { m_DisasmICNotice = disasmICNotice; }
	void SetLogMemRW(bool enabled) { m_bLogMemRW = enabled; }
	bool IsLogMemRW() const { return m_bLogMemRW; }
	void SetLogAnyJmp(bool enabled) { m_bLogAnyJmp = enabled; }
	bool IsLogAnyJmp() const { return m_bLogAnyJmp; }
	void SetLogRunner(bool enabled) { m_bLogRunner = enabled; }
	bool IsLogRunner() const { return m_bLogRunner; }
	void SetX64(bool isX64) { m_bX64 = isX64; }
	bool IsX64() const { return m_bX64; }
	void SetUsingBpCodeSizeRange(bool bUsingBpCodeSizeRange) { m_bUsingBpCodeSizeRange = bUsingBpCodeSizeRange; }
	bool IsUsingBpCodeSizeRange() const { return m_bUsingBpCodeSizeRange; }
	void SetSkipCBCallsWithNewPC(bool bSkipCBCallsWithNewPC) { m_bSkipCBCallsWithNewPC = bSkipCBCallsWithNewPC; }
	bool IsSkipCBCallsWithNewPC() const { return m_bSkipCBCallsWithNewPC; }
	void SetRWHistory(bool enabled) { m_bRWHistory = enabled; }
	bool IsRWHistory() const { return m_bRWHistory; }
	//void RequestShutdown(bool enabled) { m_bRequestShutdown = enabled; }
	//bool IsRequestedShutdown() const { return m_bRequestShutdown; }
	bool IsSymMapInitialised() const { return m_sym.size() != 0; }
	uintptr_t GetModStart() const { return m_modStart; }
	uintptr_t GetModEnd() const { return m_modEnd; }
	uintptr_t GetStackStart() const { return m_stackBase; } // esp, меньший адрес, начало памяти, логический конец стека, push уменшает esp
	uintptr_t GetStackEnd() const { return m_stackBase + m_stackSize; } // ebp, больший адрес, конец памяти, логическое начало стека
	uintptr_t GetStackMinAddrBP() const { return GetStackStart(); } // wrapper
	uintptr_t GetStackMaxAddrSP() const { return GetStackEnd(); } // wrapper
	uintptr_t GetFSTEBStart() const { return m_fsBase; }
	uintptr_t GetFSTEBEnd() const { return m_fsBase + m_fsSize; }
	bool IsStackAddr(uintptr_t p) { return IsInAddr(p, GetStackStart(), GetStackEnd()); }
	bool IsTEBAddr(uintptr_t p) { return IsInAddr(p, GetFSTEBStart(), GetFSTEBEnd()); }
	void SetFSTEBLastError(uintptr_t lastError) { m_fsLastError = lastError; }
	uintptr_t GetFSTEBLastError() const { return m_fsLastError; }
	void SetUnhandledExceptionFilter(uintptr_t unhandledExceptionFilter) { m_unhandledExceptionFilter = unhandledExceptionFilter; }
	uintptr_t GetUnhandledExceptionFilter() const { return m_unhandledExceptionFilter; }
	uint64_t GetInstructionsPerSecond() const { return m_instructionsPerSecond; }
	uint64_t GetFiletimeUnitsPerSecond() const { return m_filetimeUnitsPerSecond; }
	void SetFlsValue(uintptr_t index, uintptr_t value);
	uintptr_t GetFlsValue(uintptr_t index);
	void SetDebugCanarySecurityInitCookie(const uint8_t* pattern, size_t size) { m_DebugCanarySecurityInitCookie.assign(pattern, pattern + size); }
	void SetDebugCanarySecurityInitCookie(const std::vector<uint8_t>& pattern) { m_DebugCanarySecurityInitCookie = pattern; }
	const std::vector<uint8_t>& GetDebugCanarySecurityInitCookie() const { return m_DebugCanarySecurityInitCookie; }
	void AddRestartICPoints(uintptr_t ic) { m_RestartICPoints.push_back(ic); }
	std::vector<uintptr_t>& GetRestartICPoints() { return m_RestartICPoints; }
	void SetSecurityCookieRWNotify(uintptr_t sc) { __security_cookie = sc; }

	// core lifecycle
	void Initialise(bool bLogDisasm, bool bLogMemRW, bool bLogAnyJmp, bool bLogRunner, bool bInitUC = true); // set log, init unicorn, init disasms, alloc stack, alloc seh(:fs)
	void Shutdown();
	void ShutdownByCallback(uc_engine* uc);
	void ShutdownByHalt(uc_engine* uc);
	uc_engine* GetCTX();
	uintptr_t GetInstructionCount() const { return m_instrCount; }
	void hleEatInsN(intptr_t n) { m_instrCount += n; } // hleEatMicro, use it for module hooks so as not to shift the IC hooks

	// tools
	static inline uintptr_t AlignUp(uintptr_t x, uintptr_t a) { return (x + a - 1) & ~(a - 1); }
	static inline uintptr_t AlignDown(uintptr_t v, uintptr_t a) { return v & ~(a - 1); }
	static inline uintptr_t AlignDownPage(uintptr_t v) { return v & ~static_cast<uintptr_t>(0xFFF); }
	static inline bool IsPrintableAscii(uint8_t c) { return c >= 0x20 && c <= 0x7e; }
	static std::chrono::steady_clock::time_point CaptureTime();
	static void DumpTime(std::chrono::steady_clock::time_point start, const char* label = nullptr);
	static void DumpDeltaTime(std::chrono::steady_clock::time_point a, std::chrono::steady_clock::time_point b, const char* label = nullptr);
	static std::string PrintPtrAsciiTag(uintptr_t v, size_t width, bool bDec = false, bool bDecBracket = true);
	static std::string PrintValue(uintptr_t v, bool bDec = false);
	static uintptr_t DumpModule(uintptr_t pAddr);
	static uintptr_t DumpModule(const char* moduleName, bool bLoadLib);
	static bool DumpModuleToFile(uintptr_t pAddr, const char* fileName);
	static bool DumpModuleToFile(const char* moduleName, const char* fileName, bool bLoadLib = true);
	static uintptr_t RemapModule(uintptr_t pAddr, bool bTerminateAll); // флешка
	static uintptr_t RemapModule(const char* moduleName, bool bLoadLib = true, bool bTerminateAll = true);

	static void TestPerformanceConstants();
	void SetPerformanceConstantsHost(float k = 1.0f);
	void SetPerformanceConstants(uint64_t instructionsPerSecond = 1'706'928'617, uint64_t filetimeUnitsPerSecond = 10000000ULL);
	uint64_t CalcTime(uint64_t nInstrDelta, float k = 1.0f);
	double CalcTimeMs(uint64_t nInstrDelta, float k = 1.0f);

	uintptr_t GetMappedModuleSizeByName(LPCSTR moduleName);
	bool GetMappedModuleBounds(LPCSTR moduleName, uintptr_t& pOutStart, uintptr_t& pOutEnd, uintptr_t& nOutSize);
	std::string GetProcessName();
	std::string GetModuleName(HMODULE hMod);
	void AddExportsFromModule(HMODULE hMod, std::map<uintptr_t, tFuncNode>& addrToInfo, uintptr_t nMaxSize = AR_MAX_FSIZE);
	void CollectAllExports(std::map<uintptr_t, tFuncNode>& addrToInfo, uintptr_t nMaxSize = AR_MAX_FSIZE);
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
	static uintptr_t SearchPointerByPattern(uintptr_t ptrStart, uint32_t block_size, std::string pattern);
	static std::vector<uintptr_t> ScanPattern(uintptr_t pStart, uintptr_t pEnd, std::string pattern);
	std::vector<uintptr_t> ScanPatternV(uintptr_t pStart, uintptr_t pEnd, std::string pattern);
	static std::vector<uintptr_t> ScanBytes(uintptr_t pStart, uintptr_t pEnd, const std::vector<uint8_t>& bytes);
	static uintptr_t ScanBytesBlock(uintptr_t pStart, uintptr_t pEnd, const std::vector<std::vector<uint8_t>>& bytes, bool bStartAlignPat);
	struct tMemoryRegion
	{
		void* baseAddress;
		SIZE_T size;
	};
	// std::vector<AsmRunner::tMemoryRegion> regions = FindRegions(0x17000, MEM_PRIVATE, PAGE_READWRITE, MEM_COMMIT);
	static std::vector<tMemoryRegion> FindRegions(SIZE_T targetSize = 0, DWORD targetType = 0, DWORD targetProtect = 0, DWORD targetState = MEM_COMMIT);
	static void CompareRegionsSnapshots(const std::vector<tMemoryRegion>& oldRegions, const std::vector<tMemoryRegion>& newRegions, bool bExtra = true);
	static bool IsNTMemoryReadable(uintptr_t address, uintptr_t size = 1);
	static std::string CleanFileName(std::string name);
	static uint32_t fast_hash32(const void* key, uint32_t len, uint32_t seed = 0);
	static uint32_t hash_combine(uint32_t seed, uint32_t value);

	// Mem
	uintptr_t AddMemory(uintptr_t nSize, uint32_t nType/* = UC_PROT_ALL*/, bool bAlign /*= true*/);
	uintptr_t AddMemory(uintptr_t pFrom, uintptr_t nSize, uint32_t nType/* = UC_PROT_ALL*/, bool bAlign /*= true*/);
	bool AddMemoryTo(uintptr_t pVTo, uintptr_t nSize, uint32_t nType = UC_PROT_ALL, bool bAlign = true);
	bool AddMemoryFromBuff(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize, uint32_t nType = UC_PROT_ALL, bool bAlign = true);
	void InitNewMemory(uintptr_t pAddr, uintptr_t nSize);
	void CopyMemory(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize); // memcpy
	uintptr_t MemSet(uintptr_t pAddr, int8_t nVal, uintptr_t nSize);
	uintptr_t MemCpy(uintptr_t pVTo, uintptr_t pVFrom, uintptr_t nSize);
	uintptr_t StrLen(uintptr_t pVStr);
	bool FreeMemory(uintptr_t pVTo);
	bool FreeMemory(uintptr_t pVTo, uintptr_t nSize);
	bool ChangeMemoryType(uintptr_t pVTo, uint32_t nType = UC_PROT_ALL);
	void DumpMemory(const char* szFileOutPath, uintptr_t pStart, uintptr_t nSize); // file
	void DumpMemory(uintptr_t pStart, uintptr_t nSize); // to console DataToHexString
	void DumpMemoryNT(uintptr_t pStart, uintptr_t nSize); // to console DataToHexString
	void DumpMemoryVal(uintptr_t nVal, uintptr_t nSize); // to console DataToHexString
	void DumpMemory(uintptr_t pNativeStart, uintptr_t pVTStart, uintptr_t nSize);
	uintptr_t DumpMemoryNTAlloc(uintptr_t pStart, uintptr_t nSize);
	uintptr_t DumpMemoryAlloc(uintptr_t pStart, uintptr_t nSize); // ?
	void EditBuff(uintptr_t pVaddr, uintptr_t size);
	void WaitBuff(uintptr_t pVaddr, uintptr_t size) { EditBuff(pVaddr, size); } // wrapper
	bool IsModuleAddr(uintptr_t pAddr);
	bool IsHaltAddr(uintptr_t pAddr);
	bool InExtraRegion(uintptr_t pAddr);
	bool IsPCNormal(uintptr_t pAddr, bool bSkipHalt = false);
	void UpdatePC(uintptr_t pAddr, bool bSkipCBCallsWithNewPC = true); // false - вызвать все cb для hook уже с изменённым pc
	void CapturePC();
	bool IsPCChanged();
	bool ShouldStopCB(bool bReset);
	static bool IsInAddr(uintptr_t pAddr, uintptr_t pStart, uintptr_t pEnd); // [s, e)

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
	bool IsAnyReg(uintptr_t value, uintptr_t& outReg, std::string& outName);
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
	// вызывать StackGetArg после call перед эпилогом, после stackpop return address
	bool StackGetArg(uintptr_t& v, uint32_t idx, bool bShouldPopArgs_NoCdecl); // true=stdcall pop like, false=cdecl peek
	void InitialiseSegmentRegisters();
	uintptr_t ExtractAnyIpTransferReturn(ZydisMnemonic mn, uintptr_t from, uint32_t size);
	void SetTeb(uintptr_t pAddr = 0, uintptr_t nSize = 0, bool bUseDefaultAddr = false);
	void CopyNTSeh(uintptr_t pAddr = 0, uintptr_t nSize = 0);
	bool SetTebBase(uintptr_t base);
	uintptr_t GetTebBase() const;
	bool WriteTebValue(uint32_t offset, uintptr_t value);
	uintptr_t ReadTebValue(uint32_t offset) const;
	void SetTebLastError(uint32_t error);
	uint32_t GetTebLastError() const;

	// callbacks / execution
	struct tRWHistory
	{
		uintptr_t pc; // who
		uintptr_t addr; // when
		uintptr_t value; // res
		uintptr_t size;
		uintptr_t ic;
		bool bRead;
		std::string disasm;
	};
	void SetAnyJmpHook(uintptr_t pAddr, OnJmpCb cb, void* data = nullptr, bool callBefore = false, bool moduleHook = false, std::string sFuncName = ""); // !moduleHook for new dummy region
	void GenerateIDCIATFix(std::string outfile, uintptr_t pIATStart, uintptr_t pIATEnd, uintptr_t pIDBASLR, uintptr_t nMaxDeep = 3000, bool bGenSectionDummy = true);
	void SetIAT(uintptr_t pStart, uintptr_t pEnd, bool bTryResolveInModule = true, bool bRIMEscapeHook = true, bool bSaveRIM = false);
	bool SaveIATEnv(const char* szIATEnvFile, bool bRecaptureEnv = true);
	bool LoadIATEnv(const char* szIATEnvFile, uintptr_t nMaxSize = AR_MAX_FSIZE);
	tFuncNode* FindIATNode(uintptr_t pAddr, bool bRVA = false);
	tFuncNode* FindIATNode(std::string funcName, std::string moduleName = "", bool bLowerCmp = true, bool bContains = false);
	void SetIATCallCB(OnJmpCb cb, void* data = nullptr);
	void SetSysCallCB(OnOpcodeCb cb, void* data = nullptr);
	void SetInsnCB(uintptr_t nInsn, OnInsnCb cb, void* data = nullptr); // UC_X86_INS_CPUID warn!!! check IsInsnAllowed
	void SetAllInsnCB(OnInsnCb cb, void* data = nullptr);
	void RemoveInsnCB(uintptr_t nInsn);
	void RemoveAllInsnCB();
	void SetCallbacks(OnOpcodeCb opcode_cb = nullptr, void* opcode_data = nullptr,
		OnMemCb mem_cb = nullptr, void* mem_data = nullptr,
		OnJmpCb jmp_cb = nullptr, void* jmp_data = nullptr); // default AsmRunner hooks with disasm bDisasm, after user cb call // +other cbs
	void SetMemoryRangeCB(tRange r, OnMemCb mem_cb, void* mem_data); // you can use default OnMemCb and filter, or this SetMemoryRangeCB
	void SetICCallback(uintptr_t nIC, OnOpcodeCb opcode_cb, void* opcode_data);
	uintptr_t CopyModule(const char* szModule, uintptr_t nSize = 0); // if nSize 0 GetMappedModuleBounds, after CopyModuleToUnicorn(rename)
	bool CopyModule(uintptr_t pFrom, uintptr_t nSize = 0, std::string sModName = ""); // if nSize 0 GetMappedModuleBounds, after CopyModuleToUnicorn(rename), 
	bool CopyModule(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize, std::string sModName = "");
	void LoadModule(const char* szModule); // mz pe? (exe+dll)
	void RemapModule();
	void* SaveRunStateEnv(uintptr_t& nOutSize);
	void* SaveRunStateEnvNT(uintptr_t& nOutSize);
	void LoadRunStateEnv(void* pReadBuff, bool bRun = false);
	void SaveRunStateEnvFile(std::string file);
	void SaveRunStateEnvNTFile(std::string file);
	void LoadRunStateEnvFile(std::string file, bool bRun = false);
	void HardReset();
	void ResolveIATModule();
	uintptr_t GetRandomEntryPoint();
	void AddExecRegion(uintptr_t pStart, uintptr_t pEnd);
	std::vector<tFuncNode> GetModuleExports();
	tFuncNode GetModuleExport(const char* szModule, const char* szExportName);
	void SetPCTrace(const char* szPCTraceFileOutPath, OnOpcodeCb cb = nullptr, bool bRVA = true, uintptr_t pASLR = 0, uintptr_t nICOffset = 0, uint32_t nAnyJmpMode = 0, bool bDisasm = true);
	void SetPCTraceFull(const char* szPCTraceFileOutPath, OnOpcodeCb cb = nullptr, bool bRVA = true, uintptr_t pASLR = 0, uintptr_t nICOffset = 0, uint32_t nAnyJmpMode = 0, bool bDisasm = true,
		bool bRead = true, bool bWrite = true, bool bValNotice = true, bool bSym = true, bool bShortFmt = false, bool bDisasmRW = true);
	void ComparePCTrace(const char* szPCTraceA, const char* szPCTraceB, bool bAll, const char* szOutFileCompare = nullptr); // лучше юзай WinMerge
	bool CompressDiffs(std::vector<std::string> files, std::string outFile);
	bool RunCurrentPC(uintptr_t nStepsDeep, bool bSeh = true);
	bool TryRun(uintptr_t pEntry, uintptr_t nStepsDeep = 0, bool bSeh = true); // 0 - unlim
	bool Run(uintptr_t pEntry, uintptr_t nStepsDeep = 0, bool bSeh = true); // 0 - unlim
	bool RunOnly(uintptr_t pEntry, uintptr_t nStepsDeep, bool bSeh); // 0 - unlim
	void Pause();
	void Resume();
	void Stop();
	void Restart();
	void B(intptr_t nOps); // -2 +2 b branch like mips, update eip, manual jmp // pause, eip, Resume?
	void TraceInstruction(const char* szTraceFileOutPath, uintptr_t pStart, uint32_t nMaxCount = 0, TraceCb cb = nullptr, bool bPCArray = false); // 0 until end, cb can null autofalse
	void DumpRegisters(bool bFull = true); // and flags
	void DumpSegmentRegisters();
	void DumpFlags();
	bool GetFlag(eFlags flag);
	void SetFlag(eFlags flag, bool value);
	void DumpStack(intptr_t nCount = -1, bool bValNotice = true);
	std::string FormatRWHistoryLine(const tRWHistory& h, bool bValNotice, bool bRVA, bool bSym, bool bShortFmt, bool bDisasm);
	void DumpRWHistory(uintptr_t nLimSize = 0, bool bStartLim = false, bool bRead = true, bool bWrite = true, bool bValNotice = true, bool bRVA = true, bool bSym = true, bool bShortFmt = false, bool bDisasm = true);
	void DumpRWHistoryFile(std::string fName, uintptr_t nLimSize = 0, bool bStartLim = false, bool bRead = true, bool bWrite = true, bool bValNotice = true, bool bRVA = true, bool bSym = true, bool bShortFmt = false, bool bDisasm = true);
	void DumpRWHistorySelfModifying(uintptr_t pTextSec, uintptr_t pTextSecEnd);
	void ClearRWHistory();
	void AddDeadzoneIC(uintptr_t startIC, uintptr_t endIC, bool checkPC = true, bool showEnterMessage = true, bool skipAll = true, bool skipJmps = true, bool skipMem = true, bool skipOpcode = true, bool skipTrace = true, bool skipHistory = true);
	void InstallDangerNativeCoreFixes();
	void InstallDefaultHooks(HookNotifyCb cb);
	bool ParseModuleSections();
	void Dump();

	// Disasm (Capstone, Zydis) // if not InitialiseSymMap default disasm, else macro
	void InitialiseSymMap(const char* szPath, uintptr_t nSymASLR = 0); // ppsspp sym map like // fmt: 0xptr NAME // example [0x60F2F0DA] 0x126FDF68: call 0x1288231E  [0x60F2F0DA] 0x126FDF68: call FUNC_23
	tFuncNode* FindSymbolByRuntime(uintptr_t rtAddr);
	std::string GetSectionNameByRuntimeAddress(uintptr_t rtAddr);
	tFuncNode* GetSymByName(const char* szName);
	tFuncNode* GetSymByAddr(uintptr_t pAddr);
	std::string DisassembleWithZydis(bool bLog = false);
	std::string DisassembleWithCapstone(bool bLog = false);

	// точки останова: addr info
	struct tBpInfo
	{
		uint32_t size = 1;
		eBpType type = BP_CODE;
		OnOpcodeCb opcodeCb = nullptr;
		OnMemCb memCb = nullptr;
		void* data = nullptr;
		// TODO:? OnOpcodeCb OnMemCb condCb, это можно фильтровать просто в самих калбеках

		inline bool UseRange() { return size > 1; }
	};
	void SetBreakpointCode(uintptr_t pAddr, OnOpcodeCb cb, void* data = nullptr, uint32_t size = 1);
#ifdef AR_BP_RANGE
	void SetBreakpointRangeCode(uintptr_t pStart, uintptr_t pEnd, OnOpcodeCb cb, void* data = nullptr/*, uint32_t size = 1*/);
#endif
	void SetBreakpointMem(uintptr_t pAddr, uint32_t size, eBpType type, OnMemCb cb, void* data = nullptr);
#ifdef AR_BP_RANGE
	void SetBreakpointRangeMem(uintptr_t pStart, uintptr_t pEnd, uint32_t size, eBpType type, OnMemCb cb, void* data = nullptr);
#endif
	void RemoveBreakpoint(uintptr_t pAddr);
	tBpInfo* FindBreakpoint(uintptr_t pAddr, bool bCheckRange, uintptr_t& outBpAddr);
	bool AdjustBreakpointCodeRangeAt(uintptr_t pAtRt); // 4 runtime exec flow range brute // !! very carefully with big tolerance!!
	void DumpAllBreakpoints(void);

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
	static FILE* FileOpen(const char* filename, const char* mode = "w");
	static size_t FileSize(FILE* file);
	static size_t FileRead(FILE* file, void* pb, size_t sz);
	static void FileWrite(FILE* file, void* pb, size_t sz);
	static void FileAdd(FILE* file, const char* fmt, ...);
	static void FileClose(FILE* file);

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

#ifdef AR_DFT
	// One node in the data-flow tracking tree.
	// Each node = state of a tracked operand after the instruction stored in `disasm`.
	// Root node has no instruction (initial tracking start).
	struct tDataTraceNode
	{
		tDataTraceNode* parent = nullptr;
		std::vector<tDataTraceNode*> children;

		enum class eKind : uint8_t { Reg, Mem } kind = eKind::Reg;
		ZydisRegister reg = ZYDIS_REGISTER_NONE; // canonical; valid when kind==Reg
		uintptr_t     ptr = 0;                   // base address;  valid when kind==Mem
		uint32_t      opSz = 0;                   // operand size in bytes

		// instruction that created/modified this node
		std::string disasm;
		uintptr_t   instrAddr = 0;
		uint64_t    ic = 0;

		// value of the operand before / after the instruction
		uintptr_t            valBefore = 0;
		uintptr_t            valAfter = 0;
		std::vector<uint8_t> dataBytesBefore; // raw mem bytes (Mem kind)
		std::vector<uint8_t> dataBytesAfter;  // raw mem bytes (Mem kind)

		bool bActive = true;  // false = invalidated or replaced by a child
		bool bNeedAfter = false; // true  = valAfter not yet filled (filled next step)
	};

	using DataTraceHandle = uint32_t;

	// Comparator used by SaveDataTrace for filtering branches.
	using DTCompCB = std::function<bool(const tDataTraceNode*)>;

	struct tDataTrace
	{
		DataTraceHandle id = 0;
		bool            active = false;
		std::vector<std::unique_ptr<tDataTraceNode>> pool; // owns all nodes
		tDataTraceNode* root = nullptr;
		std::vector<tDataTraceNode*> activeLeaves; // currently monitored leaves
	};

	// Resolved operand used during _OnOpcodeOperands dispatch
	struct tDTResolvedOp
	{
		ZydisOperandType type = ZYDIS_OPERAND_TYPE_UNUSED;
		ZydisRegister    reg = ZYDIS_REGISTER_NONE; // canonical
		uintptr_t        addr = 0;                   // effective address (Mem)
		uint32_t         sz = 0;                   // size in bytes
		uintptr_t        val = 0;                   // current value (before exec)
		std::vector<uint8_t> bytes;                  // raw bytes (Mem)
	};

	// Data trace build a data-flow tree from a seed register or memory region.
	// Each branch in the tree is one propagation path of the original value.
	DataTraceHandle StartDataTrace(uint32_t reg);                  // ZydisRegister seed
	DataTraceHandle StartDataTrace(uintptr_t ptr, uintptr_t size); // memory seed
	// Save every branch as a separate file inside `dir` (created if absent).
	void SaveDataTrace(DataTraceHandle h, const char* dir);
	// Save only branches that satisfy `cb`; cb==null saves all.
	// bEndsWith=false: any node in the path matches cb save branch
	// bEndsWith=true : only the last node (leaf) matches save branch
	void SaveDataTrace(DataTraceHandle h, const char* dir, DTCompCB cb, bool bEndsWith);
	void RemoveDataTrace(DataTraceHandle h);
	// TODO: проверить eaxnode nKey = *(pStaticSbox + eaxnode) станет ли nKey node !!!!!!!!!!!!!!


	// data trace helpers
	inline ZydisRegister _CanonicalReg(ZydisRegister reg) const {
		return ZydisRegisterGetLargestEnclosing(m_bX64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32, reg);
	}
	// Called once per instruction step for any active DataTrace.
	// dst/src are resolved visible operands; instr/operands needed for addr-index heuristic.
	void _OnOpcodeOperands(uc_engine* uc, uintptr_t curPc, uint64_t ic,
		const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* operands,
		const std::vector<tDTResolvedOp>& dst, const std::vector<tDTResolvedOp>& src,
		const std::string& disasm);
	// Fill valAfter for all nodes that were created in the previous step.
	void _FillPendingAfterValues(uc_engine* uc);
	// Read the current value (and optionally raw bytes) of a node's operand.
	bool _ReadNodeCurrentValue(uc_engine* uc, const tDataTraceNode* node,
		uintptr_t& outVal, std::vector<uint8_t>* outBytes = nullptr) const;
	// Allocate a new node, add it to the pool, and wire parent link.
	tDataTraceNode* _AllocNode(tDataTrace& dt, tDataTraceNode* parent);
	// Recursively collect root leaf paths.
	static void _CollectBranches(tDataTraceNode* node,
		std::vector<tDataTraceNode*>& cur,
		std::vector<std::vector<tDataTraceNode*>>& out);
	// Write one branch path to an open file.
	void _SaveBranch(FILE* f, const std::vector<tDataTraceNode*>& path) const;
	tDataTrace* _FindDataTrace(DataTraceHandle h);

	std::vector<tDataTrace> m_dataTraces;
	uint32_t m_nextDataTraceId = 1;
	std::vector<tDataTraceNode*> m_pendingAfterNodes; // nodes awaiting valAfter fill
#endif

	// Others
	struct tScanPatternNode
	{
		std::vector<uint8_t> bytesAsm;
		int32_t type = 0;
	};

	struct tScanNeed
	{
		int32_t type = 0;
		size_t count = 0;
	};

	struct tScanWindowResult
	{
		uintptr_t address = 0;
		std::vector<size_t> counts;
	};
	static std::vector<tScanWindowResult> ScanWindow(uintptr_t pStart, uintptr_t pEnd, std::vector<tScanPatternNode> patterns,
		const std::vector<tScanNeed>& need, uintptr_t nWindowSize, bool bAdjustWindow, bool bDisplayProgress);

	//static void TestScanA(uintptr_t pStart, uintptr_t pEnd, uintptr_t pOffset);
	//static void TestScanB(uintptr_t pStart, uintptr_t pEnd, uintptr_t pOffset);
	static std::vector<uintptr_t> TestScanC(uintptr_t pStart, uintptr_t pEnd, uintptr_t pOffset);
	static void TestScanD(uintptr_t pStart, uintptr_t pEnd, uintptr_t pOffset, std::vector<uintptr_t>& outVMEntries, std::vector<uintptr_t>& outVMExits);

	template <typename T>
	T ReadMemory(uintptr_t pAddr)
	{
		static_assert(std::is_trivially_copyable_v<T>,
			"ReadMemory<T> requires trivially copyable T");

		T result{};

		if (!m_uc || !pAddr)
			return result;

		if (uc_mem_read(m_uc, pAddr, &result, sizeof(T)) != UC_ERR_OK)
		{
			if (m_bLogRunner)
				Log("ReadMemory: read failed at 0x%p, size=%zu", (void*)pAddr, sizeof(T));
			return result;
		}

		return result;
	}

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

	template<typename T>
	static std::string formatWithSeparator(T value, size_t group = 0)
	{
		static_assert(std::is_integral<T>::value, "formatWithSeparator requires integral type");

		std::string s = std::to_string(value);

		if (group == 0)
			return s;

		const bool neg = !s.empty() && s[0] == '-';
		size_t begin = neg ? 1 : 0;

		for (size_t i = s.length(); i > begin + group; i -= group)
			s.insert(i - group, 1, '\'');

		return s;
	}

	// Native
	template<typename T> void* WriteNT(void* address, T value, int offset = 0)
	{
		if (address == nullptr) {
			if (m_bLogRunner)
				Log("Write: Incorrect address.");

			return nullptr;
		}

		uintptr_t new_address = reinterpret_cast<uintptr_t>(address) + offset;

		DWORD oldProtect;
		if (!VirtualProtect(reinterpret_cast<void*>(new_address), sizeof(T), PAGE_READWRITE, &oldProtect)) {
			if (m_bLogRunner)
				Log("Write: Erorr while calling VirtualProtect.");
			return nullptr;
		}

		memcpy(reinterpret_cast<void*>(new_address), &value, sizeof(T));

		VirtualProtect(reinterpret_cast<void*>(new_address), sizeof(T), oldProtect, &oldProtect);

		return reinterpret_cast<void*>(new_address + sizeof(T));
	}

	template<typename T> bool CheckNT(void* address, T value, int offset = 0)
	{
		if (!address)
			return false;

		return *(T*)&((unsigned char*)address)[offset] == value;
	}

private:
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
		std::string funcname = "";
		struct tJmpCBArgs
		{
			uintptr_t from = 0;
			uintptr_t to = 0;
			uint32_t size = 0;
			ZydisMnemonic mnemonic = ZYDIS_MNEMONIC_INVALID;
			bool bIsCondMn = false;
			bool bCond = false;
			bool bIsInvMn = false;
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
		uintptr_t lastanyjmpinstrcount;
		uint32_t anyjmpmode; // 0 disable(default full trace), 1 ajfrom, 2 ajto, 3 ajfull
		OnOpcodeCb cb;
		bool rva;
		bool disasm;
		bool inited;

		struct tRWHistoryArgs
		{
			bool bUseRWHistory;
			bool bRead;
			bool bWrite;
			bool bValNotice;
			bool bSym;
			bool bShortFmt;
			bool bDisasm;
		} rwhistory;
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
		bool showEnterMessage; // Показать окно входа в dz (предупреждение что не будут работать почти все калбеки)
		bool skipJmps;         // Пропускать JMP колбэки
		bool skipMem;          // Пропускать MEM колбэки
		bool skipOpcode;       // Пропускать Opcode колбэки
		bool skipAll;          // Пропустить всё
		bool skipTrace;        // Пропустить трасировку (OpcodeCB)
		bool skipHistory;      // Пропустить историю (MemCB)
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

	struct tInsnHookNode
	{
		uintptr_t nInsn = 0;
		uc_hook hk = 0;
		OnInsnCb cb = nullptr;
		void* data = nullptr;
		AsmRunner* owner = nullptr; // stable back-reference for trampoline
	};

	struct tSection
	{
		std::string name;
		uintptr_t rva = 0;
		uintptr_t va = 0;
		uint32_t virtualSize = 0;
		uint32_t rawSize = 0;
		uint32_t rawPtr = 0;
		uint32_t characteristics = 0;
		bool readable = false;
		bool writable = false;
		bool executable = false;
	};

	struct tMemoryRange
	{
		tRange range;
		OnMemCb cbMem;
		void* cbMemData = nullptr;
	};

	uc_engine* m_uc = nullptr;
	bool m_bInitialised = false;
	bool m_bLogEnabled = true;
	bool m_bLogDisasm = false;
	bool m_bLogDisasmRawBytes = true;
	bool m_bLogDisasmSection = false; // manual parse + set true
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
	uintptr_t m_DisasmSepGroup = 0;
	bool m_bInitIAT = false;
	bool m_bSkipCBCallsWithNewPC = false;
	bool m_bRequestShutdown = false;
#ifdef AR_NTCORE_PATCH
	bool m_bNativeCorePatchInstalled = false;
#endif


	std::vector<tFuncNode> m_sym;
	std::vector<tAnyJmpHookNode> m_anyJmpHooks; // when any call smth from here
	std::vector<tFuncNode> m_iat;
	std::vector<tExecRegion> m_execRegions; // extra allowed no halt regions for execute
	std::map<uintptr_t, tFuncNode> exportsENV; // not unordered_map FindSymbolByRuntime upper_bound
	std::vector<tICNode> m_icHooks;
	std::vector<tDeadzoneIC> m_deadzonesIC;
	bool m_bInDeadzoneIC = false;
	int32_t m_currentDeadzoneICIndex = -1;
	std::vector<tRWHistory> m_RWHistory;
	bool m_bRWHistory = false;
	std::vector<tInsnHookNode> m_insnHooks;
	std::vector<tSection> m_sections;
	std::vector<uintptr_t> m_FlsSlots;

	uintptr_t m_iatStart = 0;
	uintptr_t m_iatEnd = 0;
	OnJmpCb m_cbIATCall; // when any call smth from m_iat
	void* m_cbIATCallData = nullptr;
	OnOpcodeCb m_cbSysCall; // syscall, int, ud2, etc
	void* m_cbSysCallData = nullptr;

	std::string m_modName = "";
	uintptr_t m_modStart = 0;
	uintptr_t m_modEnd = 0;

	uintptr_t m_stackBase = 0x00100000; // max esp
	uintptr_t m_stackSize = 0x00100000; // real base ebp (m_stackBase+m_stackSize)
	uintptr_t m_stackEPSize = 0x100; // m_bX64 ? 0x20 : 8
	uintptr_t m_allocBase = 0x20000000;
	uintptr_t m_allocCursor = 0x20000000;
	uintptr_t m_fsBase = 0; // 0x7FFDF000 0x000000007FFDF000 TEB normal when?? fs:/MSR TEB TB FS SEH PEB MSR_FS_BASE MSR IRP
	uintptr_t m_fsSize = 0;
	uintptr_t m_fsLastError = ERROR_SUCCESS; // TODO: move into fs:teb
	uintptr_t m_halt = 0x0; // 0x0 0x13371337 0xDEADBEEF
	uintptr_t m_lastPC = 0;
	std::vector<uint8_t> m_DebugCanarySecurityInitCookie;
	uintptr_t __security_cookie = 0;
	std::vector<uintptr_t> m_RestartICPoints;
	uintptr_t m_unhandledExceptionFilter = 0;

	uintptr_t m_instrCount = 0;
	uintptr_t m_nRunStepsDeep = 0;
	uc_hook m_hkCode = 0;
	uc_hook m_hkMem = 0;
	struct tMemMapEntry
	{
		uintptr_t size;
		uint32_t prot;
	};
	std::unordered_map<uintptr_t, tMemMapEntry> m_memMap; // addr -> {mapped_size, prot}

	uint64_t m_instructionsPerSecond = 0;
	uint64_t m_filetimeUnitsPerSecond = 10000000ULL;
	uint64_t m_gstftBaseFt64 = 0;      // база FILETIME на первом вызове GSTFT
	uint64_t m_gstftBaseIc = 0;        // IC на первом вызове GSTFT
	uint64_t m_gstftSleepDelta = 0;    // накопленное Sleep() в 100ns units
	bool m_gstftInited = false;

	OnOpcodeCb m_cbOpcode;
	void* m_cbOpcodeData = nullptr;
	OnMemCb m_cbMem;
	void* m_cbMemData = nullptr;
	OnJmpCb m_cbJmp;
	void* m_cbJmpData = nullptr;

	// флаги управления эмуляцией
	bool m_bPaused = false;
	bool m_bStopped = false;

	//std::unordered_map<uintptr_t, tBpInfo> m_breakpoints;
	std::map<uintptr_t, tBpInfo> m_breakpoints;
	bool m_bUsingBp = false;
	bool m_bUsingBpCodeSizeRange = false;

	tTraceState m_trace; // separate run
	tRTTrace m_rttrace; // default

	std::vector<tMemoryRange> m_memoryRangeCB;
	bool m_bUsingMemoryRangeCB = false;

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
	static void HookInsnTrampoline(uc_engine* uc, void* user_data);
	static bool IsAnyIpTransfer(ZydisMnemonic mn);
	static std::string AnyIpTransferTag(ZydisMnemonic mn);
	static bool IsSystem(ZydisMnemonic mn);
	static bool IsInsnAllowedZydis(ZydisMnemonic mn);
	static bool IsInsnAllowed(uintptr_t insn);
	bool ResolveFlagsConditional(ZydisMnemonic mn, bool& bOutCondMn, bool& bOutInvMn);
	bool TryResolveIpTransfer(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t curPc, uintptr_t& outTarget);
	bool ReadZydisRegisterValue(uc_engine* uc, ZydisRegister reg, uintptr_t& out) const;
	bool ResolveMemoryOperandAddress(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand& op, uintptr_t insnAddr, uintptr_t& outAddr) const;
	bool ResolveDirectBranchTarget(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t insnAddr, uintptr_t& outTarget) const;
	bool CopyModuleUC(uintptr_t real_base, uintptr_t emu_base, uintptr_t size);
	void UpdateDeadzoneIC(uintptr_t currentIC, uintptr_t address);
	tDeadzoneIC* GetCurrentDeadzoneIC();

	// внутренние колбэки Unicorn (static, this передаётся через user_data)
	void _OnInstructionStep(uc_engine* uc, uint64_t address, uint32_t size, void* user_data); // дизасм + user cb + брейкпоинты + трасировка
	bool _OnMemory(uc_engine* uc, uc_mem_type type, uint64_t address, uint32_t size, int64_t value, void* user_data); // лог rw + user cb + трасировка mem
	bool _OnInsn(tInsnHookNode* hook, uc_engine* uc);
	bool _OnAnyJmp(uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data); // jmp/call/ret детектируется в _OnInstructionStep
	bool _OnBreakpoint(const tBpInfo& bp, uc_engine* uc, uint64_t address, uint32_t size, void* user_data, bool bMemory, uc_mem_type type, int64_t value);
	void _OnTraceStep(uc_engine* uc, uintptr_t address, uint32_t sz); // запись шага трасировки в Tenet-файл

	// symbol helpers
	std::string FormatRuntimeAddressWithSymbol(uintptr_t rtAddr);
	std::string FormatCurrentSymbolSuffix(uintptr_t rtAddr);

	// more helpers
	void* SaveRunStateEnvImpl(uintptr_t& nOutSize, bool bIncludeModuleData, bool bIncludeAllocMap);
	void RunStateEnvLoadRegs(uc_engine* uc, bool bX64, const ArRegsBlob& r);
	ArRegsBlob RunStateEnvSaveRegs(uc_engine* uc, bool bX64);
	bool ReadBytes(uc_engine* uc, uint64_t address, uint32_t size, std::vector<uint8_t>& out) const;
	std::string RegName(uint32_t reg) const;
	bool IsInModule(uintptr_t addr) const;
	void TraceWriteLine(const std::string& s);
	std::string MakeDisasmLine(const uint8_t* bytes, size_t size, uintptr_t runtimeAddress, ZydisDecodedInstruction* instr, ZydisDecodedOperand* operands, bool& bResOK);
	bool DecodeOpcode(uc_engine* uc, ZydisDecodedInstruction* instr, ZydisDecodedOperand* operands);
	bool DecodeOpcode(const uint8_t* bytes, size_t size, ZydisDecodedInstruction* instr, ZydisDecodedOperand* operands);

	// exports / PE helpers
	static void TrimInPlace(std::string& s);
	static bool ParseHexPtr(const std::string& s, uintptr_t& out);
	bool LoadExportsFromBase(uintptr_t base, std::vector<tFuncNode>& out) const;
};

// TODO: RAII-обёртку для сегментов кода, Добавить поддержку относительных меток, 
namespace ArAsmCode
{
	enum class ImmWidth : uint8_t
	{
		Auto,
		I8,
		I16,
		I32,
		I64
	};

	struct Operand
	{
		enum class Kind : uint8_t
		{
			Reg,
			Imm,
			Mem,
			Ptr
		};

		Kind kind = Kind::Reg;

		ZydisRegister reg = ZYDIS_REGISTER_NONE;

		struct ImmOp
		{
			bool signedValue = false;
			ImmWidth width = ImmWidth::Auto;
			ZyanU64 u = 0;
			ZyanI64 s = 0;
		} imm;

		struct MemOp
		{
			ZydisRegister base = ZYDIS_REGISTER_NONE;
			ZydisRegister index = ZYDIS_REGISTER_NONE;
			ZyanU8 scale = 1;
			ZyanI64 displacement = 0;
			ZyanU16 size = 0; // bytes: 1/2/4/8
		} mem;

		struct PtrOp
		{
			ZyanU16 segment = 0;
			ZyanU32 offset = 0;
		} ptr;

		static Operand Reg(ZydisRegister r);

		template<typename T, typename std::enable_if_t<std::is_integral_v<T>, int> = 0>
		static Operand Imm(T v, ImmWidth width = ImmWidth::Auto)
		{
			Operand o;
			o.kind = Kind::Imm;
			o.imm.width = width;
			if constexpr (std::is_signed_v<T>)
			{
				o.imm.signedValue = true;
				o.imm.s = static_cast<ZyanI64>(v);
			}
			else
			{
				o.imm.signedValue = false;
				o.imm.u = static_cast<ZyanU64>(v);
			}
			return o;
		}

		static Operand Imm8(ZyanI64 v) { return Imm(v, ImmWidth::I8); }
		static Operand Imm16(ZyanI64 v) { return Imm(v, ImmWidth::I16); }
		static Operand Imm32(ZyanI64 v) { return Imm(v, ImmWidth::I32); }
		static Operand Imm64(ZyanI64 v) { return Imm(v, ImmWidth::I64); }

		static Operand UImm8(ZyanU64 v) { return Imm(v, ImmWidth::I8); }
		static Operand UImm16(ZyanU64 v) { return Imm(v, ImmWidth::I16); }
		static Operand UImm32(ZyanU64 v) { return Imm(v, ImmWidth::I32); }
		static Operand UImm64(ZyanU64 v) { return Imm(v, ImmWidth::I64); }

		static Operand Mem(ZydisRegister base = ZYDIS_REGISTER_NONE,
			ZydisRegister index = ZYDIS_REGISTER_NONE,
			ZyanU8 scale = 1,
			ZyanI64 displacement = 0,
			ZyanU16 size = 0);

		static Operand Ptr(ZyanU16 segment, ZyanU32 offset);
	};

	struct BuildOptions
	{
		ZydisAddressSizeHint address_size_hint = ZYDIS_ADDRESS_SIZE_HINT_NONE;
		ZydisOperandSizeHint operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_NONE;
		ZydisBranchType branch_type = ZYDIS_BRANCH_TYPE_NONE;
		ZydisBranchWidth branch_width = ZYDIS_BRANCH_WIDTH_NONE;
		ZydisInstructionAttributes prefixes = 0;
		ZydisEncodableEncoding allowed_encodings = ZYDIS_ENCODABLE_ENCODING_DEFAULT;
		ImmWidth force_imm_width = ImmWidth::Auto;
	};

	bool BuildAsm(std::vector<uint8_t>& bytes,
		ZydisMachineMode mode,
		ZydisMnemonic mnemonic,
		std::initializer_list<Operand> ops,
		const BuildOptions& options = BuildOptions{},
		ZyanU64 runtimeAddress = 0);

	inline bool BuildAsm86(std::vector<uint8_t>& bytes,
		ZydisMnemonic mnemonic,
		std::initializer_list<Operand> ops,
		const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm(bytes, ZYDIS_MACHINE_MODE_LEGACY_32, mnemonic, ops, options, 0);
	}

	inline bool BuildAsm86At(std::vector<uint8_t>& bytes,
		ZydisMnemonic mnemonic,
		std::initializer_list<Operand> ops,
		ZyanU64 runtimeAddress,
		const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm(bytes, ZYDIS_MACHINE_MODE_LEGACY_32, mnemonic, ops, options, runtimeAddress);
	}

	inline bool BuildAsm64(std::vector<uint8_t>& bytes,
		ZydisMnemonic mnemonic,
		std::initializer_list<Operand> ops,
		const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm(bytes, ZYDIS_MACHINE_MODE_LONG_64, mnemonic, ops, options, 0);
	}

	inline bool BuildAsm64At(std::vector<uint8_t>& bytes,
		ZydisMnemonic mnemonic,
		std::initializer_list<Operand> ops,
		ZyanU64 runtimeAddress,
		const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm(bytes, ZYDIS_MACHINE_MODE_LONG_64, mnemonic, ops, options, runtimeAddress);
	}

	inline bool BuildAsm86Op0(std::vector<uint8_t>& bytes, ZydisMnemonic mnemonic, const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm86(bytes, mnemonic, {}, options);
	}

	inline bool BuildAsm64Op0(std::vector<uint8_t>& bytes, ZydisMnemonic mnemonic, const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm64(bytes, mnemonic, {}, options);
	}

	inline bool BuildAsm86Op1(std::vector<uint8_t>& bytes, ZydisMnemonic mnemonic, Operand a, const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm86(bytes, mnemonic, { a }, options);
	}

	inline bool BuildAsm64Op1(std::vector<uint8_t>& bytes, ZydisMnemonic mnemonic, Operand a, const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm64(bytes, mnemonic, { a }, options);
	}

	inline bool BuildAsm86Op2(std::vector<uint8_t>& bytes, ZydisMnemonic mnemonic, Operand a, Operand b, const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm86(bytes, mnemonic, { a, b }, options);
	}

	inline bool BuildAsm64Op2(std::vector<uint8_t>& bytes, ZydisMnemonic mnemonic, Operand a, Operand b, const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm64(bytes, mnemonic, { a, b }, options);
	}

	inline bool BuildAsm86Op3(std::vector<uint8_t>& bytes, ZydisMnemonic mnemonic, Operand a, Operand b, Operand c, const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm86(bytes, mnemonic, { a, b, c }, options);
	}

	inline bool BuildAsm64Op3(std::vector<uint8_t>& bytes, ZydisMnemonic mnemonic, Operand a, Operand b, Operand c, const BuildOptions& options = BuildOptions{})
	{
		return BuildAsm64(bytes, mnemonic, { a, b, c }, options);
	}
}

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
//Команда fs : [0] (обращение к памяти)
//Когда ты пишешь fs : [0] — это значит :
//"Возьми индекс из регистра FS, найди по нему дескриптор в GDT, достань оттуда базовый адрес, прибавь к нему смещение 0 и прочитай память"
//Тут 0 — это СМЕЩЕНИЕ относительно базового адреса TEB.

//; Запрос function_id = 1
//mov eax, 1; В EAX - вопрос к процессору
//cpuid; Выполняем инструкцию
//; Результат:
//; EAX - информация о версии
//; EBX - дополнительная информация
//; ECX - флаги возможностей(бит 31 здесь!)
//; EDX - флаги возможностей
//
//; Проверка 31 - го бита в ECX
//test ecx, 80000000h; 80000000h = бит 31
//jnz hypervisor_found

// Themida Research Notes
//https://github.com/stuxnet147/Themida-Research
// читает в vmentry байты из кучи вне модуля правильной crc
// нет dispatcher, flow exec последовательный, в каждом handler в конце идёт декодер + джам на следующий handler (dispatch loop unroll)
// crc проверяет так: читает правильный crc из boot, virtualalloc(ctrlsectionsz) rep movsb секции, считает checksum, virtualfree kernel32
// MZ_VM_conditional_jump_handler___virtual_machine_jcc_handler_if_branch количество их в билде неограниченное // https://back.engineering/blog/09/05/2026/
// jcc(.themida) (разные константы && (v1 & 0x40) == 0) всегда v5 = (unsigned __int16)(v1 & 0x800) >> 11; v1 = (unsigned __int8)(v1 & 0x80) >> 7;
// возможно помимо CRC .boot ещё замеряет perfomance для GetSystemTimeAsFileTime и ложит в VM_CONTEXT

// links
//https://www.youtube.com/watch?v=hOFfR2APbyk
//https://github.com/colby57/VMP-Imports-Deobfuscator
//https://github.com/KuNgia09/vmp3-import-fix
//https://github.com/pulpgit/Themida-Imports-Deobfuscator-main/tree/84e8edf96a2b8a9134bf40c97ad94e8cb558ff16
//https://github.com/stuxnet147/Themida-Research
//https://back.engineering/blog/09/05/2026/
//https://github.com/MMaZaHaKa/awesome_anti_virus_engine
//https://github.com/gmh5225/awesome-game-security/tree/1f857416ca85858759eb44da277bf070046498b0
//https://github.com/samshine/VoyagerWithEPT
//https://github.com/thpatch/thcrap/blob/af5b5e190493887258a64affba7ec220c892e7a6/thcrap/src/ntdll.h
//https://github.com/jyotidwi/Vmprotect-VMP/blob/94ff35398868c7c5890e494971be404ca659e7e5/runtime/loader.cc
//
//https://github.com/unicorn-engine/unicorn
//https://github.com/DarthTon/Blackbone
//https://github.com/archercreat/vmpfix
//https://github.com/NtQuery/Scylla
//https://github.com/zyantific/zydis
//https://github.com/gabime/spdlog