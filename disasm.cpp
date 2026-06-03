#include "disasm.h"
#include <Windows.h>
#include <psapi.h>
#include <winnt.h>
#include <cassert>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <array>

#pragma comment(lib, "psapi.lib")

#ifdef _M_X64
static constexpr bool kBuild64 = true;
#else
static constexpr bool kBuild64 = false;
#endif

AsmRunner::AsmRunner(bool bX64)
{
    //m_bX64 = (sizeof(void*) == 8);
    //m_bX64 = kBuild64;
    m_bX64 = bX64;
}

AsmRunner::~AsmRunner()
{
    Shutdown();
}

void AsmRunner::Log(const char* fmt, ...) const
{
    if (!m_bLogEnabled) return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stdout, fmt, ap);
    std::fputc('\n', stdout);
    va_end(ap);
}

void AsmRunner::HookCodeTrampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    auto* self = static_cast<AsmRunner*>(user_data);
    if (self) self->_OnInstructionStep(uc, address, size, user_data);
}

bool AsmRunner::HookMemTrampoline(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
    auto* self = static_cast<AsmRunner*>(user_data);
    if (!self) return false;
    return self->_OnMemory(uc, type, address, size, value, user_data);
}

bool AsmRunner::IsAnyIpTransfer(ZydisMnemonic mn)
{
    switch (mn)
    {
        // Прямые переходы / вызовы
        case ZYDIS_MNEMONIC_CALL:
        case ZYDIS_MNEMONIC_JMP:

        // Условные переходы
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JZ:

        // Счётчик/цикл
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_JKNZD:
        case ZYDIS_MNEMONIC_JKZD:
        case ZYDIS_MNEMONIC_LOOP:
        case ZYDIS_MNEMONIC_LOOPE:
        case ZYDIS_MNEMONIC_LOOPNE:

        // Возвраты
        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
        case ZYDIS_MNEMONIC_IRETQ:

        // Прерывания / системные переходы
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_INTO:
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
        case ZYDIS_MNEMONIC_SYSEXIT:
        case ZYDIS_MNEMONIC_SYSRET:
            return true;

        default:
            return false;
    }
}

bool AsmRunner::TryResolveIpTransfer(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t curPc, uintptr_t& outTarget)
{
    switch (instr.mnemonic)
    {
        case ZYDIS_MNEMONIC_CALL:
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_JKNZD:
        case ZYDIS_MNEMONIC_JKZD:
        case ZYDIS_MNEMONIC_LOOP:
        case ZYDIS_MNEMONIC_LOOPE:
        case ZYDIS_MNEMONIC_LOOPNE:
            return ResolveDirectBranchTarget(instr, ops, curPc, outTarget);

        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
        case ZYDIS_MNEMONIC_IRETQ:
        {
            uintptr_t sp = CurrentSp(uc);
            uintptr_t ret = 0;
            const size_t ptrSize = m_bX64 ? 8 : 4;

            if (uc_mem_read(uc, sp, &ret, ptrSize) == UC_ERR_OK)
            {
                if (!m_bX64)
                    ret = static_cast<uint32_t>(ret);

                outTarget = ret;
                return true;
            }
            return false;
        }

        default:
            return false;
    }
}

bool AsmRunner::CopyModuleUC(uintptr_t real_base, uintptr_t emu_base, uintptr_t size)
{
    if (!m_uc) return false;

    uintptr_t mapSize = AlignUp(size, 0x1000);
    if(m_bLogRunner)
        Log("[*] Copying module: 0x%p -> 0x%p (0x%zx bytes, mapped 0x%zx)", (void*)real_base, (void*)emu_base, static_cast<size_t>(size), static_cast<size_t>(mapSize));

    uc_err err = uc_mem_map(m_uc, emu_base, mapSize, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        if (m_bLogRunner)
            Log("[!] Memory mapping error: %s", uc_strerror(err));
        return false;
    }

    err = uc_mem_write(m_uc, emu_base, reinterpret_cast<void*>(real_base), size);
    if (err != UC_ERR_OK) {
        if (m_bLogRunner)
            Log("[!] Write to emulator error: %s", uc_strerror(err));
        return false;
    }

    if (m_bLogRunner)
    {
        Log("[+] Copied %zu bytes", static_cast<size_t>(size));
        Log("pStart: 0x%p", (void*)real_base);
        Log("Size:   0x%zx (%zu MB)", static_cast<size_t>(size), static_cast<size_t>(size / (1024 * 1024)));
    }

    return true;
}

void AsmRunner::Initialise(bool bLogDisasm, bool bLogMemRW, bool bLogAnyJmp, bool bLogRunner, bool bInitUC)
{
    m_bLogDisasm = bLogDisasm;
    m_bLogMemRW = bLogMemRW;
    m_bLogAnyJmp = bLogAnyJmp;
    m_bLogRunner = bLogRunner;

    if (m_bInitialised || m_uc) Shutdown();

    uc_mode uc_mode_val = m_bX64 ? UC_MODE_64 : UC_MODE_32;
    uc_err ucerr = uc_open(UC_ARCH_X86, uc_mode_val, &m_uc);
    if (ucerr != UC_ERR_OK) {
        Log("[!] Unicorn ошибка: %s", uc_strerror(ucerr));
        Shutdown();
        return;
    }

#ifdef CAPSTONE
    cs_err cerr = cs_open(CS_ARCH_X86, m_bX64 ? CS_MODE_64 : CS_MODE_32, &m_csHandle);
    if (cerr != CS_ERR_OK) {
        Log("[!] Capstone failed to open: %d (%s)", cerr, cs_strerror(cerr));
        Shutdown();
        return;
    }
#endif

#ifdef ZYDIS
    ZydisDecoderInit(&m_decoder,
        m_bX64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        m_bX64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    ZydisFormatterInit(&m_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
#endif

    if (bInitUC)
    {
        SetStack();
        SetFakeSehTid();
    }

    m_bInitialised = true;
    m_bPaused = false;
    m_bStopped = false;
    m_instrCount = 0;
    m_allocCursor = m_allocBase;

    if (m_bLogRunner) {
        Log("[*] AsmRunner initialised (%s)", m_bX64 ? "x64" : "x86");
    }
}

void AsmRunner::Shutdown()
{
    if (m_uc) {
        if (m_hkCode) {
            uc_hook_del(m_uc, m_hkCode);
            m_hkCode = 0;
        }
        if (m_hkMem) {
            uc_hook_del(m_uc, m_hkMem);
            m_hkMem = 0;
        }
        for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); ++it) {
            if (it->second.hook) {
                uc_hook_del(m_uc, it->second.hook);
                it->second.hook = 0;
            }
        }
        m_breakpoints.clear();

        uc_close(m_uc);
        m_uc = nullptr;
    }

#ifdef CAPSTONE
    if (m_csHandle) {
        cs_close(&m_csHandle);
        m_csHandle = 0;
    }
#endif

    if (m_trace.file.is_open()) {
        m_trace.file.close();
    }
    m_trace.active = false;
    m_trace.count = 0;
    m_trace.prevRegs.clear();

    m_bInitialised = false;
    m_bPaused = false;
    m_bStopped = false;
    m_bInitedStack = false;
    m_bInitedSehFS = false;
    m_bDisasmAfterCB = false;
    m_bDisasmRVA = false;
    m_DisasmCustomASLR = 0;
}

uc_engine* AsmRunner::GetCTX()
{
    assert(m_uc != nullptr);
    return m_uc;
}

uintptr_t AsmRunner::CurrentPc(uc_engine* uc) const
{
    uintptr_t v = 0;
    uc_reg_read(uc, PcReg(), &v);
    if (!m_bX64) v = static_cast<uint32_t>(v);
    return v;
}

uintptr_t AsmRunner::CurrentSp(uc_engine* uc) const
{
    uintptr_t v = 0;
    uc_reg_read(uc, SpReg(), &v);
    if (!m_bX64) v = static_cast<uint32_t>(v);
    return v;
}

std::string AsmRunner::RegName(uint32_t reg) const
{
    switch (reg) {
    case UC_X86_REG_EAX: return m_bX64 ? "RAX" : "EAX";
    case UC_X86_REG_EBX: return m_bX64 ? "RBX" : "EBX";
    case UC_X86_REG_ECX: return m_bX64 ? "RCX" : "ECX";
    case UC_X86_REG_EDX: return m_bX64 ? "RDX" : "EDX";
    case UC_X86_REG_ESI: return m_bX64 ? "RSI" : "ESI";
    case UC_X86_REG_EDI: return m_bX64 ? "RDI" : "EDI";
    case UC_X86_REG_ESP: return m_bX64 ? "RSP" : "ESP";
    case UC_X86_REG_EBP: return m_bX64 ? "RBP" : "EBP";
    case UC_X86_REG_EIP: return m_bX64 ? "RIP" : "EIP";
    case UC_X86_REG_RAX: return "RAX";
    case UC_X86_REG_RBX: return "RBX";
    case UC_X86_REG_RCX: return "RCX";
    case UC_X86_REG_RDX: return "RDX";
    case UC_X86_REG_RSI: return "RSI";
    case UC_X86_REG_RDI: return "RDI";
    case UC_X86_REG_RSP: return "RSP";
    case UC_X86_REG_RBP: return "RBP";
    case UC_X86_REG_RIP: return "RIP";
    default: break;
    }
    return "REG";
}

std::string AsmRunner::FormatRuntimeAddress(uintptr_t rtAddr) const
{
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << rtAddr;
    return oss.str();
}

const tFuncNode* AsmRunner::FindSymbolByRuntime(uintptr_t rtAddr) const
{
    if (m_sym.empty()) return nullptr;

    uintptr_t rel = rtAddr;
    if (m_modStart != 0 && rtAddr >= m_modStart) {
        rel = rtAddr - m_modStart;
    }

    auto it = std::upper_bound(
        m_sym.begin(), m_sym.end(), rel,
        [](uintptr_t value, const tFuncNode& e) { return value < e.rva; });

    if (it == m_sym.begin()) return nullptr;
    --it;

    if (it->size != 0) {
        if (rel >= it->rva && rel < it->rva + it->size) return &(*it);
    }
    else {
        if (rel == it->rva) return &(*it);
    }

    //uintptr_t start = it->rva;
    //uintptr_t end = UINTPTR_MAX;
    //auto next = std::next(it);
    //if (next != m_sym.end())
    //    end = next->rva;
    //else if (it->size != 0)
    //    end = start + it->size;

    //if (rel >= start && rel < end)
    //    return &(*it);

    return nullptr;
}

std::string AsmRunner::FormatRuntimeAddressWithSymbol(uintptr_t rtAddr) const
{
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << rtAddr;

    const tFuncNode* sym = FindSymbolByRuntime(rtAddr);
    if (sym) {
        uintptr_t rel = rtAddr;
        if (m_modStart != 0 && rtAddr >= m_modStart)
            rel = rtAddr - m_modStart;

        oss << " (" << sym->name;
        if (rel > sym->rva)
            oss << "+0x" << std::hex << std::uppercase << (rel - sym->rva);
        oss << ")";
    }

    return oss.str();
}

std::string AsmRunner::FormatCurrentSymbolSuffix(uintptr_t rtAddr) const
{
    const tFuncNode* sym = FindSymbolByRuntime(rtAddr);
    if (!sym)
        return std::string();

    uintptr_t rel = rtAddr;
    if (m_modStart != 0 && rtAddr >= m_modStart)
        rel = rtAddr - m_modStart;

    std::ostringstream oss;
    oss << sym->name;
    if (rel > sym->rva)
        oss << "+0x" << std::hex << std::uppercase << (rel - sym->rva);

    return oss.str();
}

bool AsmRunner::ResolveDirectBranchTarget(const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t insnAddr, uintptr_t& outTarget) const
{
    for (uint32_t i = 0; i < instr.operand_count_visible; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative) {
            outTarget = static_cast<uintptr_t>(insnAddr + instr.length + ops[i].imm.value.s);
            return true;
        }
    }
    return false;
}

bool AsmRunner::ReadBytes(uc_engine* uc, uint64_t address, uint32_t size, std::vector<uint8_t>& out) const
{
    out.resize(size);
    if (size == 0) return true;
    return uc_mem_read(uc, address, out.data(), size) == UC_ERR_OK;
}

bool AsmRunner::IsInModule(uintptr_t addr) const
{
    return (m_modStart != 0 && m_modEnd != 0 && addr >= m_modStart && addr < m_modEnd);
}

std::string AsmRunner::MakeDisasmLine(const uint8_t* bytes, size_t size, uintptr_t runtimeAddress)
{
#ifdef ZYDIS
    ZydisDecodedInstruction instr{};
    //ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder,
        bytes,
        static_cast<ZyanUSize>(size),
        &instr,
        operands))) {
        return "???";
    }

    char buffer[256] = {};
    ZydisFormatterFormatInstruction(&m_formatter,
        &instr,
        operands,
        instr.operand_count_visible,
        buffer,
        sizeof(buffer),
        static_cast<ZyanU64>(runtimeAddress),
        ZYAN_NULL);

    std::ostringstream oss;
    oss << buffer;

    if (instr.mnemonic == ZYDIS_MNEMONIC_CALL || instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
        uintptr_t target = 0;
        if (ResolveDirectBranchTarget(instr, operands, runtimeAddress, target)) {
            oss << " ; -> " << FormatRuntimeAddressWithSymbol(target);
        }
    }

    return oss.str();
#else
    (void)bytes;
    (void)size;
    (void)runtimeAddress;
    return "???";
#endif
}

void AsmRunner::DisassembleWithZydis()
{
    if (!m_uc) return;

    uintptr_t pc = CurrentPc(m_uc);
    std::array<uint8_t, 16> bytes{};
    if (uc_mem_read(m_uc, pc, bytes.data(), bytes.size()) != UC_ERR_OK) {
        Log("[DISASM] 0x%p: [READ ERROR]", (void*)(m_bDisasmRVA ? (pc - m_modStart + m_DisasmCustomASLR) : pc));
        return;
    }

    std::string s = MakeDisasmLine(bytes.data(), bytes.size(), pc);
    Log("[DISASM] 0x%p (%s): %s", (void*)(m_bDisasmRVA ? (pc - m_modStart + m_DisasmCustomASLR) : pc), FormatRuntimeAddressWithSymbol(pc).c_str(), s.c_str());
}

void AsmRunner::DisassembleWithCapstone()
{
#ifdef CAPSTONE
    if (!m_uc) return;

    uintptr_t pc = CurrentPc(m_uc);
    std::array<uint8_t, 16> bytes{};
    if (uc_mem_read(m_uc, pc, bytes.data(), bytes.size()) != UC_ERR_OK) {
        Log("[DISASM] 0x%p: [READ ERROR]", (void*)pc);
        return;
    }

    cs_insn* insn = nullptr;
    if (cs_disasm(m_csHandle, bytes.data(), bytes.size(), pc, 1, &insn) > 0) {
        Log("[DISASM] 0x%p: %s %s", (void*)pc, insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, 1);
    }
    else {
        Log("[DISASM] 0x%p: ???", (void*)pc);
    }
#else
    Log("[DISASM] Capstone not compiled in");
#endif
}

void AsmRunner::_OnInstructionStep(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    (void)user_data;
    ++m_instrCount;

    uintptr_t curPc = static_cast<uintptr_t>(address);
    if (!m_bX64)
        curPc = static_cast<uint32_t>(curPc);

    if (m_modStart != 0 && m_modEnd != 0) {
        uintptr_t pc = CurrentPc(uc);
        if (pc < m_modStart || pc >= m_modEnd) {
            if(m_bLogRunner && !IsRetHaltOrNull(pc))
                Log("\n[!] %s (0x%p) out of bounds [0x%p - 0x%p]", m_bX64 ? "RIP" : "EIP", (void*)pc, (void*)m_modStart, (void*)m_modEnd);
            uc_emu_stop(uc);
            return;
        }
    }

    std::vector<uint8_t> bytes;
    bool readOk = ReadBytes(uc, address, size, bytes);

    std::string disasm = readOk ? MakeDisasmLine(bytes.data(), bytes.size(), curPc) : "[READ ERROR]";
    std::string curSym = FormatCurrentSymbolSuffix(curPc);

    //if (m_bLogDisasm /*|| m_bLogRunner*/) {
    //    std::ostringstream oss;
    //    oss << "[" << m_instrCount << "] ";
    //    oss << "0x" << std::hex << std::uppercase << curPc;
    //    oss << ": " << disasm;
    //    //if (!curSym.empty())
    //    //    oss << " ; " << curSym;
    //    if (!curSym.empty()) {
    //        constexpr size_t kSymFieldWidth = 70;
    //        oss << " ; " << std::setw(static_cast<int>(kSymFieldWidth))
    //            << std::right << curSym;
    //    }
    //    Log("%s", oss.str().c_str());
    //}

    if (!m_bDisasmAfterCB && (m_bLogDisasm /*|| m_bLogRunner*/)) {
        std::ostringstream oss;
        oss << "[" << m_instrCount << "] ";
        if(m_bDisasmRVA)
            oss << "0x" << std::hex << std::uppercase << (curPc - m_modStart + m_DisasmCustomASLR);
        else
            oss << "0x" << std::hex << std::uppercase << curPc;
        oss << ": " << disasm;

        std::string line = oss.str();

        constexpr size_t kSymbolColumn = 70;
        if (line.size() < kSymbolColumn) {
            line += std::string(kSymbolColumn - line.size(), ' ');
        }
        else {
            line += "  ";
        }

        if (!curSym.empty())
            line += "; " + curSym;

        Log("%s", line.c_str());
    }

    if (m_trace.active) {
        _OnTraceStep(uc, curPc, size);
        ++m_trace.count;
        if (m_trace.maxCount && m_trace.count >= m_trace.maxCount) {
            uc_emu_stop(uc);
            return;
        }
        if (m_trace.cbStop) {
            if (!m_trace.cbStop(uc, curPc, m_trace.count, nullptr)) {
                uc_emu_stop(uc);
                return;
            }
        }
    }

    ZydisMnemonic mnemonic = ZYDIS_MNEMONIC_INVALID;

#ifdef ZYDIS
    ZydisDecodedInstruction instr{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

    if (readOk && !bytes.empty()) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder,
            bytes.data(),
            static_cast<ZyanUSize>(bytes.size()),
            &instr,
            operands)))
        {
            mnemonic = instr.mnemonic;
        }
    }
#endif

    if (m_cbOpcode) {
        if (!m_cbOpcode(uc, curPc, size, mnemonic, m_cbOpcodeData)) {
            uc_emu_stop(uc);
            return;
        }
    }

#ifdef ZYDIS
    if (readOk && bytes.size() >= 1) {
        ZydisDecodedInstruction instr{};
        //ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder, bytes.data(), static_cast<ZyanUSize>(bytes.size()), &instr, operands)))
        {
#if 0 // old, 3 jmp instr
            uintptr_t target = 0;
            bool hasTarget = false;

            if (instr.mnemonic == ZYDIS_MNEMONIC_CALL || instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
                hasTarget = ResolveDirectBranchTarget(instr, operands, curPc, target);
            }
            else if (instr.mnemonic == ZYDIS_MNEMONIC_RET) {
                uintptr_t sp = CurrentSp(uc);
                uintptr_t ret = 0;
                if (uc_mem_read(uc, sp, &ret, m_bX64 ? 8 : 4) == UC_ERR_OK) {
                    if (!m_bX64)
                        ret = static_cast<uint32_t>(ret);
                    target = ret;
                    hasTarget = true;
                }
            }

            if (hasTarget) {
                _OnAnyJmp(uc, curPc, target, instr.mnemonic);
                if (m_cbJmp) {
                    if (!m_cbJmp(uc, curPc, target, instr.mnemonic, m_cbJmpData)) {
                        uc_emu_stop(uc);
                        return;
                    }
                }
            }
#endif

            uintptr_t target = 0;

            if (IsAnyIpTransfer(instr.mnemonic) &&
                TryResolveIpTransfer(uc, instr, operands, curPc, target))
            {
                _OnAnyJmp(uc, curPc, target, instr.mnemonic);

                if (m_cbJmp) {
                    if (!m_cbJmp(uc, curPc, target, instr.mnemonic, m_cbJmpData)) {
                        uc_emu_stop(uc);
                        return;
                    }
                }
            }
        }
        else {
            Log("[Zydis] mn=%u len=%u opcnt=%u", instr.mnemonic, instr.length, instr.operand_count_visible);
        }
    }
#endif

    if (m_bDisasmAfterCB && (m_bLogDisasm /*|| m_bLogRunner*/)) {
        std::ostringstream oss;
        oss << "[" << m_instrCount << "] ";
        if (m_bDisasmRVA)
            oss << "0x" << std::hex << std::uppercase << (curPc - m_modStart + m_DisasmCustomASLR);
        else
            oss << "0x" << std::hex << std::uppercase << curPc;
        oss << ": " << disasm;

        std::string line = oss.str();

        constexpr size_t kSymbolColumn = 70;
        if (line.size() < kSymbolColumn) {
            line += std::string(kSymbolColumn - line.size(), ' ');
        }
        else {
            line += "  ";
        }

        if (!curSym.empty())
            line += "; " + curSym;

        Log("%s", line.c_str());
    }

    uintptr_t pcAfter = CurrentPc(uc);
    if (m_modStart != 0 && m_modEnd != 0 && (pcAfter < m_modStart || pcAfter >= m_modEnd)) {
        if (m_bLogRunner && !IsRetHaltOrNull(pcAfter))
            Log("[!] %s (0x%p) out of bounds [0x%p - 0x%p]", m_bX64 ? "RIP" : "EIP", (void*)pcAfter, (void*)m_modStart, (void*)m_modEnd);
        uc_emu_stop(uc);
    }
}

bool AsmRunner::_OnMemory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
    (void)user_data;
    uintptr_t addr = static_cast<uintptr_t>(address);
    uintptr_t sz = static_cast<uintptr_t>(size);

    bool isWrite = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT);
    bool isRead = (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT);

    ZydisMnemonic mnemonic = ZYDIS_MNEMONIC_INVALID;

#ifdef ZYDIS
    {
        uintptr_t pc = CurrentPc(uc);
        std::array<uint8_t, 16> bytes{};
        if (uc_mem_read(uc, pc, bytes.data(), bytes.size()) == UC_ERR_OK) {
            ZydisDecodedInstruction instr{};
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder,
                bytes.data(),
                static_cast<ZyanUSize>(bytes.size()),
                &instr,
                operands)))
            {
                mnemonic = instr.mnemonic;
            }
        }
    }
#endif

    for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); ++it) {
        tBpInfo& bp = it->second;
        if (bp.type == BP_CODE) continue;

        bool hit = false;
        if (bp.type == BP_MEM_READ && isRead) hit = (addr >= it->first && addr < it->first + bp.size);
        if (bp.type == BP_MEM_WRITE && isWrite) hit = (addr >= it->first && addr < it->first + bp.size);
        if (bp.type == BP_MEM_RW && (isRead || isWrite)) hit = (addr >= it->first && addr < it->first + bp.size);

        if (hit) {
            _OnBreakpoint(uc, addr);
            if (bp.cb) {
                if (!bp.cb(uc, addr, bp.data)) {
                    uc_emu_stop(uc);
                    return false;
                }
            }
            else if (m_cbBreak) {
                if (!m_cbBreak(uc, addr, m_cbBreakData)) {
                    uc_emu_stop(uc);
                    return false;
                }
            }
            break;
        }
    }

    if (m_bLogMemRW /*|| m_bLogRunner*/) {
        const char* typeStr =
            type == UC_MEM_READ ? "READ" :
            type == UC_MEM_WRITE ? "WRITE" :
            type == UC_MEM_FETCH ? "FETCH" :
            type == UC_MEM_READ_UNMAPPED ? "READ_UNMAPPED" :
            type == UC_MEM_WRITE_UNMAPPED ? "WRITE_UNMAPPED" :
            type == UC_MEM_FETCH_UNMAPPED ? "FETCH_UNMAPPED" :
            type == UC_MEM_READ_PROT ? "READ_PROT" :
            type == UC_MEM_WRITE_PROT ? "WRITE_PROT" :
            type == UC_MEM_FETCH_PROT ? "FETCH_PROT" : "MEM";

        std::ostringstream oss;
        oss << "[MEM] " << typeStr << " addr=0x" << std::hex << std::uppercase << addr << " size=" << std::dec << size;
        if (isWrite) {
            oss << " value=0x" << std::hex << std::uppercase << static_cast<uint64_t>(value);
        }
        Log("%s", oss.str().c_str());
    }

    if (m_trace.active && m_trace.file.is_open()) {
        std::ostringstream oss;
        oss << (isWrite ? "mw" : "mr") << " = 0x" << std::hex << std::uppercase << addr << " : ";

        if (isWrite) {
            uintptr_t v = static_cast<uintptr_t>(value);
            for (uintptr_t i = 0; i < static_cast<uintptr_t>(size); ++i) {
                uint8_t b = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
            }
        }
        else {
            std::vector<uint8_t> tmp(static_cast<size_t>(size));
            if (uc_mem_read(uc, address, tmp.data(), tmp.size()) == UC_ERR_OK) {
                for (uint8_t b : tmp) {
                    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                }
            }
        }

        m_trace.file << oss.str() << "\n";
    }

    if (m_cbMem) {
        if (!m_cbMem(uc, static_cast<int32_t>(type), addr, sz, static_cast<uintptr_t>(value), mnemonic, m_cbMemData)) {
            uc_emu_stop(uc);
            return false;
        }
    }

    return true;
}

void AsmRunner::_OnAnyJmp(uc_engine* uc, uintptr_t from, uintptr_t to, ZydisMnemonic mnemonic)
{
    (void)uc;
    if (m_bLogAnyJmp) {
        Log("[JMP] 0x%p -> 0x%p (%s -> %s) (%d)",
            (void*)from, (void*)to,
            FormatRuntimeAddressWithSymbol(from).c_str(),
            FormatRuntimeAddressWithSymbol(to).c_str(),
            mnemonic);
    }
}

void AsmRunner::_OnBreakpoint(uc_engine* uc, uintptr_t address)
{
    (void)uc;
    if (m_bLogRunner) {
        Log("[BP] hit at 0x%p (%s)", (void*)address, FormatRuntimeAddressWithSymbol(address).c_str());
    }
}

void AsmRunner::_OnTraceStep(uc_engine* uc, uintptr_t address, uint32_t sz)
{
    if (!m_trace.active || !m_trace.file.is_open()) return;

    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    oss << "eip = 0x" << address;

    const tFuncNode* sym = FindSymbolByRuntime(address);
    if (sym) {
        uintptr_t rel = address;
        if (m_modStart != 0 && address >= m_modStart) rel = address - m_modStart;
        oss << " ; " << sym->name;
        if (rel > sym->rva) oss << "+0x" << (rel - sym->rva);
    }

    oss << " ; sz=" << std::dec << sz;
    m_trace.file << oss.str() << "\n";

    const uint32_t regs[] = {
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_ESP, UC_X86_REG_EBP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP
    };

    for (size_t i = 0; i < sizeof(regs) / sizeof(regs[0]); ++i) {
        uint32_t reg = regs[i];
        if (m_bX64) {
            if (reg == UC_X86_REG_EAX || reg == UC_X86_REG_EBX || reg == UC_X86_REG_ECX || reg == UC_X86_REG_EDX ||
                reg == UC_X86_REG_ESI || reg == UC_X86_REG_EDI || reg == UC_X86_REG_ESP || reg == UC_X86_REG_EBP) {
                continue;
            }
        }
        else {
            if (reg == UC_X86_REG_RAX || reg == UC_X86_REG_RBX || reg == UC_X86_REG_RCX || reg == UC_X86_REG_RDX ||
                reg == UC_X86_REG_RSI || reg == UC_X86_REG_RDI || reg == UC_X86_REG_RSP || reg == UC_X86_REG_RBP) {
                continue;
            }
        }

        uintptr_t cur = 0;
        if (uc_reg_read(uc, reg, &cur) != UC_ERR_OK) continue;
        if (!m_bX64) cur = static_cast<uint32_t>(cur);

        int key = static_cast<int>(reg);
        std::map<int, uint64_t>::iterator it = m_trace.prevRegs.find(key);
        if (it == m_trace.prevRegs.end() || it->second != cur) {
            std::ostringstream r;
            r << RegName(reg) << " = 0x" << std::hex << std::uppercase << cur;
            m_trace.file << r.str() << "\n";
            m_trace.prevRegs[key] = cur;
        }
    }
}

uintptr_t AsmRunner::GetMappedModuleSizeByName(LPCSTR moduleName)
{
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        Log("[!] GetModuleHandle failed for '%s'. Error: %lu", moduleName ? moduleName : "(main)", GetLastError());
        return 0;
    }

    MODULEINFO moduleInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
        Log("[!] GetModuleInformation failed. Error: %lu", GetLastError());
        return 0;
    }
    return static_cast<uintptr_t>(moduleInfo.SizeOfImage);
}

bool AsmRunner::GetMappedModuleBounds(LPCSTR moduleName, uintptr_t& pOutStart, uintptr_t& pOutEnd, uintptr_t& nOutSize)
{
    pOutStart = 0;
    pOutEnd = 0;
    nOutSize = 0;

    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        Log("[!] GetMappedModuleBounds: GetModuleHandle failed for '%s'. Error: %lu", moduleName ? moduleName : "(main)", GetLastError());
        return false;
    }

    MODULEINFO moduleInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
        Log("[!] GetMappedModuleBounds: GetModuleInformation failed for '%s'. Error: %lu", moduleName ? moduleName : "(main)", GetLastError());
        return false;
    }

    pOutStart = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
    nOutSize = static_cast<uintptr_t>(moduleInfo.SizeOfImage);
    pOutEnd = pOutStart + nOutSize;
    return true;
}

void AsmRunner::DataToHexString(int indent, uintptr_t startAddr, const uint8_t* data, size_t size, std::string* output)
{
    if (!output) return;
    output->clear();
    if (!data || size == 0) return;

    const int addr_width = static_cast<int>(sizeof(uintptr_t) * 2);
    char buf[64];

    for (size_t i = 0; i < size; ++i) {
        if ((i % 16) == 0) {
            if (i != 0) {
                output->push_back(' ');
                size_t lineStart = i - 16;
                for (size_t j = lineStart; j < i; ++j) {
                    output->push_back(IsPrintableAscii(data[j]) ? static_cast<char>(data[j]) : '.');
                }
                output->push_back('\n');
            }
            if (indent > 0) output->append(static_cast<size_t>(indent), ' ');
            uintptr_t addr = startAddr + static_cast<uintptr_t>(i);
            std::ostringstream a;
            a << std::uppercase << std::hex << std::setw(addr_width) << std::setfill('0') << addr;
            output->append(a.str());
            output->append("  ");
        }
        std::snprintf(buf, sizeof(buf), "%02x ", data[i]);
        output->append(buf);
    }

    if (size & 15) {
        size_t padded_size = ((size - 1) | 15) + 1;
        for (size_t j = size; j < padded_size; ++j) output->append("   ");
    }

    output->push_back(' ');
    size_t base = (size - 1) & ~static_cast<size_t>(0xF);
    for (size_t j = base; j < size; ++j) {
        output->push_back(IsPrintableAscii(data[j]) ? static_cast<char>(data[j]) : '.');
    }
}

void AsmRunner::DataToHexString(int indent, uintptr_t startAddr, const uint8_t* data, size_t size,
    const uint16_t* byteColors, const uint16_t* asciiColors)
{
    if (!data || size == 0)
        return;

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    bool haveConsole = (hConsole != INVALID_HANDLE_VALUE) && GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD oldAttr = haveConsole ? csbi.wAttributes : (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    const WORD kWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    auto setColor = [&](WORD c)
    {
        if (haveConsole)
            SetConsoleTextAttribute(hConsole, c);
    };

    auto putStr = [&](const std::string& s)
    {
        std::cout << s;
    };

    auto putChar = [&](char c)
    {
        std::cout.put(c);
    };

    const int addr_width = static_cast<int>(sizeof(uintptr_t) * 2);
    char buf[64]{};

    for (size_t i = 0; i < size; ++i)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
            {
                setColor(kWhite);
                putStr(" ");

                size_t lineStart = i - 16;
                for (size_t j = lineStart; j < i; ++j)
                {
                    WORD c = (asciiColors && asciiColors[j]) ? static_cast<WORD>(asciiColors[j]) : kWhite;
                    setColor(c);
                    putChar(IsPrintableAscii(data[j]) ? static_cast<char>(data[j]) : '.');
                }
                putStr("\n");
            }

            if (indent > 0)
                putStr(std::string(static_cast<size_t>(indent), ' '));

            std::ostringstream a;
            a << std::uppercase << std::hex << std::setw(addr_width) << std::setfill('0') << (startAddr + static_cast<uintptr_t>(i));
            setColor(kWhite);
            putStr(a.str());
            putStr("  ");
        }

        std::snprintf(buf, sizeof(buf), "%02x ", data[i]);
        WORD c = (byteColors && byteColors[i]) ? static_cast<WORD>(byteColors[i]) : kWhite;
        setColor(c);
        putStr(buf);
    }

    if (size & 15)
    {
        size_t padded_size = ((size - 1) | 15) + 1;
        setColor(kWhite);
        for (size_t j = size; j < padded_size; ++j)
            putStr("   ");
    }

    setColor(kWhite);
    putStr(" ");

    size_t base = (size - 1) & ~static_cast<size_t>(0xF);
    for (size_t j = base; j < size; ++j)
    {
        WORD c = (asciiColors && asciiColors[j]) ? static_cast<WORD>(asciiColors[j]) : kWhite;
        setColor(c);
        putChar(IsPrintableAscii(data[j]) ? static_cast<char>(data[j]) : '.');
    }

    setColor(oldAttr);
}

void AsmRunner::SetConsoleColor(int32_t mode)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (mode == 0)
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    else if (mode == 1)
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
    else if (mode == 2)
        SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE);
    else if (mode == 3)
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
    else if (mode == 4)
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE);
    else if (mode == 5)
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE);
    else if (mode == 6)
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    else if (mode == 7)
        SetConsoleTextAttribute(hConsole, 0);
}

void AsmRunner::MboxSTD(std::string msg, std::string title)
{
    MessageBoxA(HWND_DESKTOP, msg.c_str(), title.c_str(), MB_SYSTEMMODAL | MB_ICONWARNING);
}
void AsmRunner::EXIT_F()
{
    ExitProcess(EXIT_FAILURE);
}
void AsmRunner::EXIT_S()
{
    ExitProcess(EXIT_SUCCESS);
}

uintptr_t AsmRunner::RestorePointer(uintptr_t op_addr, uintptr_t offset)
{
    return op_addr + 1 + sizeof(uintptr_t) + offset;
}

uintptr_t AsmRunner::CalculateOffset(uintptr_t op_addr, uintptr_t dst)
{
    return dst - (op_addr + 1 + sizeof(uintptr_t));
}

void* AsmRunner::SearchPointerByPattern(void* ptrStart, int block_size, std::string pattern)
{
#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (INRANGE(x, '0', '9') ? x - '0' : 0))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))
    const char* buffptr_pattern = pattern.c_str();
    uintptr_t pMatch = 0;
    for (uintptr_t MemPtr = (uintptr_t)ptrStart; MemPtr < ((uintptr_t)ptrStart + block_size); MemPtr++)
    {
        if (!*buffptr_pattern) { break; }
        if (*(PBYTE)buffptr_pattern == '\?' || *(BYTE*)MemPtr == getByte(buffptr_pattern))
        {
            if (!pMatch) { pMatch = MemPtr; }
            if (!buffptr_pattern[2]) { break; }
            if (*(PWORD)buffptr_pattern == '\?\?' || *(PBYTE)buffptr_pattern != '\?') { buffptr_pattern += 3; }
            else { buffptr_pattern += 2; } //one ?
        }
        else
        {
            buffptr_pattern = pattern.c_str();
            if (pMatch) { MemPtr = pMatch; }
            pMatch = 0;
        }
    }
    if (!pMatch) { return NULL; }
    return (void*)pMatch;
#undef getByte;
#undef getBits;
#undef INRANGE;
}

std::vector<AsmRunner::tMemoryRegion> AsmRunner::FindRegions(SIZE_T targetSize, DWORD targetType, DWORD targetProtect, DWORD targetState)
{
    std::vector<AsmRunner::tMemoryRegion> regions;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;
    while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) != 0) {
        if (targetSize != 0 && mbi.RegionSize != targetSize) { address += mbi.RegionSize; continue; }
        if (targetType != 0 && mbi.Type != targetType) { address += mbi.RegionSize; continue; }
        if (targetProtect != 0 && mbi.Protect != targetProtect) { address += mbi.RegionSize; continue; }
        if (targetState != 0 && mbi.State != targetState) { address += mbi.RegionSize; continue; }
        regions.push_back({ mbi.BaseAddress, mbi.RegionSize });
        address += mbi.RegionSize;
    }
    return regions;
}

void AsmRunner::CompareRegionsSnapshots(const std::vector<tMemoryRegion>& oldRegions, const std::vector<tMemoryRegion>& newRegions, bool bExtra)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    bool haveConsole = (hConsole != INVALID_HANDLE_VALUE) && GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD oldAttr = haveConsole ? csbi.wAttributes : (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    const WORD kWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    const WORD kRed = FOREGROUND_RED | FOREGROUND_INTENSITY;
    const WORD kGreen = FOREGROUND_GREEN | FOREGROUND_INTENSITY;

    auto setColor = [&](WORD c)
    {
        if (haveConsole)
            SetConsoleTextAttribute(hConsole, c);
    };

    auto restoreColor = [&]()
    {
        if (haveConsole)
            SetConsoleTextAttribute(hConsole, oldAttr);
    };

    struct RegionKey
    {
        uintptr_t start;
        uintptr_t size;

        bool operator<(const RegionKey& other) const
        {
            if (start != other.start) return start < other.start;
            return size < other.size;
        }

        bool operator==(const RegionKey& other) const
        {
            return start == other.start && size == other.size;
        }
    };

    auto toKey = [](const tMemoryRegion& r) -> RegionKey
    {
        return {
            reinterpret_cast<uintptr_t>(r.baseAddress),
            static_cast<uintptr_t>(r.size)
        };
    };

    std::vector<RegionKey> a;
    std::vector<RegionKey> b;
    a.reserve(oldRegions.size());
    b.reserve(newRegions.size());

    for (const auto& r : oldRegions) a.push_back(toKey(r));
    for (const auto& r : newRegions) b.push_back(toKey(r));

    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());

    std::cout << "[REGIONS] old=" << std::dec << a.size()
        << " new=" << b.size() << '\n';

    size_t i = 0, j = 0;
    size_t removed = 0, added = 0;

    while (i < a.size() || j < b.size())
    {
        if (j >= b.size() || (i < a.size() && a[i] < b[j]))
        {
            setColor(kRed);
            std::cout << "[-] region disappeared: "
                << "0x" << std::hex << std::uppercase << a[i].start
                << " size=0x" << a[i].size << '\n';
            ++i;
            ++removed;
        }
        else if (i >= a.size() || b[j] < a[i])
        {
            setColor(kGreen);
            std::cout << "[+] region appeared:   "
                << "0x" << std::hex << std::uppercase << b[j].start
                << " size=0x" << b[j].size << '\n';
            ++j;
            ++added;
        }
        else
        {
            ++i;
            ++j;
        }
    }

    setColor(kWhite);
    std::cout << "[REGIONS] removed=" << std::dec << removed
        << " added=" << added << '\n';

    restoreColor();
    std::cout << std::flush;
}

#if 0
void AsmRunner::CompareRegionsSnapshots(const std::vector<tMemoryRegion>& oldRegions, const std::vector<tMemoryRegion>& newRegions, bool bExtra)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    bool haveConsole = (hConsole != INVALID_HANDLE_VALUE) && GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD oldAttr = haveConsole ? csbi.wAttributes : (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    const WORD kWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    const WORD kRed = FOREGROUND_RED | FOREGROUND_INTENSITY;
    const WORD kGreen = FOREGROUND_GREEN | FOREGROUND_INTENSITY;

    auto setColor = [&](WORD c)
    {
        if (haveConsole)
            SetConsoleTextAttribute(hConsole, c);
    };

    auto restoreColor = [&]()
    {
        if (haveConsole)
            SetConsoleTextAttribute(hConsole, oldAttr);
    };

    struct RegionKey
    {
        uintptr_t start{};
        uintptr_t size{};
        std::string extra;

        bool operator<(const RegionKey& other) const
        {
            if (start != other.start) return start < other.start;
            if (size != other.size)   return size < other.size;
            return extra < other.extra;
        }

        bool sameBasic(const RegionKey& other) const
        {
            return start == other.start && size == other.size;
        }
    };

    auto makeKey = [&](const tMemoryRegion& r) -> RegionKey
    {
        RegionKey k{};
        k.start = reinterpret_cast<uintptr_t>(r.baseAddress);
        k.size = static_cast<uintptr_t>(r.size);

        if (bExtra)
        {
            // TODO WinApi request by baseAddress get \Device\HarddiskVolume5\ntdll.dll like cheatengine
            //k.extra = r.extra;
        }

        return k;
    };

    auto formatRegion = [&](const RegionKey& r) -> std::string
    {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase << r.start
            << " - 0x" << (r.start + r.size)
            << " size=0x" << r.size;

        if (bExtra && !r.extra.empty())
            oss << " extra=\"" << r.extra << "\"";

        return oss.str();
    };

    std::vector<RegionKey> a;
    std::vector<RegionKey> b;
    a.reserve(oldRegions.size());
    b.reserve(newRegions.size());

    for (const auto& r : oldRegions) a.push_back(makeKey(r));
    for (const auto& r : newRegions) b.push_back(makeKey(r));

    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());

    std::cout << "[REGIONS] old=" << std::dec << a.size()
        << " new=" << b.size()
        << " extra=" << (bExtra ? "on" : "off") << '\n';

    size_t i = 0, j = 0;
    size_t removed = 0, added = 0, same = 0;

    while (i < a.size() || j < b.size())
    {
        if (j >= b.size() || (i < a.size() && a[i] < b[j]))
        {
            setColor(kRed);
            std::cout << "[-] disappeared: " << formatRegion(a[i]) << '\n';
            ++removed;
            ++i;
        }
        else if (i >= a.size() || b[j] < a[i])
        {
            setColor(kGreen);
            std::cout << "[+] appeared:   " << formatRegion(b[j]) << '\n';
            ++added;
            ++j;
        }
        else
        {
            ++same;
            ++i;
            ++j;
        }
    }

    setColor(kWhite);
    std::cout << "[REGIONS] same=" << std::dec << same
        << " removed=" << removed
        << " added=" << added << '\n';

    restoreColor();
    std::cout << std::flush;
}
#endif

uintptr_t AsmRunner::AddMemory(uintptr_t nSize, uint32_t nType)
{
    if (!m_uc || nSize == 0) return 0;
    uintptr_t sz = AlignUp(nSize, 0x1000);
    uintptr_t addr = AlignUp(m_allocCursor, 0x1000);
    if (uc_mem_map(m_uc, addr, sz, nType) != UC_ERR_OK) return 0;
    m_allocCursor = addr + sz;
    return addr;
}

uintptr_t AsmRunner::AddMemory(uintptr_t pFrom, uintptr_t nSize, uint32_t nType)
{
    uintptr_t addr = AddMemory(nSize, nType);
    if (addr && nSize) {
        uc_mem_write(m_uc, addr, reinterpret_cast<void*>(pFrom), nSize);
    }
    return addr;
}

bool AsmRunner::AddMemoryTo(uintptr_t pVTo, uintptr_t nSize, uint32_t nType)
{
    if (!m_uc || !pVTo || !nSize) return false;
#if 1
    uintptr_t mapSize = AlignUp(nSize, 0x1000);
    uc_mem_map(m_uc, pVTo, mapSize, nType);
#else
    const uintptr_t pageSize = 0x1000;
    const uintptr_t base = AlignDown(pVTo, pageSize);
    const uintptr_t end = AlignUp(pVTo + nSize, pageSize);
    const uintptr_t mapSize = end - base;

    uc_err err = uc_mem_map(m_uc, base, mapSize, nType);
    if (err != UC_ERR_OK)
    {
        if (m_bLogRunner)
            Log("[!] uc_mem_map failed: %s (base=0x%p size=0x%zx)",
                uc_strerror(err), (void*)base, (size_t)mapSize);
        return false;
    }
#endif
    return true;
}

bool AsmRunner::AddMemoryFromBuff(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize, uint32_t nType)
{
    if (!m_uc || !pVTo || !pFrom || !nSize) return false;
    //uintptr_t mapSize = AlignUp(nSize, 0x1000);
    //uc_mem_map(m_uc, pVTo, mapSize, nType);
    bool bRes = AddMemoryTo(pVTo, nSize, nType);
    if(bRes)
        uc_mem_write(m_uc, pVTo, reinterpret_cast<void*>(pFrom), nSize);
    return bRes;
}

void AsmRunner::_CopyMemory(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize)
{
    if (!m_uc || !pVTo || !pFrom || !nSize) return;
    uc_mem_write(m_uc, pVTo, reinterpret_cast<void*>(pFrom), nSize);
}

bool AsmRunner::FreeMemory(uintptr_t pVTo)
{
    if (!m_uc || !pVTo) return false;
    uc_mem_unmap(m_uc, pVTo, 0x1000);
    return true;
}

bool AsmRunner::ChangeMemoryType(uintptr_t pVTo, uint32_t nType)
{
    if (!m_uc || !pVTo) return false;
    uc_mem_protect(m_uc, pVTo, 0x1000, nType);
    return true;
}

void AsmRunner::DumpMemory(const char* szFileOutPath, uintptr_t pStart, uintptr_t nSize)
{
    if (!m_uc || !szFileOutPath || !pStart || !nSize) return;
    std::vector<uint8_t> buf(static_cast<size_t>(nSize));
    if (uc_mem_read(m_uc, pStart, buf.data(), buf.size()) != UC_ERR_OK) return;
    std::ofstream f(szFileOutPath, std::ios::binary);
    if (!f.is_open()) return;
    f.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
}

void AsmRunner::DumpMemory(uintptr_t pStart, uintptr_t nSize)
{
    if (!m_uc || !pStart || !nSize) return;
    std::vector<uint8_t> buf(static_cast<size_t>(nSize));
    if (uc_mem_read(m_uc, pStart, buf.data(), buf.size()) != UC_ERR_OK) return;
    std::string out;
    DataToHexString(0, pStart, buf.data(), buf.size(), &out);
    Log("%s", out.c_str());
}

void AsmRunner::DumpMemory(uintptr_t pNativeStart, uintptr_t pStart, uintptr_t nSize)
{
    (void)pNativeStart;
    DumpMemory(pStart, nSize);
}

uintptr_t AsmRunner::DumpMemoryNTAlloc(uintptr_t pStart, uintptr_t nSize)
{
    if (!m_uc || !pStart || !nSize)
        return 0;

    void* p = std::malloc(static_cast<size_t>(nSize));
    if (!p)
        return 0;

    if (uc_mem_read(m_uc, pStart, p, static_cast<size_t>(nSize)) != UC_ERR_OK)
    {
        std::free(p);
        return 0;
    }

    return reinterpret_cast<uintptr_t>(p);
}

// todo: ??
uintptr_t AsmRunner::DumpMemoryAlloc(uintptr_t pStart, uintptr_t nSize)
{
    if (!m_uc || !pStart || !nSize) return 0;
    uintptr_t addr = AddMemory(nSize, UC_PROT_ALL);
    if (!addr) return 0;
    if (uc_mem_write(m_uc, addr, reinterpret_cast<void*>(pStart), nSize) != UC_ERR_OK) {
        uc_mem_unmap(m_uc, addr, AlignUp(nSize, 0x1000));
        return 0;
    }
    return addr;
}

bool AsmRunner::IsModuleAddr(uintptr_t pAddr)
{
    return IsInAddr(pAddr, m_modStart, m_modEnd);
}

bool AsmRunner::IsRetHaltOrNull(uintptr_t pAddr)
{
    return pAddr == m_halt;
}

bool AsmRunner::IsInAddr(uintptr_t pAddr, uintptr_t pStart, uintptr_t pEnd)
{
    if (pStart == 0 || pEnd == 0)
        return false;

    return (pAddr >= pStart && pAddr < pEnd);
}

void AsmRunner::SetRegister(uint32_t nRegister, uintptr_t arg)
{
    if (!m_uc) return;
    uc_reg_write(m_uc, nRegister, &arg);
}

uintptr_t AsmRunner::GetRegister(uint32_t nRegister)
{
    if (!m_uc) return 0;
    uintptr_t v = 0;
    uc_reg_read(m_uc, nRegister, &v);
    if (!m_bX64) v = static_cast<uint32_t>(v);
    return v;
}

void AsmRunner::SetStack(uintptr_t pStack, uintptr_t nSize)
{
    assert(m_bInitedStack == false);
    if (!m_uc) return;
    uintptr_t mapSize = AlignUp(nSize, 0x1000);
    if (uc_mem_map(m_uc, pStack, mapSize, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) return;
    //uintptr_t sp = pStack + mapSize - (m_bX64 ? 0x20 : 8);
    uintptr_t sp = pStack + mapSize - m_stackEPSize; // call emu + ep args
    uc_reg_write(m_uc, SpReg(), &sp);
    //uc_mem_write(m_uc, GetRegister(SpReg()), &m_halt, sizeof(m_halt)); // same
    uc_mem_write(m_uc, sp, &m_halt, sizeof(m_halt));
    m_bInitedStack = true;
}

void AsmRunner::SetStack()
{
    SetStack(m_stackBase, m_stackSize);
}

uintptr_t AsmRunner::GetStack(uint32_t nIdx)
{
    if (!m_uc) return 0;
    uintptr_t sp = CurrentSp(m_uc);
    uintptr_t ptrSize = m_bX64 ? 8 : 4;
    uintptr_t v = 0;
    uc_mem_read(m_uc, sp + (static_cast<uintptr_t>(nIdx) * ptrSize), &v, ptrSize);
    if (!m_bX64) v = static_cast<uint32_t>(v);
    return v;
}

void AsmRunner::SetEntryPointStackArg(uint32_t nArgIdx, uintptr_t arg)
{
    if (!m_uc) return;
    uintptr_t sp = CurrentSp(m_uc);
    uintptr_t ptrSize = m_bX64 ? 8 : 4;
    uintptr_t slot = sp + ptrSize * (static_cast<uintptr_t>(nArgIdx) + 1);
    uc_mem_write(m_uc, slot, &arg, ptrSize);
}

void AsmRunner::SetStackArgEbpIndex(uint32_t nIdx, uintptr_t arg)
{
    if (!m_uc) return;
    uintptr_t fp = 0;
    uc_reg_read(m_uc, FpReg(), &fp);
    uintptr_t ptrSize = m_bX64 ? 8 : 4;
    uintptr_t slot = fp + ptrSize * (static_cast<uintptr_t>(nIdx) + 1);
    uc_mem_write(m_uc, slot, &arg, ptrSize);
}

void AsmRunner::SetFakeSehTid(uintptr_t pAddr, uintptr_t nSize)
{
    assert(m_bInitedSehFS == false);
    if (!m_uc) return;
    if (pAddr == 0) pAddr = 0x0;
    if (nSize == 0) nSize = 0x1000;

    uintptr_t mapSize = AlignUp(nSize, 0x1000);
    uc_err err = uc_mem_map(m_uc, pAddr, mapSize, UC_PROT_READ | UC_PROT_WRITE);
    if (err == UC_ERR_MAP) {
        if (m_bLogRunner)
            Log("[!] UC_ERR_MAP map zero page failed: %s", uc_strerror(err));
        return;
    }

    if (err != UC_ERR_OK) {
        if (m_bLogRunner)
            Log("[!] map zero page failed: %s", uc_strerror(err));
        return;
    }

    uint32_t seh_head = 0;
    err = uc_mem_write(m_uc, pAddr, &seh_head, sizeof(seh_head));
    if (err != UC_ERR_OK) {
        if (m_bLogRunner)
            Log("[!] write zero page failed: %s", uc_strerror(err));
    }
    m_bInitedSehFS = true;
}

void AsmRunner::SetCallbacks(OnOpcodeCb opcode_cb, void* opcode_data, OnMemCb mem_cb, void* mem_data, OnJmpCb jmp_cb, void* jmp_data)
{
    m_cbOpcode = std::move(opcode_cb);
    m_cbOpcodeData = opcode_data;
    m_cbMem = std::move(mem_cb);
    m_cbMemData = mem_data;
    m_cbJmp = std::move(jmp_cb);
    m_cbJmpData = jmp_data;
}

void AsmRunner::CopyModule(const char* szModule, uintptr_t nSize)
{
    assert(szModule != nullptr);

    uintptr_t pStart = 0, pEnd = 0, iSize = 0;
    if (!GetMappedModuleBounds(szModule, pStart, pEnd, iSize)) {
        Shutdown();
        return;
    }

    if (m_bLogRunner)
        Log("[%s] base=0x%p end=0x%p size=0x%zx\n", szModule, (void*)pStart, (void*)pEnd, (size_t)iSize);

    uintptr_t copySize = (nSize == 0) ? iSize : nSize;
    if (!CopyModuleUC(pStart, pStart, copySize)) {
        Shutdown();
        return;
    }

    m_modStart = pStart;
    m_modEnd = pEnd;

    //if (m_bLogRunner)
    //{
    //    Log("=== %s ===", szModule);
    //    Log("pStart: 0x%p", (void*)pStart);
    //    Log("pEnd:   0x%p", (void*)pEnd);
    //    Log("Size:   0x%zx (%zu MB)", static_cast<size_t>(iSize), static_cast<size_t>(iSize / (1024 * 1024)));
    //}
}

void AsmRunner::CopyModule(uintptr_t pFrom, uintptr_t nSize)
{
    assert(pFrom != 0);

    if (!nSize) {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pFrom);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(pFrom + dos->e_lfanew);
        nSize = nt->OptionalHeader.SizeOfImage;
    }

    if (!CopyModuleUC(pFrom, pFrom, nSize)) {
        Shutdown();
        return;
    }

    m_modStart = pFrom;
    m_modEnd = pFrom + nSize;
}

void AsmRunner::LoadModule(const char* szModule)
{
    CopyModule(szModule, 0);
}

bool AsmRunner::LoadExportsFromBase(uintptr_t base, std::vector<tFuncNode>& out) const
{
    out.clear();
    if (!base) return false;

    //__try
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dir.VirtualAddress || !dir.Size) return false;

        auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
        auto* names = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
        auto* ords = reinterpret_cast<WORD*>(base + exp->AddressOfNameOrdinals);
        auto* funcs = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);

        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            const char* nm = reinterpret_cast<const char*>(base + names[i]);
            WORD ord = ords[i];
            DWORD rva = funcs[ord];
            if (!nm || !*nm) continue;

            tFuncNode n;
            n.rva = static_cast<uintptr_t>(rva);
            n.size = 0;
            n.name = nm;
            out.push_back(n);
        }
    }
    //__except (EXCEPTION_EXECUTE_HANDLER) { return false; }

    std::sort(out.begin(), out.end(), [](const tFuncNode& a, const tFuncNode& b) { return a.rva < b.rva; });
    return !out.empty();
}

std::vector<tFuncNode> AsmRunner::GetModuleExports()
{
    std::vector<tFuncNode> out;
    if (m_modStart) {
        LoadExportsFromBase(m_modStart, out);
    }
    return out;
}

tFuncNode AsmRunner::GetModuleExport(const char* szModule, const char* szExportName)
{
    tFuncNode empty;
    if (!szExportName || !*szExportName) return empty;

    uintptr_t base = m_modStart;
    if (szModule && *szModule) {
        HMODULE h = GetModuleHandleA(szModule);
        if (!h) return empty;
        base = reinterpret_cast<uintptr_t>(h);
    }

    std::vector<tFuncNode> exps;
    if (!LoadExportsFromBase(base, exps)) return empty;

    for (size_t i = 0; i < exps.size(); ++i) {
        if (_stricmp(exps[i].name.c_str(), szExportName) == 0) {
            return exps[i];
        }
    }

    return empty;
}

void AsmRunner::Run(uintptr_t pEntry, uintptr_t nStepsDeep)
{
    if (!m_uc) return;

    uintptr_t pc = pEntry;
    if (!m_bX64) pc = static_cast<uint32_t>(pc);
    uc_reg_write(m_uc, PcReg(), &pc);

    if (!m_hkCode) {
        uc_err err = uc_hook_add(m_uc, &m_hkCode, UC_HOOK_CODE, reinterpret_cast<void*>(HookCodeTrampoline), this, 1, 0);
        if (err != UC_ERR_OK) {
            Log("[!] uc_hook_add CODE failed: %s", uc_strerror(err));
            return;
        }
    }

    if (!m_hkMem) {
        uc_err err = uc_hook_add(m_uc, &m_hkMem,
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE |
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_PROT |
            UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT,
            reinterpret_cast<void*>(HookMemTrampoline), this, 1, 0);
        if (err != UC_ERR_OK) {
            Log("[!] uc_hook_add MEM failed: %s", uc_strerror(err));
            return;
        }
    }

    m_bPaused = false;
    m_bStopped = false;

    if (m_bLogRunner) {
        Log("[*] Entry = 0x%p", (void*)pc);
        Log("[*] Steps = %zu", static_cast<size_t>(nStepsDeep));
        Log("[*] Bounds = [0x%p - 0x%p]", (void*)m_modStart, (void*)m_modEnd);
    }

    uint64_t count = nStepsDeep ? static_cast<uint64_t>(nStepsDeep) : 0;
    uc_err err = uc_emu_start(m_uc, pc, m_modEnd ? m_modEnd : 0, 0, count);

    if (m_bLogRunner) {
        Log("[*] emu end, err=%s, instr=%zu", uc_strerror(err), static_cast<size_t>(m_instrCount));

        if (err != UC_ERR_OK) {
            SetConsoleColor(0);
            const char* errMsg = uc_strerror(err);
            uintptr_t pc_stop = CurrentPc(m_uc);

            Log("[!] emu stopped with error: %s (code: %d)", errMsg, err);
            Log("[!] Stopped at PC = 0x%p (%s)", (void*)pc_stop, FormatRuntimeAddressWithSymbol(pc_stop).c_str());

            switch (err)
            {
                case UC_ERR_FETCH_UNMAPPED:
                    Log("[!] Cause: Attempt to execute code from unmapped memory");
                    break;
                case UC_ERR_READ_UNMAPPED:
                    Log("[!] Cause: Attempt to read from unmapped memory");
                    break;
                case UC_ERR_WRITE_UNMAPPED:
                    Log("[!] Cause: Attempt to write to unmapped memory");
                    break;
                case UC_ERR_FETCH_PROT:
                    Log("[!] Cause: Attempt to execute from non-executable memory");
                    break;
                case UC_ERR_READ_PROT:
                    Log("[!] Cause: Attempt to read from non-readable memory");
                    break;
                case UC_ERR_WRITE_PROT:
                    Log("[!] Cause: Attempt to write to non-writable memory");
                    break;
                case UC_ERR_INSN_INVALID:
                    Log("[!] Cause: Invalid instruction encountered");
                    break;
            }

            DumpRegisters();
            SetConsoleColor(6);
        }
    }
}

void AsmRunner::Pause()
{
    if (!m_uc) return;
    m_bPaused = true;
    uc_emu_stop(m_uc);
}

void AsmRunner::Resume()
{
    if (!m_uc || !m_bPaused) return;
    m_bPaused = false;
    uintptr_t pc = CurrentPc(m_uc);
    uc_emu_start(m_uc, pc, m_modEnd ? m_modEnd : 0, 0, 0);
}

void AsmRunner::Stop()
{
    if (!m_uc) return;
    m_bStopped = true;
    uc_emu_stop(m_uc);
}

void AsmRunner::B(intptr_t nOps)
{
    if (!m_uc || nOps == 0) return;
    uintptr_t pc = CurrentPc(m_uc);
    uint64_t count = static_cast<uint64_t>(nOps > 0 ? nOps : -nOps);
    uc_emu_start(m_uc, pc, m_modEnd ? m_modEnd : 0, 0, count);
}

void AsmRunner::DumpRegisters(bool bCol)
{
    if (!m_uc) return;

    auto read = [&](uint32_t reg) -> uintptr_t {
        uintptr_t v = 0;
        uc_reg_read(m_uc, reg, &v);
        if (!m_bX64) v = static_cast<uint32_t>(v);
        return v;
    };

    uintptr_t eax = read(m_bX64 ? UC_X86_REG_RAX : UC_X86_REG_EAX);
    uintptr_t ebx = read(m_bX64 ? UC_X86_REG_RBX : UC_X86_REG_EBX);
    uintptr_t ecx = read(m_bX64 ? UC_X86_REG_RCX : UC_X86_REG_ECX);
    uintptr_t edx = read(m_bX64 ? UC_X86_REG_RDX : UC_X86_REG_EDX);
    uintptr_t esi = read(m_bX64 ? UC_X86_REG_RSI : UC_X86_REG_ESI);
    uintptr_t edi = read(m_bX64 ? UC_X86_REG_RDI : UC_X86_REG_EDI);
    uintptr_t esp = read(SpReg());
    uintptr_t ebp = read(FpReg());
    uintptr_t eip = read(PcReg());

    auto fmt = [&](uintptr_t v) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase << v;
        return oss.str();
    };

    if (bCol) {
        Log("=== REGISTERS ===");
        Log("%-12s = %s", "EAX/RAX", fmt(eax).c_str());
        Log("%-12s = %s", "EBX/RBX", fmt(ebx).c_str());
        Log("%-12s = %s", "ECX/RCX", fmt(ecx).c_str());
        Log("%-12s = %s", "EDX/RDX", fmt(edx).c_str());
        Log("%-12s = %s", "ESI/RSI", fmt(esi).c_str());
        Log("%-12s = %s", "EDI/RDI", fmt(edi).c_str());
        Log("%-12s = %s", "ESP/RSP", fmt(esp).c_str());
        Log("%-12s = %s", "EBP/RBP", fmt(ebp).c_str());
        Log("%-12s = %s", m_bX64 ? "RIP" : "EIP", fmt(eip).c_str());
    } else {
        Log("=== REGISTERS ===");
        Log("EAX/RAX=%s EBX/RBX=%s ECX/RCX=%s EDX/RDX=%s", fmt(eax).c_str(), fmt(ebx).c_str(), fmt(ecx).c_str(), fmt(edx).c_str());
        Log("ESI/RSI=%s EDI/RDI=%s ESP/RSP=%s EBP/RBP=%s", fmt(esi).c_str(), fmt(edi).c_str(), fmt(esp).c_str(), fmt(ebp).c_str());
        Log("%s=%s", m_bX64 ? "RIP" : "EIP", fmt(eip).c_str());
    }
}

void AsmRunner::TrimInPlace(std::string& s)
{
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    s = s.substr(b, e - b);
}

bool AsmRunner::ParseHexPtr(const std::string& s, uintptr_t& out)
{
    char* end = nullptr;
    unsigned long long v = _strtoui64(s.c_str(), &end, 16);
    if (end == s.c_str()) return false;
    out = static_cast<uintptr_t>(v);
    return true;
}

void AsmRunner::InitialiseSymMap(const char* szPath, uintptr_t nSymASLR)
{
    m_sym.clear();

    if (!szPath || !*szPath) return;

    std::ifstream f(szPath);
    if (!f.is_open()) {
        Log("[!] Не удалось открыть map: %s", szPath);
        return;
    }

    std::string line;
    while (std::getline(f, line)) {
        TrimInPlace(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        size_t sp = line.find_first_of(" \t");
        size_t comma = line.rfind(',');
        if (sp == std::string::npos || comma == std::string::npos || comma <= sp) continue;

        std::string sAddr = line.substr(0, sp);
        std::string sName = line.substr(sp + 1, comma - sp - 1);
        std::string sSize = line.substr(comma + 1);
        TrimInPlace(sAddr);
        TrimInPlace(sName);
        TrimInPlace(sSize);

        uintptr_t ptr = 0;
        uintptr_t sizeVal = 0;
        if (!ParseHexPtr(sAddr, ptr)) continue;
        ParseHexPtr(sSize, sizeVal);

        tFuncNode e;
        e.rva = ptr - nSymASLR;
        e.size = static_cast<size_t>(sizeVal);
        e.name = sName;
        m_sym.push_back(e);
    }

    std::sort(m_sym.begin(), m_sym.end(), [](const tFuncNode& a, const tFuncNode& b) { return a.rva < b.rva; });
    Log("[+] loaded symbols: %zu", m_sym.size());
}

tFuncNode AsmRunner::GetSymByName(const char* szName)
{
    if (!szName || !*szName) return tFuncNode{};
    for (size_t i = 0; i < m_sym.size(); ++i) {
        if (_stricmp(m_sym[i].name.c_str(), szName) == 0) return m_sym[i];
    }
    return tFuncNode{};
}

tFuncNode AsmRunner::GetSymByAddr(uintptr_t pAddr)
{
    const tFuncNode* s = FindSymbolByRuntime(pAddr);
    return s ? *s : tFuncNode{};
}

void AsmRunner::SetBreakpoint(uintptr_t pAddr, eBpType type, uint32_t size, OnBreakpointCb cb, void* data)
{
    tBpInfo& bp = m_breakpoints[pAddr];
    bp.size = size ? size : 1;
    bp.type = type;
    bp.cb = std::move(cb);
    bp.data = data;
}

void AsmRunner::RemoveBreakpoint(uintptr_t pAddr)
{
    std::map<uintptr_t, tBpInfo>::iterator it = m_breakpoints.find(pAddr);
    if (it != m_breakpoints.end()) {
        if (m_uc && it->second.hook) {
            uc_hook_del(m_uc, it->second.hook);
        }
        m_breakpoints.erase(it);
    }
}

void AsmRunner::TraceWriteLine(const std::string& s)
{
    if (!m_trace.file.is_open()) return;
    m_trace.file << s << '\n';
}

void AsmRunner::TraceInstruction(const char* szTraceFileOutPath, uintptr_t pStart, uint32_t nMaxCount, TraceCb cb)
{
    if (!m_uc) return;
    if (!szTraceFileOutPath || !*szTraceFileOutPath) return;

    if (m_trace.file.is_open()) m_trace.file.close();
    m_trace.file.open(szTraceFileOutPath, std::ios::out | std::ios::trunc);
    if (!m_trace.file.is_open()) {
        Log("[!] cannot open trace file: %s", szTraceFileOutPath);
        return;
    }

    m_trace.count = 0;
    m_trace.maxCount = nMaxCount;
    m_trace.cbStop = std::move(cb);
    m_trace.active = true;
    m_trace.prevRegs.clear();
    m_trace.lastMemAddr = 0;
    m_trace.lastMemSize = 0;
    m_trace.lastMemWrite = false;
    m_trace.lastMemData.clear();

    Run(pStart, nMaxCount);

    m_trace.active = false;
    m_trace.file.flush();
    m_trace.file.close();
}

std::string AsmRunner::SanitizeIdaName(const std::string& in)
{
    std::string s = in;
    for (char& c : s)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!(std::isalnum(uc) || c == '_'))
            c = '_';
    }
    if (s.empty())
        s = "unk";
    if (std::isdigit(static_cast<unsigned char>(s[0])))
        s = "_" + s;
    return s;
}

std::string AsmRunner::ClearStr(std::string input, std::string charsToRemove)
{
    std::string result = input;
    result.erase(std::remove_if(result.begin(), result.end(),
        [&charsToRemove](char c) { return charsToRemove.find(c) != std::string::npos; }),
        result.end());
    return result;
}

#define BUFF_SIZE (512)
std::string AsmRunner::SetName(uintptr_t pAddr, std::string name, bool snt)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "set_name(0x%X, \"%s\", SN_AUTO);", pAddr, (snt ? SanitizeIdaName(name) : name).c_str());
    return std::string(buff);
}

std::string AsmRunner::SetComment(uintptr_t pAddr, std::string comment, uint32_t nType)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "set_cmt(0x%X, \"%s\", %d);", pAddr, comment.c_str(), nType);
    return std::string(buff);
}

std::string AsmRunner::MakeArray(uintptr_t pAddr, uint32_t nArraySize)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "MakeArray(0x%X, %d);", pAddr, nArraySize); // kek need before define each element as type
    return std::string(buff);
}

std::string AsmRunner::SetType(uintptr_t pAddr, std::string type)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "SetType(0x%X, \"%s\");", pAddr, type.c_str());
    return std::string(buff);
}

std::string AsmRunner::SetColor(uintptr_t pAddr, uint8_t r, uint8_t g, uint8_t b)
{
    char buff[BUFF_SIZE];
    uint32_t color = (b << 16) | (g << 8) | r;
    sprintf_s(buff, sizeof(buff), "SetColor(0x%X, CIC_FUNC, 0x%X);", pAddr, color); // BGR
    return std::string(buff);
}

std::string AsmRunner::CreateSegment(uintptr_t pStart, uintptr_t pEnd, std::string name, bool snt)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff),
        "AddSegEx(0x%X, 0x%X, 0, 1, 3, 2, ADDSEG_QUIET);"
        "SetSegmentAttr(0x%X, SEGATTR_PERM, 7);"
        "SegClass(0x%X, \"CODE\");"
        "RenameSeg(0x%X, \"API_SEG_%s\");",
        pStart, pEnd,
        pStart,
        pStart,
        pStart, (snt ? SanitizeIdaName(name) : name).c_str());
    return std::string(buff);
}

std::string AsmRunner::PatchByte(uintptr_t pAddr, uint8_t val)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "PatchByte(0x%X, 0x%02X);", pAddr, val);
    return std::string(buff);
}

std::string AsmRunner::AddFunc(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "add_func(0x%X, BADADDR);", pAddr);
    return std::string(buff);
}

std::string AsmRunner::MakeCode(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "MakeCode(0x%X);", pAddr);
    return std::string(buff);
}

std::string AsmRunner::Message(std::string message)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "Message(\"%s\");", message.c_str());
    return std::string(buff);
}

std::string AsmRunner::DelItems(uintptr_t pAddr, uintptr_t nSize)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "del_items(0x%X, DELIT_SIMPLE, 0x%X);", pAddr, nSize);
    return std::string(buff);
}

std::string AsmRunner::get_type(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "get_type(0x%X);", pAddr);
    return std::string(buff);
}

std::string AsmRunner::GetType(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "GetType(0x%X);", pAddr);
    return std::string(buff);
}

std::string AsmRunner::Name(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "Name(0x%X);", pAddr);
    return std::string(buff);
}

std::string AsmRunner::isCode(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "isCode(0x%X);", pAddr);
    return std::string(buff);
}

std::string AsmRunner::isData(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "isData(0x%X);", pAddr);
    return std::string(buff);
}

std::string AsmRunner::isASCII(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "isASCII(0x%X);", pAddr);
    return std::string(buff);
}

std::string AsmRunner::get_func_name(uintptr_t pAddr)
{
    char buff[BUFF_SIZE];
    sprintf_s(buff, sizeof(buff), "get_func_name(0x%X);", pAddr);
    return std::string(buff);
}
#undef BUFF_SIZE

// Проверка допустимых режимов:
// "r"  - чтение (файл должен существовать)
// "w"  - запись (создает новый или перезаписывает)
// "a"  - добавление (в конец файла)
// "r+" - чтение и запись (файл должен существовать)
// "w+" - чтение и запись (создает новый или перезаписывает)
// "a+" - чтение и добавление (создает новый, если не существует)

FILE* AsmRunner::FileOpen(const char* filename, const char* mode)
{
    if (!filename || !mode) return nullptr;

    FILE* file = nullptr;
    errno_t err = fopen_s(&file, filename, mode);
    return err != 0 ? nullptr : file;
}

void AsmRunner::FileAdd(FILE* file, const char* fmt, ...)
{
    if (!file) return;

    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(file, fmt, ap);
    std::fputc('\n', file);
    va_end(ap);
}

void AsmRunner::FileClose(FILE* file)
{
    if (file)
        fclose(file);
}

AsmRunner::tMemSnapshot AsmRunner::MakeSnapshot(uintptr_t pStart, uintptr_t pEnd)
{
    tMemSnapshot s;
    if (!m_uc || pEnd <= pStart)
        return s;

    s.pStart = pStart;
    s.size = static_cast<size_t>(pEnd - pStart);
    s.data.resize(s.size);

    if (s.size == 0)
        return s;

    if (uc_mem_read(m_uc, pStart, s.data.data(), static_cast<size_t>(s.size)) != UC_ERR_OK)
    {
        s.data.clear();
        s.size = 0;
        s.pStart = 0;
    }

    return s;
}

AsmRunner::tMemSnapshot AsmRunner::MakeSnapshotS(uintptr_t pStart, uintptr_t nSize)
{
    tMemSnapshot s;
    if (!m_uc || nSize == 0)
        return s;

    s.pStart = pStart;
    s.size = static_cast<size_t>(nSize);
    s.data.resize(s.size);

    if (uc_mem_read(m_uc, pStart, s.data.data(), static_cast<size_t>(s.size)) != UC_ERR_OK)
    {
        s.data.clear();
        s.size = 0;
        s.pStart = 0;
    }

    return s;
}

void AsmRunner::CompareSnapshots(const tMemSnapshot& a, const tMemSnapshot& b, bool bDiffOnly)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    bool haveConsole = (hConsole != INVALID_HANDLE_VALUE) && GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD oldAttr = haveConsole ? csbi.wAttributes : (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    const WORD kWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    const WORD kRed = FOREGROUND_RED | FOREGROUND_INTENSITY;
    const WORD kGreen = FOREGROUND_GREEN | FOREGROUND_INTENSITY;

    auto setColor = [&](WORD c)
    {
        if (haveConsole)
            SetConsoleTextAttribute(hConsole, c);
    };

    auto restoreColor = [&]()
    {
        if (haveConsole)
            SetConsoleTextAttribute(hConsole, oldAttr);
    };

    const size_t cmpSize = min(a.data.size(), b.data.size());

    if (a.data.size() != b.data.size() && m_bLogRunner)
    {
        Log("[!] CompareSnapshots: sizes differ, compare only first 0x%zx bytes (A=0x%zx, B=0x%zx)",
            cmpSize, a.data.size(), b.data.size());
    }

    size_t diffCount = 0;
    size_t firstDiff = static_cast<size_t>(-1);
    size_t lastDiff = 0;

    std::vector<uint16_t> colorsA(cmpSize, 0);
    std::vector<uint16_t> colorsB(cmpSize, 0);

    for (size_t i = 0; i < cmpSize; ++i)
    {
        if (a.data[i] != b.data[i])
        {
            if (firstDiff == static_cast<size_t>(-1))
                firstDiff = i;

            lastDiff = i;
            ++diffCount;

            colorsA[i] = kRed;
            colorsB[i] = kGreen;
        }
    }

    std::ostringstream info;
    info << "[SNAP] A=0x" << std::hex << std::uppercase << a.pStart
        << " size=0x" << a.data.size()
        << " | B=0x" << std::hex << std::uppercase << b.pStart
        << " size=0x" << b.data.size()
        << " | compare=0x" << std::hex << std::uppercase << cmpSize;
    std::cout << info.str() << '\n';

    std::ostringstream diffInfo;
    diffInfo << "[SNAP] changed=" << std::dec << diffCount;

    if (cmpSize == 0)
    {
        diffInfo << " | empty compare range";
        std::cout << diffInfo.str() << '\n';
        restoreColor();
        return;
    }

    if (diffCount == 0)
    {
        diffInfo << " | snapshots identical in compared range";
    }
    else
    {
        diffInfo
            << " | first=A+0x" << std::hex << std::uppercase << firstDiff
            << " (0x" << (a.pStart + firstDiff) << ")"
            << " / B+0x" << firstDiff
            << " (0x" << (b.pStart + firstDiff) << ")"
            << " | last=A+0x" << std::hex << std::uppercase << lastDiff
            << " (0x" << (a.pStart + lastDiff) << ")"
            << " / B+0x" << lastDiff
            << " (0x" << (b.pStart + lastDiff) << ")";
    }

    if (a.data.size() != b.data.size())
    {
        diffInfo << " | tail not compared: A+" << std::dec << (a.data.size() - cmpSize)
            << " / B+" << (b.data.size() - cmpSize) << " bytes";
    }

    std::cout << diffInfo.str() << '\n';

    auto printBlockDiffOnly = [&](const char* title, const tMemSnapshot& s, const std::vector<uint16_t>& cols)
    {
        std::cout << title << '\n';

        bool printedAnyLine = false;
        size_t prevPrintedEnd = 0;

        for (size_t lineStart = 0; lineStart < cmpSize; lineStart += 16)
        {
            const size_t lineLen = std::min<size_t>(16, cmpSize - lineStart);

            bool lineHasDiff = false;
            for (size_t j = 0; j < lineLen; ++j)
            {
                if (a.data[lineStart + j] != b.data[lineStart + j])
                {
                    lineHasDiff = true;
                    break;
                }
            }

            if (!lineHasDiff)
                continue;

            if (printedAnyLine && lineStart > prevPrintedEnd)
            {
                std::cout << "...\n";
            }

            DataToHexString(
                0,
                s.pStart + lineStart,
                s.data.data() + lineStart,
                lineLen,
                cols.data() + lineStart,
                cols.data() + lineStart
            );
            std::cout << '\n';

            printedAnyLine = true;
            prevPrintedEnd = lineStart + lineLen;
        }

        if (!printedAnyLine)
            std::cout << "(no differences)\n";
    };

    if (bDiffOnly)
    {
        if (diffCount == 0)
        {
            std::cout << "[SNAP] no differences\n";
            restoreColor();
            std::cout << std::flush;
            return;
        }

        printBlockDiffOnly("[SNAP] A (diff only)", a, colorsA);
        std::cout << '\n';
        printBlockDiffOnly("[SNAP] B (diff only)", b, colorsB);
    }
    else
    {
        std::cout << "[SNAP] A\n";
        DataToHexString(0, a.pStart, a.data.data(), cmpSize,
            colorsA.empty() ? nullptr : colorsA.data(),
            colorsA.empty() ? nullptr : colorsA.data());
        std::cout << '\n';

        std::cout << "\n[SNAP] B\n";
        DataToHexString(0, b.pStart, b.data.data(), cmpSize,
            colorsB.empty() ? nullptr : colorsB.data(),
            colorsB.empty() ? nullptr : colorsB.data());
        std::cout << '\n';

        if (a.data.size() > cmpSize)
        {
            std::cout << "\n[SNAP] A tail (not compared)\n";
            DataToHexString(0, a.pStart + cmpSize, a.data.data() + cmpSize, a.data.size() - cmpSize, nullptr, nullptr);
            std::cout << '\n';
        }

        if (b.data.size() > cmpSize)
        {
            std::cout << "\n[SNAP] B tail (not compared)\n";
            DataToHexString(0, b.pStart + cmpSize, b.data.data() + cmpSize, b.data.size() - cmpSize, nullptr, nullptr);
            std::cout << '\n';
        }
    }

    restoreColor();
    std::cout << std::flush;
}

#if 0
void TestUsage1()
{
    AsmRunner runner(false);
    void* pEntry = (void*)(0x62E4686F);


    //uintptr_t pStart = 0;
    //uintptr_t pEnd = 0;
    //uintptr_t nSize = 0;
    //runner.GetMappedModuleBounds(STEAM_LIB, pStart, pEnd, nSize);

    //if (nSize == 0 || pStart == 0)
    //{
    //	MboxSTD("VMENTRY_UT_HK", "module not found");
    //	return;
    //}

    //printf("[%s] base=0x%p end=0x%p size=0x%zx\n", "mdl.dll", (void*)pStart, (void*)pEnd, (size_t)nSize);

    auto OpcodeCb = [&pThemidaStart, &pThemidaEnd](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        //printf("OpcodeCb 0x%p (%d)\n", (void*)address, mnemonic);
        self->DumpRegisters(true);
        return true;

        if (self->IsInAddr(address, pThemidaStart, pThemidaEnd)) {
            SetConsoleColor(0); // red
        }
        else {
            SetConsoleColor(1);
        }

        if (self->GetInstructionCount() > /*5080*/110000) {
            self->SetLogDisasm(true);
        }
        else {
            self->SetLogDisasm(false);
        }

        if (self->IsSymMapInitialised()) {
            static const tFuncNode* lastsym = nullptr;
            const tFuncNode* sym = self->FindSymbolByRuntime(address);
            if (sym && sym != lastsym) {
                printf("%s\n", sym->name.c_str());
                lastsym = sym;
            }
        }

        return true;
    };

    auto MemCb = [](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        //printf("MemCb 0x%p %d %d %d\n", (void*)address, type, size, value);

        if (!self || !uc || size == 0)
            return true;

        //////std::vector<uint8_t> bytes(size);
        //////if (uc_mem_read(uc, address, bytes.data(), size) != UC_ERR_OK) { // !! old and wrong
        //////	SetConsoleColor(3);
        //////	printf("[!] Failed to read bytes at 0x%p\n", (void*)address);
        //////	self->AddMemoryTo(address, size, UC_PROT_READ | UC_PROT_WRITE);
        //////	printf("[!] Created Region at 0x%p [%d]\n", (void*)address, size);
        //////	SetConsoleColor(1);
        //////	return true;
        //////}

        const bool isUnmapped =
            type == UC_MEM_READ_UNMAPPED ||
            type == UC_MEM_WRITE_UNMAPPED ||
            type == UC_MEM_FETCH_UNMAPPED;

        const bool isProt =
            type == UC_MEM_READ_PROT ||
            type == UC_MEM_WRITE_PROT ||
            type == UC_MEM_FETCH_PROT;

        const uintptr_t pageSize = 0x1000;
        const uintptr_t base = self->AlignDown(address, pageSize);
        const uintptr_t end = self->AlignUp(address + size, pageSize);
        const uintptr_t mapSize = end - base;

        if (isUnmapped)
        {
            SetConsoleColor(3);
            printf("[!] Unmapped access at 0x%p, mapping 0x%zx bytes from 0x%p size 0x%zx bytes\n", (void*)address, (size_t)mapSize, (void*)base, size);
            MboxSTD("Warn! isUnmapped", "MemCb");

            if (!self->AddMemoryTo(base, mapSize, UC_PROT_READ | UC_PROT_WRITE))
            {
                printf("[!] Failed to map region at 0x%p\n", (void*)base);
                SetConsoleColor(1);
                return false;
            }

            printf("[+] Created Region at 0x%p [0x%zx]\n", (void*)base, (size_t)mapSize);
            SetConsoleColor(1);

            { // custom
                self->CompareRegionsSnapshots(regionsBF, regionsAF);
                self->_CopyMemory(address, address, size); // maping equal in native proc // докопирую данные в которые оно лезет, где то зашит регион в vmctx
                self->DumpMemory(address, size); // uc copy result view
                MboxSTD("custom wait", "MemCb");
            }

            return true;
        }

        if (isProt)
        {
            SetConsoleColor(3);
            printf("[!] Protection fault at 0x%p, trying to relax protection\n", (void*)address);
            MboxSTD("Warn! isProt", "MemCb");

            if (!self->ChangeMemoryType(base, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC))
            {
                printf("[!] Failed to change protection at 0x%p\n", (void*)base);
                SetConsoleColor(1);
                return false;
            }

            SetConsoleColor(1);
            return true;
        }

        return true;
    };

    auto JmpCb = [](uc_engine* uc, uintptr_t from, uintptr_t to, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);

        //printf("JmpCb 0x%p %d\n", (void*)to, mnemonic);

        if (!self->IsModuleAddr(to) && !self->IsRetHaltOrNull(to)) {
            MboxSTD("module escape", "asm runner");
            return false;
        }

        return true;
    };

    runner.Initialise(true, false, false, true);      // disasm + memrw + runner logs
    runner.InitialiseSymMap("idasym.txt", 0x60F00000); // IDB base -> RVA map
    //runner.CopyModule(pStart, nSize);         // копируем модуль в Unicorn по тому же base
    runner.CopyModule("mdl.dll");
    runner.SetCallbacks(OpcodeCb, &runner, MemCb, &runner, JmpCb, &runner);
    //runner.TraceInstruction("C:\\trace.txt", reinterpret_cast<uintptr_t>(pEntry), 300); return; // автостарт

    // Пример брейка по адресу
    // runner.SetBreakpoint(reinterpret_cast<uintptr_t>(pEntry), [](AsmRunner*, uint64_t a){ printf("BP hit 0x%llx\n", (unsigned long long)a); }, true);

    printf("[*] entry=0x%p\n", pEntry);

    runner.Run(reinterpret_cast<uintptr_t>(pEntry), 300); // 0 = без лимита по шагам
    runner.Shutdown();
}

void TestUsage2()
{
    AsmRunner runner(false);
    void* pEntry = (void*)(0x60F2F0C0);
    void* pEntryArg = (void*)(0x615CDB58);

    //uintptr_t pStart = 0;
    //uintptr_t pEnd = 0;
    //uintptr_t nSize = 0;
    //runner.GetMappedModuleBounds("mdl.dll", pStart, pEnd, nSize);

    //if (nSize == 0 || pStart == 0)
    //{
    //    //MboxSTD("VMENTRY_UT_HK", "module not found");
    //    return;
    //}

    //printf("[%s] base=0x%p end=0x%p size=0x%zx\n", "mdl.dll", (void*)pStart, (void*)pEnd, (size_t)nSize);

    runner.Initialise(true, false, false, true);      // disasm + memrw + runner logs
    runner.InitialiseSymMap("idasym.txt", 0x60F00000); // IDB base -> RVA map
    //runner.CopyModule(pStart, nSize);         // копируем модуль в Unicorn по тому же base
    runner.CopyModule("mdl.dll");
    // if bInitUC false
    ////runner.SetStack();                        // отдельный stack region    // !!!!!! already in Init
    ////runner.SetFakeSehTid();                   // fs:0 / zero page заглушка // !!!!!! already in Init
    // runner.SetCallbacks(...);              // при желании свои callback'и

    // UC буфер 0x1000 под аргумент entrypoint
    //uintptr_t pEntryArg = runner.AddMemory(0x1000, UC_PROT_READ | UC_PROT_WRITE);
    //if (!pEntryArg)
    //{
    //	MboxSTD("VMENTRY_UT_HK", "alloc uc buffer failed");
    //	runner.Shutdown();
    //	return;
    //}

    runner.SetEntryPointStackArg(0, reinterpret_cast<uintptr_t>(pEntryArg));
    runner.SetRegister(UC_X86_REG_ECX, reinterpret_cast<uintptr_t>(pEntryArg)); // if thiscall-style ctx is needed

    //{ // diff test
    //    auto s1 = runner.MakeSnapshotS((uintptr_t)pEntry, 0x1000);
    //    char* buf = (char*)runner.DumpMemoryNTAlloc((uintptr_t)pEntry, 0x1000);
    //    buf[0] = 0xCC;
    //    buf[100] = 0xCC;
    //    runner._CopyMemory((uintptr_t)pEntry, (uintptr_t)buf, 0x1000);
    //    free(buf);
    //    auto s2 = runner.MakeSnapshotS((uintptr_t)pEntry, 0x1000);
    //    runner.CompareSnapshots(s1, s2);
    //    return;
    //}

    // Пример брейка по адресу
    // runner.SetBreakpoint(reinterpret_cast<uintptr_t>(pEntry), [](AsmRunner*, uint64_t a){ printf("BP hit 0x%llx\n", (unsigned long long)a); }, true);

    printf("[*] entry=0x%p\n", pEntry);
    //runner.DisassembleWithZydis(); // покажет первые инструкции модуля с именами

    runner.Run(reinterpret_cast<uintptr_t>(pEntry), 100); // 0 = без лимита по шагам
    runner.Shutdown();
}

void TestStackArgs()
{
    HMODULE hDll = LoadLibraryA("c_export_test_dll.dll");

    if (hDll == NULL)
    {
        printf("Failed to load DLL\n");
        return;
    }

    printf("DLL loaded successfully at address: %p\n", hDll);
    void* f = GetProcAddress(hDll, "_MyMemcpy@12");
    if (f == NULL) {
        printf("Function not found! Error: %d\n", GetLastError());
        return;
    }
    void* f2 = GetProcAddress(hDll, "_PrintMessage@4");
    if (f2 == NULL) {
        printf("_PrintMessage Function not found! Error: %d\n", GetLastError());
        return;
    }

    AsmRunner runner(false);
    auto OpcodeCb = [&pThemidaStart, &pThemidaEnd](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        //printf("OpcodeCb 0x%p (%d)\n", (void*)address, mnemonic);
        //self->DumpRegisters(true);
        if (self->IsInAddr(address, pThemidaStart, pThemidaEnd)) {
            SetConsoleColor(0); // red
        }
        else {
            SetConsoleColor(1);
        }

        if (self->GetInstructionCount() > /*5080*/110000) {
            self->SetLogDisasm(true);
        }
        else {
            self->SetLogDisasm(false);
        }

        if (self->IsSymMapInitialised()) {
            static const tFuncNode* lastsym = nullptr;
            const tFuncNode* sym = self->FindSymbolByRuntime(address);
            if (sym && sym != lastsym) {
                printf("%s\n", sym->name.c_str());
                lastsym = sym;
            }
        }

        return true;
    };

    auto MemCb = [](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        //printf("MemCb 0x%p %d %d %d\n", (void*)address, type, size, value);

        if (!self || !uc || size == 0)
            return true;

        //////std::vector<uint8_t> bytes(size);
        //////if (uc_mem_read(uc, address, bytes.data(), size) != UC_ERR_OK) { // !! old and wrong
        //////	SetConsoleColor(3);
        //////	printf("[!] Failed to read bytes at 0x%p\n", (void*)address);
        //////	self->AddMemoryTo(address, size, UC_PROT_READ | UC_PROT_WRITE);
        //////	printf("[!] Created Region at 0x%p [%d]\n", (void*)address, size);
        //////	SetConsoleColor(1);
        //////	return true;
        //////}

        const bool isUnmapped =
            type == UC_MEM_READ_UNMAPPED ||
            type == UC_MEM_WRITE_UNMAPPED ||
            type == UC_MEM_FETCH_UNMAPPED;

        const bool isProt =
            type == UC_MEM_READ_PROT ||
            type == UC_MEM_WRITE_PROT ||
            type == UC_MEM_FETCH_PROT;

        const uintptr_t pageSize = 0x1000;
        const uintptr_t base = self->AlignDown(address, pageSize);
        const uintptr_t end = self->AlignUp(address + size, pageSize);
        const uintptr_t mapSize = end - base;

        if (isUnmapped)
        {
            SetConsoleColor(3);
            printf("[!] Unmapped access at 0x%p, mapping 0x%zx bytes from 0x%p size 0x%zx bytes\n", (void*)address, (size_t)mapSize, (void*)base, size);
            MboxSTD("Warn! isUnmapped", "MemCb");

            if (!self->AddMemoryTo(base, mapSize, UC_PROT_READ | UC_PROT_WRITE))
            {
                printf("[!] Failed to map region at 0x%p\n", (void*)base);
                SetConsoleColor(1);
                return false;
            }

            printf("[+] Created Region at 0x%p [0x%zx]\n", (void*)base, (size_t)mapSize);
            SetConsoleColor(1);

            { // custom
                self->CompareRegionsSnapshots(regionsBF, regionsAF);
                self->_CopyMemory(address, address, size); // maping equal in native proc // докопирую данные в которые оно лезет, где то зашит регион в vmctx
                self->DumpMemory(address, size); // uc copy result view
                MboxSTD("custom wait", "MemCb");
            }

            return true;
        }

        if (isProt)
        {
            SetConsoleColor(3);
            printf("[!] Protection fault at 0x%p, trying to relax protection\n", (void*)address);
            MboxSTD("Warn! isProt", "MemCb");

            if (!self->ChangeMemoryType(base, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC))
            {
                printf("[!] Failed to change protection at 0x%p\n", (void*)base);
                SetConsoleColor(1);
                return false;
            }

            SetConsoleColor(1);
            return true;
        }

        return true;
    };

    auto JmpCb = [](uc_engine* uc, uintptr_t from, uintptr_t to, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);

        //printf("JmpCb 0x%p %d\n", (void*)to, mnemonic);

        if (!self->IsModuleAddr(to) && !self->IsRetHaltOrNull(to)) {
            MboxSTD("module escape", "asm runner");
            return false;
        }

        return true;
    };

    runner.Initialise(true, false, false, true);      // disasm + memrw + runner logs
    runner.CopyModule("c_export_test_dll.dll");
    runner.SetCallbacks(OpcodeCb, &runner, MemCb, &runner, JmpCb, &runner);
    const char* pArg = "AZAZIN";
    uintptr_t pEntryArg = runner.AddMemory((uintptr_t)pArg, strlen(pArg) + 1, UC_PROT_READ | UC_PROT_WRITE);
    uintptr_t pEntryArg2 = runner.AddMemory(strlen(pArg) + 1, UC_PROT_READ | UC_PROT_WRITE);
    printf("pEntryArg (src) = 0x%p\n", (void*)pEntryArg);
    printf("pEntryArg2 (dest) = 0x%p\n", (void*)pEntryArg2);
    char* buf = (char*)runner.DumpMemoryNTAlloc((uintptr_t)pEntryArg2, strlen(pArg) + 1);
    printf("bf from uc %s\n", buf);
    //MyMemcpy(void *dest, const void *src, unsigned int count)
    runner.SetEntryPointStackArg(0, pEntryArg2); // dst
    runner.SetEntryPointStackArg(1, pEntryArg); // src
    runner.SetEntryPointStackArg(2, strlen(pArg) + 1); // sz
    runner.Run(reinterpret_cast<uintptr_t>(f), 300); // 0 = без лимита по шагам
    buf = (char*)runner.DumpMemoryNTAlloc((uintptr_t)pEntryArg2, strlen(pArg) + 1);
    printf("af from uc %s\n", buf);
    runner.Shutdown();
    MboxSTD("halt", "hold");
}
#endif