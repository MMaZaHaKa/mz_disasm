#ifdef _WIN32 // AR_IDA_WS
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#endif

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
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")

#ifdef _M_X64
static constexpr bool kBuild64 = true;
#else
static constexpr bool kBuild64 = false;
#endif

AsmRunner::AsmRunner(bool bX64)
{
    Shutdown();

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
    if (!self) {
        printf("[!] HookCodeTrampoline: Error!\n");
        return;
    }
    self->_OnInstructionStep(uc, address, size, user_data);
}

bool AsmRunner::HookMemTrampoline(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
    auto* self = static_cast<AsmRunner*>(user_data);
    if (!self) {
        printf("[!] HookMemTrampoline: Error!\n");
        return false;
    }
    return self->_OnMemory(uc, type, address, size, value, user_data);
}

void AsmRunner::HookInsnTrampoline(uc_engine* uc, void* user_data)
{
    auto* hook = static_cast<tInsnHookNode*>(user_data);
    if (!hook || !hook->owner) {
        printf("[!] HookInsnTrampoline: Error! hook 0x%p, hook->owner 0x%p\n", hook, hook->owner);
        return;
    }

    hook->owner->_OnInsn(hook, uc);
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
#ifdef AR_SYSCALL_JUMP_CB
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_INTO:
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
        case ZYDIS_MNEMONIC_SYSEXIT:
        case ZYDIS_MNEMONIC_SYSRET:

        case ZYDIS_MNEMONIC_UD2:
        case ZYDIS_MNEMONIC_UD1:
        case ZYDIS_MNEMONIC_UD0:
        case ZYDIS_MNEMONIC_HLT:
#endif

            return true;
    }

    return false;
}

std::string AsmRunner::AnyIpTransferTag(ZydisMnemonic mn)
{
    switch (mn)
    {
        // Прямые переходы / вызовы
        case ZYDIS_MNEMONIC_CALL:   return "call";
        case ZYDIS_MNEMONIC_JMP:    return "jmp";

        // Условные переходы
        case ZYDIS_MNEMONIC_JB:     return "jb";
        case ZYDIS_MNEMONIC_JBE:    return "jbe";
        case ZYDIS_MNEMONIC_JNB:    return "jnb";
        case ZYDIS_MNEMONIC_JNBE:   return "jnbe";
        case ZYDIS_MNEMONIC_JL:     return "jl";
        case ZYDIS_MNEMONIC_JLE:    return "jle";
        case ZYDIS_MNEMONIC_JNL:    return "jnl";
        case ZYDIS_MNEMONIC_JNLE:   return "jnle";
        case ZYDIS_MNEMONIC_JNO:    return "jno";
        case ZYDIS_MNEMONIC_JNP:    return "jnp";
        case ZYDIS_MNEMONIC_JNS:    return "jns";
        case ZYDIS_MNEMONIC_JNZ:    return "jnz";
        case ZYDIS_MNEMONIC_JO:     return "jo";
        case ZYDIS_MNEMONIC_JP:     return "jp";
        case ZYDIS_MNEMONIC_JS:     return "js";
        case ZYDIS_MNEMONIC_JZ:     return "jz";

        // Счётчик/цикл
        case ZYDIS_MNEMONIC_JCXZ:   return "jcxz";
        case ZYDIS_MNEMONIC_JECXZ:  return "jecxz";
        case ZYDIS_MNEMONIC_JRCXZ:  return "jrcxz";
        case ZYDIS_MNEMONIC_JKNZD:  return "jknzd";
        case ZYDIS_MNEMONIC_JKZD:   return "jkzd";
        case ZYDIS_MNEMONIC_LOOP:   return "loop";
        case ZYDIS_MNEMONIC_LOOPE:  return "loope";
        case ZYDIS_MNEMONIC_LOOPNE: return "loopne";

        // Возвраты
        case ZYDIS_MNEMONIC_RET:    return "ret";
        case ZYDIS_MNEMONIC_IRET:   return "iret";
        case ZYDIS_MNEMONIC_IRETD:  return "iretd";
        case ZYDIS_MNEMONIC_IRETQ:  return "iretq";

        // Прерывания / системные переходы
#ifdef AR_SYSCALL_JUMP_CB
        case ZYDIS_MNEMONIC_INT:    return "int";
        case ZYDIS_MNEMONIC_INT1:   return "int1";
        case ZYDIS_MNEMONIC_INT3:   return "int3";
        case ZYDIS_MNEMONIC_INTO:   return "into";
        case ZYDIS_MNEMONIC_SYSCALL:return "syscall";
        case ZYDIS_MNEMONIC_SYSENTER:return "sysenter";
        case ZYDIS_MNEMONIC_SYSEXIT:return "sysexit";
        case ZYDIS_MNEMONIC_SYSRET: return "sysret";

        case ZYDIS_MNEMONIC_UD2:    return "ud2";
        case ZYDIS_MNEMONIC_UD1:    return "ud1";
        case ZYDIS_MNEMONIC_UD0:    return "ud0";
        case ZYDIS_MNEMONIC_HLT:    return "hlt";
#endif
    }

    return "";
}

bool AsmRunner::IsSystem(ZydisMnemonic mn)
{
    switch (mn)
    {
        // Прерывания / системные переходы
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_INTO:
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
        case ZYDIS_MNEMONIC_SYSEXIT:
        case ZYDIS_MNEMONIC_SYSRET:

        case ZYDIS_MNEMONIC_UD2:
        case ZYDIS_MNEMONIC_UD1:
        case ZYDIS_MNEMONIC_UD0:
        case ZYDIS_MNEMONIC_HLT:
            return true;
    }

    return false;
}

bool AsmRunner::IsInsnAllowedZydis(ZydisMnemonic mn)
{
    switch (mn)
    {
        case ZYDIS_MNEMONIC_IN:
        case ZYDIS_MNEMONIC_OUT:
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
        case ZYDIS_MNEMONIC_CPUID:

        // ARM64
        //case ZYDIS_MNEMONIC_MRS:
        //case ZYDIS_MNEMONIC_MSR:
        //case ZYDIS_MNEMONIC_SYS:
        //case ZYDIS_MNEMONIC_SYSL:
            return true;
    }

    return false;
}

bool AsmRunner::IsInsnAllowed(uintptr_t insn)
{
    switch (insn)
    { // see also SetAllInsnCB list
        case UC_X86_INS_IN:
        case UC_X86_INS_OUT:
        case UC_X86_INS_SYSCALL:
        case UC_X86_INS_SYSENTER:
        case UC_X86_INS_CPUID:
        
        // ARM64
        case UC_ARM64_INS_MRS:
        case UC_ARM64_INS_MSR:
        case UC_ARM64_INS_SYS:
        case UC_ARM64_INS_SYSL:
            return true;
    }

    return false;
}

bool AsmRunner::ResolveFlagsConditional(ZydisMnemonic mn, bool& bOutCondMn, bool& bOutInvMn)
{
    bOutCondMn = false;
    bOutInvMn = false;

    if (!m_uc)
        return false;

    const bool cf = GetFlag(CARRY_FLAG);
    const bool pf = GetFlag(PARITY_FLAG);
    const bool zf = GetFlag(ZERO_FLAG);
    const bool sf = GetFlag(SIGN_FLAG);
    const bool of = GetFlag(OVERFLOW_FLAG);

    auto readCounter = [&]() -> uintptr_t
    {
        uintptr_t v = 0;
        if (uc_reg_read(m_uc, CxReg(), &v) != UC_ERR_OK)
            return 0;

        if (!m_bX64)
            v = static_cast<uint32_t>(v);

        return v;
    };

    switch (mn)
    {
        // CF
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JNBE:
            bOutCondMn = true;
            bOutInvMn = (mn == ZYDIS_MNEMONIC_JNB || mn == ZYDIS_MNEMONIC_JNBE);
            if (mn == ZYDIS_MNEMONIC_JB)   return cf;
            if (mn == ZYDIS_MNEMONIC_JNB)  return !cf;
            if (mn == ZYDIS_MNEMONIC_JBE)  return cf || zf;
            return !cf && !zf; // JNBE

        // ZF
        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_JNZ:
            bOutCondMn = true;
            bOutInvMn = (mn == ZYDIS_MNEMONIC_JNZ);
            return (mn == ZYDIS_MNEMONIC_JZ) ? zf : !zf;

        // SF
        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JNS:
            bOutCondMn = true;
            bOutInvMn = (mn == ZYDIS_MNEMONIC_JNS);
            return (mn == ZYDIS_MNEMONIC_JS) ? sf : !sf;

        // PF
        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JNP:
            bOutCondMn = true;
            bOutInvMn = (mn == ZYDIS_MNEMONIC_JNP);
            return (mn == ZYDIS_MNEMONIC_JP) ? pf : !pf;

        // OF
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JNO:
            bOutCondMn = true;
            bOutInvMn = (mn == ZYDIS_MNEMONIC_JNO);
            return (mn == ZYDIS_MNEMONIC_JO) ? of : !of;

        // signed compare
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNLE:
            bOutCondMn = true;
            bOutInvMn = (mn == ZYDIS_MNEMONIC_JNL || mn == ZYDIS_MNEMONIC_JNLE);
            if (mn == ZYDIS_MNEMONIC_JL)   return sf != of;
            if (mn == ZYDIS_MNEMONIC_JNL)  return sf == of;
            if (mn == ZYDIS_MNEMONIC_JLE)  return zf || (sf != of);
            return !zf && (sf == of); // JNLE

        // counter-based branches
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_LOOP:
        case ZYDIS_MNEMONIC_LOOPE:
        case ZYDIS_MNEMONIC_LOOPNE:
        {
            bOutCondMn = true;
            bOutInvMn = false;

            const uintptr_t cx = readCounter();

            switch (mn)
            {
                case ZYDIS_MNEMONIC_JCXZ:
                case ZYDIS_MNEMONIC_JECXZ:
                case ZYDIS_MNEMONIC_JRCXZ:
                    return cx == 0;

                case ZYDIS_MNEMONIC_LOOP:
                    // LOOP: dec counter; jnz
                    return cx != 1;

                case ZYDIS_MNEMONIC_LOOPE:
                    return (cx != 1) && zf;

                case ZYDIS_MNEMONIC_LOOPNE:
                    bOutInvMn = true;
                    return (cx != 1) && !zf;

                default:
                    return false;
            }
        }

        default:
            return false;
    }
}

uintptr_t AsmRunner::ExtractAnyIpTransferReturn(ZydisMnemonic mn, uintptr_t from, uint32_t size) // from - curr transfer op
{
    const uintptr_t fallback = (from + size);

    if (!m_uc || !m_bInitedStack)
        return fallback;

    uintptr_t retaddr = 0;

    switch (mn)
    {
        case ZYDIS_MNEMONIC_CALL:
            // call already has a canonical return address
            return fallback;

        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
        case ZYDIS_MNEMONIC_IRETQ:
            // push ret; push func; ret  -> [to, return]
            (void)StackPop(retaddr); // to
            if (StackPop(retaddr)) // return
                return retaddr;
            return fallback;

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
#ifdef AR_SYSCALL_JUMP_CB
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_INTO:
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
        case ZYDIS_MNEMONIC_SYSEXIT:
        case ZYDIS_MNEMONIC_SYSRET:
        case ZYDIS_MNEMONIC_UD2:
        case ZYDIS_MNEMONIC_UD1:
        case ZYDIS_MNEMONIC_UD0:
        case ZYDIS_MNEMONIC_HLT:
#endif
            // push ret; jmp func  -> [ret]
            if (StackPop(retaddr)) // return
                return retaddr;
            return fallback;

        default:
            return fallback;
    }
}

#if 0
uintptr_t AsmRunner::CalcAnyIpTransferReturn(ZydisMnemonic mn, uintptr_t from, uint32_t size) // from - curr transfer op
{
    const uintptr_t fallback = (from + size);

    if (!m_uc || !m_bInitedStack)
        return fallback;

    uintptr_t retaddr = 0;
    const auto try_stack_top = [&](uint32_t idx, uintptr_t& out) -> bool
    {
        out = 0;
        return StackPeek(out, idx);
    };

    switch (mn)
    {
        case ZYDIS_MNEMONIC_CALL:
            // call already has a canonical return address
            return fallback;

        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
        case ZYDIS_MNEMONIC_IRETQ:
            // push ret; push func; ret  -> [to, return]
            if (try_stack_top(1, retaddr))
                return retaddr;
            if (try_stack_top(0, retaddr))
                return retaddr;
            return fallback;

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
#ifdef AR_SYSCALL_JUMP_CB
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_INTO:
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
        case ZYDIS_MNEMONIC_SYSEXIT:
        case ZYDIS_MNEMONIC_SYSRET:
        case ZYDIS_MNEMONIC_UD2:
        case ZYDIS_MNEMONIC_UD1:
        case ZYDIS_MNEMONIC_UD0:
        case ZYDIS_MNEMONIC_HLT:
#endif
            // push ret; jmp func  -> [ret]
            if (try_stack_top(0, retaddr))
                return retaddr;
            return fallback;

        default:
            return fallback;
    }
}
#endif

#ifndef AR_DEBUG
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
            return ResolveDirectBranchTarget(uc, instr, ops, curPc, outTarget);

        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
        case ZYDIS_MNEMONIC_IRETQ:
        {
            uintptr_t sp = CurrentSp(uc);
            uintptr_t ret = 0;
            const size_t ptrSize = PointerSize();

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

bool AsmRunner::ReadZydisRegisterValue(uc_engine* uc, ZydisRegister reg, uintptr_t& out) const
{
    if (!uc)
        return false;

    auto readU = [&](uint32_t ucReg, size_t truncBytes = sizeof(uintptr_t)) -> bool
    {
        uintptr_t v = 0;
        if (uc_reg_read(uc, ucReg, &v) != UC_ERR_OK)
            return false;

        if (truncBytes == 4)
            v = static_cast<uint32_t>(v);

        out = v;
        return true;
    };

    switch (reg)
    {
        case ZYDIS_REGISTER_RIP:
        case ZYDIS_REGISTER_EIP:
            out = CurrentPc(uc);
            return true;

        case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX:
            return readU(m_bX64 ? UC_X86_REG_RAX : UC_X86_REG_EAX, (reg == ZYDIS_REGISTER_EAX) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX:
            return readU(m_bX64 ? UC_X86_REG_RBX : UC_X86_REG_EBX, (reg == ZYDIS_REGISTER_EBX) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX:
            return readU(m_bX64 ? UC_X86_REG_RCX : UC_X86_REG_ECX, (reg == ZYDIS_REGISTER_ECX) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX:
            return readU(m_bX64 ? UC_X86_REG_RDX : UC_X86_REG_EDX, (reg == ZYDIS_REGISTER_EDX) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI:
            return readU(m_bX64 ? UC_X86_REG_RSI : UC_X86_REG_ESI, (reg == ZYDIS_REGISTER_ESI) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI:
            return readU(m_bX64 ? UC_X86_REG_RDI : UC_X86_REG_EDI, (reg == ZYDIS_REGISTER_EDI) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP:
            return readU(m_bX64 ? UC_X86_REG_RSP : UC_X86_REG_ESP, (reg == ZYDIS_REGISTER_ESP) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP:
            return readU(m_bX64 ? UC_X86_REG_RBP : UC_X86_REG_EBP, (reg == ZYDIS_REGISTER_EBP) ? 4 : sizeof(uintptr_t));

        case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:  return readU(UC_X86_REG_R8, (reg == ZYDIS_REGISTER_R8D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:  return readU(UC_X86_REG_R9, (reg == ZYDIS_REGISTER_R9D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: return readU(UC_X86_REG_R10, (reg == ZYDIS_REGISTER_R10D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: return readU(UC_X86_REG_R11, (reg == ZYDIS_REGISTER_R11D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: return readU(UC_X86_REG_R12, (reg == ZYDIS_REGISTER_R12D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: return readU(UC_X86_REG_R13, (reg == ZYDIS_REGISTER_R13D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: return readU(UC_X86_REG_R14, (reg == ZYDIS_REGISTER_R14D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: return readU(UC_X86_REG_R15, (reg == ZYDIS_REGISTER_R15D) ? 4 : sizeof(uintptr_t));

        default:
            return false;
    }
}

bool AsmRunner::ResolveMemoryOperandAddress(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand& op, uintptr_t insnAddr, uintptr_t& outAddr) const
{
    if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)
        return false;

    uintptr_t ea = 0;
    bool hasAny = false;

    if (op.mem.base != ZYDIS_REGISTER_NONE)
    {
        if (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP)
        {
            ea += insnAddr + instr.length;
            hasAny = true;
        }
        else
        {
            uintptr_t base = 0;
            if (!ReadZydisRegisterValue(uc, op.mem.base, base))
                return false;
            ea += base;
            hasAny = true;
        }
    }

    if (op.mem.index != ZYDIS_REGISTER_NONE)
    {
        uintptr_t idx = 0;
        if (!ReadZydisRegisterValue(uc, op.mem.index, idx))
            return false;

        ea += idx * static_cast<uintptr_t>(op.mem.scale);
        hasAny = true;
    }

    if (op.mem.disp.has_displacement)
    {
        ea += static_cast<int64_t>(op.mem.disp.value);
        hasAny = true;
    }

    if (!hasAny)
        return false;

    outAddr = ea;
    return true;
}

bool AsmRunner::ResolveDirectBranchTarget(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t insnAddr, uintptr_t& outTarget) const
{
    for (uint32_t i = 0; i < instr.operand_count_visible; ++i)
    {
        const auto& op = ops[i];

        switch (op.type)
        {
            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                if (op.imm.is_relative)
                {
                    outTarget = static_cast<uintptr_t>(insnAddr + instr.length + op.imm.value.s);
                    return true;
                }
                break;

            case ZYDIS_OPERAND_TYPE_REGISTER:
            {
                uintptr_t v = 0;
                if (ReadZydisRegisterValue(uc, op.reg.value, v))
                {
                    outTarget = v;
                    return true;
                }
                break;
            }

            case ZYDIS_OPERAND_TYPE_MEMORY:
            {
                uintptr_t ea = 0;
                if (!ResolveMemoryOperandAddress(uc, instr, op, insnAddr, ea))
                    break;

                const size_t ptrSize = (op.size >= 8) ? static_cast<size_t>(op.size / 8) : (m_bX64 ? 8 : 4);
                uintptr_t v = 0;
                if (uc_mem_read(uc, ea, &v, ptrSize) == UC_ERR_OK)
                {
                    if (!m_bX64)
                        v = static_cast<uint32_t>(v);
                    else if (ptrSize == 4)
                        v = static_cast<uint32_t>(v);

                    outTarget = v;
                    return true;
                }
                else {
                    if (m_bLogRunner)
                        Log("ResolveDirectBranchTarget: Failed to read %zu bytes from address 0x%p (ptrSize=%zu, op.size=%d)",
                            ptrSize, (void*)ea, ptrSize, op.size);
                    MboxSTD("ResolveDirectBranchTarget: Error Read", AR_SNAME);
                }
                break;
            }

            case ZYDIS_OPERAND_TYPE_POINTER:
                outTarget = static_cast<uintptr_t>(op.ptr.offset);
                return true;

            default:
                break;
        }
    }

    return false;
}
#else
bool AsmRunner::TryResolveIpTransfer(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t curPc, uintptr_t& outTarget)
{
    Log("[TryResolveIpTransfer] ENTER: mnemonic=0x%x, curPc=0x%llx\n", instr.mnemonic, (unsigned long long)curPc);

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
            Log("[TryResolveIpTransfer] Branch/Call/Jump instruction -> calling ResolveDirectBranchTarget\n");
            return ResolveDirectBranchTarget(uc, instr, ops, curPc, outTarget);

        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
        case ZYDIS_MNEMONIC_IRETQ:
        {
            Log("[TryResolveIpTransfer] Return instruction detected\n");
            uintptr_t sp = CurrentSp(uc);
            uintptr_t ret = 0;
            const size_t ptrSize = PointerSize();

            Log("[TryResolveIpTransfer] SP=0x%llx, ptrSize=%zu, m_bX64=%d\n",
                (unsigned long long)sp, ptrSize, m_bX64);

            if (uc_mem_read(uc, sp, &ret, ptrSize) == UC_ERR_OK)
            {
                Log("[TryResolveIpTransfer] Read return address from stack: 0x%llx\n", (unsigned long long)ret);
                if (!m_bX64)
                {
                    uint32_t oldRet = (uint32_t)ret;
                    ret = static_cast<uint32_t>(ret);
                    Log("[TryResolveIpTransfer] Truncated to 32-bit: 0x%x -> 0x%llx\n", oldRet, (unsigned long long)ret);
                }

                outTarget = ret;
                Log("[TryResolveIpTransfer] Return target=0x%llx\n", (unsigned long long)outTarget);
                return true;
            }
            Log("[TryResolveIpTransfer] FAILED to read return address from stack!\n");
            return false;
        }

        default:
            Log("[TryResolveIpTransfer] Unknown mnemonic, returning false\n");
            return false;
    }
}

bool AsmRunner::ReadZydisRegisterValue(uc_engine* uc, ZydisRegister reg, uintptr_t& out) const
{
    Log("[ReadZydisRegisterValue] ENTER: reg=%d, m_bX64=%d\n", reg, m_bX64);

    if (!uc)
    {
        Log("[ReadZydisRegisterValue] ERROR: uc is NULL\n");
        return false;
    }

    auto readU = [&](uint32_t ucReg, size_t truncBytes = sizeof(uintptr_t)) -> bool
    {
        Log("[ReadZydisRegisterValue] readU: ucReg=0x%x, truncBytes=%zu\n", ucReg, truncBytes);
        uintptr_t v = 0;
        if (uc_reg_read(uc, ucReg, &v) != UC_ERR_OK)
        {
            Log("[ReadZydisRegisterValue] readU: uc_reg_read FAILED for ucReg=0x%x\n", ucReg);
            return false;
        }

        Log("[ReadZydisRegisterValue] readU: raw value=0x%llx\n", (unsigned long long)v);

        if (truncBytes == 4)
        {
            uint32_t oldV = (uint32_t)v;
            v = static_cast<uint32_t>(v);
            Log("[ReadZydisRegisterValue] readU: truncated to 32-bit: 0x%x -> 0x%llx\n", oldV, (unsigned long long)v);
        }

        out = v;
        return true;
    };

    switch (reg)
    {
        case ZYDIS_REGISTER_RIP:
        case ZYDIS_REGISTER_EIP:
            out = CurrentPc(uc);
            Log("[ReadZydisRegisterValue] RIP/EIP: CurrentPc=0x%llx\n", (unsigned long long)out);
            return true;

        case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX:
            Log("[ReadZydisRegisterValue] Reading RAX/EAX\n");
            return readU(m_bX64 ? UC_X86_REG_RAX : UC_X86_REG_EAX, (reg == ZYDIS_REGISTER_EAX) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX:
            Log("[ReadZydisRegisterValue] Reading RBX/EBX\n");
            return readU(m_bX64 ? UC_X86_REG_RBX : UC_X86_REG_EBX, (reg == ZYDIS_REGISTER_EBX) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX:
            Log("[ReadZydisRegisterValue] Reading RCX/ECX\n");
            return readU(m_bX64 ? UC_X86_REG_RCX : UC_X86_REG_ECX, (reg == ZYDIS_REGISTER_ECX) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX:
            Log("[ReadZydisRegisterValue] Reading RDX/EDX\n");
            return readU(m_bX64 ? UC_X86_REG_RDX : UC_X86_REG_EDX, (reg == ZYDIS_REGISTER_EDX) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI:
            Log("[ReadZydisRegisterValue] Reading RSI/ESI\n");
            return readU(m_bX64 ? UC_X86_REG_RSI : UC_X86_REG_ESI, (reg == ZYDIS_REGISTER_ESI) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI:
            Log("[ReadZydisRegisterValue] Reading RDI/EDI\n");
            return readU(m_bX64 ? UC_X86_REG_RDI : UC_X86_REG_EDI, (reg == ZYDIS_REGISTER_EDI) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP:
            Log("[ReadZydisRegisterValue] Reading RSP/ESP\n");
            return readU(m_bX64 ? UC_X86_REG_RSP : UC_X86_REG_ESP, (reg == ZYDIS_REGISTER_ESP) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP:
            Log("[ReadZydisRegisterValue] Reading RBP/EBP\n");
            return readU(m_bX64 ? UC_X86_REG_RBP : UC_X86_REG_EBP, (reg == ZYDIS_REGISTER_EBP) ? 4 : sizeof(uintptr_t));

        case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:
            Log("[ReadZydisRegisterValue] Reading R8/R8D\n");
            return readU(UC_X86_REG_R8, (reg == ZYDIS_REGISTER_R8D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:
            Log("[ReadZydisRegisterValue] Reading R9/R9D\n");
            return readU(UC_X86_REG_R9, (reg == ZYDIS_REGISTER_R9D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D:
            Log("[ReadZydisRegisterValue] Reading R10/R10D\n");
            return readU(UC_X86_REG_R10, (reg == ZYDIS_REGISTER_R10D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D:
            Log("[ReadZydisRegisterValue] Reading R11/R11D\n");
            return readU(UC_X86_REG_R11, (reg == ZYDIS_REGISTER_R11D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D:
            Log("[ReadZydisRegisterValue] Reading R12/R12D\n");
            return readU(UC_X86_REG_R12, (reg == ZYDIS_REGISTER_R12D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D:
            Log("[ReadZydisRegisterValue] Reading R13/R13D\n");
            return readU(UC_X86_REG_R13, (reg == ZYDIS_REGISTER_R13D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D:
            Log("[ReadZydisRegisterValue] Reading R14/R14D\n");
            return readU(UC_X86_REG_R14, (reg == ZYDIS_REGISTER_R14D) ? 4 : sizeof(uintptr_t));
        case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D:
            Log("[ReadZydisRegisterValue] Reading R15/R15D\n");
            return readU(UC_X86_REG_R15, (reg == ZYDIS_REGISTER_R15D) ? 4 : sizeof(uintptr_t));

        default:
            Log("[ReadZydisRegisterValue] UNKNOWN register: %d\n", reg);
            return false;
    }
}

bool AsmRunner::ResolveMemoryOperandAddress(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand& op, uintptr_t insnAddr, uintptr_t& outAddr) const
{
    Log("[ResolveMemoryOperandAddress] ENTER: insnAddr=0x%llx, op.type=%d\n", (unsigned long long)insnAddr, op.type);

    if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)
    {
        Log("[ResolveMemoryOperandAddress] Not a memory operand, returning false\n");
        return false;
    }

    uintptr_t ea = 0;
    bool hasAny = false;

    Log("[ResolveMemoryOperandAddress] base=%d, index=%d, scale=%d, disp=%lld\n",
        op.mem.base, op.mem.index, op.mem.scale, (long long)op.mem.disp.value);

    if (op.mem.base != ZYDIS_REGISTER_NONE)
    {
        if (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP)
        {
            ea += insnAddr + instr.length;
            Log("[ResolveMemoryOperandAddress] RIP-relative: insnAddr=0x%llx, instr.length=%d, ea=0x%llx\n",
                (unsigned long long)insnAddr, instr.length, (unsigned long long)ea);
            hasAny = true;
        }
        else
        {
            uintptr_t base = 0;
            Log("[ResolveMemoryOperandAddress] Reading base register\n");
            if (!ReadZydisRegisterValue(uc, op.mem.base, base))
            {
                Log("[ResolveMemoryOperandAddress] FAILED to read base register\n");
                return false;
            }
            ea += base;
            Log("[ResolveMemoryOperandAddress] base=0x%llx, ea now=0x%llx\n", (unsigned long long)base, (unsigned long long)ea);
            hasAny = true;
        }
    }

    if (op.mem.index != ZYDIS_REGISTER_NONE)
    {
        uintptr_t idx = 0;
        Log("[ResolveMemoryOperandAddress] Reading index register\n");
        if (!ReadZydisRegisterValue(uc, op.mem.index, idx))
        {
            Log("[ResolveMemoryOperandAddress] FAILED to read index register\n");
            return false;
        }

        uintptr_t scaledIdx = idx * static_cast<uintptr_t>(op.mem.scale);
        ea += scaledIdx;
        Log("[ResolveMemoryOperandAddress] idx=0x%llx, scale=%d, scaled=0x%llx, ea now=0x%llx\n",
            (unsigned long long)idx, op.mem.scale, (unsigned long long)scaledIdx, (unsigned long long)ea);
        hasAny = true;
    }

    if (op.mem.disp.has_displacement)
    {
        ea += static_cast<int64_t>(op.mem.disp.value);
        Log("[ResolveMemoryOperandAddress] Added displacement %lld, ea=0x%llx\n",
            (long long)op.mem.disp.value, (unsigned long long)ea);
        hasAny = true;
    }

    if (!hasAny)
    {
        Log("[ResolveMemoryOperandAddress] No address components found!\n");
        return false;
    }

    outAddr = ea;
    Log("[ResolveMemoryOperandAddress] Final address=0x%llx\n", (unsigned long long)outAddr);
    return true;
}

bool AsmRunner::ResolveDirectBranchTarget(uc_engine* uc, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* ops, uintptr_t insnAddr, uintptr_t& outTarget) const
{
    Log("[ResolveDirectBranchTarget] ENTER: insnAddr=0x%llx, operand_count=%d\n",
        (unsigned long long)insnAddr, instr.operand_count_visible);

    for (uint32_t i = 0; i < instr.operand_count_visible; ++i)
    {
        const auto& op = ops[i];
        Log("[ResolveDirectBranchTarget] Processing operand %d: type=%d\n", i, op.type);

        switch (op.type)
        {
            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                Log("[ResolveDirectBranchTarget] Immediate operand: is_relative=%d, value.s=%lld\n",
                    op.imm.is_relative, (long long)op.imm.value.s);
                if (op.imm.is_relative)
                {
                    outTarget = static_cast<uintptr_t>(insnAddr + instr.length + op.imm.value.s);
                    Log("[ResolveDirectBranchTarget] Relative branch: 0x%llx + %d + %lld = 0x%llx\n",
                        (unsigned long long)insnAddr, instr.length, (long long)op.imm.value.s, (unsigned long long)outTarget);
                    return true;
                }
                break;

            case ZYDIS_OPERAND_TYPE_REGISTER:
                Log("[ResolveDirectBranchTarget] Register operand: reg=%d\n", op.reg.value);
                {
                    uintptr_t v = 0;
                    if (ReadZydisRegisterValue(uc, op.reg.value, v))
                    {
                        outTarget = v;
                        Log("[ResolveDirectBranchTarget] Register jump: target=0x%llx\n", (unsigned long long)outTarget);
                        return true;
                    }
                    Log("[ResolveDirectBranchTarget] FAILED to read register value\n");
                    break;
                }

            case ZYDIS_OPERAND_TYPE_MEMORY:
                Log("[ResolveDirectBranchTarget] Memory operand: size=%d\n", op.size);
                {
                    uintptr_t ea = 0;
                    if (!ResolveMemoryOperandAddress(uc, instr, op, insnAddr, ea))
                    {
                        Log("[ResolveDirectBranchTarget] FAILED to resolve memory address\n");
                        break;
                    }

                    const size_t ptrSize = (op.size >= 8) ? static_cast<size_t>(op.size / 8) : (m_bX64 ? 8 : 4);
                    Log("[ResolveDirectBranchTarget] Reading from address 0x%llx, ptrSize=%zu\n", (unsigned long long)ea, ptrSize);

                    uintptr_t v = 0;
                    if (uc_mem_read(uc, ea, &v, ptrSize) == UC_ERR_OK)
                    {
                        Log("[ResolveDirectBranchTarget] Raw read value=0x%llx\n", (unsigned long long)v);

                        if (!m_bX64)
                        {
                            uint32_t oldV = (uint32_t)v;
                            v = static_cast<uint32_t>(v);
                            Log("[ResolveDirectBranchTarget] 32-bit mode, truncated: 0x%x -> 0x%llx\n", oldV, (unsigned long long)v);
                        }
                        else if (ptrSize == 4)
                        {
                            uint32_t oldV = (uint32_t)v;
                            v = static_cast<uint32_t>(v);
                            Log("[ResolveDirectBranchTarget] 64-bit mode but reading 32-bit ptr, truncated: 0x%x -> 0x%llx\n", oldV, (unsigned long long)v);
                        }

                        outTarget = v;
                        Log("[ResolveDirectBranchTarget] Memory jump: target=0x%llx\n", (unsigned long long)outTarget);
                        return true;
                    }
                    else {
                        if (m_bLogRunner)
                            Log("ResolveDirectBranchTarget: Failed to read %zu bytes from address 0x%p (ptrSize=%zu, op.size=%d)",
                                ptrSize, (void*)ea, ptrSize, op.size);
                        MboxSTD("ResolveDirectBranchTarget: Error Read", AR_SNAME);
                    }

                    Log("[ResolveDirectBranchTarget] FAILED to read from memory at 0x%llx\n", (unsigned long long)ea);
                    break;
                }

            case ZYDIS_OPERAND_TYPE_POINTER:
                Log("[ResolveDirectBranchTarget] Pointer operand: offset=0x%llx, segment=0x%x\n",
                    (unsigned long long)op.ptr.offset, op.ptr.segment);
                outTarget = static_cast<uintptr_t>(op.ptr.offset);
                return true;

            default:
                Log("[ResolveDirectBranchTarget] Unhandled operand type: %d\n", op.type);
                break;
        }
    }

    Log("[ResolveDirectBranchTarget] FAILED to resolve target\n");
    return false;
}
#endif

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
    m_memMap[emu_base] = { mapSize, UC_PROT_ALL };

    err = uc_mem_write(m_uc, emu_base, reinterpret_cast<void*>(real_base), size);
    if (err != UC_ERR_OK) {
        if (m_bLogRunner)
            Log("[!] Write to emulator error: %s", uc_strerror(err));
        return false;
    }

    //if (m_bLogRunner)
    //{
    //    Log("[+] Copied %zu bytes", static_cast<size_t>(size));
    //    Log("pStart: 0x%p", (void*)real_base);
    //    Log("Size:   0x%zx (%zu MB)", static_cast<size_t>(size), static_cast<size_t>(size / (1024 * 1024)));
    //}

    return true;
}

void AsmRunner::UpdateDeadzoneIC(uintptr_t currentIC, uintptr_t address)
{
    for (size_t i = 0; i < m_deadzonesIC.size(); ++i) {
        const auto& dz = m_deadzonesIC[i];
        if (currentIC >= dz.startIC && currentIC <= dz.endIC)
        {
            if (!m_bInDeadzoneIC) { // entry
                if (m_bLogRunner)
                    Log("[!] Warn! ENTERING INTO DEAD ZONE %d-%d [IC %zu] pc 0x%p ( +0x%p)",
                        dz.startIC, dz.endIC, static_cast<size_t>(m_instrCount), (void*)address, (void*)(address - m_modStart));
                if (dz.showEnterMessage)
                    MboxSTD("Warn! ENTERING INTO DEAD ZONE! No CB/HOOKS other than BP will work!", AR_SNAME);
            }

            m_bInDeadzoneIC = true;
            m_currentDeadzoneICIndex = static_cast<int32_t>(i);
            return;
        }
    }

    m_bInDeadzoneIC = false;
    m_currentDeadzoneICIndex = -1;
}

AsmRunner::tDeadzoneIC* AsmRunner::GetCurrentDeadzoneIC()
{
    if (!m_bInDeadzoneIC)
        return nullptr;

    if (m_currentDeadzoneICIndex < 0)
        return nullptr;

    const size_t idx = static_cast<size_t>(m_currentDeadzoneICIndex);
    if (idx >= m_deadzonesIC.size())
        return nullptr;

    return &m_deadzonesIC[idx];
}

uintptr_t AsmRunner::GetFlsValue(uintptr_t index) {
    if (index < m_FlsSlots.size()) {
        return m_FlsSlots[index];
    }
    return 0;
}

void AsmRunner::SetFlsValue(uintptr_t index, uintptr_t value) {
    if (index >= m_FlsSlots.size()) {
        m_FlsSlots.resize(index + 1, 0);
    }
    m_FlsSlots[index] = value;
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
#if 0
        CopyNTSeh();
        CopyNTStack();
#else
        SetTeb();
        SetStack();
#endif
        //InitialiseSegmentRegisters();
    }

    m_bInitialised = true;
    m_bPaused = false;
    m_bStopped = false;
    m_instrCount = 0;
    m_allocCursor = m_allocBase;

#ifdef AR_NTCORE_PATCH
    //InstallDangerNativeCoreFixes();
#endif

    if (m_bLogRunner) {
        Log("[*] AsmRunner initialised (%s)", m_bX64 ? "x64" : "x86");
    }
}

void AsmRunner::Shutdown()
{
    if (m_bLogRunner) {
        Log("[!] Shutdown!");
    }

    if (m_uc) {
        if (m_hkCode) {
            uc_hook_del(m_uc, m_hkCode);
            m_hkCode = 0;
        }
        if (m_hkMem) {
            uc_hook_del(m_uc, m_hkMem);
            m_hkMem = 0;
        }
        RemoveAllInsnCB();
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
    m_memMap.clear();
    m_breakpoints.clear();
    m_bUsingBp = false;
    m_bUsingBpCodeSizeRange = false;
    m_bInitedStack = false;
    m_bInitedSehFS = false;
    m_bDisasmAfterCB = false;
    m_bDisasmRVA = false;
    m_DisasmCustomASLR = 0;
    m_DisasmICNotice = 0;
    m_DisasmSepGroup = 0;
    m_anyJmpHooks.clear();
    m_iat.clear();
    exportsENV.clear();
    m_DebugCanarySecurityInitCookie.clear();
    m_RestartICPoints.clear();
    m_bInitIAT = false;
    m_bSkipCBCallsWithNewPC = false;
    m_bRequestShutdown = false;
#ifdef AR_NTCORE_PATCH
    m_bNativeCorePatchInstalled = false;
#endif
    m_iatStart = 0;
    m_iatEnd = 0;
    m_cbIATCall = nullptr;
    m_cbIATCallData = nullptr;
    m_cbSysCall = nullptr;
    m_cbSysCallData = nullptr;
    m_execRegions.clear();
    if (m_rttrace.file.is_open()) {
        m_rttrace.file.close();
    }
    m_rttrace.aslr = 0;
    m_rttrace.icoffset = 0;
    m_rttrace.lastanyjmpinstrcount = 0;
    m_rttrace.anyjmpmode = 0;
    m_rttrace.cb = nullptr;
    m_rttrace.rva = false;
    m_rttrace.disasm = false;
    m_rttrace.bin = false;
    m_rttrace.inited = false;
    m_rttrace.rwhistory.bUseRWHistory = false;
    m_rttrace.rwhistory.bRead = false;
    m_rttrace.rwhistory.bWrite = false;
    m_rttrace.rwhistory.bValNotice = false;
    m_rttrace.rwhistory.bSym = false;
    m_rttrace.rwhistory.bShortFmt = false;
    m_rttrace.rwhistory.bDisasm = false;
    m_memoryRangeCB.clear();
    m_bUsingMemoryRangeCB = false;
    m_icHooks.clear();
    m_deadzonesIC.clear();
    m_bInDeadzoneIC = false;
    m_currentDeadzoneICIndex = -1;
    m_RWHistory.clear();
    m_bRWHistory = false;
    m_gstftBaseFt64 = 0;
    m_gstftBaseIc = 0;
    m_gstftSleepDelta = 0;
    m_gstftInited = false;
    m_insnHooks.clear();
    m_sections.clear();
    m_FlsSlots.clear();
#ifdef AR_DFT
    m_dataTraces.clear();
    m_nextDataTraceId = 1;
    m_pendingAfterNodes.clear();
#endif
}

void AsmRunner::ShutdownByCallback(uc_engine* uc)
{
    m_bStopped = true;

    uc_engine* ctx = uc ? uc : m_uc;
    if (!ctx)
        return;

    if (m_bLogRunner)
    {
        uintptr_t pc = CurrentPc(ctx);
        Log("[!] Shutdown by Callback at 0x%p", (void*)pc);
    }

    uc_emu_stop(ctx);
}

void AsmRunner::ShutdownByHalt(uc_engine* uc)
{
    m_bStopped = true;

    uc_engine* ctx = uc ? uc : m_uc;
    if (!ctx)
        return;

    if (m_bLogRunner)
    {
        uintptr_t pc = CurrentPc(ctx);
        Log("[!] HALT reached at 0x%p", (void*)pc);
    }

    uc_emu_stop(ctx);
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
    switch (reg)
    {
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

tFuncNode* AsmRunner::FindSymbolByRuntime(uintptr_t rtAddr)
{
    if (!m_sym.empty())
    {
        uintptr_t rel = rtAddr;
        if (m_modStart != 0 && rtAddr >= m_modStart) {
            rel = rtAddr - m_modStart;
        }

        auto it = std::upper_bound(
            m_sym.begin(), m_sym.end(), rel,
            [](uintptr_t value, const tFuncNode& e) { return value < e.funcRva; });

        if (it != m_sym.begin())
        {
            --it;
            if (it->funcSize != 0) {
                if (rel >= it->funcRva && rel < it->funcRva + it->funcSize) return &(*it);
            }
            else {
                if (rel == it->funcRva) return &(*it);
            }
        }

        //if (IsInAddr(rtAddr, GetModStart(), GetModEnd()))
        //    return nullptr; // dont show export self
    }

    // try search in iat env
    if (exportsENV.empty())
        CollectAllExports(exportsENV);

    if (!exportsENV.empty())
    {
        auto it2 = exportsENV.upper_bound(rtAddr);
        if (it2 != exportsENV.begin())
        {
            --it2;
            uintptr_t absAddr = it2->second.GetAbsolute();
            if (rtAddr >= absAddr && rtAddr < absAddr + it2->second.funcSize) return &(it2->second);

            //if (it->funcSize != 0) {
            //    if (rel >= it->funcRva && rel < it->funcRva + it->funcSize) return &(*it);
            //}
            //else {
            //    if (rel == it->funcRva) return &(*it);
            //}
        }
    }

    return nullptr;
}

//tFuncNode* AsmRunner::FindSymbolByRuntime(uintptr_t rtAddr)
//{
//    if (m_sym.empty()) return nullptr;
//
//    uintptr_t rel = rtAddr;
//    if (m_modStart != 0 && rtAddr >= m_modStart) {
//        rel = rtAddr - m_modStart;
//    }
//
//    auto it = std::upper_bound(
//        m_sym.begin(), m_sym.end(), rel,
//        [](uintptr_t value, const tFuncNode& e) { return value < e.funcRva; });
//
//    if (it == m_sym.begin()) return nullptr;
//    --it;
//
//    if (it->funcSize != 0) {
//        if (rel >= it->funcRva && rel < it->funcRva + it->funcSize) return &(*it);
//    }
//    else {
//        if (rel == it->funcRva) return &(*it);
//    }
//
//    //uintptr_t start = it->rva;
//    //uintptr_t end = UINTPTR_MAX;
//    //auto next = std::next(it);
//    //if (next != m_sym.end())
//    //    end = next->rva;
//    //else if (it->size != 0)
//    //    end = start + it->size;
//
//    //if (rel >= start && rel < end)
//    //    return &(*it);
//
//    return nullptr;
//}

std::string AsmRunner::GetSectionNameByRuntimeAddress(uintptr_t addr)
{
    if (m_sections.empty() || m_modStart == 0)
        return {};

    const uintptr_t rva = addr - m_modStart;

    for (const auto& s : m_sections)
    {
        const uintptr_t secEnd = s.rva + std::max<uint32_t>(s.virtualSize, s.rawSize);
        if (rva >= s.rva && rva < secEnd)
        {
            std::string name = s.name;

            size_t spaceCount = std::count(name.begin(), name.end(), ' '); // themida kek
            if (spaceCount == name.size() && !name.empty()) {
                std::fill(name.begin(), name.end(), '_');
            }

            return name;
        }
    }

    return {};
}

std::string AsmRunner::FormatRuntimeAddressWithSymbol(uintptr_t rtAddr)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << rtAddr;

    tFuncNode* sym = FindSymbolByRuntime(rtAddr);
    if (sym) {
        uintptr_t rel = rtAddr - sym->moduleBase;

        oss << " (" << sym->funcName;
        if (rel >= sym->funcRva)
            oss << "+0x" << std::hex << std::uppercase << (rel - sym->funcRva);
        oss << ")";
    }

    return oss.str();
}

std::string AsmRunner::FormatCurrentSymbolSuffix(uintptr_t rtAddr)
{
    tFuncNode* sym = FindSymbolByRuntime(rtAddr);
    if (!sym)
        return std::string();

    uintptr_t rel = rtAddr - sym->moduleBase;

    std::ostringstream oss;
    oss << sym->funcName;
    if (rel >= sym->funcRva)
        oss << "+0x" << std::hex << std::uppercase << (rel - sym->funcRva);

    return oss.str();
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

std::string AsmRunner::MakeDisasmLine(const uint8_t* bytes, size_t size, uintptr_t runtimeAddress, ZydisDecodedInstruction* instr, ZydisDecodedOperand* operands, bool& bResOK)
{
    //ZydisDecodedInstruction instr{};
    ////ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
    //ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

    bResOK = false;

    if (!bytes || size == 0 || !instr || !operands)
        return "???";

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder,
        bytes,
        static_cast<ZyanUSize>(size),
        instr,
        operands))) {
        return "???";
    }

    bResOK = true;

    char buffer[256] = {};
    ZydisFormatterFormatInstruction(&m_formatter,
        instr,
        operands,
        instr->operand_count_visible,
        buffer,
        sizeof(buffer),
        static_cast<ZyanU64>(runtimeAddress),
        ZYAN_NULL);

    std::ostringstream oss;
    oss << buffer;

    //if (instr->mnemonic == ZYDIS_MNEMONIC_CALL || instr->mnemonic == ZYDIS_MNEMONIC_JMP)
    if (IsAnyIpTransfer(instr->mnemonic))
    {
        uintptr_t target = 0;
        if (ResolveDirectBranchTarget(m_uc, *instr, operands, runtimeAddress, target)) {
            oss << " ; -> " << FormatRuntimeAddressWithSymbol(target);
        }
    }

    return oss.str();
}

bool AsmRunner::DecodeOpcode(uc_engine* uc, ZydisDecodedInstruction* instr, ZydisDecodedOperand* operands)
{
    if (!uc || !instr || !operands)
        return false;

    //ZydisDecodedInstruction instr{};
    ////ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
    //ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

    uintptr_t pc = CurrentPc(uc);
    std::array<uint8_t, 16> bytes{};
    if (uc_mem_read(uc, pc, bytes.data(), bytes.size()) == UC_ERR_OK) {
        return DecodeOpcode(bytes.data(), bytes.size(), instr, operands);
    }

    return false;
}

bool AsmRunner::DecodeOpcode(const uint8_t* bytes, size_t size, ZydisDecodedInstruction* instr, ZydisDecodedOperand* operands)
{
    if (!bytes || size == 0 || !instr || !operands)
        return false;

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder,
        bytes,
        static_cast<ZyanUSize>(size),
        instr,
        operands))) {
        return false;
    }

    return true;
}

std::string AsmRunner::DisassembleWithZydis(bool bLog)
{
    if (!m_uc) return "???";

    uintptr_t curPc = CurrentPc(m_uc);
    if (!m_bX64)
        curPc = static_cast<uint32_t>(curPc);

    ZydisDecodedInstruction instr{};
    ////ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    bool bDecodeOK = false;

    std::vector<uint8_t> bytes;
    bool bReadOk = ReadBytes(m_uc, curPc, 16, bytes);

    std::string disasm = bReadOk ? MakeDisasmLine(bytes.data(), bytes.size(), curPc, &instr, operands, bDecodeOK) : "[READ ERROR]";
    std::string curSym = FormatCurrentSymbolSuffix(curPc);
    bytes.resize(instr.length);

    if (!bReadOk || !bDecodeOK) {
        MboxSTD("Error 1 (DisassembleWithZydis)", AR_SNAME);
        return "???";
    }

    bool bOutCondMn = false; // is cond mn
    bool bOutInvMn = false; // is inversed mn
    const bool bCond = ResolveFlagsConditional(instr.mnemonic, bOutCondMn, bOutInvMn);

    bool bPrefix = false;
    if (bOutCondMn) {
        bPrefix = true;
        if (bOutInvMn)
            disasm += std::string(" ; (inv cond=") + (bCond ? "true" : "false") + ")";
        else
            disasm += std::string(" ; (cond=") + (bCond ? "true" : "false") + ")";
    }

    if (m_bLogDisasmRawBytes && bReadOk && !bytes.empty()) {
        std::ostringstream bb;
        if (!bPrefix) {
            bb << " ; [";
            bPrefix = true;
        }
        else
            bb << " [";
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (i != 0)
                bb << ' ';
            bb << "0x" << std::hex << std::uppercase
                << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(bytes[i]);
        }
        bb << "]";
        disasm += bb.str();
    }

    if (m_bLogDisasmSection) {
        const std::string secName = GetSectionNameByRuntimeAddress(curPc);
        if (!secName.empty()) {
            if (!bPrefix) {
                disasm += " ; (" + secName + ")";
                bPrefix = true;
            }
            else
                disasm += " (" + secName + ")";
        }
    }


    std::ostringstream oss;
    oss << "[" << formatWithSeparator(m_instrCount, m_DisasmSepGroup) << "] ";
    //if (m_bDisasmAfterCB)
    //    oss << "AFCB ";
    //else
    //    oss << "BFCB "; // -
    if (m_bDisasmRVA && m_DisasmCustomASLR == 0)
        oss << "0x" << std::hex << std::uppercase << (curPc - m_modStart);
    else if (m_bDisasmRVA)
        oss << "0x" << std::hex << std::uppercase << CalcWithCASLR(curPc) << " ( +0x" << (curPc - m_modStart) << ")";
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

    if(bLog)
        Log("%s", line.c_str());

    return line;
}

std::string AsmRunner::DisassembleWithCapstone(bool bLog)
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
    return "";
}

// unallocated halt can only be caught in TryResolveIpTransfer target==halt or memcb when pc==halt and UC_ERR_FETCH_UNMAPPED/UC_ERR_FETCH_PROT
void AsmRunner::_OnInstructionStep(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    (void)user_data;
    ++m_instrCount;

    uintptr_t curPc = static_cast<uintptr_t>(address);
    if (!m_bX64)
        curPc = static_cast<uint32_t>(curPc);

    UpdateDeadzoneIC(m_instrCount, curPc);

    auto IsAllowedPc = [&](uintptr_t pc) -> bool
    {
#ifdef AR_HALT_ADDR_ONLY
        return !IsHaltAddr(pc); // fast
#else
        return IsPCNormal(pc);
#endif
    };

    //if (m_bRequestShutdown) {
    //    ShutdownByCallback(uc);
    //    m_bRequestShutdown = false;
    //    return;
    //}

#ifndef AR_BP_AFTER_DZ
    if (m_bUsingBp) // fast, is any bp added
    {
        uintptr_t bpBase = 0;
        tBpInfo* bp = FindBreakpoint(curPc, m_bUsingBpCodeSizeRange, bpBase);
        if (bp && bp->type == BP_CODE && bp->opcodeCb)
        {
            if (!_OnBreakpoint(*bp, uc, address, size, user_data, false, (uc_mem_type)0, 0)) {
                return;
            }
            if (ShouldStopCB(true)) {
                return; // prevent notice in cb with old pc opcode
            }
        }
    }
#endif

    tDeadzoneIC* dz = GetCurrentDeadzoneIC();
    if (dz && (dz->skipAll || dz->skipOpcode))
    {
        // pc
        if (dz->checkPC && !IsAllowedPc(CurrentPc(uc))) { // dz halt in rwx allocated halt region
            ShutdownByHalt(uc);
            return;
        }

        // notice
        if (m_DisasmICNotice != 0 && (m_instrCount % m_DisasmICNotice == 0))
        {
            if (dz->checkPC && !IsAllowedPc(CurrentPc(uc))) { // dz halt in rwx allocated halt region // if !checkPC, but notice, seems fine
                ShutdownByHalt(uc);
                return;
            }

            ZydisDecodedInstruction instr{};
            ////ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
            bool bDecodeOK = false;

            std::vector<uint8_t> bytes;
            bool bReadOk = ReadBytes(uc, address, size, bytes);
            std::string disasm = bReadOk ? MakeDisasmLine(bytes.data(), bytes.size(), curPc, &instr, operands, bDecodeOK) : "[READ ERROR]";
            std::string curSym = FormatCurrentSymbolSuffix(curPc);

            if (!bReadOk || !bDecodeOK) {
                DumpMemory(address, size);
                if (m_bLogRunner) {
                    Log("AsmRunner::_OnInstructionStep(0x%p, 0x%p, 0x%p, 0x%p), bReadOk %d, bDecodeOK %d", uc, (void*)address, size, user_data, bReadOk, bDecodeOK);
                }
                MboxSTD(!bReadOk ? "Error 1 (!bReadOk OnInstructionStep)" : "Error 1 (!bDecodeOK OnInstructionStep)", AR_SNAME);
                ShutdownByHalt(uc);
                return;
            }

            bool bOutCondMn = false; // is cond mn
            bool bOutInvMn = false; // is inversed mn
            const bool bCond = ResolveFlagsConditional(instr.mnemonic, bOutCondMn, bOutInvMn);

            bool bPrefix = false;
            if (bOutCondMn) {
                bPrefix = true;
                if (bOutInvMn)
                    disasm += std::string(" ; (inv cond=") + (bCond ? "true" : "false") + ")";
                else
                    disasm += std::string(" ; (cond=") + (bCond ? "true" : "false") + ")";
            }

            if (m_bLogDisasmRawBytes && bReadOk && !bytes.empty()) {
                std::ostringstream bb;
                if (!bPrefix) {
                    bb << " ; [";
                    bPrefix = true;
                }
                else
                    bb << " [";
                for (size_t i = 0; i < bytes.size(); ++i)
                {
                    if (i != 0)
                        bb << ' ';
                    bb << "0x" << std::hex << std::uppercase
                        << std::setw(2) << std::setfill('0')
                        << static_cast<unsigned>(bytes[i]);
                }
                bb << "]";
                disasm += bb.str();
            }

            if (m_bLogDisasmSection) {
                const std::string secName = GetSectionNameByRuntimeAddress(curPc);
                if (!secName.empty()) {
                    if (!bPrefix) {
                        disasm += " ; (" + secName + ")";
                        bPrefix = true;
                    }
                    else
                        disasm += " (" + secName + ")";
                }
            }

            std::ostringstream oss;
            oss << "[" << formatWithSeparator(m_instrCount, m_DisasmSepGroup) << "] [IN DEAD ZONE " << m_currentDeadzoneICIndex << "] ";
            if (m_bDisasmRVA && m_DisasmCustomASLR == 0)
                oss << "0x" << std::hex << std::uppercase << (curPc - m_modStart);
            else if (m_bDisasmRVA)
                oss << "0x" << std::hex << std::uppercase << CalcWithCASLR(curPc) << " ( +0x" << (curPc - m_modStart) << ")";
            else
                oss << "0x" << std::hex << std::uppercase << curPc;
            oss << ": " << disasm;

            std::string line = oss.str();
            constexpr size_t kSymbolColumn = 70;
            if (line.size() < kSymbolColumn)
                line += std::string(kSymbolColumn - line.size(), ' ');
            else
                line += "  ";

            if (!curSym.empty())
                line += "; " + curSym;

            Log("%s", line.c_str());
        }

        // dz default trace
        if (!dz->skipTrace && m_rttrace.inited && m_rttrace.anyjmpmode == 0 && m_rttrace.file.is_open() && m_instrCount > m_rttrace.icoffset)
        {
            if (m_rttrace.bin) // asm
            {
                std::vector<uint8_t> bytes;
                bool bReadOk = ReadBytes(uc, address, size, bytes);
                m_rttrace.file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            }
            else // text
            {
                uintptr_t outPc = curPc;
                if (m_rttrace.rva)
                    outPc = curPc - m_modStart;
                if (m_rttrace.aslr != 0)
                    outPc = curPc - m_modStart + m_rttrace.aslr;

                if (m_rttrace.disasm) {
                    m_rttrace.file << "0x" << std::hex << std::uppercase << outPc << ' ' << DisassembleWithZydis() << '\n';
                }
                else {
                    m_rttrace.file << "0x" << std::hex << std::uppercase << outPc << '\n';
                }
            }

            if (m_rttrace.cb)
            {
                if (!m_rttrace.cb(uc, address, size, ZYDIS_MNEMONIC_INVALID, user_data)) { // temp fast ZYDIS_MNEMONIC_INVALID, todo
                    ShutdownByCallback(uc);
                    return;
                }
                if (ShouldStopCB(true)) {
                    return; // prevent notice in cb with old pc opcode
                }
            }
        }

        return;
    } // DZ

#ifdef AR_BP_AFTER_DZ
    if (m_bUsingBp) // fast, is any bp added
    {
        uintptr_t bpBase = 0;
        tBpInfo* bp = FindBreakpoint(curPc, m_bUsingBpCodeSizeRange, bpBase);
        if (bp && bp->type == BP_CODE && bp->opcodeCb)
        {
            if (!_OnBreakpoint(*bp, uc, address, size, user_data, false, (uc_mem_type)0, 0)) {
                return;
            }
            if (ShouldStopCB(true)) {
                return; // prevent notice in cb with old pc opcode
            }
        }
    }
#endif

#ifdef AR_DFT
    // Fill valAfter for nodes created at the previous step.
    // At this point registers hold results of the previous instruction — that IS the after-value.
    if (!m_pendingAfterNodes.empty())
        _FillPendingAfterValues(uc);
#endif

    // IsAllowedPc checks m_anyJmpHooks
    if (!IsAllowedPc(CurrentPc(uc))) { // halt in rwx allocated halt region
        ShutdownByHalt(uc);
        return;
    }

    // !before m_anyJmpHooks calls
    for (auto& h : m_anyJmpHooks) // can be outside module (import dependencies dummy)
    {
        if (!h.cb || h.before || !h.bfArgs.valid || h.pAddr != curPc)
            continue;

        const auto args = h.bfArgs;
        h.bfArgs.valid = false;

        if (!h.cb(uc, args.from, args.to, args.size, args.mnemonic, args.bIsCondMn, args.bCond, args.bIsInvMn, h.data)) {
            ShutdownByCallback(uc);
            return;
        }
        if (ShouldStopCB(true)) {
            return; // prevent notice in cb with old pc opcode
        }
    }

    ZydisDecodedInstruction instr{};
    ////ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    bool bDecodeOK = false;

    std::vector<uint8_t> bytes;
    bool bReadOk = ReadBytes(uc, address, size, bytes);

    std::string disasm = bReadOk ? MakeDisasmLine(bytes.data(), bytes.size(), curPc, &instr, operands, bDecodeOK) : "[READ ERROR]";
    std::string curSym = FormatCurrentSymbolSuffix(curPc);

    if (!bReadOk || !bDecodeOK) {
        DumpMemory(address, size);
        if (m_bLogRunner) {
            Log("AsmRunner::_OnInstructionStep(0x%p, 0x%p, 0x%X, 0x%p), bReadOk %d, bDecodeOK %d", uc, (void*)address, size, user_data, bReadOk, bDecodeOK);
        }
        MboxSTD(!bReadOk ? "Error 1 (!bReadOk OnInstructionStep)" : "Error 1 (!bDecodeOK OnInstructionStep)", AR_SNAME);
        ShutdownByHalt(uc);
        return;
    }

#ifdef AR_DFT
    if (!m_dataTraces.empty() && bDecodeOK)
    {
        std::vector<tDTResolvedOp> dtDstOps, dtSrcOps;
        for (uint8_t oi = 0; oi < instr.operand_count_visible; ++oi)
        {
            const auto& op = operands[oi];
            const bool isRead = (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
            const bool isWrite = (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
            if (!isRead && !isWrite) continue;

            tDTResolvedOp res;
            res.sz = op.size / 8;
            if (res.sz == 0) res.sz = 1;

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                res.type = ZYDIS_OPERAND_TYPE_REGISTER;
                res.reg = _CanonicalReg(op.reg.value);
                if (res.reg == ZYDIS_REGISTER_NONE) continue;
                ReadZydisRegisterValue(uc, res.reg, res.val);
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                uintptr_t ea = 0;
                if (!ResolveMemoryOperandAddress(uc, instr, op, curPc, ea)) continue;
                res.type = ZYDIS_OPERAND_TYPE_MEMORY;
                res.addr = ea;
                ReadBytes(uc, static_cast<uint64_t>(ea), res.sz, res.bytes);
                if (!res.bytes.empty())
                {
                    const uint32_t lim = std::min((uint32_t)res.bytes.size(), (uint32_t)sizeof(uintptr_t));
                    for (uint32_t bi = 0; bi < lim; ++bi)
                        res.val |= (uintptr_t)res.bytes[bi] << (bi * 8);
                }
            }
            else continue;

            if (isWrite) dtDstOps.push_back(res);
            if (isRead)  dtSrcOps.push_back(res);
        }

        if (!dtDstOps.empty() || !dtSrcOps.empty())
            _OnOpcodeOperands(uc, curPc, m_instrCount, instr, operands, dtDstOps, dtSrcOps, disasm);
    }
#endif

    bool bOutCondMn = false; // is cond mn
    bool bOutInvMn = false; // is inversed mn
    const bool bCond = ResolveFlagsConditional(instr.mnemonic, bOutCondMn, bOutInvMn);

    bool bPrefix = false;
    if (bOutCondMn) {
        bPrefix = true;
        if (bOutInvMn)
            disasm += std::string(" ; (inv cond=") + (bCond ? "true" : "false") + ")";
        else
            disasm += std::string(" ; (cond=") + (bCond ? "true" : "false") + ")";
    }

    if (m_bLogDisasmRawBytes && bReadOk && !bytes.empty()) {
        std::ostringstream bb;
        if (!bPrefix) {
            bb << " ; [";
            bPrefix = true;
        }
        else
            bb << " [";
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (i != 0)
                bb << ' ';
            bb << "0x" << std::hex << std::uppercase
                << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(bytes[i]);
        }
        bb << "]";
        disasm += bb.str();
    }

    if (m_bLogDisasmSection) {
        const std::string secName = GetSectionNameByRuntimeAddress(curPc);
        if (!secName.empty()) {
            if (!bPrefix) {
                disasm += " ; (" + secName + ")";
                bPrefix = true;
            }
            else
                disasm += " (" + secName + ")";
        }
    }

    // default trace
    if (m_rttrace.inited && m_rttrace.anyjmpmode == 0 && m_rttrace.file.is_open() && m_instrCount > m_rttrace.icoffset)
    {
        if (m_rttrace.bin) // asm
        {
            std::vector<uint8_t> bytes;
            bool bReadOk = ReadBytes(uc, address, size, bytes);
            m_rttrace.file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        }
        else // text
        {
            uintptr_t outPc = curPc;
            if (m_rttrace.rva)
                outPc = curPc - m_modStart;
            if (m_rttrace.aslr != 0)
                outPc = curPc - m_modStart + m_rttrace.aslr;

            if (m_rttrace.disasm) {
                m_rttrace.file << "0x" << std::hex << std::uppercase << outPc << ' ' << DisassembleWithZydis() << '\n';
            }
            else {
                m_rttrace.file << "0x" << std::hex << std::uppercase << outPc << '\n';
            }
        }

        if (m_rttrace.cb)
        {
            if (!m_rttrace.cb(uc, address, size, instr.mnemonic, user_data)) {
                ShutdownByCallback(uc);
                return;
            }
            if (ShouldStopCB(true)) {
                return; // prevent notice in cb with old pc opcode
            }
        }
    }

    if (!m_bDisasmAfterCB && ((m_DisasmICNotice != 0 && (m_instrCount % m_DisasmICNotice == 0)) || m_bLogDisasm)) {
        std::ostringstream oss;
        oss << "[" << formatWithSeparator(m_instrCount, m_DisasmSepGroup) << "] ";
        if(m_bDisasmAfterCB)
            oss << "AFCB ";
        else
            oss << "BFCB "; // -
        if (m_bDisasmRVA && m_DisasmCustomASLR == 0)
            oss << "0x" << std::hex << std::uppercase << (curPc - m_modStart);
        else if (m_bDisasmRVA)
            oss << "0x" << std::hex << std::uppercase << CalcWithCASLR(curPc) << " ( +0x" << (curPc - m_modStart) << ")";
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
                ShutdownByCallback(uc);
                return;
            }
        }
    }

    // what about UC_HOOK_INTR?
    if (m_cbSysCall && IsSystem(instr.mnemonic)) {
        if (!m_cbSysCall(uc, curPc, size, instr.mnemonic, m_cbSysCallData)) {
            ShutdownByCallback(uc);
            return;
        }
        if (ShouldStopCB(true)) {
            return; // prevent notice in cb with old pc opcode
        }
    }

    for (const auto& n : m_icHooks) {
        if (n.nIC != m_instrCount || !n.cb)
            continue;

        if (!n.cb(uc, curPc, size, instr.mnemonic, n.data)) {
            ShutdownByCallback(uc);
            return;
        }
        if (ShouldStopCB(true)) {
            return; // prevent notice in cb with old pc opcode
        }
    }

    if (m_cbOpcode) {
        if (!m_cbOpcode(uc, curPc, size, instr.mnemonic, m_cbOpcodeData)) {
            ShutdownByCallback(uc);
            return;
        }
        if (ShouldStopCB(true)) {
            return; // prevent notice in cb with old pc opcode
        }
    }

    if (IsAnyIpTransfer(instr.mnemonic)) {
        uintptr_t target = 0;
        if (TryResolveIpTransfer(uc, instr, operands, curPc, target))
        {
            // AR_HALT_JMPCB узнать заранее прыжок в halt UC_ERR_FETCH_UNMAPPED/UC_ERR_FETCH_PROT так и allocated halt
#ifndef AR_HALT_JMPCB
            if (!IsAllowedPc(target)) { // skip jmp cb to halt, pc on last instruction
                ShutdownByHalt(uc);
                return;
            }
#endif

            if (!_OnAnyJmp(uc, curPc, target, size, instr.mnemonic, bOutCondMn, bCond, bOutInvMn, user_data))
                return;

#ifdef AR_HALT_JMPCB
            if (!IsAllowedPc(target)) { // skip jmp cb to halt, pc on last instruction
                ShutdownByHalt(uc);
                return;
            }
#endif

            if (ShouldStopCB(true)) {
                return; // prevent notice in cb with old pc opcode
            }
        }
        else {
            if (m_bLogRunner) {
                Log("[!] TryResolveIpTransfer failed: pc=0x%p mn=%u len=%u opcnt=%u",
                    (void*)curPc, (unsigned)instr.mnemonic, (unsigned)instr.length,
                    (unsigned)instr.operand_count_visible);
            }
            MboxSTD("Warn! transfer op TryResolveIpTransfer not resolved", AR_SNAME);
        }
    }

    if (m_bDisasmAfterCB && ((m_DisasmICNotice != 0 && (m_instrCount % m_DisasmICNotice == 0)) || m_bLogDisasm)) {
        std::ostringstream oss;
        oss << "[" << formatWithSeparator(m_instrCount, m_DisasmSepGroup) << "] ";
        if (m_bDisasmAfterCB)
            oss << "AFCB "; // -
        else
            oss << "BFCB ";
        if (m_bDisasmRVA && m_DisasmCustomASLR == 0)
            oss << "0x" << std::hex << std::uppercase << (curPc - m_modStart);
        else if (m_bDisasmRVA)
            oss << "0x" << std::hex << std::uppercase << CalcWithCASLR(curPc) << " ( +0x" << (curPc - m_modStart) << ")";
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

    //uintptr_t pcAfter = CurrentPc(uc);
    //if (m_modStart != 0 && m_modEnd != 0 && !IsAllowedPc(pcAfter)) {
    //    if (m_bLogRunner && !IsHaltAddr(pcAfter))
    //        Log("[!] %s (0x%p) out of bounds [0x%p - 0x%p]", m_bX64 ? "RIP" : "EIP", (void*)pcAfter, (void*)m_modStart, (void*)m_modEnd);
    //    uc_emu_stop(uc);
    //}
}

// note: halt shutdown in memcb leaves an (unalloc) memerror // UC_ERR_FETCH_UNMAPPED/UC_ERR_FETCH_PROT, reset "halt" error only fix + retun true;
// address == CurrentPc(uc) mostly UC_ERR_FETCH_PROT
bool AsmRunner::_OnMemory(uc_engine* uc, uc_mem_type type, uint64_t address, uint32_t size, int64_t value, void* user_data)
{
    (void)user_data;

    bool isRead = (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT || type == UC_MEM_READ_AFTER);
    bool isWrite = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT);
    bool isAnyFetch = (type == UC_MEM_FETCH || type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT); // code read

    uintptr_t addr = static_cast<uintptr_t>(address);
    uintptr_t sz = static_cast<uintptr_t>(size);

//#ifdef AR_TRY_FIX_TCG
//    uc_ctl(uc, UC_CTL_TB_FLUSH);
//    uc_ctl(uc, UC_CTL_TB_REMOVE_CACHE, m_modStart, m_modEnd);
//    uc_ctl(uc, UC_CTL_TB_FLUSH, 0);
//
//    uc_ctl(uc, UC_CTL_TB_REMOVE_CACHE, m_modStart, m_modEnd);
//    uc_ctl(uc, UC_CTL_TB_FLUSH);
//#endif

    // Invalidate the QEMU translation-block cache for any written range to prevent
    // stale tb_add_jump chains (SMC bug in QEMU backend).
//#ifdef AR_TRY_FIX_TCG
//    if (type == UC_MEM_WRITE) {
//        uc_ctl_remove_cache(uc, address, address + static_cast<uint64_t>(size)); // anti tcg tb_add_jump crash on smc code (not work)
//        //uc_ctl_flush_tlb(uc);
//    }
//#endif

    if (__security_cookie != 0 && address == __security_cookie) {
        const char* typeStr = isRead ? "READ" : (isWrite ? "WRITE" : (isAnyFetch ? "FETCH" : "UNKNOWN"));
        char msg[256];
        snprintf(msg, sizeof(msg), "OnMemory %s __security_cookie trigger at 0x%p (size=%u, value=0x%p)", typeStr, (void*)address, size, value);

        if (m_bLogRunner)
            Log(msg);

        MboxSTD(msg, AR_SNAME);
    }

#ifndef AR_BP_AFTER_DZ
    if (m_bUsingBp) // fast, is any bp added
    {
        uintptr_t bpBase = 0;
        tBpInfo* bp = FindBreakpoint(address, true, bpBase);
        if (bp && ((bp->type == BP_MEM_READ && isRead) || (bp->type == BP_MEM_WRITE && isWrite) || (bp->type == BP_MEM_RW && (isRead || isWrite))) && bp->memCb)
        {
            if (!_OnBreakpoint(*bp, uc, address, size, user_data, true, type, value)) {
                return false;
            }
            if (ShouldStopCB(true)) {
                return true; // prevent notice in cb with old pc opcode
            }
        }
    }
#endif

    auto makeRWHistory = [&]() -> tRWHistory
    {
        uintptr_t pc = CurrentPc(uc);
        uintptr_t histVal = 0;

        if (isWrite)
        {
            histVal = static_cast<uintptr_t>(value);
            if (!m_bX64)
                histVal = static_cast<uint32_t>(histVal);
        }
        else if (isRead)
        {
            // пробуем зафиксировать фактически прочитанное значение
            // (если память доступна; если нет — останется 0)
            (void)uc_mem_read(uc, addr, &histVal, static_cast<size_t>(sz));
            if (!m_bX64)
                histVal = static_cast<uint32_t>(histVal);
        }

        tRWHistory h;
        h.pc = pc;
        h.addr = addr;
        h.value = histVal;
        h.size = sz;
        h.ic = m_instrCount;
        h.bRead = isRead;
        h.disasm = DisassembleWithZydis();

        return h;
    };

    const tDeadzoneIC* dz = GetCurrentDeadzoneIC();
    if (dz && (dz->skipAll || dz->skipMem))
    {
        // pc UC_ERR_FETCH_UNMAPPED/UC_ERR_FETCH_PROT
#ifdef AR_HALT_ADDR_ONLY
        if (dz->checkPC && address == CurrentPc(uc) && IsHaltAddr(address)) { // err dz prot/unalloc exec
#else
        if (dz->checkPC && address == CurrentPc(uc) && !IsPCNormal(address)) { // err dz prot/unalloc exec
#endif
            ShutdownByHalt(uc);
            return false;
        }

        // history
        if (!dz->skipHistory && m_bRWHistory) {
            m_RWHistory.push_back(makeRWHistory());
        }

        // dz trace
        if (!dz->skipTrace && m_rttrace.inited && m_rttrace.rwhistory.bUseRWHistory)
        {
            tRWHistory h = makeRWHistory();

            m_rttrace.file << FormatRWHistoryLine(h, m_rttrace.rwhistory.bValNotice, m_rttrace.rva, m_rttrace.rwhistory.bSym, m_rttrace.rwhistory.bShortFmt, m_rttrace.rwhistory.bDisasm) << '\n';
            //if (m_rttrace.rwhistory.bDisasm && !h.disasm.empty())
            //    m_rttrace.file << '\n';

            if (m_rttrace.cb)
            {
                //ZydisDecodedInstruction instr{};
                //ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
                //bool bDecodeOK = DecodeOpcode(uc, &instr, operands);
                //ZydisMnemonic mnemonic = bDecodeOK ? instr.mnemonic : ZYDIS_MNEMONIC_INVALID;

                //if (!m_rttrace.cb(uc, address, size, mnemonic, user_data)) {
                if (!m_rttrace.cb(uc, address, size, ZYDIS_MNEMONIC_INVALID, user_data)) { // temp fast ZYDIS_MNEMONIC_INVALID
                    ShutdownByCallback(uc);
                    return false;
                }
                if (ShouldStopCB(true)) {
                    return true; // prevent notice in cb with old pc opcode
                }
            }
        }

        return true; // dz
    }

#ifdef AR_BP_AFTER_DZ
    if (m_bUsingBp) // fast, is any bp added
    {
        uintptr_t bpBase = 0;
        tBpInfo* bp = FindBreakpoint(address, true, bpBase);
        if (bp && ((bp->type == BP_MEM_READ && isRead) || (bp->type == BP_MEM_WRITE && isWrite) || (bp->type == BP_MEM_RW && (isRead || isWrite))) && bp->memCb)
        {
            if (!_OnBreakpoint(*bp, uc, address, size, user_data, true, type, value)) {
                return false;
            }
            if (ShouldStopCB(true)) {
                return true; // prevent notice in cb with old pc opcode
            }
        }
    }
#endif

    //UC_ERR_FETCH_UNMAPPED/UC_ERR_FETCH_PROT
#ifdef AR_HALT_ADDR_ONLY
    if (address == CurrentPc(uc) && IsHaltAddr(address)) { // err prot/unalloc exec
#else
    if (address == CurrentPc(uc) && !IsPCNormal(address)) { // err prot/unalloc exec
#endif
        ShutdownByHalt(uc);
        return false;
    }

    // Range CB
    if (m_bUsingMemoryRangeCB && !m_memoryRangeCB.empty())
    {
        uintptr_t addr = static_cast<uintptr_t>(address);

        for (const auto& mr : m_memoryRangeCB)
        {
            bool inRange = false;
            if (mr.range.sExcl && mr.range.eExcl)
                inRange = (addr > mr.range.start && addr < mr.range.end);
            else if (mr.range.sExcl)
                inRange = (addr > mr.range.start && addr <= mr.range.end);
            else if (mr.range.eExcl)
                inRange = (addr >= mr.range.start && addr < mr.range.end);
            else
                inRange = (addr >= mr.range.start && addr <= mr.range.end);

            if (inRange && mr.cbMem)
            {
                ZydisDecodedInstruction instr{};
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
                bool bDecodeOK = DecodeOpcode(uc, &instr, operands);
                ZydisMnemonic mnemonic = bDecodeOK ? instr.mnemonic : ZYDIS_MNEMONIC_INVALID;

                if (!mr.cbMem(uc, static_cast<int32_t>(type), addr, static_cast<uintptr_t>(size),
                    static_cast<uintptr_t>(value), mnemonic, mr.cbMemData))
                {
                    ShutdownByCallback(uc);
                    return false;
                }

                if (ShouldStopCB(true)) {
                    return true;  // prevent notice in cb with old pc opcode
                }
            }
        }
    }

    // RW History
    if (m_bRWHistory) {
        m_RWHistory.push_back(makeRWHistory());
    }

    // Trace
    if (m_rttrace.inited && m_rttrace.rwhistory.bUseRWHistory)
    {
        tRWHistory h = makeRWHistory();

        m_rttrace.file << FormatRWHistoryLine(h, m_rttrace.rwhistory.bValNotice, m_rttrace.rva, m_rttrace.rwhistory.bSym, m_rttrace.rwhistory.bShortFmt, m_rttrace.rwhistory.bDisasm) << '\n';
        //if (m_rttrace.rwhistory.bDisasm && !h.disasm.empty())
        //    m_rttrace.file << '\n';

        if (m_rttrace.cb)
        {
            if (!m_rttrace.cb(uc, address, size, ZYDIS_MNEMONIC_INVALID, user_data)) { // temp fast ZYDIS_MNEMONIC_INVALID, todo
                ShutdownByCallback(uc);
                return false;
            }
            if (ShouldStopCB(true)) {
                return true; // prevent notice in cb with old pc opcode
            }
        }
    }

    if (m_bLogMemRW) {
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

    if (m_cbMem)
    {
        // unshure: is need mnemonic for memory cb? mb delete or default ZYDIS_MNEMONIC_INVALID
        ZydisDecodedInstruction instr{};
        ////ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        bool bDecodeOK = DecodeOpcode(uc, &instr, operands);
        ZydisMnemonic mnemonic = bDecodeOK ? instr.mnemonic : ZYDIS_MNEMONIC_INVALID;

        if (!m_cbMem(uc, static_cast<int32_t>(type), addr, sz, static_cast<uintptr_t>(value), mnemonic, m_cbMemData)) {
            ShutdownByCallback(uc);
            return false;
        }

        if (ShouldStopCB(true)) {
            return true;
        }
    }

    return true;
}

bool AsmRunner::_OnInsn(tInsnHookNode* hook, uc_engine* uc)
{
    if (!hook || !uc || !hook->cb)
        return true;

    ZydisDecodedInstruction instr{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

    if (!DecodeOpcode(uc, &instr, operands))
    {
        if (m_bLogRunner)
            Log("[INSN] decode failed for UC_X86_INS_%zu", hook->nInsn);
        return true;
    }

    const uintptr_t pc = CurrentPc(uc);
    const uintptr_t size = static_cast<uintptr_t>(instr.length);
    const ZydisMnemonic mnemonic = instr.mnemonic;

    if (m_bLogRunner)
    {
        Log("[INSN] 0x%p (%s) size=%u insn=%zu mn=%d", (void*)pc, FormatRuntimeAddressWithSymbol(pc).c_str(), (unsigned)size, (size_t)hook->nInsn, mnemonic);
    }

    if (!hook->cb(uc, pc, static_cast<uint32_t>(size), hook->nInsn, mnemonic, hook->data))
    {
        ShutdownByCallback(uc);
        return false;
    }

    if (ShouldStopCB(false))
        return true;

    return true;
}

bool AsmRunner::_OnAnyJmp(uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data)
{
    tDeadzoneIC* dz = GetCurrentDeadzoneIC();
    if (dz && (dz->skipAll || dz->skipJmps))
    {
        // trace (mostly unused when OnOpcode skip)
        if (!dz->skipTrace && m_rttrace.inited && m_rttrace.anyjmpmode != 0 && m_rttrace.file.is_open() && m_instrCount > m_rttrace.icoffset)
        {
            uintptr_t outPc = from;
            uintptr_t outTo = to;
            if (m_rttrace.rva) {
                outPc = from - m_modStart;
                outTo = to - m_modStart;
            }
            if (m_rttrace.aslr != 0) {
                outPc = from - m_modStart + m_rttrace.aslr;
                outTo = to - m_modStart + m_rttrace.aslr;
            }

            std::string dis = m_rttrace.disasm ? (" " + DisassembleWithZydis()) : "";

            if (m_rttrace.anyjmpmode == 1) { // from
                if (IsInAddr(from, GetModStart(), GetModEnd()))
                    m_rttrace.file << "0x" << std::hex << std::uppercase << outPc << dis << '\n';
                else
                    m_rttrace.file << "0x" << std::hex << std::uppercase << from << dis << '\n'; // skip wrong module rva
            }
            else if (m_rttrace.anyjmpmode == 2) { // to
                if (IsInAddr(to, GetModStart(), GetModEnd()))
                    m_rttrace.file << "0x" << std::hex << std::uppercase << outTo << dis << '\n';
                else
                    m_rttrace.file << "0x" << std::hex << std::uppercase << to << dis << '\n'; // skip wrong module rva
            }
            else { // full
                std::string condStr = "";
                if (bIsCondMn) {
                    if (bIsInvMn)
                        condStr = std::string(" [inv cond=") + (bCond ? "true" : "false") + "]";
                    else
                        condStr = std::string(" [cond=") + (bCond ? "true" : "false") + "]";
                }
            
                const bool bFromInMdl = IsInAddr(from, GetModStart(), GetModEnd());
                const bool bToInMdl = IsInAddr(to, GetModStart(), GetModEnd());
                const bool bCurrTransitJmp = (m_rttrace.lastanyjmpinstrcount + 1 == GetInstructionCount());
                std::string sTransit = ((bCurrTransitJmp && bFromInMdl && bToInMdl) ? (bIsCondMn ? " (COND TRANSIT)" : " (TRANSIT)") : "");
                if (bFromInMdl && bToInMdl) { // in module
                    m_rttrace.file << std::dec << m_instrCount << " " << AnyIpTransferTag(mnemonic) << condStr;
                    m_rttrace.file << " F 0x" << std::hex << std::uppercase << outPc << " T 0x" << outTo << sTransit << '\n';
                }
                else { // кто то не в модуле, нужно найти ему описание
                    if (exportsENV.empty()) { // lazy env init
                        CollectAllExports(exportsENV);
                        if (m_bLogRunner)
                            Log("[*] _OnAnyJmp: %zu exports", exportsENV.size());
                    }

                    tFuncNode* pFromIATNode = FindIATNode(from);
                    tFuncNode* pToIATNode = FindIATNode(to);
                    tAnyJmpHookNode* pFromHNode = nullptr;
                    tAnyJmpHookNode* pToHNode = nullptr;

                    for (auto& h : m_anyJmpHooks)
                    {
                        if (h.pAddr == from)
                            pFromHNode = &h;
                        if (h.pAddr == to)
                            pToHNode = &h;
                        if (pFromHNode && pToHNode)
                            break;
                    }

                    // Base
                    //m_rttrace.file << std::dec << m_instrCount << " " << AnyIpTransferTag(mnemonic) << condStr;
                    m_rttrace.file << std::dec << formatWithSeparator(m_instrCount, m_DisasmSepGroup) << " " << AnyIpTransferTag(mnemonic) << condStr;

                    // From
                    if (!bFromInMdl && (pFromIATNode || pFromHNode)) { // !bFromInMdl, fake rva
                        if(pFromIATNode)
                            m_rttrace.file << " F 0x" << std::hex << std::uppercase << from << " I(" << pFromIATNode->GetAbsoluteName() << ")";
                        else
                            m_rttrace.file << " F 0x" << std::hex << std::uppercase << from << " H(" << pFromHNode->funcname << ")";
                    }
                    else // default or cant find node info
                        m_rttrace.file << " F 0x" << std::hex << std::uppercase << (bFromInMdl ? outPc : from);

                    // To
                    if (!bToInMdl && (pToIATNode || pToHNode)) { // !bToInMdl, fake rva
                        if (pToIATNode)
                            m_rttrace.file << " T 0x" << std::hex << std::uppercase << to << " I(" << pToIATNode->GetAbsoluteName() << ")";
                        else
                            m_rttrace.file << " T 0x" << std::hex << std::uppercase << to << " H(" << pToHNode->funcname << ")";
                    }
                    else // default or cant find node info
                        m_rttrace.file << " T 0x" << std::hex << std::uppercase << (bToInMdl ? outTo : to);

                    m_rttrace.file << sTransit << dis << '\n';
                }
            }

            if (m_rttrace.cb)
            {
                if (!m_rttrace.cb(uc, from, size, mnemonic, user_data)) {
                    ShutdownByCallback(uc);
                    return false;
                }

                if (ShouldStopCB(false)) // clear in call side
                    return true; // prevent notice in cb with old pc opcode
            }

            m_rttrace.lastanyjmpinstrcount = GetInstructionCount();
        }

        return true;
    }

    // trace
    if (m_rttrace.inited && m_rttrace.anyjmpmode != 0 && m_rttrace.file.is_open() && m_instrCount > m_rttrace.icoffset)
    {
        uintptr_t outPc = from;
        uintptr_t outTo = to;
        if (m_rttrace.rva) {
            outPc = from - m_modStart;
            outTo = to - m_modStart;
        }
        if (m_rttrace.aslr != 0) {
            outPc = from - m_modStart + m_rttrace.aslr;
            outTo = to - m_modStart + m_rttrace.aslr;
        }

        if (m_rttrace.anyjmpmode == 1) { // from
            if (IsInAddr(from, GetModStart(), GetModEnd()))
                m_rttrace.file << "0x" << std::hex << std::uppercase << outPc << '\n';
            else
                m_rttrace.file << "0x" << std::hex << std::uppercase << from << '\n'; // skip wrong module rva
        }
        else if (m_rttrace.anyjmpmode == 2) { // to
            if (IsInAddr(to, GetModStart(), GetModEnd()))
                m_rttrace.file << "0x" << std::hex << std::uppercase << outTo << '\n';
            else
                m_rttrace.file << "0x" << std::hex << std::uppercase << to << '\n'; // skip wrong module rva
        }
        else { // full
            std::string condStr = "";
            if (bIsCondMn) {
                if (bIsInvMn)
                    condStr = std::string(" [inv cond=") + (bCond ? "true" : "false") + "]";
                else
                    condStr = std::string(" [cond=") + (bCond ? "true" : "false") + "]";
            }

            const bool bFromInMdl = IsInAddr(from, GetModStart(), GetModEnd());
            const bool bToInMdl = IsInAddr(to, GetModStart(), GetModEnd());
            const bool bCurrTransitJmp = (m_rttrace.lastanyjmpinstrcount + 1 == GetInstructionCount());
            std::string sTransit = ((bCurrTransitJmp && bFromInMdl && bToInMdl) ? (bIsCondMn ? " (COND TRANSIT)" : " (TRANSIT)") : "");
            if (bFromInMdl && bToInMdl) { // in module
                m_rttrace.file << std::dec << m_instrCount << " " << AnyIpTransferTag(mnemonic) << condStr;
                m_rttrace.file << " F 0x" << std::hex << std::uppercase << outPc << " T 0x" << outTo << sTransit << '\n';
            }
            else { // кто то не в модуле, нужно найти ему описание
                if (exportsENV.empty()) { // lazy env init
                    CollectAllExports(exportsENV);
                    if (m_bLogRunner)
                        Log("[*] _OnAnyJmp: %zu exports", exportsENV.size());
                }

                tFuncNode* pFromIATNode = FindIATNode(from);
                tFuncNode* pToIATNode = FindIATNode(to);
                tAnyJmpHookNode* pFromHNode = nullptr;
                tAnyJmpHookNode* pToHNode = nullptr;

                for (auto& h : m_anyJmpHooks)
                {
                    if (h.pAddr == from)
                        pFromHNode = &h;
                    if (h.pAddr == to)
                        pToHNode = &h;
                    if (pFromHNode && pToHNode)
                        break;
                }

                // Base
                m_rttrace.file << std::dec << m_instrCount << " " << AnyIpTransferTag(mnemonic) << condStr;

                // From
                if (!bFromInMdl && (pFromIATNode || pFromHNode)) { // !bFromInMdl, fake rva
                    if (pFromIATNode)
                        m_rttrace.file << " F 0x" << std::hex << std::uppercase << from << " I(" << pFromIATNode->GetAbsoluteName() << ")";
                    else
                        m_rttrace.file << " F 0x" << std::hex << std::uppercase << from << " H(" << pFromHNode->funcname << ")";
                }
                else // default or cant find node info
                    m_rttrace.file << " F 0x" << std::hex << std::uppercase << (bFromInMdl ? outPc : from);

                // To
                if (!bToInMdl && (pToIATNode || pToHNode)) { // !bToInMdl, fake rva
                    if (pToIATNode)
                        m_rttrace.file << " T 0x" << std::hex << std::uppercase << to << " I(" << pToIATNode->GetAbsoluteName() << ")";
                    else
                        m_rttrace.file << " T 0x" << std::hex << std::uppercase << to << " H(" << pToHNode->funcname << ")";
                }
                else // default or cant find node info
                    m_rttrace.file << " T 0x" << std::hex << std::uppercase << (bToInMdl ? outTo : to);

                m_rttrace.file << sTransit << '\n';
            }
        }

        if (m_rttrace.cb)
        {
            if (!m_rttrace.cb(uc, from, size, mnemonic, user_data)) {
                ShutdownByCallback(uc);
                return false;
            }

            if (ShouldStopCB(false)) // clear in call side
                return true; // prevent notice in cb with old pc opcode
        }

        m_rttrace.lastanyjmpinstrcount = GetInstructionCount();
    }

    if (m_bLogAnyJmp)
    {
        Log("[JMP] 0x%p -> 0x%p (%s -> %s) (%d)",
            (void*)from, (void*)to,
            FormatRuntimeAddressWithSymbol(from).c_str(),
            FormatRuntimeAddressWithSymbol(to).c_str(),
            mnemonic);
    }

    for (auto& h : m_anyJmpHooks)
    {
        if (h.pAddr == to && h.cb)
        {
            if (!h.before) // cache args for cb call when pc == pAddr
            {
                h.bfArgs.from = from;
                h.bfArgs.to = to;
                h.bfArgs.size = size;
                h.bfArgs.mnemonic = mnemonic;
                h.bfArgs.bIsCondMn = bIsCondMn;
                h.bfArgs.bCond = bCond;
                h.bfArgs.bIsInvMn = bIsInvMn;
                h.bfArgs.valid = true;
            }
            else
            {
                if (!h.cb(uc, from, to, size, mnemonic, bIsCondMn, bCond, bIsInvMn, h.data)) {
                    ShutdownByCallback(uc);
                    return false;
                }

                if (ShouldStopCB(false)) // clear in call side
                    return true; // prevent notice in cb with old pc opcode
            }
        }
    }

    if (m_bInitIAT && m_cbIATCall)
    {
        for (const auto& n : m_iat)
        {
            if (n.moduleBase && n.funcRva && (n.moduleBase + n.funcRva) == to)
            {
                if (!m_cbIATCall(uc, from, to, size, mnemonic, bIsCondMn, bCond, bIsInvMn, m_cbIATCallData)) {
                    ShutdownByCallback(uc);
                    return false;
                }

                if (ShouldStopCB(false)) // clear in call side
                    return true; // prevent notice in cb with old pc opcode
            }
        }
    }

    if (m_cbJmp)
    {
        if (!m_cbJmp(uc, from, to, size, mnemonic, bIsCondMn, bCond, bIsInvMn, m_cbJmpData)) {
            ShutdownByCallback(uc);
            return false;
        }

        if (ShouldStopCB(false)) // clear in call side
            return true; // prevent notice in cb with old pc opcode
    }

    return true;
}

bool AsmRunner::_OnBreakpoint(const tBpInfo& bp, uc_engine* uc, uint64_t address, uint32_t size, void* user_data, bool bMemory, uc_mem_type type, int64_t value)
{
    (void)uc;
    if (m_bLogRunner) {
        Log("[BP %s] hit at 0x%p ( +0x%p) IC %zu", bMemory ? "MEM" : "CODE", (void*)address, (void*)(address - m_modStart), static_cast<size_t>(m_instrCount));
    }

    ZydisDecodedInstruction instr{};
    ////ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{}; // invalid
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!DecodeOpcode(uc, &instr, operands)) {
        if (m_bLogRunner)
            Log("OnBreakpoint Error Decode!");
        return false;
    }

    if (!bMemory) // code
    {
        uintptr_t curPc = static_cast<uintptr_t>(address);
        if (!m_bX64)
            curPc = static_cast<uint32_t>(curPc);

        if (!bp.opcodeCb(uc, curPc, size, instr.mnemonic, bp.data)) {
            ShutdownByCallback(uc);
            return false;
        }
        if (ShouldStopCB(false)) {
            return true; // prevent notice in cb with old pc opcode
        }
    }
    else // memory
    {
        // unshure: is need mnemonic for memory cb? mb delete or default ZYDIS_MNEMONIC_INVALID
        uintptr_t addr = static_cast<uintptr_t>(address);
        uintptr_t sz = static_cast<uintptr_t>(size);
        if (!bp.memCb(uc, static_cast<int32_t>(type), addr, sz, static_cast<uintptr_t>(value), instr.mnemonic, bp.data)) {
            ShutdownByCallback(uc);
            return false;
        }

        if (ShouldStopCB(false)) {
            return true;
        }
    }
}

void AsmRunner::_OnTraceStep(uc_engine* uc, uintptr_t address, uint32_t sz)
{
    if (!m_trace.active || !m_trace.file.is_open()) return;

    if (m_trace.PCArray) {
        m_trace.file << "0x" << std::hex << std::uppercase << address << "\n";
        return;
    }

    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    oss << "eip = 0x" << address;

    const tFuncNode* sym = FindSymbolByRuntime(address);
    if (sym) {
        uintptr_t rel = address;
        if (m_modStart != 0 && address >= m_modStart) rel = address - m_modStart;
        oss << " ; " << sym->funcName;
        if (rel > sym->funcRva) oss << "+0x" << (rel - sym->funcRva);
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

std::chrono::steady_clock::time_point AsmRunner::CaptureTime()
{
    return std::chrono::steady_clock::now();
}

void AsmRunner::DumpTime(std::chrono::steady_clock::time_point start, const char* label)
{
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(CaptureTime() - start).count();
    if (label) printf("[%s] %.3fms (%lldus)\n", label, us / 1000.0, us);
    else printf("[%.3fms (%lldus)]\n", us / 1000.0, us);
}

void AsmRunner::DumpDeltaTime(std::chrono::steady_clock::time_point a, std::chrono::steady_clock::time_point b, const char* label)
{
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(b - a).count();
    if (label) printf("[Delta %s] %.3fms (%lldus)\n", label, us / 1000.0, us);
    else printf("[Delta] %.3fms (%lldus)\n", us / 1000.0, us);
}

std::string AsmRunner::PrintPtrAsciiTag(uintptr_t v, size_t width, bool bDec, bool bDecBracket)
{
    std::string ascii;
    ascii.reserve(width);

    for (size_t i = 0; i < width; ++i)
    {
        const uint8_t c = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
        ascii.push_back(IsPrintableAscii(c) ? static_cast<char>(c) : '.');
    }

    std::ostringstream oss;
    if(bDec)
        oss << "0x" << std::hex << std::uppercase << v << std::dec << (bDecBracket ? " (" : " ") << static_cast<uint64_t>(v) << (bDecBracket ? ") '" : " '") << ascii << "'";
    else
        oss << "0x" << std::hex << std::uppercase << v << " '" << ascii << "'";
    return oss.str();
}

std::string AsmRunner::PrintValue(uintptr_t v, bool bDec)
{
    std::ostringstream oss;
    if (bDec)
        oss << "0x" << std::hex << std::uppercase << v << std::dec << " (" << static_cast<uint64_t>(v) << ")";
    else
        oss << "0x" << std::hex << std::uppercase << v;
    return oss.str();
}

// VirtualFree((void*)RemapModule(0x123456789), 0, MEM_RELEASE);
//1. .boot запустился на хосте
//2. У него есть анти - отладочный поток(крутится, проверяет)
//3. RemapModule() - TerminateThread убивает ВСЕ потоки
//4. .boot мертв, потоки мертвы, анти - отладка мертва
//5. Осталась RWX флешка с готовым VM - состоянием
//6. Вызываем VM - обработчики прямо из натива или передаём в unicorn
// дамп живого состояния для последующего анализа без риска
// Призрак - модуль есть, а для Windows его нет Итог: "труп" модуля с готовым замороженным VM-состоянием для эмуляции/анализа
uintptr_t AsmRunner::DumpModule(uintptr_t pAddr)
{
    printf("DumpModule: pAddr=0x%p\n", (void*)pAddr);

    if (!pAddr) {
        printf("DumpModule: ERROR - Null address\n");
        return 0;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pAddr;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("DumpModule: ERROR - Invalid DOS header\n");
        return 0;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pAddr + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("DumpModule: ERROR - Invalid NT header\n");
        return 0;
    }

    SIZE_T sz = pNt->OptionalHeader.SizeOfImage;
    if (!sz) {
        printf("DumpModule: ERROR - Zero image size\n");
        return 0;
    }

    printf("DumpModule: Image size = %zu bytes\n", sz);

    // Сохраняем права доступа к страницам модуля
    DWORD oldProtect;
    VirtualProtect((LPVOID)pAddr, sz, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Копируем модуль
    void* backup = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!backup) {
        printf("DumpModule: ERROR - VirtualAlloc for backup failed, error=%d\n", GetLastError());
        VirtualProtect((LPVOID)pAddr, sz, oldProtect, &oldProtect);
        return 0;
    }

    memcpy(backup, (void*)pAddr, sz);

    // Освобождаем модуль
    HMODULE hMod = (HMODULE)pAddr;
    while (FreeLibrary(hMod)) {
        printf("DumpModule: Freed one reference\n");
    }
    VirtualFree((LPVOID)pAddr, 0, MEM_RELEASE);

    // Аллоцируем память по тому же адресу
    void* newBase = VirtualAlloc((void*)pAddr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) {
        DWORD err = GetLastError();
        printf("DumpModule: ERROR - VirtualAlloc at 0x%p failed, error=%d\n", (void*)pAddr, err);
        VirtualFree(backup, 0, MEM_RELEASE);
        return 0;
    }

    if (newBase != (void*)pAddr) {
        printf("DumpModule: ERROR - Got different address 0x%p\n", newBase);
        VirtualFree(newBase, 0, MEM_RELEASE);
        VirtualFree(backup, 0, MEM_RELEASE);
        return 0;
    }

    // Восстанавливаем данные
    memcpy(newBase, backup, sz);
    VirtualFree(backup, 0, MEM_RELEASE);

    // Восстанавливаем права доступа для секций
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
        DWORD protect = PAGE_READWRITE;

        if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (pSection->Characteristics & IMAGE_SCN_MEM_READ) {
                if (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    protect = PAGE_EXECUTE_READWRITE;
                }
                else {
                    protect = PAGE_EXECUTE_READ;
                }
            }
            else {
                protect = PAGE_EXECUTE;
            }
        }
        else {
            if (pSection->Characteristics & IMAGE_SCN_MEM_READ) {
                if (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    protect = PAGE_READWRITE;
                }
                else {
                    protect = PAGE_READONLY;
                }
            }
            else {
                protect = PAGE_NOACCESS;
            }
        }

        DWORD oldProtectSection;
        VirtualProtect((LPVOID)((uintptr_t)newBase + pSection->VirtualAddress),
            pSection->Misc.VirtualSize,
            protect,
            &oldProtectSection);
    }

    printf("DumpModule: SUCCESS - Module dumped at 0x%p\n", newBase);
    printf("DumpModule: Module is now raw memory, not a Windows module\n");
    printf("DumpModule: To free use: VirtualFree((void*)0x%p, 0, MEM_RELEASE)\n", newBase);
    return (uintptr_t)newBase;
}

uintptr_t AsmRunner::DumpModule(const char* moduleName, bool bLoadLib)
{
    printf("DumpModule: Looking for module '%s' (bLoadLib=%d)\n", moduleName ? moduleName : "null", bLoadLib);

    if (!moduleName) {
        printf("DumpModule: ERROR - Null module name\n");
        return 0;
    }

    HMODULE hMod = GetModuleHandleA(moduleName);

    if (!hMod && bLoadLib) {
        printf("DumpModule: Module '%s' not loaded, trying LoadLibraryA\n", moduleName);
        hMod = LoadLibraryA(moduleName);
        if (!hMod) {
            printf("DumpModule: ERROR - LoadLibraryA failed for '%s', error=%d\n", moduleName, GetLastError());
            return 0;
        }
        printf("DumpModule: LoadLibraryA succeeded, module at 0x%p\n", hMod);
    }

    if (!hMod) {
        printf("DumpModule: ERROR - Module '%s' not found, error=%d\n", moduleName, GetLastError());
        return 0;
    }

    printf("DumpModule: Found module '%s' at 0x%p\n", moduleName, hMod);
    return DumpModule((uintptr_t)hMod);
}

#if 0
bool AsmRunner::DumpModuleToFile(uintptr_t pAddr, const char* fileName)
{
    printf("DumpModuleToFile: pAddr=0x%p, fileName='%s'\n", (void*)pAddr, fileName ? fileName : "null");

    if (!pAddr || !fileName) {
        printf("DumpModuleToFile: ERROR - Null address or filename\n");
        return false;
    }

    // Проверяем DOS заголовок
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pAddr;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("DumpModuleToFile: ERROR - Invalid DOS header\n");
        return false;
    }

    // Проверяем NT заголовок
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pAddr + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("DumpModuleToFile: ERROR - Invalid NT header\n");
        return false;
    }

    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;
    if (!imageSize) {
        printf("DumpModuleToFile: ERROR - Zero image size\n");
        return false;
    }

    printf("DumpModuleToFile: Image size = %zu bytes\n", imageSize);

    // Открываем файл для записи
    HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("DumpModuleToFile: ERROR - CreateFileA failed, error=%d\n", GetLastError());
        return false;
    }

    // Сохраняем права доступа к страницам модуля
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)pAddr, imageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("DumpModuleToFile: ERROR - VirtualProtect failed, error=%d\n", GetLastError());
        CloseHandle(hFile);
        DeleteFileA(fileName);
        return false;
    }

    // Собираем информацию о секциях для правильного дампа
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    WORD numSections = pNt->FileHeader.NumberOfSections;

    // Вектор для хранения информации о секциях
    struct SectionInfo {
        DWORD virtualAddress;
        DWORD virtualSize;
        DWORD rawAddress;
        DWORD rawSize;
    };
    std::vector<SectionInfo> sections;

    // Записываем заголовки (DOS + NT + Section headers)
    DWORD headersSize = pSection ? (DWORD)((uintptr_t)pSection - pAddr) : 0;
    if (headersSize > 0) {
        DWORD bytesWritten;
        if (!WriteFile(hFile, (LPCVOID)pAddr, headersSize, &bytesWritten, NULL) || bytesWritten != headersSize) {
            printf("DumpModuleToFile: ERROR - Failed to write headers, error=%d\n", GetLastError());
            VirtualProtect((LPVOID)pAddr, imageSize, oldProtect, &oldProtect);
            CloseHandle(hFile);
            DeleteFileA(fileName);
            return false;
        }
        printf("DumpModuleToFile: Written headers: %u bytes\n", headersSize);
    }

    // Собираем информацию о секциях и записываем их данные
    for (WORD i = 0; i < numSections; i++, pSection++) {
        SectionInfo info;
        info.virtualAddress = pSection->VirtualAddress;
        info.virtualSize = pSection->Misc.VirtualSize;
        info.rawAddress = pSection->PointerToRawData;
        info.rawSize = pSection->SizeOfRawData;

        sections.push_back(info);

        // Если секция имеет данные в файле (raw size > 0)
        if (info.rawSize > 0 && info.rawAddress > 0) {
            // Проверяем, что данные секции не выходят за пределы образа
            if (info.rawAddress + info.rawSize <= imageSize) {
                // Выравниваем позицию в файле до rawAddress
                LARGE_INTEGER filePos;
                filePos.QuadPart = info.rawAddress;
                if (!SetFilePointerEx(hFile, filePos, NULL, FILE_BEGIN)) {
                    printf("DumpModuleToFile: WARNING - Failed to seek to raw address 0x%X\n", info.rawAddress);
                }

                DWORD bytesWritten;
                LPVOID sectionData = (LPVOID)(pAddr + info.virtualAddress);
                if (!WriteFile(hFile, sectionData, info.rawSize, &bytesWritten, NULL) || bytesWritten != info.rawSize) {
                    printf("DumpModuleToFile: WARNING - Failed to write section %d, error=%d\n", i, GetLastError());
                }
                else {
                    printf("DumpModuleToFile: Written section %d: VA=0x%X, Size=%u bytes\n",
                        i, info.virtualAddress, info.rawSize);
                }
            }
            else {
                printf("DumpModuleToFile: WARNING - Section %d out of bounds\n", i);
            }
        }
    }

    // Закрываем файл
    CloseHandle(hFile);

    // Восстанавливаем права доступа
    VirtualProtect((LPVOID)pAddr, imageSize, oldProtect, &oldProtect);

    printf("DumpModuleToFile: SUCCESS - Module dumped to '%s'\n", fileName);
    return true;
}

//bool AsmRunner::DumpModuleToFile(uintptr_t pAddr, const char* fileName) // пишет по секциям, но результат не сходится, TODO
//{
//    if (!pAddr || !fileName) {
//        printf("ERROR: Null address or filename\n");
//        return false;
//    }
//
//    // Проверяем DOS заголовок
//    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pAddr;
//    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
//        printf("ERROR: Invalid DOS header\n");
//        return false;
//    }
//
//    // Проверяем NT заголовок
//    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pAddr + pDos->e_lfanew);
//    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
//        printf("ERROR: Invalid NT header\n");
//        return false;
//    }
//
//    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;
//    if (!imageSize) {
//        printf("ERROR: Zero image size\n");
//        return false;
//    }
//
//    printf("Dumping module at 0x%p, size: %zu bytes to '%s'\n", (void*)pAddr, imageSize, fileName);
//
//    // Выделяем буфер для выровненного образа
//    std::vector<BYTE> buffer(imageSize, 0); // Инициализируем нулями
//
//    // Копируем заголовки (DOS + NT + Section headers)
//    SIZE_T headersSize = pNt->OptionalHeader.SizeOfHeaders;
//    if (headersSize > 0 && headersSize <= imageSize) {
//        // Проверяем доступность памяти для заголовков
//        MEMORY_BASIC_INFORMATION mbi;
//        if (VirtualQuery((LPCVOID)pAddr, &mbi, sizeof(mbi))) {
//            if (mbi.State == MEM_COMMIT) {
//                SIZE_T copySize = std::min(headersSize, mbi.RegionSize);
//                memcpy(buffer.data(), (LPCVOID)pAddr, copySize);
//            }
//        }
//    }
//
//    // Копируем секции
//    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
//    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
//        DWORD va = pSection[i].VirtualAddress;
//        DWORD size = pSection[i].SizeOfRawData;
//
//        if (size > 0 && va + size <= imageSize) {
//            uintptr_t sectionAddr = pAddr + va;
//
//            // Проверяем доступность каждой страницы секции
//            bool sectionValid = true;
//            SIZE_T bytesChecked = 0;
//
//            while (bytesChecked < size) {
//                MEMORY_BASIC_INFORMATION mbi;
//                if (!VirtualQuery((LPCVOID)(sectionAddr + bytesChecked), &mbi, sizeof(mbi))) {
//                    sectionValid = false;
//                    break;
//                }
//
//                if (mbi.State != MEM_COMMIT) {
//                    sectionValid = false;
//                    break;
//                }
//
//                bytesChecked += mbi.RegionSize;
//                if (bytesChecked > size) bytesChecked = size;
//            }
//
//            if (sectionValid) {
//                // Копируем валидную секцию
//                memcpy(buffer.data() + va, (LPCVOID)sectionAddr, size);
//                printf("  Copied section '%s' (VA: 0x%X, size: %d bytes)\n",
//                    pSection[i].Name, va, size);
//            }
//            else {
//                printf("  WARNING: Section '%s' has unaccessible memory, filled with zeros\n",
//                    pSection[i].Name);
//                // Секция останется нулевой (уже инициализирована)
//            }
//        }
//    }
//
//    // Открываем файл
//    HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL,
//        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
//    if (hFile == INVALID_HANDLE_VALUE) {
//        printf("ERROR: Failed to create file, error=%d\n", GetLastError());
//        return false;
//    }
//
//    // Пишем буфер целиком
//    DWORD bytesWritten;
//    BOOL success = WriteFile(hFile, buffer.data(), (DWORD)imageSize, &bytesWritten, NULL);
//    CloseHandle(hFile);
//
//    if (!success || bytesWritten != imageSize) {
//        printf("ERROR: Failed to write file, error=%d\n", GetLastError());
//        DeleteFileA(fileName);
//        return false;
//    }
//
//    printf("SUCCESS: Dumped %u bytes to '%s'\n", bytesWritten, fileName);
//    return true;
//}
#endif

bool AsmRunner::DumpModuleToFile(uintptr_t pAddr, const char* fileName)
{
    if (!pAddr || !fileName) {
        printf("ERROR: Null address or filename\n");
        return false;
    }

    // Проверяем DOS заголовок
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pAddr;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("ERROR: Invalid DOS header\n");
        return false;
    }

    // Проверяем NT заголовок и получаем размер образа
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pAddr + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("ERROR: Invalid NT header\n");
        return false;
    }

    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;
    if (!imageSize) {
        printf("ERROR: Zero image size\n");
        return false;
    }

    printf("Dumping module at 0x%p, size: %zu bytes to '%s'\n",
        (void*)pAddr, imageSize, fileName);

    // Открываем файл
    HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("ERROR: Failed to create file, error=%d\n", GetLastError());
        return false;
    }

    // Пишем весь образ целиком
    DWORD bytesWritten;
    BOOL success = WriteFile(hFile, (LPCVOID)pAddr, (DWORD)imageSize, &bytesWritten, NULL);

    // Закрываем файл
    CloseHandle(hFile);

    if (!success || bytesWritten != imageSize) {
        printf("ERROR: Failed to write file, error=%d\n", GetLastError());
        DeleteFileA(fileName);
        return false;
    }

    printf("SUCCESS: Dumped %u bytes to '%s'\n", bytesWritten, fileName);
    return true;
}

bool AsmRunner::DumpModuleToFile(const char* moduleName, const char* fileName, bool bLoadLib)
{
    printf("DumpModuleToFile: Looking for module '%s' (bLoadLib=%d)\n", moduleName ? moduleName : "null", bLoadLib);

    if (!moduleName || !fileName) {
        printf("DumpModuleToFile: ERROR - Null module name or filename\n");
        return false;
    }

    HMODULE hMod = GetModuleHandleA(moduleName);

    if (!hMod && bLoadLib) {
        printf("DumpModuleToFile: Module '%s' not loaded, trying LoadLibraryA\n", moduleName);
        hMod = LoadLibraryA(moduleName);
        if (!hMod) {
            printf("DumpModuleToFile: ERROR - LoadLibraryA failed for '%s', error=%d\n", moduleName, GetLastError());
            return false;
        }
        printf("DumpModuleToFile: LoadLibraryA succeeded, module at 0x%p\n", hMod);
    }

    if (!hMod) {
        printf("DumpModuleToFile: ERROR - Module '%s' not found, error=%d\n", moduleName, GetLastError());
        return false;
    }

    printf("DumpModuleToFile: Found module '%s' at 0x%p\n", moduleName, hMod);
    return DumpModuleToFile((uintptr_t)hMod, fileName);
}

#if 0
uintptr_t AsmRunner::RemapModule(uintptr_t pAddr, bool bTerminateAll)
{
    printf("RemapModule: pAddr=0x%p, bTerminateAll=%s\n", (void*)pAddr, bTerminateAll ? "true" : "false");

    if (!pAddr) {
        printf("RemapModule: ERROR - Null address\n");
        return 0;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pAddr;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("RemapModule: ERROR - Invalid DOS header\n");
        return 0;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pAddr + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("RemapModule: ERROR - Invalid NT header\n");
        return 0;
    }

    SIZE_T sz = pNt->OptionalHeader.SizeOfImage;
    if (!sz) {
        printf("RemapModule: ERROR - Zero image size\n");
        return 0;
    }

    printf("RemapModule: Image size = %zu bytes\n", sz);

    // Collect all threads (except current) for suspension or termination
    std::vector<HANDLE> hThreads;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId() &&
                    te.th32ThreadID != GetCurrentThreadId()) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | (bTerminateAll ? THREAD_TERMINATE : 0),
                        FALSE, te.th32ThreadID);
                    if (hThread) {
                        hThreads.push_back(hThread);
                        if (!bTerminateAll) {
                            SuspendThread(hThread);
                        }
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
    }

    // If bTerminateAll, terminate all threads now
    if (bTerminateAll) {
        printf("RemapModule: Terminating all threads (bTerminateAll=true)\n");
        for (HANDLE hThread : hThreads) {
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
        }
        hThreads.clear();
        printf("RemapModule: All threads terminated\n");
    }

    void* backup = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!backup) {
        printf("RemapModule: ERROR - VirtualAlloc for backup failed, error=%d\n", GetLastError());

        // Resume threads if not terminating
        if (!bTerminateAll) {
            for (HANDLE hThread : hThreads) {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }
        return 0;
    }

    memcpy(backup, (void*)pAddr, sz);

    HMODULE hMod = (HMODULE)pAddr;
    while (FreeLibrary(hMod)) {
        printf("RemapModule: Freed one reference\n");
    }
    VirtualFree((LPVOID)pAddr, 0, MEM_RELEASE); // recheck

    void* newBase = VirtualAlloc((void*)pAddr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) {
        DWORD err = GetLastError();
        printf("RemapModule: ERROR - VirtualAlloc at 0x%p failed, error=%d\n", (void*)pAddr, err);
        VirtualFree(backup, 0, MEM_RELEASE);

        if (!bTerminateAll) {
            for (HANDLE hThread : hThreads) {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }
        return 0;
    }

    if (newBase != (void*)pAddr) {
        printf("RemapModule: ERROR - Got different address 0x%p\n", newBase);
        VirtualFree(newBase, 0, MEM_RELEASE);
        VirtualFree(backup, 0, MEM_RELEASE);

        if (!bTerminateAll) {
            for (HANDLE hThread : hThreads) {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }
        return 0;
    }

    memcpy(newBase, backup, sz);
    VirtualFree(backup, 0, MEM_RELEASE);

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
        DWORD protect = PAGE_READWRITE;

        if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (pSection->Characteristics & IMAGE_SCN_MEM_READ) {
                if (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    protect = PAGE_EXECUTE_READWRITE;
                }
                else {
                    protect = PAGE_EXECUTE_READ;
                }
            }
            else {
                protect = PAGE_EXECUTE;
            }
        }
        else {
            if (pSection->Characteristics & IMAGE_SCN_MEM_READ) {
                if (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    protect = PAGE_READWRITE;
                }
                else {
                    protect = PAGE_READONLY;
                }
            }
            else {
                protect = PAGE_NOACCESS;
            }
        }

        DWORD oldProtectSection;
        VirtualProtect((LPVOID)((uintptr_t)newBase + pSection->VirtualAddress),
            pSection->Misc.VirtualSize,
            protect,
            &oldProtectSection);
    }

    // Resume threads only if not terminating
    if (!bTerminateAll) {
        printf("RemapModule: Resuming all threads (bTerminateAll=false)\n");
        for (HANDLE hThread : hThreads) {
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }
    else {
        // Clean up thread handles (already terminated and closed)
        for (HANDLE hThread : hThreads) {
            CloseHandle(hThread);
        }
    }

    printf("RemapModule: SUCCESS - Module remapped at 0x%p\n", newBase);
    printf("RemapModule: Module is now raw memory, not a Windows module\n");
    printf("RemapModule: To free use: VirtualFree((void*)0x%p, 0, MEM_RELEASE)\n", newBase);
    return (uintptr_t)newBase;
}

uintptr_t AsmRunner::RemapModule(const char* moduleName, bool bLoadLib, bool bTerminateAll)
{
    printf("RemapModule: Looking for module '%s' (bLoadLib=%d)\n", moduleName ? moduleName : "null", bLoadLib);

    if (!moduleName) {
        printf("RemapModule: ERROR - Null module name\n");
        return 0;
    }

    HMODULE hMod = GetModuleHandleA(moduleName);

    if (!hMod && bLoadLib) {
        printf("RemapModule: Module '%s' not loaded, trying LoadLibraryA\n", moduleName);
        hMod = LoadLibraryA(moduleName);
        if (!hMod) {
            printf("RemapModule: ERROR - LoadLibraryA failed for '%s', error=%d\n", moduleName, GetLastError());
            return 0;
        }
        printf("RemapModule: LoadLibraryA succeeded, module at 0x%p\n", hMod);
    }

    if (!hMod) {
        printf("RemapModule: ERROR - Module '%s' not found, error=%d\n", moduleName, GetLastError());
        return 0;
    }

    printf("RemapModule: Found module '%s' at 0x%p\n", moduleName, hMod);
    return RemapModule((uintptr_t)hMod, bTerminateAll);
}
#endif

void AsmRunner::TestPerformanceConstants()
{
    const uint64_t TEST_INSTRUCTIONS = 100'000'000; // 100 млн NOP'ов

    auto start = std::chrono::high_resolution_clock::now();

    for (uint64_t i = 0; i < TEST_INSTRUCTIONS; i++) { __asm { nop }; }

    auto end = std::chrono::high_resolution_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    uint64_t realIPS = (TEST_INSTRUCTIONS * 1'000'000'000ULL) / ns;
    uint64_t realMIPS = realIPS / 1'000'000;
    double nsPerInstr = (double)ns / TEST_INSTRUCTIONS;

    const uint64_t FILETIME_UNITS_PER_SECOND = 10'000'000; // 100ns интервалов в секунде
    uint64_t instructionsPerFiletimeUnit = realIPS / FILETIME_UNITS_PER_SECOND;
    uint64_t filetimeUnitsPerInstruction = FILETIME_UNITS_PER_SECOND / realIPS;

    printf("========== Performance Test ==========\n");
    printf("Test instructions: %llu NOPs\n", TEST_INSTRUCTIONS);
    printf("Time elapsed: %.3f ms (%.3f seconds)\n", ns / 1'000'000.0, ns / 1'000'000'000.0);
    printf("Time elapsed: %llu ns\n", ns);
    printf("\n");
    printf("Results:\n");
    printf("  Real IPS: %llu instructions/second\n", realIPS);
    printf("  Real MIPS: %llu million instructions/second\n", realMIPS);
    printf("  %.2f ns per instruction\n", nsPerInstr);
    printf("\n");
    printf("Constants for CalcTime():\n");
    printf("  INSTRUCTIONS_PER_SECOND = %lluULL\n", realIPS);
    printf("  FILETIME_UNITS_PER_SECOND = %lluULL\n", FILETIME_UNITS_PER_SECOND);
    printf("\n");
    printf("Derived values:\n");
    printf("  %.2f instructions per 100ns (FileTime unit)\n", (double)realIPS / FILETIME_UNITS_PER_SECOND);
    printf("  %.4f FileTime units per instruction\n", (double)FILETIME_UNITS_PER_SECOND / realIPS);
    printf("\n");

    // Пример: сколько времени займут 1000 инструкций
    uint64_t testInstr = 1000;
    uint64_t emulatedTime = (testInstr * FILETIME_UNITS_PER_SECOND) / realIPS;
    printf("Example: %llu instructions = %llu FileTime units (%.3f ms)\n",
        testInstr, emulatedTime, emulatedTime / 10'000.0);
    printf("=======================================\n");
}

void AsmRunner::SetPerformanceConstantsHost(float k)
{
    const uint64_t TEST_INSTRUCTIONS = 100'000'000;
    auto start = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < TEST_INSTRUCTIONS; i++) { __asm { nop }; }
    auto end = std::chrono::high_resolution_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

#if 1
    // Apply scaling factor k:
    // k = 1.0 -> normal speed
    // k < 1.0 (e.g., 0.9) -> slower (simulate weaker CPU)
    // k > 1.0 (e.g., 1.2) -> faster (simulate powerful CPU)
    uint64_t measuredIPS = (TEST_INSTRUCTIONS * 1'000'000'000ULL) / ns;
    m_instructionsPerSecond = static_cast<uint64_t>(measuredIPS * k);
    m_filetimeUnitsPerSecond = 10'000'000ULL;

    if (m_bLogRunner) {
        Log("SetPerformanceConstants: Performance test completed: %llu instructions in %llu ns = %llu measured IPS",
            TEST_INSTRUCTIONS, ns, measuredIPS);
        Log("SetPerformanceConstants: Applied scaling factor k=%.2f -> Effective IPS = %llu (%.2f%% of measured)",
            k, m_instructionsPerSecond, k * 100.0);
}
#else
    m_instructionsPerSecond = (TEST_INSTRUCTIONS * 1'000'000'000ULL) / ns;
    m_filetimeUnitsPerSecond = 10'000'000ULL;

    if (m_bLogRunner)
        Log("SetPerformanceConstants: Performance test completed: %llu instructions in %llu ns = %llu IPS", TEST_INSTRUCTIONS, ns, m_instructionsPerSecond);
#endif
}

void AsmRunner::SetPerformanceConstants(uint64_t instructionsPerSecond, uint64_t filetimeUnitsPerSecond)
{
    m_instructionsPerSecond = instructionsPerSecond;
    m_filetimeUnitsPerSecond = filetimeUnitsPerSecond;

    if (m_bLogRunner) {
        Log("Performance constants set: IPS=%llu, FT_USEC=%llu",
            m_instructionsPerSecond, m_filetimeUnitsPerSecond);
        Log("Instructions per 100ns: %.2f",
            (double)m_instructionsPerSecond / m_filetimeUnitsPerSecond);
    }
}

uint64_t AsmRunner::CalcTime(uint64_t nInstrDelta, float k)
{
    if (m_instructionsPerSecond == 0) {
        if (m_bLogRunner) {
            Log("WARNING: CalcTime called but performance constants not set!");
        }
        return 0;
    }

    // Apply scaling factor k to the effective IPS for this calculation
    // k = 1.0 -> normal speed
    // k < 1.0 (e.g., 0.9) -> slower (more time)
    // k > 1.0 (e.g., 1.2) -> faster (less time)
    uint64_t effectiveIPS = static_cast<uint64_t>(m_instructionsPerSecond * k);

    if (effectiveIPS == 0) {
        if (m_bLogRunner) {
            Log("WARNING: CalcTime called with k=%.2f resulting in zero effective IPS!", k);
        }
        return 0;
    }

    uint64_t result = (nInstrDelta * m_filetimeUnitsPerSecond) / effectiveIPS;

    if (m_bLogRunner) {
        Log("CalcTime: %llu instructions * k=%.2f = %llu FileTime units",
            nInstrDelta, k, result);
    }

    return result;
}

double AsmRunner::CalcTimeMs(uint64_t nInstrDelta, float k)
{
    return CalcTime(nInstrDelta, k) / 10000.0; // 1 ms = 10000 units of 100ns
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

std::string AsmRunner::GetProcessName()
{
    char path[MAX_PATH] = { 0 };
    GetModuleBaseNameA(GetCurrentProcess(), NULL, path, MAX_PATH);
    return std::string(path);
}

std::string AsmRunner::GetModuleName(HMODULE hMod)
{
    char path[MAX_PATH] = { 0 };
    GetModuleBaseNameA(GetCurrentProcess(), hMod, path, MAX_PATH);
    return std::string(path);
}

void AsmRunner::AddExportsFromModule(HMODULE hMod, std::map<uintptr_t, tFuncNode>& addrToInfo, uintptr_t nMaxSize)
{
    MODULEINFO mi = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
        return;

    BYTE* base = reinterpret_cast<BYTE*>(mi.lpBaseOfDll);
    std::string moduleName = GetModuleName(hMod);
    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(base);

    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        return;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size)
        return;

    IMAGE_EXPORT_DIRECTORY* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    if (!exp)
        return;

    DWORD* funcs = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);
    DWORD* names = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
    WORD* ords = reinterpret_cast<WORD*>(base + exp->AddressOfNameOrdinals);

    std::vector<std::string> perIndex(exp->NumberOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        DWORD idx = ords[i];
        if (idx < exp->NumberOfFunctions)
        {
            const char* nm = reinterpret_cast<const char*>(base + names[i]);
            if (nm && *nm)
                perIndex[idx] = nm;
        }
    }

    DWORD expStart = dir.VirtualAddress;
    DWORD expEnd = dir.VirtualAddress + dir.Size;

    for (DWORD i = 0; i < exp->NumberOfFunctions; ++i)
    {
        DWORD rva = funcs[i];
        if (!rva)
            continue;

        if (rva >= expStart && rva < expEnd)
            continue;

        uintptr_t addr = reinterpret_cast<uintptr_t>(base + rva);

        std::string funcName = perIndex[i];
        if (funcName.empty())
        {
            char tmp[64];
            sprintf_s(tmp, "ord%u", exp->Base + i);
            funcName = tmp;
        }

        if (addrToInfo.find(addr) == addrToInfo.end())
        {
            tFuncNode n;
            n.moduleName = moduleName;
            n.funcName = funcName;
            n.moduleBase = moduleBase;
            n.funcRva = rva;
            n.funcSize = 0;
            addrToInfo[addr] = std::move(n);
            //addrToInfo.emplace(addr, std::move(n));
        }
    }

    std::vector<uintptr_t> sortedAddrs;
    sortedAddrs.reserve(exp->NumberOfFunctions);

    for (const auto& pair : addrToInfo)
    {
        if (pair.second.moduleBase == moduleBase)
            sortedAddrs.push_back(pair.first);
    }

    std::sort(sortedAddrs.begin(), sortedAddrs.end());

    for (size_t i = 0; i < sortedAddrs.size(); ++i)
    {
        uintptr_t currAddr = sortedAddrs[i];

        if (i + 1 < sortedAddrs.size())
            addrToInfo[currAddr].funcSize = sortedAddrs[i + 1] - currAddr;
        else
            addrToInfo[currAddr].funcSize = (moduleBase + mi.SizeOfImage) - currAddr;
        if (nMaxSize > 0 && addrToInfo[currAddr].funcSize > nMaxSize)
            addrToInfo[currAddr].funcSize = nMaxSize;
    }
}

void AsmRunner::CollectAllExports(std::map<uintptr_t, tFuncNode>& addrToInfo, uintptr_t nMaxSize)
{
    HMODULE mods[1024] = { 0 };
    DWORD needed = 0;

    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return;

    size_t count = needed / sizeof(HMODULE);
    for (size_t i = 0; i < count; ++i)
        AddExportsFromModule(mods[i], addrToInfo, nMaxSize);
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
            a << "0x" << std::uppercase << std::hex << std::setw(addr_width) << std::setfill('0') << addr;
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
            a << "0x" << std::uppercase << std::hex << std::setw(addr_width) << std::setfill('0') << (startAddr + static_cast<uintptr_t>(i));
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

HANDLE AsmRunner::InitConsole()
{
    AllocConsole();

    //SetConsoleOutputCP(866);
    setlocale(LC_ALL, "Russian");
    SetConsoleOutputCP(1251);
    SetConsoleCP(1251);

    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);

    return hConsole;
}

void AsmRunner::CopyToClipboard(const char* text)
{
    if (!OpenClipboard(NULL))
        return;

    EmptyClipboard();
    size_t len = strlen(text) + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if (hMem) {
        memcpy(GlobalLock(hMem), text, len);
        GlobalUnlock(hMem);
        SetClipboardData(CF_TEXT, hMem);
    }
    CloseClipboard();
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

uintptr_t AsmRunner::SearchPointerByPattern(uintptr_t ptrStart, uint32_t block_size, std::string pattern)
{
#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (INRANGE(x, '0', '9') ? x - '0' : 0))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))
    const char* buffptr_pattern = pattern.c_str();
    uintptr_t pMatch = 0;
    for (uintptr_t MemPtr = ptrStart; MemPtr < (ptrStart + block_size); MemPtr++)
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
    return pMatch;
#undef getByte;
#undef getBits;
#undef INRANGE;
}

std::vector<uintptr_t> AsmRunner::ScanPattern(uintptr_t pStart, uintptr_t pEnd, std::string pattern)
{
    std::vector<uintptr_t> scanRes;
    if (pStart == 0 || pEnd == 0 || pEnd <= pStart || pattern.empty()) // !0 native memory
        return scanRes;

    uintptr_t current = pStart;
    while (current < pEnd) {
        uintptr_t found = (uintptr_t)SearchPointerByPattern(current, pEnd - current, pattern);
        if (found == 0) break;
        scanRes.push_back(found);
        current = (found + 1);
    }

    return scanRes;
}

std::vector<uintptr_t> AsmRunner::ScanPatternV(uintptr_t pStart, uintptr_t pEnd, std::string pattern)
{
    std::vector<uintptr_t> result;

    if (!m_uc || pStart == 0 || pEnd == 0 || pStart > pEnd || pattern.empty())
        return result;

    std::vector<int> pat;
    {
        auto hex = [](char c) -> int
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        };

        std::istringstream iss(pattern);
        std::string tok;
        while (iss >> tok)
        {
            if (tok == "?" || tok == "??")
            {
                pat.push_back(-1);
                continue;
            }

            if (tok.size() != 2)
                return result;

            int hi = hex(tok[0]);
            int lo = hex(tok[1]);
            if (hi < 0 || lo < 0)
                return result;

            pat.push_back((hi << 4) | lo);
        }
    }

    if (pat.empty())
        return result;

    const size_t patLen = pat.size();
    const uintptr_t scanEnd = pEnd + 1; // inclusive pEnd
    const uintptr_t pageSize = 0x1000;

    std::vector<uint8_t> tail;
    tail.reserve(patLen > 0 ? patLen - 1 : 0);

    auto matchAt = [&](const std::vector<uint8_t>& data, size_t pos) -> bool
    {
        for (size_t i = 0; i < patLen; ++i)
        {
            if (pat[i] >= 0 && data[pos + i] != (uint8_t)pat[i])
                return false;
        }
        return true;
    };

    for (uintptr_t cur = pStart; cur < scanEnd; )
    {
        uintptr_t pageEnd = AlignUp(cur + 1, pageSize);
        if (pageEnd > scanEnd)
            pageEnd = scanEnd;

        const size_t chunkSize = (size_t)(pageEnd - cur);
        if (chunkSize == 0)
            break;

        std::vector<uint8_t> chunk(chunkSize);
        if (uc_mem_read(m_uc, cur, chunk.data(), chunkSize) != UC_ERR_OK)
        {
            tail.clear();
            cur = pageEnd;
            continue;
        }

        std::vector<uint8_t> data;
        data.reserve(tail.size() + chunk.size());
        data.insert(data.end(), tail.begin(), tail.end());
        data.insert(data.end(), chunk.begin(), chunk.end());

        const uintptr_t baseAddr = cur - (uintptr_t)tail.size();

        if (data.size() >= patLen)
        {
            for (size_t i = 0; i + patLen <= data.size(); ++i)
            {
                if (matchAt(data, i))
                    result.push_back(baseAddr + i);
            }
        }

        if (patLen > 1)
        {
            const size_t keep = patLen - 1;
            if (data.size() >= keep)
                tail.assign(data.end() - keep, data.end());
            else
                tail = data;
        }
        else
        {
            tail.clear();
        }

        cur = pageEnd;
    }

    return result;
}

std::vector<uintptr_t> AsmRunner::ScanBytes(uintptr_t pStart, uintptr_t pEnd, const std::vector<uint8_t>& bytes)
{
    std::vector<uintptr_t> scanRes;
    if(pStart == 0 || pEnd == 0 || pEnd <= pStart || bytes.size() == 0) // !0 native memory
        return scanRes;

    size_t bytesLen = bytes.size();

    if ((pEnd - pStart) < bytesLen)
        return scanRes;

    for (uintptr_t MemPtr = pStart; MemPtr <= pEnd - bytesLen; MemPtr++) {
        if (memcmp((void*)MemPtr, bytes.data(), bytesLen) == 0) {
            scanRes.push_back(MemPtr);
        }
    }

    return scanRes;
}

uintptr_t AsmRunner::ScanBytesBlock(uintptr_t pStart, uintptr_t pEnd, const std::vector<std::vector<uint8_t>>& bytes, bool bStartAlignPat)
{
    if (pStart == 0 || pEnd == 0 || pEnd <= pStart || bytes.empty())
        return 0;

    uintptr_t minFirst = pEnd;
    bool allFound = true;

    for (const auto& pat : bytes) {
        if (pat.empty()) continue;
        uintptr_t found = 0;
        for (uintptr_t p = pStart; p <= pEnd - pat.size(); p++) {
            if (memcmp((void*)p, pat.data(), pat.size()) == 0) {
                found = p;
                break;
            }
        }
        if (!found) {
            allFound = false;
            break;
        }
        if (found < minFirst) minFirst = found;
    }

    if (!allFound) return 0;

    return bStartAlignPat ? minFirst : pStart;
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

bool AsmRunner::IsNTMemoryReadable(uintptr_t address, uintptr_t size)
{
    if (address == 0 || size == 0)
        return false;

    MEMORY_BASIC_INFORMATION mbi = { 0 };

    if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0)
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return false;

    if (mbi.Protect == PAGE_READWRITE ||
        mbi.Protect == PAGE_READONLY ||
        mbi.Protect == PAGE_EXECUTE_READ ||
        mbi.Protect == PAGE_EXECUTE_READWRITE)
    {
        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (address + size <= regionEnd)
            return true;
    }

    return false;
}

std::string AsmRunner::CleanFileName(std::string name)
{
    const std::string invalid = "\\/:*?\"<>|";
    std::replace_if(name.begin(), name.end(), [&](char c) { return invalid.find(c) != std::string::npos; }, '_');
    return name;
}

uint32_t AsmRunner::fast_hash32(const void* key, uint32_t len, uint32_t seed)
{
    const uint32_t m = 0x5bd1e995u;
    const int r = 24;
    uint32_t h = seed ^ static_cast<uint32_t>(len);
    const unsigned char* data = static_cast<const unsigned char*>(key);
    while (len >= 4)
    {
        uint32_t k;
        memcpy(&k, data, sizeof(k));
        k *= m;
        k ^= k >> r;
        k *= m;
        h *= m;
        h ^= k;
        data += 4;
        len -= 4;
    }
    switch (len) {
        case 3: h ^= uint32_t(data[2]) << 16;
        case 2: h ^= uint32_t(data[1]) << 8;
        case 1: h ^= uint32_t(data[0]); h *= m;
    }
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;
    return h;
}

uint32_t AsmRunner::hash_combine(uint32_t seed, uint32_t value)
{
    return seed ^ (value + 0x9e3779b9u + (seed << 6) + (seed >> 2));
}

uintptr_t AsmRunner::AddMemory(uintptr_t nSize, uint32_t nType, bool bAlign)
{
    if (!m_uc || nSize == 0) return 0;
    uintptr_t sz = bAlign ? AlignUp(nSize, 0x1000) : nSize;
    uintptr_t addr = bAlign ? AlignUp(m_allocCursor, 0x1000) : m_allocCursor;
    if (uc_mem_map(m_uc, addr, sz, nType) != UC_ERR_OK) return 0;
    m_memMap[addr] = { sz, nType };
    m_allocCursor = addr + sz;
    InitNewMemory(addr, sz);
    return addr;
}

uintptr_t AsmRunner::AddMemory(uintptr_t pFrom, uintptr_t nSize, uint32_t nType, bool bAlign)
{
    uintptr_t addr = AddMemory(nSize, nType, bAlign);
    if (addr && nSize) {
        uc_mem_write(m_uc, addr, reinterpret_cast<void*>(pFrom), nSize);
    }
    return addr;
}

bool AsmRunner::AddMemoryTo(uintptr_t pVTo, uintptr_t nSize, uint32_t nType, bool bAlign)
{
    if (!m_uc || !pVTo || !nSize) return false;
#if 1
    uintptr_t mapSize = bAlign ? AlignUp(nSize, 0x1000) : nSize;
    if (uc_mem_map(m_uc, pVTo, mapSize, nType) == UC_ERR_OK)
        m_memMap[pVTo] = { mapSize, nType };
#else
    const uintptr_t pageSize = 0x1000;
    const uintptr_t base = bAlign ? AlignDown(pVTo, pageSize) : pVTo;
    const uintptr_t end = bAlign ? AlignUp(pVTo + nSize, pageSize) : (pVTo + nSize);
    const uintptr_t mapSize = end - base;

    uc_err err = uc_mem_map(m_uc, base, mapSize, nType);
    if (err != UC_ERR_OK)
    {
        if (m_bLogRunner)
            Log("[!] uc_mem_map failed: %s (base=0x%p size=0x%zx)",
                uc_strerror(err), (void*)base, (size_t)mapSize);
        return false;
    }
    m_memMap[pVTo] = { mapSize, nType };
#endif
    InitNewMemory(pVTo, mapSize);
    return true;
}

bool AsmRunner::AddMemoryFromBuff(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize, uint32_t nType, bool bAlign)
{
    if (!m_uc || !pVTo || !pFrom || !nSize) return false;
    //uintptr_t mapSize = bAlign ? AlignUp(nSize, 0x1000) : nSize;
    //uc_mem_map(m_uc, pVTo, mapSize, nType);
    bool bRes = AddMemoryTo(pVTo, nSize, nType, bAlign);
    if(bRes)
        uc_mem_write(m_uc, pVTo, reinterpret_cast<void*>(pFrom), nSize);
    return bRes;
}

void AsmRunner::InitNewMemory(uintptr_t pAddr, uintptr_t nSize)
{
    if (m_DebugCanarySecurityInitCookie.empty() || nSize == 0)
        return;

    const uint8_t* patternData = m_DebugCanarySecurityInitCookie.data();
    const size_t patternSize = m_DebugCanarySecurityInitCookie.size();

    uintptr_t offset = 0;
    while (offset < nSize) {
        const size_t chunk = std::min<size_t>(patternSize, nSize - offset);
        CopyMemory(pAddr + offset, reinterpret_cast<uintptr_t>(patternData), chunk);
        offset += chunk;
    }
}

void AsmRunner::CopyMemory(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize)
{
    if (!m_uc || !pVTo || !pFrom || !nSize) return;
    uc_mem_write(m_uc, pVTo, reinterpret_cast<void*>(pFrom), nSize);
}

uintptr_t AsmRunner::MemSet(uintptr_t pAddr, int8_t nVal, uintptr_t nSize)
{
    if (!m_uc || !pAddr || !nSize) return 0;
    uint8_t* arr = new uint8_t[nSize];
    memset(arr, nVal, nSize);
    CopyMemory(pAddr, (uintptr_t)arr, nSize);
    delete[] arr;
    arr = nullptr;
    return pAddr;
}

uintptr_t AsmRunner::MemCpy(uintptr_t pVTo, uintptr_t pVFrom, uintptr_t nSize)
{
    if (!m_uc || !pVTo || !pVFrom || !nSize)
        return 0;

    std::vector<uint8_t> buf;
    buf.resize(static_cast<size_t>(nSize));

    if (uc_mem_read(m_uc, pVFrom, buf.data(), static_cast<size_t>(nSize)) != UC_ERR_OK)
    {
        if (m_bLogRunner)
            Log("MemCpy: read failed, from=0x%p size=0x%zx", (void*)pVFrom, static_cast<size_t>(nSize));
        return 0;
    }

    if (uc_mem_write(m_uc, pVTo, buf.data(), static_cast<size_t>(nSize)) != UC_ERR_OK)
    {
        if (m_bLogRunner)
            Log("MemCpy: write failed, to=0x%p size=0x%zx", (void*)pVTo, static_cast<size_t>(nSize));
        return 0;
    }

    return pVTo;
}

uintptr_t AsmRunner::StrLen(uintptr_t pVStr)
{
    if (!m_uc || !pVStr)
        return 0;

    uintptr_t len = 0;
    uint8_t ch = 0;

    while (true)
    {
        if (uc_mem_read(m_uc, pVStr + len, &ch, 1) != UC_ERR_OK)
        {
            if (m_bLogRunner)
                Log("StrLen: read failed at 0x%p", (void*)(pVStr + len));
            return 0;
        }

        if (ch == 0)
            break;

        ++len;
    }

    return len;
}

bool AsmRunner::FreeMemory(uintptr_t pVTo)
{
    if (!m_uc || !pVTo) return false;
    auto it = m_memMap.find(pVTo);
    if (it == m_memMap.end())
    {
        if (m_bLogRunner)
            Log("[!] FreeMemory: no map entry for 0x%p", (void*)pVTo);
        return false;
    }
    uintptr_t sz = it->second.size;
    m_memMap.erase(it);
    return uc_mem_unmap(m_uc, pVTo, sz) == UC_ERR_OK;
}

bool AsmRunner::FreeMemory(uintptr_t pVTo, uintptr_t nSize)
{
    if (!m_uc || !pVTo || !nSize)
        return false;

    uintptr_t alignedSize = AlignUp(nSize, 0x1000);
    auto it = m_memMap.find(pVTo);
    if (it != m_memMap.end())
        m_memMap.erase(it);
    else if (m_bLogRunner)
        Log("[!] FreeMemory(addr,size): no memMap entry for 0x%p", (void*)pVTo);

    return uc_mem_unmap(m_uc, pVTo, alignedSize) == UC_ERR_OK;
}

bool AsmRunner::ChangeMemoryType(uintptr_t pVTo, uint32_t nType)
{
    if (!m_uc || !pVTo) return false;
    auto it = m_memMap.find(pVTo);
    uintptr_t sz = (it != m_memMap.end()) ? it->second.size : 0x1000;
    uc_err err = uc_mem_protect(m_uc, pVTo, sz, nType);
    if (err == UC_ERR_OK && it != m_memMap.end())
        it->second.prot = nType;
    return err == UC_ERR_OK;
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

void AsmRunner::DumpMemoryNT(uintptr_t pStart, uintptr_t nSize)
{
    if (!pStart || !nSize) return;
    std::string out;
    DataToHexString(0, pStart, (uint8_t*)pStart, nSize, &out);
    Log("%s", out.c_str());
}

void AsmRunner::DumpMemoryVal(uintptr_t nVal, uintptr_t nSize)
{
    if (!nSize) return;
    std::string out;
    DataToHexString(0, 0, (uint8_t*)&nVal, std::min(sizeof(nVal), nSize), &out);
    Log("%s", out.c_str());
}

void AsmRunner::DumpMemory(uintptr_t pNativeStart, uintptr_t pVTStart, uintptr_t nSize)
{
    if (!m_uc || !pNativeStart || !pVTStart || !nSize) return;

    uc_mem_read(m_uc, pVTStart, reinterpret_cast<void*>(pNativeStart), static_cast<size_t>(nSize));
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
    uintptr_t addr = AddMemory(nSize, UC_PROT_ALL, true);
    if (!addr) return 0;
    if (uc_mem_write(m_uc, addr, reinterpret_cast<void*>(pStart), nSize) != UC_ERR_OK) {
        uc_mem_unmap(m_uc, addr, AlignUp(nSize, 0x1000));
        return 0;
    }
    return addr;
}

void AsmRunner::EditBuff(uintptr_t pVaddr, uintptr_t size)
{
    if (!pVaddr || !size)
        return;

    void* buff = VirtualAlloc(nullptr,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!buff)
        return;

    DumpMemory((uintptr_t)buff, pVaddr, size);
    Log("[*] WaitBuff: buff 0x%p -> 0x%p  End: 0x%p", buff, size, (void*)(((uintptr_t)buff) + size));

    MessageBoxA(nullptr,
        "Buffer is copied into native memory.\n"
        "You can inspect it in the debugger.\n"
        "Press OK to free it.",
        "WaitBuff",
        MB_OK);

    CopyMemory(pVaddr, (uintptr_t)buff, size);

    VirtualFree(buff, 0, MEM_RELEASE);
    buff = nullptr;
}

bool AsmRunner::IsModuleAddr(uintptr_t pAddr)
{
    return IsInAddr(pAddr, m_modStart, m_modEnd);
}

bool AsmRunner::IsHaltAddr(uintptr_t pAddr)
{
    return pAddr == m_halt;
}

bool AsmRunner::InExtraRegion(uintptr_t pAddr)
{
    for (const auto& r : m_execRegions)
    {
        if (pAddr >= r.pStart && pAddr < r.pEnd)
            return true;
    }
    return false;
}

bool AsmRunner::IsPCNormal(uintptr_t pc, bool bSkipHalt)
{
    if (!bSkipHalt && IsHaltAddr(pc))
        return false;

    if (IsModuleAddr(pc) || InExtraRegion(pc))
        return true;

    for (const auto& h : m_anyJmpHooks)
    {
        if (h.pAddr == pc)
            return true;
    }

    return false;
}

void AsmRunner::UpdatePC(uintptr_t pAddr, bool bSkipCBCallsWithNewPC)
{
    if (IsHaltAddr(pAddr)) {
        if (m_bLogRunner)
            Log("[!] UpdatePC Set HALT Addr 0x%p! Shutdown", (void*)pAddr);
        ShutdownByHalt(m_uc);
        return;
    }

    SetRegister(PcReg(), pAddr);
    SetSkipCBCallsWithNewPC(bSkipCBCallsWithNewPC);
}

void AsmRunner::CapturePC()
{
    m_lastPC = CurrentPc(m_uc);
}

bool AsmRunner::IsPCChanged()
{
    uintptr_t currentPC = CurrentPc(m_uc);
    return (currentPC != m_lastPC);
}

bool AsmRunner::ShouldStopCB(bool bReset)
{
    //if (IsPCChanged())
    //    return true;

    if (m_bSkipCBCallsWithNewPC) {
        if(bReset)
            m_bSkipCBCallsWithNewPC = false;
        return true; // prevent notice in cb with old pc opcode
    }

    return false;
}

bool AsmRunner::IsInAddr(uintptr_t pAddr, uintptr_t pStart, uintptr_t pEnd)
{
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

bool AsmRunner::IsAnyReg(uintptr_t value, uintptr_t& outReg, std::string& outName)
{
    struct REG_INFO {
        uintptr_t reg;
        const char* name;
    };

    static const REG_INFO regs32[] =
    {
        { UC_X86_REG_EAX, "EAX" },
        { UC_X86_REG_EBX, "EBX" },
        { UC_X86_REG_ECX, "ECX" },
        { UC_X86_REG_EDX, "EDX" },
        { UC_X86_REG_ESI, "ESI" },
        { UC_X86_REG_EDI, "EDI" },
        { UC_X86_REG_EBP, "EBP" },
        { UC_X86_REG_ESP, "ESP" },
        { UC_X86_REG_EIP, "EIP" },
    };

    static const REG_INFO regs64[] =
    {
        { UC_X86_REG_RAX, "RAX" },
        { UC_X86_REG_RBX, "RBX" },
        { UC_X86_REG_RCX, "RCX" },
        { UC_X86_REG_RDX, "RDX" },
        { UC_X86_REG_RSI, "RSI" },
        { UC_X86_REG_RDI, "RDI" },
        { UC_X86_REG_RBP, "RBP" },
        { UC_X86_REG_RSP, "RSP" },
        { UC_X86_REG_R8,  "R8"  },
        { UC_X86_REG_R9,  "R9"  },
        { UC_X86_REG_R10, "R10" },
        { UC_X86_REG_R11, "R11" },
        { UC_X86_REG_R12, "R12" },
        { UC_X86_REG_R13, "R13" },
        { UC_X86_REG_R14, "R14" },
        { UC_X86_REG_R15, "R15" },
        { UC_X86_REG_RIP, "RIP" },
    };

    const REG_INFO* regs = m_bX64 ? regs64 : regs32;
    const size_t count = m_bX64 ? std::size(regs64) : std::size(regs32);

    for (size_t i = 0; i < count; ++i)
    {
        uintptr_t regValue = GetRegister(regs[i].reg);
        if (regValue == value)
        {
            outReg = regs[i].reg;
            outName = regs[i].name;
            return true;
        }
    }

    outReg = UC_X86_REG_INVALID;
    outName.clear();
    return false;
}

void AsmRunner::SetStack(uintptr_t pStack, uintptr_t nSize)
{
    // pStack m_stackBase = 0x00100000
    // nSize m_stackSize = 0x00100000
    // m_stackEPSize = 0x100
    // |start 0x00100000| ... STACK ... |SP+FP| EP|retHalt,A0,A1,A2..| ... |end 0x00100000 + 0x00100000|
    assert(m_bInitedStack == false);
    if (!m_uc) return;
    uintptr_t mapSize = AlignUp(nSize, 0x1000);
    uintptr_t pStackEnd = pStack + mapSize;
    if (uc_mem_map(m_uc, pStack, mapSize, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) return;
    m_memMap[pStack] = { mapSize, UC_PROT_READ | UC_PROT_WRITE };
    //uintptr_t sp = pStackEnd - (m_bX64 ? 0x20 : 8);
    uintptr_t sp = pStackEnd - m_stackEPSize; // call emu + ep args
    uintptr_t bp = pStackEnd - m_stackEPSize;

    uc_reg_write(m_uc, SpReg(), &sp);
    uc_reg_write(m_uc, FpReg(), &bp);
    //uc_mem_write(m_uc, GetRegister(SpReg()), &m_halt, sizeof(m_halt)); // same
    uc_mem_write(m_uc, sp, &m_halt, sizeof(m_halt));
    m_bInitedStack = true;
}

// TODO
void AsmRunner::CopyNTStack(uintptr_t pStack, uintptr_t nSize)
{
    assert(m_bInitedStack == false);
    if (!m_uc)
        return;

    ULONG_PTR lowLimit = 0, highLimit = 0;
    GetCurrentThreadStackLimits(&lowLimit, &highLimit);

    CONTEXT ctx{};
    RtlCaptureContext(&ctx);

#ifdef _AMD64_
    //uintptr_t nativeSp = m_bX64 ? static_cast<uintptr_t>(ctx.Rsp) : static_cast<uintptr_t>(ctx.Esp);
    //uintptr_t nativeBp = m_bX64 ? static_cast<uintptr_t>(ctx.Rbp) : static_cast<uintptr_t>(ctx.Ebp);
#else
    uintptr_t nativeSp = m_bX64 ? 0 : static_cast<uintptr_t>(ctx.Esp);
    uintptr_t nativeBp = m_bX64 ? 0 : static_cast<uintptr_t>(ctx.Ebp);
#endif

    if (pStack == 0)
        pStack = m_stackBase;

    if (nSize == 0)
        nSize = static_cast<uintptr_t>(highLimit - lowLimit);

    const uintptr_t mapSize = AlignUp(nSize, 0x1000);
    if (uc_mem_map(m_uc, pStack, mapSize, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK)
        return;
    m_memMap[pStack] = { mapSize, UC_PROT_READ | UC_PROT_WRITE };

    // Копируем безопасное окно вокруг текущих SP/BP.
    // Не лезем в guard page, не пытаемся тащить весь reserved stack.
    const uintptr_t pad = 0x4000;
    uintptr_t copyLow = (nativeSp < nativeBp) ? nativeSp : nativeBp;
    uintptr_t copyHigh = (nativeSp > nativeBp) ? nativeSp : nativeBp;

    copyLow = (copyLow > pad) ? (copyLow - pad) : static_cast<uintptr_t>(lowLimit);
    copyHigh += pad;

    if (copyLow < static_cast<uintptr_t>(lowLimit))
        copyLow = static_cast<uintptr_t>(lowLimit);
    if (copyHigh > static_cast<uintptr_t>(highLimit))
        copyHigh = static_cast<uintptr_t>(highLimit);

    copyLow = AlignDown(copyLow, PointerSize());
    copyHigh = AlignUp(copyHigh, PointerSize());

    if (copyHigh > copyLow)
    {
        const size_t sz = static_cast<size_t>(copyHigh - copyLow);
        std::vector<uint8_t> buf(sz);
        std::memcpy(buf.data(), reinterpret_cast<void*>(copyLow), sz);
        uc_mem_write(m_uc, pStack + (copyLow - static_cast<uintptr_t>(lowLimit)), buf.data(), buf.size());
    }

    uintptr_t emuSp = pStack + (nativeSp - static_cast<uintptr_t>(lowLimit));
    uintptr_t emuBp = pStack + (nativeBp - static_cast<uintptr_t>(lowLimit));

    uc_reg_write(m_uc, SpReg(), &emuSp);
    uc_reg_write(m_uc, FpReg(), &emuBp);

    // halt sentinel как и раньше
    uc_mem_write(m_uc, pStack + mapSize - m_stackEPSize, &m_halt, sizeof(m_halt));

    m_bInitedStack = true;

    if (m_bLogRunner)
        Log("[*] CopyNTStack done: base=0x%p size=0x%zx SP=0x%p BP=0x%p",
            (void*)pStack, (size_t)mapSize, (void*)emuSp, (void*)emuBp);
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

bool AsmRunner::StackPush(uintptr_t v)
{
    if (!m_uc || !m_bInitedStack)
        return false;

    uintptr_t sp = CurrentSp(m_uc);
    const uintptr_t ptrSize = PointerSize();
    const uintptr_t stackLow = m_stackBase;
    const uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000);

    if (sp < stackLow + ptrSize)
        return false;

    sp -= ptrSize;
    if (sp < stackLow || (sp + ptrSize) > stackHigh)
        return false;

    if (uc_mem_write(m_uc, sp, &v, ptrSize) != UC_ERR_OK)
        return false;

    if (!m_bX64)
        v = static_cast<uint32_t>(v);

    uc_reg_write(m_uc, SpReg(), &sp);
    return true;
}

bool AsmRunner::StackPop(uintptr_t& v)
{
    if (!m_uc || !m_bInitedStack)
        return false;

    uintptr_t sp = CurrentSp(m_uc);
    const uintptr_t ptrSize = PointerSize();
    const uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000);

    if ((sp + ptrSize) > stackHigh)
        return false;

    v = 0;
    if (uc_mem_read(m_uc, sp, &v, ptrSize) != UC_ERR_OK)
        return false;

    if (!m_bX64)
        v = static_cast<uint32_t>(v);

    sp += ptrSize;
    uc_reg_write(m_uc, SpReg(), &sp);
    return true;
}

uintptr_t AsmRunner::StackPop()
{
    uintptr_t v = 0;
    if (!StackPop(v))
        return 0;
    return v;
}

bool AsmRunner::StackPeek(uintptr_t& v, uint32_t nIdx)
{
    if (!m_uc || !m_bInitedStack)
        return false;

    uintptr_t sp = CurrentSp(m_uc);
    const uintptr_t ptrSize = PointerSize();
    const uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000);

    uintptr_t addr = sp + static_cast<uintptr_t>(nIdx) * ptrSize;
    if ((addr + ptrSize) > stackHigh)
        return false;

    v = 0;
    if (uc_mem_read(m_uc, addr, &v, ptrSize) != UC_ERR_OK)
        return false;

    if (!m_bX64)
        v = static_cast<uint32_t>(v);

    return true;
}

uintptr_t AsmRunner::StackPeek(uint32_t nIdx)
{
    uintptr_t v = 0;
    if (!StackPeek(v, nIdx))
        return 0;
    return v;
}

bool AsmRunner::StackPeekBP(uintptr_t& v, int32_t nIdx)
{
    if (!m_uc || !m_bInitedStack)
        return false;

    uintptr_t bp = GetRegister(FpReg());
    const uintptr_t ptrSize = PointerSize();
    const uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000);

    intptr_t addr = static_cast<intptr_t>(bp) + static_cast<intptr_t>(nIdx) * static_cast<intptr_t>(ptrSize);
    if (addr < 0)
        return false;

    uintptr_t uaddr = static_cast<uintptr_t>(addr);
    if ((uaddr + ptrSize) > stackHigh)
        return false;

    v = 0;
    if (uc_mem_read(m_uc, uaddr, &v, ptrSize) != UC_ERR_OK)
        return false;

    if (!m_bX64)
        v = static_cast<uint32_t>(v);

    return true;
}

uintptr_t AsmRunner::StackPeekBP(int32_t nIdx)
{
    uintptr_t v = 0;
    if (!StackPeekBP(v, nIdx))
        return 0;
    return v;
}

uintptr_t AsmRunner::StackAt(bool bEsp, int32_t nIdx)
{
    if (!m_uc || !m_bInitedStack)
        return 0;

    uintptr_t base = bEsp ? CurrentSp(m_uc) : GetRegister(FpReg());
    uintptr_t ptrSize = PointerSize();
    uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000);

    intptr_t addr = static_cast<intptr_t>(base) + static_cast<intptr_t>(nIdx) * static_cast<intptr_t>(ptrSize);
    if (addr < 0)
        return 0;

    uintptr_t uaddr = static_cast<uintptr_t>(addr);
    if ((uaddr + ptrSize) > stackHigh)
        return 0;

    return uaddr;
}

bool AsmRunner::StackSetValue(uintptr_t v, bool bEsp, int32_t nIdx)
{
    if (!m_uc || !m_bInitedStack)
        return false;

    const uintptr_t addr = StackAt(bEsp, nIdx);
    if (addr == 0)
        return false;

    const uintptr_t ptrSize = PointerSize();
    if (!m_bX64)
        v = static_cast<uint32_t>(v);

    return uc_mem_write(m_uc, addr, &v, ptrSize) == UC_ERR_OK;
}

bool AsmRunner::StackGetArg(uintptr_t& v, uint32_t idx, bool bShouldPopArgs_NoCdecl, bool bSkipRetAddrInStack)
{
    v = 0;

    if (!m_uc || !m_bInitedStack)
        return false;

    if (bSkipRetAddrInStack)
        ++idx; // in stack not extracted return addr

    if (IsX64())
    {
        ///old// x64 calling convention (fastcall)
        // x64 Windows calling convention:
        // RCX, RDX, R8, R9, then stack arguments after shadow space.
        switch (idx)
        {
            case 0: v = GetRegister(UC_X86_REG_RCX); return true;
            case 1: v = GetRegister(UC_X86_REG_RDX); return true;
            case 2: v = GetRegister(UC_X86_REG_R8);  return true;
            case 3: v = GetRegister(UC_X86_REG_R9);  return true;
            default:
            {
                uintptr_t sp = CurrentSp(m_uc);

                // после pop retaddr: [rsp] = shadow space, стек-аргументы начинаются с [rsp + 0x20]
                uintptr_t addr = sp + 0x20 + static_cast<uintptr_t>(idx - 4) * 8;

                uint64_t v64 = 0;
                if (uc_mem_read(m_uc, addr, &v64, 8) != UC_ERR_OK)
                    return false;

                v = static_cast<uintptr_t>(v64);
                return true;
            }
        }
        return false;
    }

    // x86 stdcall (args on stack) // LIFO
    if (bShouldPopArgs_NoCdecl)
        return StackPop(v); // stdcall, my func must clean args in ret 4(N arg stack bytes); // sp+=N

    return StackPeek(v, idx); // cdecl, my func not clear args
}

// Unicorn keeps GDT/segment defaults internally in the QEMU context but uc_reg_read returns 0
// before first execution, so SaveRunStateEnv captures 0 and LoadRunStateEnv restores 0 which
// breaks the runtime.  Write the standard Windows user-mode selectors explicitly so that
// save/load round-trips produce consistent non-zero values.
// TODO: Unhandled CPU exception
#if 0
void AsmRunner::InitialiseSegmentRegisters()
{
    if (!m_uc) return;

    auto wr16 = [&](int reg, uint16_t v) { uc_reg_write(m_uc, reg, &v); };
    auto wr32 = [&](int reg, uint32_t v) { uc_reg_write(m_uc, reg, &v); };

    if (m_bX64)
    {
        // x64 Windows user-mode selectors
        wr16(UC_X86_REG_CS, 0x0033); // 64-bit code, ring 3
        wr16(UC_X86_REG_DS, 0x002B); // data, ring 3
        wr16(UC_X86_REG_ES, 0x002B);
        wr16(UC_X86_REG_SS, 0x002B);
        wr16(UC_X86_REG_FS, 0x0053); // TEB / not used directly; FS_BASE carries the address
        wr16(UC_X86_REG_GS, 0x002B); // GS_BASE carries the address
    }
    else
    {
        // x86 Windows user-mode selectors
        wr16(UC_X86_REG_CS, 0x0023); // 32-bit code, ring 3
        wr16(UC_X86_REG_DS, 0x002B); // data, ring 3
        wr16(UC_X86_REG_ES, 0x002B);
        wr16(UC_X86_REG_SS, 0x002B);
        wr16(UC_X86_REG_FS, 0x0053); // TEB selector
        wr16(UC_X86_REG_GS, 0x002B);
    }

    // IF=1 + reserved bit 1 always set — same as post-reset state on real hardware
    uint32_t eflags = 0x202;
    wr32(UC_X86_REG_EFLAGS, eflags);

    if (m_bLogRunner)
        Log("[*] InitialiseSegmentRegisters: CS/DS/ES/SS/FS/GS/EFLAGS set (%s)", m_bX64 ? "x64" : "x86");
}
#endif

void AsmRunner::SetEntryPointStackArg(uint32_t nArgIdx, uintptr_t arg)
{
    StackSetValue(arg, true, static_cast<int32_t>(nArgIdx) + 1);
}

void AsmRunner::SetStackArgEbpIndex(uint32_t nArgIdx, uintptr_t arg)
{
    StackSetValue(arg, false, static_cast<int32_t>(nArgIdx) + 1);
}

//TEB TB FS SEH PEB MSR_FS_BASE MSR IRP etc https://github.com/thpatch/thcrap/blob/af5b5e190493887258a64affba7ec220c892e7a6/thcrap/src/ntdll.h
#if 0 // temp hack avoid fakin skip write UC_X86_REG_FS_BASE in SetTebBase
void AsmRunner::SetTeb(uintptr_t pAddr, uintptr_t nSize, bool bUseDefaultAddr)
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
    m_memMap[pAddr] = { mapSize, UC_PROT_READ | UC_PROT_WRITE };

    uint32_t seh_head = 0;
    err = uc_mem_write(m_uc, pAddr, &seh_head, sizeof(seh_head));
    if (err != UC_ERR_OK) {
        if (m_bLogRunner)
            Log("[!] write zero page failed: %s", uc_strerror(err));
    }
    m_fsBase = pAddr;
    m_fsSize = nSize;

    m_bInitedSehFS = true;
}
#else
void AsmRunner::SetTeb(uintptr_t pAddr, uintptr_t nSize, bool bUseDefaultAddr)
{
    assert(m_bInitedSehFS == false);
    if (!m_uc) return;

    // Windows TEB/SEH scratch area.
    // x86 uses FS, x64 uses GS.
    if (pAddr == 0 && bUseDefaultAddr)
        pAddr = m_bX64 ? static_cast<uintptr_t>(0x000000007FFDF000ull) : static_cast<uintptr_t>(0x7FFDF000u);

    if (nSize == 0)
        nSize = 0x1000; // 0x2000?

    const uintptr_t mapSize = AlignUp(nSize, 0x1000);
    uc_err err = uc_mem_map(m_uc, pAddr, mapSize, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK)
    {
        if (m_bLogRunner)
            Log("[!] TEB/SEH map failed at 0x%p: %s", (void*)pAddr, uc_strerror(err));
        return;
    }
    m_memMap[pAddr] = { mapSize, UC_PROT_READ | UC_PROT_WRITE };

    std::vector<uint8_t> zero(mapSize, 0);
    err = uc_mem_write(m_uc, pAddr, zero.data(), zero.size());
    if (err != UC_ERR_OK)
    {
        if (m_bLogRunner)
            Log("[!] TEB/SEH zero init failed at 0x%p: %s", (void*)pAddr, uc_strerror(err));
        return;
    }

    auto writePtrRaw = [&](uintptr_t offset, uintptr_t value) -> bool
    {
        return uc_mem_write(m_uc, pAddr + offset, &value, PointerSize()) == UC_ERR_OK;
    };

    // TODO: перепиши на GetSet и уже там константы или поля _TEB
    const uintptr_t selfOffset = m_bX64 ? 0x30 : 0x18;
    const uintptr_t pebOffset = m_bX64 ? 0x60 : 0x30;
    const uintptr_t lastErrorOffset = m_bX64 ? 0x68 : 0x34;
    const uintptr_t stackBaseOffset = m_bX64 ? 0x08 : 0x04;
    const uintptr_t stackLimitOffset = m_bX64 ? 0x10 : 0x08;
    const uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000);

    uintptr_t nullPtr = 0;
    writePtrRaw(0x00, nullPtr);          // ExceptionList
    writePtrRaw(stackBaseOffset, m_stackBase); // StackBase
    writePtrRaw(stackLimitOffset, stackHigh); // StackLimit
    writePtrRaw(selfOffset, pAddr);      // Self
    writePtrRaw(pebOffset, nullPtr);     // PEB placeholder
    writePtrRaw(lastErrorOffset, 0);     // LastErrorValue

    if (!SetTebBase(pAddr))
    {
        if (m_bLogRunner)
            Log("[!] Failed to set TEB base for %s", m_bX64 ? "GS" : "FS");
        return;
    }
    m_fsBase = pAddr;
    m_fsSize = nSize;

    m_bInitedSehFS = true;
    if (m_bLogRunner)
        Log("[*] TEB/SEH initialized at 0x%p (%s, base=%s)", (void*)pAddr, m_bX64 ? "x64" : "x86", m_bX64 ? "GS" : "FS");
}
#endif

void AsmRunner::CopyNTSeh(uintptr_t pAddr, uintptr_t nSize)
{
    assert(m_bInitedSehFS == false);
    if (!m_uc)
        return;

    const size_t ps = PointerSize();

    if (pAddr == 0)
        pAddr = m_bX64 ? static_cast<uintptr_t>(0x000000007FFDF000ull) : 0x0; // x86: zero page mirror

    if (nSize == 0)
        nSize = 0x1000;

    const uintptr_t mapSize = AlignUp(nSize, 0x1000);

    uc_err err = uc_mem_map(m_uc, pAddr, mapSize, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK)
    {
        if (m_bLogRunner)
            Log("[!] CopyNTSeh map failed at 0x%p: %s", (void*)pAddr, uc_strerror(err));
        return;
    }
    m_memMap[pAddr] = { mapSize, UC_PROT_READ | UC_PROT_WRITE };

    std::vector<uint8_t> zero(mapSize, 0);
    uc_mem_write(m_uc, pAddr, zero.data(), zero.size());

    auto writePtr = [&](uintptr_t off, uintptr_t v) -> bool
    {
        return uc_mem_write(m_uc, pAddr + off, &v, ps) == UC_ERR_OK;
    };

    auto writeDword = [&](uintptr_t off, uint32_t v) -> bool
    {
        return uc_mem_write(m_uc, pAddr + off, &v, sizeof(v)) == UC_ERR_OK;
    };

    // Минимальный TEB/NT_TIB набор, который реально нужен эмулятору.
    // x64 — зеркалим по текущему native TEB.
    // x86 — оставляем zero-page mirror и только ставим stack bounds.
    ULONG_PTR lowLimit = 0, highLimit = 0;
    GetCurrentThreadStackLimits(&lowLimit, &highLimit);

    if (m_bX64)
    {
        auto* teb = reinterpret_cast<uint8_t*>(NtCurrentTeb());
        if (teb)
        {
            writePtr(0x00, 0); // ExceptionList (x64 не используется как на x86)
            writePtr(0x08, *reinterpret_cast<uintptr_t*>(teb + 0x08)); // StackBase
            writePtr(0x10, *reinterpret_cast<uintptr_t*>(teb + 0x10)); // StackLimit
            writePtr(0x30, reinterpret_cast<uintptr_t>(teb));          // Self
            writePtr(0x60, *reinterpret_cast<uintptr_t*>(teb + 0x60)); // PEB
            writeDword(0x68, *reinterpret_cast<uint32_t*>(teb + 0x68)); // LastErrorValue
        }

        (void)SetTebBase(pAddr);
    }
    else
    {
        writePtr(0x00, 0); // ExceptionList
        writePtr(0x04, static_cast<uintptr_t>(highLimit)); // StackBase
        writePtr(0x08, static_cast<uintptr_t>(lowLimit));   // StackLimit
        writePtr(0x18, 0); // Self / Teb pointer not used via FS_BASE here
        writePtr(0x30, 0); // PEB placeholder
        writeDword(0x34, 0); // LastErrorValue

        // если FS_BASE не выставляется в твоей сборке Unicorn, zero-page mirror всё равно работает
        (void)SetTebBase(0);
    }
    m_fsBase = pAddr;
    m_fsSize = nSize;

    m_bInitedSehFS = true;

    if (m_bLogRunner)
        Log("[*] CopyNTSeh done: base=0x%p (%s)", (void*)pAddr, m_bX64 ? "x64" : "x86");
}

// TODO: Not work x86 uc_reg_write UC_X86_REG_FS_BASE!!
// UC_X86_REG_FS UC_X86_REG_FS_BASE: UC_X86_REG_FS [0, 3] selector idx
bool AsmRunner::SetTebBase(uintptr_t base)
{
    if (!m_uc)
        return false;

    uc_err err = UC_ERR_OK;
    uint64_t v = static_cast<uint64_t>(base);
    if (m_bX64)
        err = uc_reg_write(m_uc, UC_X86_REG_GS_BASE, &v);
    else
        err = uc_reg_write(m_uc, UC_X86_REG_FS_BASE, &v);

    return err == UC_ERR_OK;
}

//bool AsmRunner::SetTebBase(uintptr_t base)
//{ // MSR GDT LDT
//    if (!m_uc)
//        return false;
//
//    // Маска MSR для FS_BASE (0xC0000100) [citation:1]
//    const uint32_t MSR_FS_BASE = 0xC0000100;
//    // Маска MSR для GS_BASE (0xC0000101), если нужна
//    // const uint32_t MSR_GS_BASE = 0xC0000101;
//
//    uc_x86_msr msr;
//    msr.rid = MSR_FS_BASE;
//    msr.value = static_cast<uint64_t>(base);
//
//    uc_err err = uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);
//
//    if (err != UC_ERR_OK) {
//        if (m_bLogRunner) {
//            Log("[!] Failed to write FS_BASE via MSR. Error: %s", uc_strerror(err));
//        }
//        return false;
//    }
//
//    // Если вы эмулируете 64-битный код, вам также нужно будет обновить сегментный селектор.
//    // Для 32-битного кода записи в MSR достаточно для установки базового адреса.
//    if (m_bX64) {
//        // Для x64: также запишите 0 в селектор GS, чтобы указать, что используется база из MSR.
//        uint16_t gs_selector = 0;
//        uc_reg_write(m_uc, UC_X86_REG_GS, &gs_selector);
//    }
//    else {
//        // Для x86: обнулите селектор FS, чтобы система использовала базовый адрес из MSR.
//        uint16_t fs_selector = 0;
//        uc_reg_write(m_uc, UC_X86_REG_FS, &fs_selector);
//    }
//
//    return true;
//}

uintptr_t AsmRunner::GetTebBase() const
{
    if (!m_uc)
        return 0;

    uint64_t v = 0;
    if (m_bX64)
    {
        if (uc_reg_read(m_uc, UC_X86_REG_GS_BASE, &v) != UC_ERR_OK)
            return 0;
    }
    else
    {
        if (uc_reg_read(m_uc, UC_X86_REG_FS_BASE, &v) != UC_ERR_OK)
            return 0;
    }

    return static_cast<uintptr_t>(v);
}

bool AsmRunner::WriteTebValue(uint32_t offset, uintptr_t value)
{
    if (!m_uc || !m_bInitedSehFS)
        return false;

    const uintptr_t tebBase = GetTebBase();
    if (!tebBase)
        return false;

    const size_t sz = PointerSize();
    return uc_mem_write(m_uc, tebBase + offset, &value, sz) == UC_ERR_OK;
}

uintptr_t AsmRunner::ReadTebValue(uint32_t offset) const
{
    if (!m_uc || !m_bInitedSehFS)
        return 0;

    const uintptr_t tebBase = GetTebBase();
    if (!tebBase)
        return 0;

    uintptr_t value = 0;
    const size_t sz = m_bX64 ? 8 : 4;
    if (uc_mem_read(m_uc, tebBase + offset, &value, sz) != UC_ERR_OK)
        return 0;

    if (!m_bX64)
        value = static_cast<uint32_t>(value);

    return value;
}

void AsmRunner::SetTebLastError(uint32_t error)
{
    const uint32_t offset = m_bX64 ? 0x68 : 0x34;
    (void)WriteTebValue(offset, static_cast<uintptr_t>(error));
}

uint32_t AsmRunner::GetTebLastError() const
{
    const uint32_t offset = m_bX64 ? 0x68 : 0x34;
    return static_cast<uint32_t>(ReadTebValue(offset));
}

void AsmRunner::SetAnyJmpHook(uintptr_t pAddr, OnJmpCb cb, void* data, bool callBefore, bool moduleHook, std::string sFuncName)
{
    if (!pAddr)
        return;

    if (!moduleHook && GetModStart() != 0 && GetModEnd() != 0 && IsInAddr(pAddr, GetModStart(), GetModEnd())) {
        if (m_bLogRunner)
            Log("[!] AnyJmpHook: ERROR! Install external hook in module");
        MboxSTD("AnyJmpHook: ERROR! Install external hook in module", AR_SNAME);
        return;
    }

    for (const auto& h : m_anyJmpHooks) {
        if (h.pAddr == pAddr) {
            if(m_bLogRunner)
                Log("[!] AnyJmpHook already exists for this address");
            MboxSTD("AnyJmpHook already exists for this address", AR_SNAME);
            return;
        }
    }

    m_anyJmpHooks.push_back({ pAddr, std::move(cb), data, callBefore, sFuncName, tAnyJmpHookNode::tJmpCBArgs() });

    if (!callBefore && !moduleHook) {
        if (!m_uc)
        {
            MboxSTD("Error 1 SetAnyJmpHook (init uc)", AR_SNAME);
            return;
        }

        const uintptr_t pageSize = 0x1000; // real 4-8b at pAddr
        const uintptr_t pageBase = AlignDown(pAddr, pageSize);
        bool ok = AddMemoryTo(pageBase, pageSize, UC_PROT_ALL);
        if (!ok)
            ok = ChangeMemoryType(pageBase, UC_PROT_ALL);

        if (!ok)
        {
            MboxSTD("Error 2 SetAnyJmpHook (map rwx page)", AR_SNAME);
            return;
        }

        const uint8_t nop = 0x90;
        CopyMemory(pAddr, reinterpret_cast<uintptr_t>(&nop), 1);
    }
}

void AsmRunner::GenerateIDCIATFix(std::string outfile, uintptr_t pIATStart, uintptr_t pIATEnd, uintptr_t pIDBASLR, uintptr_t nMaxDeep, bool bGenSectionDummy)
{
    if (outfile.empty() || pIATStart == 0 || pIATEnd == 0 || pIATEnd <= pIATStart) {
        if (m_bLogRunner)
            Log("[!] GenerateIDCIATFix: invalid parameters");
        return;
    }

    if (exportsENV.empty())
        CollectAllExports(exportsENV);

    enum eErr {
        API_RESOLVED = 0,
        NULL_POINTER, // probably dynamic load?
        ALREADY_RESOLVED,
        JUNK_RESOLVED_STEPS_LIMIT,
        RET_ADDR_NOT_EXISTS_IN_EXPORTS,
    };

    struct tLazyImportNode {
        uintptr_t pApi; // resolved // на winapi
        uintptr_t pIAT; // iat // на массив iat
        uintptr_t pIATWrapper; // iat wrapper // на модульную функцию *pIAT
        uint32_t nErr; // eErr
    };
    std::vector<tLazyImportNode> db;

    const uintptr_t ptrSize = PointerSize();

    auto readPtr = [&](uintptr_t addr, uintptr_t& out) -> bool {
        out = 0;
        DumpMemory((uintptr_t)&out, addr, ptrSize);
        if (!m_bX64)
            out = static_cast<uint32_t>(out);
        return true;
    };

    auto resolveWrapperEscape = [&](uintptr_t thunkEntry, uintptr_t& outResolved) -> bool {
        outResolved = 0;

        if (m_modStart == 0 || m_modEnd <= m_modStart)
            return false;

        if (!IsModuleAddr(thunkEntry))
            return false;

        AsmRunner resolver(m_bX64);
        bool bDbg = false;
        resolver.Initialise(bDbg, bDbg, bDbg, bDbg);

        // Read module memory
        const size_t moduleSize = static_cast<size_t>(m_modEnd - m_modStart);
        uintptr_t pModuleData = DumpMemoryNTAlloc(m_modStart, moduleSize);
        if (!pModuleData) {
            if (m_bLogRunner)
                Log("[!] resolveWrapperEscape: failed to dump module memory");
            return false;
        }

        // Copy module
        if (!resolver.CopyModule(m_modStart, pModuleData, moduleSize, m_modName)) {
            if (m_bLogRunner)
                Log("[!] resolveWrapperEscape: failed to copy module to resolver");
            free(reinterpret_cast<void*>(pModuleData));
            return false;
        }

        free(reinterpret_cast<void*>(pModuleData));

        uintptr_t captured = 0;

        auto OpcodeCb = [&](uc_engine*, uintptr_t, uint32_t, ZydisMnemonic, void*) -> bool { return true; };
        //auto MemCb = [&](uc_engine*, int32_t, uintptr_t, uintptr_t, uintptr_t, ZydisMnemonic, void*) -> bool { return true; };

        auto MemCb = [&](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
            auto* self = static_cast<AsmRunner*>(user_data);
            bool isRead = (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT || type == UC_MEM_READ_AFTER);
            bool isWrite = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT);
            bool isAnyFetch = (type == UC_MEM_FETCH || type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT); // code read
            uintptr_t a = self->CalcWithCASLR(address);

            //printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n", (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);
            if (!self || !uc || size == 0)
                return true;

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
                if(bDbg)
                    printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                        (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

                if (!self->AddMemoryTo(base, mapSize, UC_PROT_READ | UC_PROT_WRITE))
                //if (!self->AddMemoryTo(address, size, UC_PROT_READ | UC_PROT_WRITE))
                {
                    if (bDbg)
                        printf("[!] Failed to map region at 0x%p\n", (void*)base);
                    SetConsoleColor(1);
                    return false;
                }

                if (bDbg)
                    printf("[+] Created Region at 0x%p [0x%zx]\n", (void*)base, (size_t)mapSize);
                SetConsoleColor(1);

                // 0x767A003C [4] 0xF0 0x00 0x00 0x00 kernel32 this program
                //if (address == 0x767A003C) // TMP
                if(size == 4)
                    self->WriteMemory<uint32_t>(address, 0x00'00'00'F0);
                else
                    MboxSTD("wd MemCb isUnmapped", AR_SNAME);

                return true;
            }

            if (isProt)
            {
                if (bDbg)
                    printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                        (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

                if (!self->ChangeMemoryType(base, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC))
                {
                    if (bDbg)
                        printf("[!] Failed to change protection at 0x%p\n", (void*)base);
                    SetConsoleColor(1);
                    return false;
                }
                MboxSTD("wd MemCb isProt", AR_SNAME);

                SetConsoleColor(1);
                return true;
            }

            return true;
        };

        auto JmpCb = [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool {
            auto* self = static_cast<AsmRunner*>(user_data);
            (void)from;
            (void)mnemonic;

            if (!self->IsModuleAddr(to)) {
                captured = to;
                return false;
            }

            return true;
        };

        resolver.SetCallbacks(OpcodeCb, &resolver, MemCb, &resolver, JmpCb, &resolver);
        resolver.Run(thunkEntry, nMaxDeep);

        if (captured != 0) {
            outResolved = captured;
            return true;
        }

        return false;
    };

    size_t iatIndex = 0;
    for (uintptr_t addr = pIATStart; addr < pIATEnd; addr += ptrSize)
    {
        uintptr_t funcPtr = 0;
        readPtr(addr, funcPtr);

        if (funcPtr == 0) {
            if (m_bLogRunner)
                Log("[GenerateIDCIATFix] %d 0x%p skip null @0x%p", iatIndex, (void*)(addr - m_modStart + pIDBASLR), (void*)addr);
            db.push_back({ 0, addr, 0, NULL_POINTER });
            iatIndex++;
            continue;
        }

        auto itExp = exportsENV.find(funcPtr);
        if (itExp != exportsENV.end()) {
            if (m_bLogRunner) {
                const auto& n = itExp->second;
                Log("[GenerateIDCIATFix] %d 0x%p direct 0x%p -> %s!%s base=0x%p rva=0x%p",
                    iatIndex,
                    (void*)(addr - m_modStart + pIDBASLR),
                    (void*)funcPtr,
                    n.moduleName.c_str(),
                    n.funcName.c_str(),
                    (void*)n.moduleBase,
                    (void*)n.funcRva);
            }
            db.push_back({ funcPtr, addr, 0, ALREADY_RESOLVED });
            iatIndex++;
            continue;
        }

        if (IsModuleAddr(funcPtr))
        {
            uintptr_t escaped = 0;
            if (resolveWrapperEscape(funcPtr, escaped)) {
                auto itEsc = exportsENV.find(escaped);
                if (itEsc != exportsENV.end()) {
                    if (m_bLogRunner) {
                        const auto& n = itEsc->second;
                        Log("[GenerateIDCIATFix] %d 0x%p wrapper 0x%p -> escape 0x%p -> %s!%s base=0x%p rva=0x%p",
                            iatIndex,
                            (void*)(addr - m_modStart + pIDBASLR),
                            (void*)funcPtr,
                            (void*)escaped,
                            n.moduleName.c_str(),
                            n.funcName.c_str(),
                            (void*)n.moduleBase,
                            (void*)n.funcRva);
                    }
                    db.push_back({ escaped, addr, funcPtr, API_RESOLVED });
                }
                else {
                    if (m_bLogRunner)
                        Log("[GenerateIDCIATFix] %d 0x%p wrapper 0x%p escaped to 0x%p but export not found",
                            iatIndex, (void*)(addr - m_modStart + pIDBASLR), (void*)funcPtr, (void*)escaped);
                    db.push_back({ escaped, addr, funcPtr, RET_ADDR_NOT_EXISTS_IN_EXPORTS });
                }
            }
            else {
                if (m_bLogRunner)
                    Log("[GenerateIDCIATFix] %d 0x%p wrapper 0x%p unresolved", iatIndex, (void*)(addr - m_modStart + pIDBASLR), (void*)funcPtr);
                db.push_back({ funcPtr, addr, 0, JUNK_RESOLVED_STEPS_LIMIT });
            }
            iatIndex++;
            continue;
        }

        if (m_bLogRunner)
            Log("[GenerateIDCIATFix] %d 0x%p skip non-export 0x%p", iatIndex, (void*)(addr - m_modStart + pIDBASLR), (void*)funcPtr);
        db.push_back({ funcPtr, addr, 0, RET_ADDR_NOT_EXISTS_IN_EXPORTS });
        iatIndex++;
    }

    if (m_bLogRunner)
        Log("[*] GenerateIDCIATFix: %zu entries resolved", db.size());


    // gen idc for fix name iat node and iat wrapper  // text:6137B344(iatnode) IsProcessorFeaturePresentL dd offset IsProcessorFeaturePresent_Wrapper
    FILE* file = FileOpen(outfile.c_str(), "w");
    if (file == nullptr) {
        if (m_bLogRunner)
            Log("[!] Failed to open file: %s", outfile.c_str());
        return;
    }

    // lib mapping
    if (bGenSectionDummy) // сегменты для modeulebase.dll
    {
        std::unordered_map<uintptr_t, std::string> uniqueLibs;
        for (uint32_t i = 0; i < db.size(); ++i) // сегменты dll base
        {
            switch (db[i].nErr)
            {
                case API_RESOLVED:
                case ALREADY_RESOLVED:
                {
                    auto it = exportsENV.find(db[i].pApi);
                    assert(it != exportsENV.end());
                    const tFuncNode& exp = it->second;
                    if (uniqueLibs.find(exp.moduleBase) == uniqueLibs.end())
                    {
                        uniqueLibs[exp.moduleBase] = exp.moduleName;

                        std::string nameS = SanitizeIdaName(exp.moduleName);
                        nameS = exp.moduleName;
                        uintptr_t pStart = /*TransposeLibBase*/(exp.moduleBase);
                        uintptr_t pEnd = pStart + 4; // dummy

                        // dummy small seg
                        FileAdd(file, "AddSegEx(0x%p, 0x%p, 0, 1, 3, 2, ADDSEG_QUIET);", (void*)pStart, (void*)pEnd);
                        FileAdd(file, "SetSegmentAttr(0x%p, SEGATTR_PERM, 7);", (void*)pStart);
                        FileAdd(file, "SegClass(0x%p, \"CODE\");", (void*)pStart);
                        FileAdd(file, "RenameSeg(0x%p, \".%s\");", (void*)pStart, nameS.c_str());
                    }
                    break;
                }
                case NULL_POINTER:
                case JUNK_RESOLVED_STEPS_LIMIT:
                case RET_ADDR_NOT_EXISTS_IN_EXPORTS:
                {
                    break;
                }
            }
        }
        uniqueLibs.clear();
    }

    for (uint32_t i = 0; i < db.size(); ++i)
    {
        uintptr_t pIATRVA = (db[i].pIAT - m_modStart); // оффсет к полю в массиве iat
        std::string name = "iat_unknown_" + std::to_string(i); // имя поля в массиве
        uintptr_t pIATRVAWrapper = (db[i].pIATWrapper - m_modStart); // оффсет к функции врапперу
        std::string nameWrapper = "iat_unknown_wrapper_" + std::to_string(i); // имя фуфнкции враппера
        bool bFixFrapper = false;

        switch (db[i].nErr)
        {
            case API_RESOLVED:
            case ALREADY_RESOLVED:
            {
                auto it = exportsENV.find(db[i].pApi);
                assert(it != exportsENV.end());
                const tFuncNode& exp = it->second;
                name = SanitizeIdaName(exp.funcName + "__" + exp.moduleName);
                if (db[i].nErr == API_RESOLVED) {
                    nameWrapper = SanitizeIdaName(exp.funcName + "_Wrapper_" + exp.moduleName);
                    bFixFrapper = true;
                }
                break;
            }
            case NULL_POINTER:
            {
                name = "IAT_NULL_" + std::to_string(i);
                break;
            }
            case JUNK_RESOLVED_STEPS_LIMIT:
            {
                name = "IAT_JUNK_LIMIT_" + std::to_string(i);
                nameWrapper = "IAT_JUNK_LIMIT_WRAPPER_" + std::to_string(i);
                bFixFrapper = true;
                break;
            }
            case RET_ADDR_NOT_EXISTS_IN_EXPORTS:
            {
                char addrBuffer[32];
                //sprintf_s(addrBuffer, "_0x%p", db[i].pApi); // raw esp
                sprintf_s(addrBuffer, "_0x%p", (db[i].pApi - m_modStart) + pIDBASLR); // todo recheck pApi is in module + size
                name = "IAT_TODO_NOT_IN_EXPORTS_" + std::to_string(i) + std::string(addrBuffer);
                nameWrapper = "IAT_TODO_NOT_IN_EXPORTS_WRAPPER_" + std::to_string(i) + std::string(addrBuffer);
                bFixFrapper = true;
                break;
            }
        }

        FileAdd(file, "set_name(0x%p, \"%s\", SN_AUTO);", (void*)(pIATRVA + pIDBASLR), name.c_str());
        if (bFixFrapper) { // есть ли враппер, не директ
            FileAdd(file, "set_name(0x%p, \"%s\", SN_AUTO);", (void*)(pIATRVAWrapper + pIDBASLR), nameWrapper.c_str());
            //FileAdd(file, "SetColor(0x%p, CIC_FUNC, 0x685328);", (void*)(pIATRVAWrapper + pIDBASLR)); // BGR
            FileAdd(file, "SetColor(0x%p, CIC_FUNC, 0x734500);", (void*)(pIATRVAWrapper + pIDBASLR)); // BGR, non native import color
            FileAdd(file, "SetType(0x%p, \"int F(int a1, int a2, int a3, int a4, int a5, int a6, int a7)\");", (void*)(pIATRVAWrapper + pIDBASLR));
        }

        if (bGenSectionDummy && db[i].nErr == ALREADY_RESOLVED) // сегменты для winapi функций заглушек
        {
            auto it = exportsENV.find(db[i].pApi);
            assert(it != exportsENV.end());
            const tFuncNode& exp = it->second;
            std::string nameS = SanitizeIdaName(exp.funcName + "__" + exp.moduleName);
            std::string nameF = "IAT_" + SanitizeIdaName(exp.funcName);
            uintptr_t pStart = /*TransposeLibBase*/(exp.moduleBase) + exp.funcRva;
            uintptr_t pEnd = pStart + 4; // dummy

            // dummy small seg
            FileAdd(file, "AddSegEx(0x%p, 0x%p, 0, 1, 3, 2, ADDSEG_QUIET);", (void*)pStart, (void*)pEnd);
            FileAdd(file, "SetSegmentAttr(0x%p, SEGATTR_PERM, 7);", (void*)pStart);
            FileAdd(file, "SegClass(0x%p, \"CODE\");", (void*)pStart);
            FileAdd(file, "RenameSeg(0x%p, \"API_SEG_%s\");", (void*)pStart, nameS.c_str());

            //SetType(addr, "CObject");
            //set_cmt(0x0938D400, "abc", 0);

            // create dummy function as in psp nid import
            FileAdd(file, "PatchByte(0x%p, 0xC3);", (void*)pStart);
            FileAdd(file, "MakeCode(0x%p);", (void*)pStart);
            FileAdd(file, "add_func(0x%p, BADADDR);", (void*)pStart);
            FileAdd(file, "set_name(0x%p, \"%s\", SN_AUTO);", (void*)pStart, nameF.c_str());
            FileAdd(file, "SetColor(0x%p, CIC_FUNC, 0x685328);", (void*)pStart); // BGR
            FileAdd(file, "SetType(0x%p, \"int F(int a1, int a2, int a3, int a4, int a5, int a6, int a7)\");", (void*)pStart);
            break;
        }
    }

    FileClose(file);
    file = nullptr;

    if (m_bLogRunner)
        Log("[*] GenerateIDCIATFix completed: %s", outfile.c_str());
}

// Collect Env and try some resolve
void AsmRunner::SetIAT(uintptr_t pStart, uintptr_t pEnd, bool bTryResolveInModule, bool bRIMEscapeHook, bool bSaveRIM)
{
    exportsENV.clear();
    m_iat.clear();
    m_iatStart = pStart;
    m_iatEnd = pEnd;
    m_bInitIAT = false;

    CollectAllExports(exportsENV);

    if (m_bLogRunner)
        Log("[*] CollectAllExports: %zu exports", exportsENV.size());

    if (pStart == 0 || pEnd == 0 || pEnd <= pStart)
    {
        m_bInitIAT = true;
        return;
    }

    const uintptr_t ptrSize = PointerSize();
    const uint32_t nMaxJunkSteps = 3000;

    FILE* rim = nullptr;
    if (bSaveRIM)
        rim = FileOpen("log_iat_resolve.log", "w");

    auto readPtr = [&](uintptr_t addr, uintptr_t& out) -> bool {
        out = 0;
        DumpMemory((uintptr_t)&out, addr, ptrSize);
        if (!m_bX64)
            out = static_cast<uint32_t>(out);
        return true;
    };

    auto resolveWrapperEscape = [&](uintptr_t thunkEntry, uintptr_t& outResolved) -> bool
    {
        outResolved = 0;

        if (!bTryResolveInModule)
            return false;

        if (m_modStart == 0 || m_modEnd <= m_modStart)
            return false;

        if (!IsModuleAddr(thunkEntry))
            return false;

        AsmRunner resolver(m_bX64);
        bool bDbg = false;
        resolver.Initialise(bDbg, bDbg, bDbg, bDbg);

        // Read module memory
        const size_t moduleSize = static_cast<size_t>(m_modEnd - m_modStart);
        uintptr_t pModuleData = DumpMemoryNTAlloc(m_modStart, moduleSize);
        if (!pModuleData) {
            if (m_bLogRunner)
                Log("[!] resolveWrapperEscape: failed to dump module memory");
            return false;
        }

        // Copy module
        if (!resolver.CopyModule(m_modStart, pModuleData, moduleSize, m_modName)) {
            if (m_bLogRunner)
                Log("[!] resolveWrapperEscape: failed to copy module to resolver");
            free(reinterpret_cast<void*>(pModuleData));
            return false;
        }

        free(reinterpret_cast<void*>(pModuleData));

        uintptr_t captured = 0;

        auto OpcodeCb = [&](uc_engine*, uintptr_t, uint32_t, ZydisMnemonic, void*) -> bool { return true; };
        //auto MemCb = [&](uc_engine*, int32_t, uintptr_t, uintptr_t, uintptr_t, ZydisMnemonic, void*) -> bool { return true; };

        auto MemCb = [&](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
            auto* self = static_cast<AsmRunner*>(user_data);
            bool isRead = (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT || type == UC_MEM_READ_AFTER);
            bool isWrite = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT);
            bool isAnyFetch = (type == UC_MEM_FETCH || type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT); // code read
            uintptr_t a = self->CalcWithCASLR(address);

            //printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n", (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);
            if (!self || !uc || size == 0)
                return true;

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
                if (bDbg)
                    printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                        (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

                if (!self->AddMemoryTo(base, mapSize, UC_PROT_READ | UC_PROT_WRITE))
                    //if (!self->AddMemoryTo(address, size, UC_PROT_READ | UC_PROT_WRITE))
                {
                    if (bDbg)
                        printf("[!] Failed to map region at 0x%p\n", (void*)base);
                    SetConsoleColor(1);
                    return false;
                }

                if (bDbg)
                    printf("[+] Created Region at 0x%p [0x%zx]\n", (void*)base, (size_t)mapSize);
                SetConsoleColor(1);

                // 0x767A003C [4] 0xF0 0x00 0x00 0x00 kernel32 this program
                //if (address == 0x767A003C) // TMP
                if (size == 4)
                    self->WriteMemory<uint32_t>(address, 0x00'00'00'F0);
                else
                    MboxSTD("wd MemCb isUnmapped", AR_SNAME);

                return true;
            }

            if (isProt)
            {
                if (bDbg)
                    printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                        (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

                if (!self->ChangeMemoryType(base, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC))
                {
                    if (bDbg)
                        printf("[!] Failed to change protection at 0x%p\n", (void*)base);
                    SetConsoleColor(1);
                    return false;
                }
                MboxSTD("wd MemCb isProt", AR_SNAME);

                SetConsoleColor(1);
                return true;
            }

            return true;
        };

        auto JmpCb = [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            (void)from;
            (void)mnemonic;

            if (!self->IsModuleAddr(to))
            {
                captured = to;
                return false;
            }

            return true;
        };

        resolver.SetCallbacks(OpcodeCb, &resolver, MemCb, &resolver, JmpCb, &resolver);
        resolver.Run(thunkEntry, nMaxJunkSteps);

        if (captured != 0)
        {
            outResolved = captured;
            return true;
        }

        return false;
    };

    const size_t iatSize = static_cast<size_t>(pEnd - pStart) / static_cast<size_t>(ptrSize);
    m_iat.reserve(iatSize);

    size_t iatIndex = 0;
    for (uintptr_t addr = pStart; addr < pEnd; addr += ptrSize)
    {
        uintptr_t funcPtr = 0;
        readPtr(addr, funcPtr);

        if (funcPtr == 0)
        {
            if (m_bLogRunner)
                Log("[IAT] skip null @0x%p", (void*)addr);

            if (rim)
                FileAdd(rim, "%zu", iatIndex);

            iatIndex++;
            continue;
        }

        auto itExp = exportsENV.find(funcPtr);
        if (itExp != exportsENV.end())
        {
            m_iat.push_back(itExp->second);

            if (m_bLogRunner)
            {
                const auto& n = itExp->second;
                Log("[IAT] direct 0x%p -> %s!%s base=0x%p rva=0x%p",
                    (void*)funcPtr,
                    n.moduleName.c_str(),
                    n.funcName.c_str(),
                    (void*)n.moduleBase,
                    (void*)n.funcRva);

                if (rim)
                    FileAdd(rim, "%zu %s %s", iatIndex, n.funcName.c_str(), n.moduleName.c_str());
            }

            iatIndex++;
            continue;
        }

        if (IsModuleAddr(funcPtr))
        {
            uintptr_t escaped = 0;
            if (resolveWrapperEscape(funcPtr, escaped))
            {
                auto itEsc = exportsENV.find(escaped);
                if (itEsc != exportsENV.end())
                {
                    if (bRIMEscapeHook)
                    {
                        tFuncNode fakeWrapperNode;
                        fakeWrapperNode.moduleName = GetModuleName((HMODULE)m_modStart);
                        fakeWrapperNode.funcName = "fake_" + itEsc->second.funcName;
                        fakeWrapperNode.moduleBase = m_modStart;
                        fakeWrapperNode.funcRva = escaped - m_modStart;
                        m_iat.push_back(fakeWrapperNode); // for hook cb when any call target is our iat wrapper
                    }
                    else
                        m_iat.push_back(itEsc->second); // iat target

                    if (m_bLogRunner)
                    {
                        const auto& n = itEsc->second;
                        Log("[IAT] wrapper 0x%p -> escape 0x%p -> %s!%s base=0x%p rva=0x%p",
                            (void*)funcPtr,
                            (void*)escaped,
                            n.moduleName.c_str(),
                            n.funcName.c_str(),
                            (void*)n.moduleBase,
                            (void*)n.funcRva);

                        if (rim)
                            FileAdd(rim, "%zu %s %s", iatIndex, n.funcName.c_str(), n.moduleName.c_str());
                    }
                }
                else
                {
                    if (m_bLogRunner)
                        Log("[IAT] wrapper 0x%p escaped to 0x%p but export not found", (void*)funcPtr, (void*)escaped);

                    if (rim)
                        FileAdd(rim, "%zu", iatIndex);
                }
            }
            else
            {
                if (m_bLogRunner) {
                    if(bTryResolveInModule)
                        Log("[IAT] wrapper 0x%p unresolved", (void*)funcPtr);
                    else
                        Log("[IAT] module wrapper 0x%p skip resolve", (void*)funcPtr);
                }

                if (rim)
                    FileAdd(rim, "%zu", iatIndex);
            }

            iatIndex++;
            continue;
        }

        if (m_bLogRunner)
            Log("[IAT] skip non-export 0x%p", (void*)funcPtr);

        if (rim)
            FileAdd(rim, "%zu", iatIndex);
    }

    if (rim)
        FileClose(rim);

    m_bInitIAT = true;

    if (m_bLogRunner)
    {
        Log("[*] SetIAT completed: %zu entries, IAT range [0x%p-0x%p]",
            m_iat.size(), (void*)m_iatStart, (void*)m_iatEnd);
    }
}

bool AsmRunner::SaveIATEnv(const char* szIATEnvFile, bool bRecaptureEnv)
{
    if (!szIATEnvFile || !*szIATEnvFile)
    {
        if (m_bLogRunner)
            Log("[!] SaveIATEnv: invalid file name");
        return false;
    }

    std::map<uintptr_t, tFuncNode> localExports;
    CollectAllExports(localExports);

    if (bRecaptureEnv)
        exportsENV = localExports;

    if (m_bLogRunner)
        Log("[*] SaveIATEnv: collected %zu exports%s",
            localExports.size(),
            bRecaptureEnv ? " and recaptured exportsENV" : "");

    std::ofstream f(szIATEnvFile, std::ios::out | std::ios::trunc);
    if (!f.is_open())
    {
        if (m_bLogRunner)
            Log("[!] SaveIATEnv: cannot open file: %s", szIATEnvFile);
        return false;
    }

    std::vector<std::pair<uintptr_t, tFuncNode>> items;
    items.reserve(localExports.size());

    for (const auto& kv : localExports)
        items.push_back(kv);

    std::sort(items.begin(), items.end(),
        [](const std::pair<uintptr_t, tFuncNode>& a, const std::pair<uintptr_t, tFuncNode>& b)
        {
            return a.first < b.first;
        });

    for (const auto& kv : items)
    {
        const tFuncNode& n = kv.second;

        f << "0x" << std::hex << std::uppercase << static_cast<uintptr_t>(n.moduleBase)
            << " 0x" << std::hex << std::uppercase << static_cast<uintptr_t>(n.funcRva)
            << " 0x" << std::hex << std::uppercase << static_cast<uintptr_t>(n.funcSize)
            << " " << n.funcName
            << " " << n.moduleName
            << "\n";
    }

    f.flush();

    if (!f.good())
    {
        if (m_bLogRunner)
            Log("[!] SaveIATEnv: write error: %s", szIATEnvFile);
        return false;
    }

    if (m_bLogRunner)
        Log("[+] SaveIATEnv: saved %zu entries to %s", items.size(), szIATEnvFile);

    return true;
}

bool AsmRunner::LoadIATEnv(const char* szIATEnvFile, uintptr_t nMaxSize)
{
    if (!szIATEnvFile || !*szIATEnvFile)
    {
        if (m_bLogRunner)
            Log("[!] LoadIATEnv: invalid file name");
        return false;
    }

    exportsENV.clear();

    std::ifstream f(szIATEnvFile);
    if (!f.is_open())
    {
        if (m_bLogRunner)
            Log("[!] LoadIATEnv: cannot open file: %s", szIATEnvFile);
        return false;
    }

    size_t lineNo = 0;
    size_t okCount = 0;
    std::string line;

    while (std::getline(f, line))
    {
        ++lineNo;

        TrimInPlace(line);
        if (line.empty())
            continue;
        if (line[0] == ';' || line[0] == '#')
            continue;

        std::istringstream iss(line);
        std::string sBase, sRva, sSize;

        if (!(iss >> sBase >> sRva >> sSize))
            continue;

        std::vector<std::string> tail;
        for (std::string tok; iss >> tok; )
            tail.push_back(tok);

        if (tail.size() < 2)
            continue;

        std::string moduleName = tail.back();
        tail.pop_back();

        std::string funcName;
        for (size_t i = 0; i < tail.size(); ++i)
        {
            if (i)
                funcName.push_back(' ');
            funcName += tail[i];
        }

        uintptr_t moduleBase = 0;
        uintptr_t funcRva = 0;
        uintptr_t funcSize = 0;

        if (!ParseHexPtr(sBase, moduleBase) || !ParseHexPtr(sRva, funcRva) || !ParseHexPtr(sSize, funcSize))
            continue;

        if (funcName.empty() || moduleName.empty())
            continue;

        tFuncNode n;
        n.moduleName = std::move(moduleName);
        n.funcName = std::move(funcName);
        n.moduleBase = moduleBase;
        n.funcRva = funcRva;
        n.funcSize = funcSize;
        if (nMaxSize > 0 && funcSize > nMaxSize) {
            n.funcSize = nMaxSize;

            if (m_bLogRunner)
                Log("[*] LoadIATEnv Limit: %s from 0x%p to 0x%p", n.GetAbsoluteName().c_str(), funcSize, nMaxSize);
        }

        exportsENV[n.GetAbsolute()] = std::move(n);
        ++okCount;
    }

    if (m_bLogRunner)
        Log("[+] LoadIATEnv: loaded %zu entries from %s", okCount, szIATEnvFile);

    return true;
}

tFuncNode* AsmRunner::FindIATNode(uintptr_t pAddr, bool bRVA)
{
    if (bRVA) {
        for (auto& e : exportsENV) {
            if (e.second.funcRva == pAddr)
                return &e.second;
        }
    }
    else {
        auto itExp = exportsENV.find(pAddr);
        if (itExp != exportsENV.end())
            return &itExp->second;
    }
    return nullptr;
}

tFuncNode* AsmRunner::FindIATNode(std::string funcName, std::string moduleName, bool bLowerCmp, bool bContains)
{
    std::string searchFunc = funcName;
    std::string searchModule = moduleName;

    if (bLowerCmp) {
        std::transform(searchFunc.begin(), searchFunc.end(), searchFunc.begin(), ::tolower);
        std::transform(searchModule.begin(), searchModule.end(), searchModule.begin(), ::tolower);
    }

    for (auto& e : exportsENV) {
        std::string currentFunc = e.second.funcName;
        std::string currentModule = e.second.moduleName;

        if (bLowerCmp) {
            std::transform(currentFunc.begin(), currentFunc.end(), currentFunc.begin(), ::tolower);
            std::transform(currentModule.begin(), currentModule.end(), currentModule.begin(), ::tolower);
        }

        bool funcMatches = false;
        bool moduleMatches = false;

        if (bContains) {
            funcMatches = searchFunc.empty() || currentFunc.find(searchFunc) != std::string::npos;
            moduleMatches = searchModule.empty() || currentModule.find(searchModule) != std::string::npos;
        }
        else {
            funcMatches = searchFunc.empty() || currentFunc == searchFunc;
            moduleMatches = searchModule.empty() || currentModule == searchModule;
        }

        if (funcMatches && moduleMatches) {
            return &e.second;
        }
    }

    return nullptr;
}

void AsmRunner::SetIATCallCB(OnJmpCb cb, void* data)
{
    m_cbIATCall = std::move(cb);
    m_cbIATCallData = data;
}

void AsmRunner::SetSysCallCB(OnOpcodeCb cb, void* data)
{
    // what about UC_HOOK_INTR?
    m_cbSysCall = std::move(cb);
    m_cbSysCallData = data;
}

void AsmRunner::SetInsnCB(uintptr_t nInsn, OnInsnCb cb, void* data)
{
    if (!m_uc || !nInsn || !cb)
        return;

    if (!IsInsnAllowed(nInsn))
    {
        if (m_bLogRunner)
            Log("[!] UC_HOOK_INSN not allowed: insn=%d", nInsn);
        return;
    }

    for (const auto& h : m_insnHooks)
    {
        if (h.nInsn == nInsn)
        {
            if (m_bLogRunner)
                Log("InsnHook already exists for insn=%d", nInsn);
            MboxSTD("InsnHook already exists for this insn", AR_SNAME);
            return;
        }
    }

    m_insnHooks.push_back({});
    auto it = std::prev(m_insnHooks.end());

    it->nInsn = nInsn;
    it->cb = std::move(cb);
    it->data = data;
    it->owner = this;

    // UC_HOOK_INSN expects the instruction id as the extra variadic argument.
    const uc_err err = uc_hook_add(
        m_uc,
        &it->hk,
        UC_HOOK_INSN,
        reinterpret_cast<void*>(HookInsnTrampoline),
        &(*it),
        1,
        0,
        static_cast<int>(nInsn));

    if (err != UC_ERR_OK)
    {
        if (m_bLogRunner)
            Log("uc_hook_add(UC_HOOK_INSN) failed for insn=%zu: %s",
                (size_t)nInsn, uc_strerror(err));
        m_insnHooks.pop_back();
        return;
    }

    if (m_bLogRunner)
        Log("[*] Insn hook added: insn=%zu", (size_t)nInsn);
}

void AsmRunner::SetAllInsnCB(OnInsnCb cb, void* data)
{
    // see also IsInsnAllowed list
    SetInsnCB(UC_X86_INS_IN, cb, data);
    SetInsnCB(UC_X86_INS_OUT, cb, data);
    SetInsnCB(UC_X86_INS_SYSCALL, cb, data);
    SetInsnCB(UC_X86_INS_SYSENTER, cb, data);
    SetInsnCB(UC_X86_INS_CPUID, cb, data);

    // ARM64
    SetInsnCB(UC_ARM64_INS_MRS, cb, data);
    SetInsnCB(UC_ARM64_INS_MSR, cb, data);
    SetInsnCB(UC_ARM64_INS_SYS, cb, data);
    SetInsnCB(UC_ARM64_INS_SYSL, cb, data);
}

void AsmRunner::RemoveInsnCB(uintptr_t nInsn)
{
    if (!m_uc || !nInsn)
        return;

    for (auto it = m_insnHooks.begin(); it != m_insnHooks.end(); ++it)
    {
        if (it->nInsn == nInsn)
        {
            if (it->hk)
                uc_hook_del(m_uc, it->hk);

            if (m_bLogRunner)
                Log("[*] Insn hook removed: insn=%zu", (size_t)nInsn);

            m_insnHooks.erase(it);
            return;
        }
    }
}

void AsmRunner::RemoveAllInsnCB()
{
    if (m_uc)
    {
        for (auto& h : m_insnHooks)
        {
            if (h.hk)
                uc_hook_del(m_uc, h.hk);
        }
    }

    m_insnHooks.clear();
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

void AsmRunner::SetMemoryRangeCB(tRange r, OnMemCb mem_cb, void* mem_data)
{
    if (!mem_cb)
        return;

    if (r.start >= r.end)
    {
        if (m_bLogRunner)
            Log("[!] SetMemoryRangeCB: invalid range [0x%p - 0x%p]", (void*)r.start, (void*)r.end);
        return;
    }

    for (const auto& existing : m_memoryRangeCB)
    {
        bool overlap = !(r.end <= existing.range.start || existing.range.end <= r.start);
        if (overlap)
        {
            if (m_bLogRunner)
                Log("[!] SetMemoryRangeCB: range [0x%p - 0x%p] overlaps with existing [0x%p - 0x%p]",
                    (void*)r.start, (void*)r.end,
                    (void*)existing.range.start, (void*)existing.range.end);
            return;
        }
    }

    tMemoryRange mr;
    mr.range = r;
    mr.cbMem = std::move(mem_cb);
    mr.cbMemData = mem_data;
    m_memoryRangeCB.push_back(mr);
    m_bUsingMemoryRangeCB = true;

    if (m_bLogRunner)
        Log("[*] MemoryRangeCB added: [0x%p - 0x%p]%s%s", (void*)r.start, (void*)r.end, r.sExcl ? " (start exclusive)" : "", r.eExcl ? " (end exclusive)" : "");
}

void AsmRunner::SetICCallback(uintptr_t nIC, OnOpcodeCb opcode_cb, void* opcode_data)
{
    if (!nIC)
        return;

    for (const auto& h : m_icHooks)
    {
        if (h.nIC == nIC)
        {
            if (m_bLogRunner)
                Log("ICCallback already exists for this nIC");
            MboxSTD("ICCallback already exists for this nIC", AR_SNAME);
            return;
        }
    }

    m_icHooks.push_back({ nIC, std::move(opcode_cb), opcode_data });
}

uintptr_t AsmRunner::CopyModule(const char* szModule, uintptr_t nSize)
{
    assert(szModule != nullptr);

    uintptr_t pStart = 0, pEnd = 0, iSize = 0;
    if (!GetMappedModuleBounds(szModule, pStart, pEnd, iSize)) {
        Shutdown();
        return 0;
    }

    if (m_bLogRunner)
        Log("[%s] base=0x%p end=0x%p size=0x%zx", szModule, (void*)pStart, (void*)pEnd, (size_t)iSize);

    uintptr_t copySize = (nSize == 0) ? iSize : nSize;
    if (!CopyModule(pStart, pStart, copySize, std::string(szModule))) { // emuTo, ntFrom, size
        return 0;
    }

    return pStart;
}

bool AsmRunner::CopyModule(uintptr_t pFrom, uintptr_t nSize, std::string sModName) // pFrom as hModule
{
    if (!pFrom || nSize == 0) {
        if (m_bLogRunner)
            Log("[!] CopyModule: Error in args, pFrom 0x%p, nSize %d", (void*)pFrom, nSize);
        return false;
    }

    if (!nSize) {
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pFrom);
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(pFrom + dos->e_lfanew);
        nSize = nt->OptionalHeader.SizeOfImage;
        if (m_bLogRunner)
            Log("IMAGE_NT_HEADERS: 0x%zx", nSize);
    }

    return CopyModule(pFrom, pFrom, nSize, sModName); // emuTo, ntFrom, size
}

bool AsmRunner::CopyModule(uintptr_t pVTo, uintptr_t pFrom, uintptr_t nSize, std::string sModName)
{
    if (!pVTo || !pFrom || nSize == 0) {
        if (m_bLogRunner)
            Log("[!] CopyModule: Error in args, pVTo 0x%p, pFrom 0x%p, nSize %d", (void*)pVTo, (void*)pFrom, nSize);
        return false;
    }

    if (!CopyModuleUC(pFrom, pVTo, nSize)) {
        if (m_bLogRunner) {
            Log("[!] CopyModule: Error in CopyModuleUC");
        }
        Shutdown();
        return false;
    }

    m_modName = sModName;
    m_modStart = pVTo;
    m_modEnd = pVTo + nSize;

    for (tFuncNode& node : m_sym) {
        node.moduleName = m_modName;
        node.moduleBase = m_modStart; // when sym was loaded before module
    }

    if (m_bLogRunner)
    {
        //Log("=== %s ===", szModule);
        Log("pStart: 0x%p", (void*)m_modStart);
        Log("pEnd:   0x%p", (void*)m_modEnd);
        Log("Size:   0x%zx (%zu MB)", static_cast<size_t>(nSize), static_cast<size_t>(nSize / (1024 * 1024)));
    }

    return true;
}

void AsmRunner::LoadModule(const char* szModule) // wrapper
{
    CopyModule(szModule, 0);
}

void AsmRunner::RemapModule()
{
#if 0
    if (!m_uc || m_modStart == 0) return;

    size_t size = m_modEnd - m_modStart;
    std::vector<uint8_t> backup(size);

    uc_mem_read(m_uc, m_modStart, backup.data(), size);
    uc_mem_unmap(m_uc, m_modStart, size);
    uc_ctl(m_uc, UC_CTL_TB_FLUSH);
    uc_mem_map(m_uc, m_modStart, size, UC_PROT_ALL);
    uc_mem_write(m_uc, m_modStart, backup.data(), size);
#else
    if (!m_uc || m_modStart == 0 || m_modEnd == 0)
        return;

    const uintptr_t size = m_modEnd - m_modStart;
    if (!size)
        return;

    // Backup
    std::vector<uint8_t> backup(size);
    if (!ReadBytes(m_uc, m_modStart, size, backup))
    {
        if (m_bLogRunner)
            Log("[!] RemapModule: failed to backup module");
        return;
    }

    //FreeMemory(m_modStart);
    FreeMemory(m_modStart, m_modEnd - m_modStart);
    uc_ctl(m_uc, UC_CTL_TB_FLUSH);

    if (!CopyModuleUC((uintptr_t)backup.data(), m_modStart, size))
    {
        if (m_bLogRunner)
            Log("[!] RemapModule: failed to restore module");
        return;
    }

    if (m_bLogRunner)
        Log("[*] RemapModule: module restored");
#endif
}

ArRegsBlob AsmRunner::RunStateEnvSaveRegs(uc_engine* uc, bool bX64)
{
    ArRegsBlob r{};
    auto rd32 = [&](int32_t reg) -> uint64_t { uint32_t v = 0; uc_reg_read(uc, reg, &v); return v; };
    auto rd64 = [&](int32_t reg) -> uint64_t { uint64_t v = 0; uc_reg_read(uc, reg, &v); return v; };
    auto rd16 = [&](int32_t reg) -> uint16_t { uint16_t v = 0; uc_reg_read(uc, reg, &v); return v; };

    if (bX64) {
        r.ax = rd64(UC_X86_REG_RAX); r.bx = rd64(UC_X86_REG_RBX);
        r.cx = rd64(UC_X86_REG_RCX); r.dx = rd64(UC_X86_REG_RDX);
        r.si = rd64(UC_X86_REG_RSI); r.di = rd64(UC_X86_REG_RDI);
        r.bp = rd64(UC_X86_REG_RBP); r.sp = rd64(UC_X86_REG_RSP);
        r.ip = rd64(UC_X86_REG_RIP);
        r.r8 = rd64(UC_X86_REG_R8);  r.r9 = rd64(UC_X86_REG_R9);
        r.r10 = rd64(UC_X86_REG_R10); r.r11 = rd64(UC_X86_REG_R11);
        r.r12 = rd64(UC_X86_REG_R12); r.r13 = rd64(UC_X86_REG_R13);
        r.r14 = rd64(UC_X86_REG_R14); r.r15 = rd64(UC_X86_REG_R15);
//#ifdef AR_STATE_SEG
        r.fs_base = rd64(UC_X86_REG_FS_BASE);
        r.gs_base = rd64(UC_X86_REG_GS_BASE);
//#endif
    }
    else {
        r.ax = rd32(UC_X86_REG_EAX); r.bx = rd32(UC_X86_REG_EBX);
        r.cx = rd32(UC_X86_REG_ECX); r.dx = rd32(UC_X86_REG_EDX);
        r.si = rd32(UC_X86_REG_ESI); r.di = rd32(UC_X86_REG_EDI);
        r.bp = rd32(UC_X86_REG_EBP); r.sp = rd32(UC_X86_REG_ESP);
        r.ip = rd32(UC_X86_REG_EIP);
    }
    r.flags = rd32(UC_X86_REG_EFLAGS);
//#ifdef AR_STATE_SEG // пусть сохраняет, это не сломает
    r.cs = rd16(UC_X86_REG_CS);
    r.ds = rd16(UC_X86_REG_DS);
    r.es = rd16(UC_X86_REG_ES);
    r.fs_sel = rd16(UC_X86_REG_FS);
    r.gs_sel = rd16(UC_X86_REG_GS);
    r.ss = rd16(UC_X86_REG_SS);
//#endif
    return r;
}

void AsmRunner::RunStateEnvLoadRegs(uc_engine* uc, bool bX64, const ArRegsBlob& r)
{
    auto wr32 = [&](int32_t reg, uint32_t v) { uc_reg_write(uc, reg, &v); };
    auto wr64 = [&](int32_t reg, uint64_t v) { uc_reg_write(uc, reg, &v); };
    auto wr16 = [&](int32_t reg, uint16_t v) { uc_reg_write(uc, reg, &v); };

    if (bX64) {
        wr64(UC_X86_REG_RAX, r.ax); wr64(UC_X86_REG_RBX, r.bx);
        wr64(UC_X86_REG_RCX, r.cx); wr64(UC_X86_REG_RDX, r.dx);
        wr64(UC_X86_REG_RSI, r.si); wr64(UC_X86_REG_RDI, r.di);
        wr64(UC_X86_REG_RBP, r.bp); wr64(UC_X86_REG_RSP, r.sp);
        wr64(UC_X86_REG_RIP, r.ip);
        wr64(UC_X86_REG_R8, r.r8);  wr64(UC_X86_REG_R9, r.r9);
        wr64(UC_X86_REG_R10, r.r10); wr64(UC_X86_REG_R11, r.r11);
        wr64(UC_X86_REG_R12, r.r12); wr64(UC_X86_REG_R13, r.r13);
        wr64(UC_X86_REG_R14, r.r14); wr64(UC_X86_REG_R15, r.r15);
#ifdef AR_STATE_SEG
        // warn!! seg может сломать было 0 запись 0 меняет поведение сам факт записи даже тех самых значений лол блять
        wr64(UC_X86_REG_FS_BASE, r.fs_base);
        wr64(UC_X86_REG_GS_BASE, r.gs_base);
#endif
    }
    else {
        wr32(UC_X86_REG_EAX, (uint32_t)r.ax); wr32(UC_X86_REG_EBX, (uint32_t)r.bx);
        wr32(UC_X86_REG_ECX, (uint32_t)r.cx); wr32(UC_X86_REG_EDX, (uint32_t)r.dx);
        wr32(UC_X86_REG_ESI, (uint32_t)r.si); wr32(UC_X86_REG_EDI, (uint32_t)r.di);
        wr32(UC_X86_REG_EBP, (uint32_t)r.bp); wr32(UC_X86_REG_ESP, (uint32_t)r.sp);
        wr32(UC_X86_REG_EIP, (uint32_t)r.ip);
    }
    uint32_t flags32 = (uint32_t)r.flags;
    wr32(UC_X86_REG_EFLAGS, flags32);
#ifdef AR_STATE_SEG
    // warn!! seg может сломать было 0 запись 0 меняет поведение сам факт записи даже тех самых значений лол блять
    //регистр CS становился равен 0 (вместо правильного 0x23).
    //В 16-битном режиме инструкция and edx, 0x72CF079E имеет длину 4 байта (вместо 6 в 32-битном), поэтому хук получал size=4.
    wr16(UC_X86_REG_CS, r.cs); // ломает, 81 E2 9E 07 CF 72 and edx, 72CF079Eh opsize 4 место 6
    wr16(UC_X86_REG_DS, r.ds); // ломает, MemCb address 0x00000CC0
    wr16(UC_X86_REG_ES, r.es); // ломает, MemCb address 0x00000CC0
    wr16(UC_X86_REG_FS, r.fs_sel); // ломает, MemCb address 0x00000CC0
    wr16(UC_X86_REG_GS, r.gs_sel); // ломает, MemCb address 0x00000CC0
    wr16(UC_X86_REG_SS, r.ss); // вроде ок
#endif
}

// bIncludeModuleData=false  -> module entry saved without bytes (NT variant)
// bIncludeAllocMap=false    -> only regs+stack+TEB, no module, no generic regions
void* AsmRunner::SaveRunStateEnvImpl(uintptr_t& nOutSize, bool bIncludeModuleData, bool bIncludeAllocMap)
{
    nOutSize = 0;
    if (!m_uc || !m_bInitialised) {
        Log("[!] SaveRunStateEnv: not initialised");
        return nullptr;
    }

    // Collect hook dummy page bases to skip
    std::set<uintptr_t> hookPages;
    for (const auto& h : m_anyJmpHooks) {
        if (!h.before) {
            uintptr_t pb = AlignDown(h.pAddr, 0x1000);
            if (!IsInAddr(pb, m_modStart, m_modEnd) &&
                !IsInAddr(pb, m_stackBase, m_stackBase + m_stackSize) &&
                !IsInAddr(pb, m_fsBase, m_fsBase + m_fsSize))
                hookPages.insert(pb);
        }
    }

    std::vector<uint8_t> buf;
    buf.reserve(4 * 1024 * 1024);

    // Header
    ArFileHdr hdr{};
    hdr.magic = kArMagic;
    hdr.version = kArVersion;
    hdr.bis64 = (uint8_t)m_bX64;
    hdr.bHasModuleData = (uint8_t)(bIncludeModuleData ? 1 : 0);
    hdr.iccount = (uint64_t)(m_instrCount - 1); // -1 save already in current op, load+perform increment
    hdr.stepsDeep = (uint64_t)m_nRunStepsDeep;
    hdr.modStart = (uint64_t)m_modStart;
    hdr.modEnd = (uint64_t)m_modEnd;
    strncpy(hdr.modName, m_modName.c_str(), sizeof(hdr.modName) - 1);
    hdr.stackBase = (uint64_t)m_stackBase;
    hdr.stackSize = (uint64_t)m_stackSize;
    hdr.fsBase = (uint64_t)m_fsBase;
    hdr.fsSize = (uint64_t)m_fsSize;
    hdr.fsLastError = (uint64_t)m_fsLastError;
    hdr.allocBase = (uint64_t)m_allocBase;
    hdr.allocCursor = (uint64_t)m_allocCursor;
    hdr.savedPC = (uint64_t)CurrentPc(m_uc);
    buf.insert(buf.end(), (const uint8_t*)&hdr, (const uint8_t*)&hdr + sizeof hdr);
    //_BufAppT(buf, hdr);

    Log("[*] SaveRunStateEnv: bis64=%d iccount=%zu stepsDeep=%zu PC=0x%p modData=%d allocMap=%d",
        (int)m_bX64, (size_t)m_instrCount, (size_t)m_nRunStepsDeep,
        (void*)hdr.savedPC, (int)bIncludeModuleData, (int)bIncludeAllocMap);

    // REGS chunk
    {
        ArRegsBlob regs = RunStateEnvSaveRegs(m_uc, m_bX64);
        ArChunkHdr ch{ kChunkREGS, (uint32_t)sizeof(regs) };
        buf.insert(buf.end(), (const uint8_t*)&ch, (const uint8_t*)&ch + sizeof ch);
        buf.insert(buf.end(), (const uint8_t*)&regs, (const uint8_t*)&regs + sizeof regs);
        //_BufAppT(buf, ch);
        //_BufAppT(buf, regs);
        Log("[*] SaveRunStateEnv: REGS saved");
    }

    // MEMS chunk
    {
        std::vector<uint8_t> memsPayload;

        // First pass: count regions
        uint32_t count = 0;
        for (auto it = m_memMap.begin(); it != m_memMap.end(); ++it) {
            uintptr_t addr = it->first;
            const tMemMapEntry& e = it->second;

            if (hookPages.count(addr)) continue;
            bool isModule = (m_modStart != 0 && addr == m_modStart);
            bool isStack = (m_bInitedStack && addr == m_stackBase);
            bool isTeb = (m_bInitedSehFS && addr == m_fsBase);
            bool isGeneric = !isModule && !isStack && !isTeb;
            if (!bIncludeAllocMap && isGeneric) continue;
            count++;
        }
        memsPayload.insert(memsPayload.end(), (const uint8_t*)&count, (const uint8_t*)&count + sizeof count);
        //_BufAppT(memsPayload, count);

        // Second pass: write data
        uintptr_t totalBytes = 0;
        for (auto it = m_memMap.begin(); it != m_memMap.end(); ++it) {
            uintptr_t addr = it->first;
            const tMemMapEntry& e = it->second;

            if (hookPages.count(addr)) {
                Log("[*] SaveRunStateEnv: skip hook dummy 0x%p sz=0x%zx", (void*)addr, (size_t)e.size);
                continue;
            }
            bool isModule = (m_modStart != 0 && addr == m_modStart);
            bool isStack = (m_bInitedStack && addr == m_stackBase);
            bool isTeb = (m_bInitedSehFS && addr == m_fsBase);
            bool isGeneric = !isModule && !isStack && !isTeb;
            if (!bIncludeAllocMap && isGeneric) continue;

            uint8_t rtype = 0;
            if (isModule) rtype = 3;
            else if (isStack) rtype = 1;
            else if (isTeb)   rtype = 2;

            uint8_t hasData = (isModule && !bIncludeModuleData) ? 0 : 1;

            ArMemEntry me{};
            me.addr = (uint64_t)addr;
            me.mapSize = (uint64_t)e.size;
            me.prot = e.prot;
            me.regionType = rtype;
            me.hasData = hasData;
            memsPayload.insert(memsPayload.end(), (const uint8_t*)&me, (const uint8_t*)&me + sizeof me);
            //_BufAppT(memsPayload, me);

            if (hasData) {
                std::vector<uint8_t> data(e.size);
                uc_err err = uc_mem_read(m_uc, addr, data.data(), e.size);
                if (err != UC_ERR_OK) {
                    Log("[!] SaveRunStateEnv: uc_mem_read 0x%p sz=0x%zx: %s",
                        (void*)addr, (size_t)e.size, uc_strerror(err));
                    memset(data.data(), 0, e.size);
                }
                memsPayload.insert(memsPayload.end(), data.data(), data.data() + data.size());
                //_BufApp(memsPayload, data.data(), data.size());
                totalBytes += e.size;
            }
            Log("[*] SaveRunStateEnv: region 0x%p sz=0x%zx prot=0x%x type=%d hasData=%d",
                (void*)addr, (size_t)e.size, e.prot, (int)rtype, (int)hasData);
        }

        ArChunkHdr ch{ kChunkMEMS, (uint32_t)memsPayload.size() };
        buf.insert(buf.end(), (const uint8_t*)&ch, (const uint8_t*)&ch + sizeof ch);
        buf.insert(buf.end(), memsPayload.data(), memsPayload.data() + memsPayload.size());
        //_BufAppT(buf, ch);
        //_BufApp(buf, memsPayload.data(), memsPayload.size());
        Log("[*] SaveRunStateEnv: MEMS %u regions, data=%zu bytes", count, (size_t)totalBytes);
    }

    {
        ArChunkHdr ch{ kChunkEND, 0 };
        buf.insert(buf.end(), (const uint8_t*)&ch, (const uint8_t*)&ch + sizeof ch);
        //_BufAppT(buf, ch);
    }

    nOutSize = buf.size();
    void* out = malloc(nOutSize);
    if (!out) {
        Log("[!] SaveRunStateEnv: malloc(%zu) failed", (size_t)nOutSize);
        nOutSize = 0;
        return nullptr;
    }
    memcpy(out, buf.data(), nOutSize);
    Log("[+] SaveRunStateEnv: done, %zu bytes (%.2f MB)",
        (size_t)nOutSize, (double)nOutSize / (1024.0 * 1024.0));
    return out;
}

void* AsmRunner::SaveRunStateEnv(uintptr_t& nOutSize)
{
    return SaveRunStateEnvImpl(nOutSize, true, true);
}

void* AsmRunner::SaveRunStateEnvNT(uintptr_t& nOutSize)
{
    // Minimal: regs + stack + TEB only; iccount/stepsDeep zeroed
    void* p = SaveRunStateEnvImpl(nOutSize, false, false);
    if (p && nOutSize >= sizeof(ArFileHdr)) {
        ArFileHdr* hdr = reinterpret_cast<ArFileHdr*>(p);
        hdr->iccount = 0;
        hdr->stepsDeep = 0;
    }
    return p;
}

void AsmRunner::LoadRunStateEnv(void* pReadBuff, bool bRun)
{
    if (!pReadBuff) { Log("[!] LoadRunStateEnv: null buffer"); return; }
    if (!m_uc || !m_bInitialised) { Log("[!] LoadRunStateEnv: not initialised"); return; }

    const uint8_t* p = (const uint8_t*)pReadBuff;

    ArFileHdr hdr{};
    memcpy(&hdr, p, sizeof hdr);
    p += sizeof hdr;

    if (hdr.magic != kArMagic) { Log("[!] LoadRunStateEnv: bad magic 0x%08X", hdr.magic); return; }
    if (hdr.version != kArVersion) { Log("[!] LoadRunStateEnv: unsupported version %u", hdr.version); return; }
    if ((bool)hdr.bis64 != m_bX64) {
        Log("[!] LoadRunStateEnv: mode mismatch: file=%s current=%s",
            hdr.bis64 ? "x64" : "x86", m_bX64 ? "x64" : "x86");
        return;
    }
    Log("[*] LoadRunStateEnv: v=%u bis64=%d PC=0x%p ic=%zu steps=%zu",
        hdr.version, (int)hdr.bis64, (void*)hdr.savedPC,
        (size_t)hdr.iccount, (size_t)hdr.stepsDeep);

    // Collect hook dummy page bases — must survive the unmap (same logic as SaveRunStateEnvImpl)
    std::set<uintptr_t> hookPages;
    for (const auto& h : m_anyJmpHooks) {
        if (!h.before) {
            uintptr_t pb = AlignDown(h.pAddr, 0x1000);
            if (!IsInAddr(pb, m_modStart, m_modEnd) &&
                !IsInAddr(pb, m_stackBase, m_stackBase + m_stackSize) &&
                !IsInAddr(pb, m_fsBase, m_fsBase + m_fsSize))
                hookPages.insert(pb);
        }
    }

    // Unmap all existing regions from UC except hook dummy pages
    {
        std::vector<std::pair<uintptr_t, uintptr_t>> toUnmap;
        for (auto it = m_memMap.begin(); it != m_memMap.end(); ++it) {
            if (!hookPages.count(it->first))
                toUnmap.push_back(std::make_pair(it->first, it->second.size));
        }
        for (auto it = toUnmap.begin(); it != toUnmap.end(); ++it) {
            uintptr_t addr = it->first;
            uintptr_t sz = it->second;
            uc_err err = uc_mem_unmap(m_uc, addr, sz);
            if (err != UC_ERR_OK)
                Log("[!] LoadRunStateEnv: unmap 0x%p sz=0x%zx: %s",
                    (void*)addr, (size_t)sz, uc_strerror(err));
            m_memMap.erase(addr);
        }
        m_bInitedStack = false;
        m_bInitedSehFS = false;
        m_modStart = 0;
        m_modEnd = 0;
    }

    // Restore scalar fields from header
    m_instrCount = (uintptr_t)hdr.iccount;
    m_nRunStepsDeep = (uintptr_t)hdr.stepsDeep;
    m_modName = std::string(hdr.modName);
    m_stackBase = (uintptr_t)hdr.stackBase;
    m_stackSize = (uintptr_t)hdr.stackSize;
    m_fsBase = (uintptr_t)hdr.fsBase;
    m_fsSize = (uintptr_t)hdr.fsSize;
    m_fsLastError = (uintptr_t)hdr.fsLastError;
    m_allocBase = (uintptr_t)hdr.allocBase;
    m_allocCursor = (uintptr_t)hdr.allocCursor;

    ArRegsBlob regs{};
    bool bGotRegs = false;

    while (true) {
        ArChunkHdr ch{};
        memcpy(&ch, p, sizeof ch);
        p += sizeof ch;
        if (ch.tag == kChunkEND) break;

        if (ch.tag == kChunkREGS) {
            if (ch.size >= sizeof(ArRegsBlob)) {
                memcpy(&regs, p, sizeof regs);
                bGotRegs = true;
                Log("[*] LoadRunStateEnv: REGS parsed");
            }
            else {
                Log("[!] LoadRunStateEnv: REGS chunk too small (%u)", ch.size);
            }
            p += ch.size;
        }
        else if (ch.tag == kChunkMEMS) {
            const uint8_t* mp = p;
            uint32_t count = 0;
            memcpy(&count, mp, sizeof count);
            mp += sizeof count;
            Log("[*] LoadRunStateEnv: MEMS %u regions", count);

            for (uint32_t i = 0; i < count; ++i) {
                ArMemEntry me{};
                memcpy(&me, mp, sizeof me);
                mp += sizeof me;

                uc_err err = uc_mem_map(m_uc, me.addr, (size_t)me.mapSize, me.prot);
                if (err != UC_ERR_OK) {
                    Log("[!] LoadRunStateEnv: map 0x%p sz=0x%zx: %s — retry after unmap",
                        (void*)me.addr, (size_t)me.mapSize, uc_strerror(err));
                    uc_mem_unmap(m_uc, me.addr, (size_t)me.mapSize);
                    err = uc_mem_map(m_uc, me.addr, (size_t)me.mapSize, me.prot);
                    if (err != UC_ERR_OK) {
                        Log("[!] LoadRunStateEnv: retry failed, skip 0x%p", (void*)me.addr);
                        if (me.hasData) mp += (size_t)me.mapSize;
                        continue;
                    }
                }
                m_memMap[(uintptr_t)me.addr] = { (uintptr_t)me.mapSize, me.prot };

                if (me.hasData) {
                    err = uc_mem_write(m_uc, me.addr, mp, (size_t)me.mapSize);
                    if (err != UC_ERR_OK)
                        Log("[!] LoadRunStateEnv: write 0x%p sz=0x%zx: %s",
                            (void*)me.addr, (size_t)me.mapSize, uc_strerror(err));
                    mp += (size_t)me.mapSize;
                }

                if (me.regionType == 1) m_bInitedStack = true;
                else if (me.regionType == 2) m_bInitedSehFS = true;
                else if (me.regionType == 3) {
                    m_modStart = (uintptr_t)hdr.modStart;
                    m_modEnd = (uintptr_t)hdr.modEnd;
                }
                Log("[*] LoadRunStateEnv: mapped 0x%p sz=0x%zx prot=0x%x type=%d hasData=%d",
                    (void*)me.addr, (size_t)me.mapSize, me.prot, (int)me.regionType, (int)me.hasData);
            }
            p += ch.size;
        }
        else {
            Log("[!] LoadRunStateEnv: unknown chunk 0x%08X sz=%u, skip", ch.tag, ch.size);
            p += ch.size;
        }
    }

    // Module bounds from header (valid even when no module data in save)
    if (hdr.modStart && hdr.modEnd) {
        m_modStart = (uintptr_t)hdr.modStart;
        m_modEnd = (uintptr_t)hdr.modEnd;
    }

    if (bGotRegs) {
        RunStateEnvLoadRegs(m_uc, m_bX64, regs);
        Log("[*] LoadRunStateEnv: registers restored, PC=0x%p", (void*)hdr.savedPC);
    }

    uc_ctl(m_uc, UC_CTL_TB_FLUSH);
    uc_ctl_flush_tlb(m_uc);

    Log("[+] LoadRunStateEnv: done, modStart=0x%p modEnd=0x%p IC=%zu steps=%zu",
        (void*)m_modStart, (void*)m_modEnd, (size_t)m_instrCount, (size_t)m_nRunStepsDeep);

    if (bRun && m_modStart && m_modEnd) {
        uintptr_t pc = (uintptr_t)hdr.savedPC;
        uintptr_t remain = (m_nRunStepsDeep > m_instrCount) ? (m_nRunStepsDeep - m_instrCount) : 0;
        Log("[*] LoadRunStateEnv: resume PC=0x%p remain=%zu", (void*)pc, (size_t)remain);
        Run(pc, remain);
    }
}

void AsmRunner::SaveRunStateEnvFile(std::string file)
{
    uintptr_t sz = 0;
    void* p = SaveRunStateEnv(sz);
    if (!p || !sz) { Log("[!] SaveRunStateEnvFile: save failed"); return; }
    FILE* f = FileOpen(file.c_str(), "wb");
    if (!f) { Log("[!] SaveRunStateEnvFile: can't open '%s'", file.c_str()); free(p); return; }
    FileWrite(f, p, sz);
    FileClose(f);
    free(p);
    Log("[+] SaveRunStateEnvFile: '%s' %zu bytes", file.c_str(), (size_t)sz);
}

void AsmRunner::SaveRunStateEnvNTFile(std::string file)
{
    uintptr_t sz = 0;
    void* p = SaveRunStateEnvNT(sz);
    if (!p || !sz) { Log("[!] SaveRunStateEnvNTFile: save failed"); return; }
    FILE* f = FileOpen(file.c_str(), "wb");
    if (!f) { Log("[!] SaveRunStateEnvNTFile: can't open '%s'", file.c_str()); free(p); return; }
    FileWrite(f, p, sz);
    FileClose(f);
    free(p);
    Log("[+] SaveRunStateEnvNTFile: '%s' %zu bytes", file.c_str(), (size_t)sz);
}

void AsmRunner::LoadRunStateEnvFile(std::string file, bool bRun)
{
    FILE* f = FileOpen(file.c_str(), "rb");
    if (!f) { Log("[!] LoadRunStateEnvFile: can't open '%s'", file.c_str()); return; }
    size_t sz = FileSize(f);
    if (!sz) { Log("[!] LoadRunStateEnvFile: empty '%s'", file.c_str()); FileClose(f); return; }
    void* buf = malloc(sz);
    if (!buf) { Log("[!] LoadRunStateEnvFile: malloc(%zu) failed", sz); FileClose(f); return; }
    FileRead(f, buf, sz);
    FileClose(f);
    Log("[*] LoadRunStateEnvFile: '%s' %zu bytes", file.c_str(), sz);
    LoadRunStateEnv(buf, bRun);
    free(buf);
}

void AsmRunner::HardReset()
{
    if (!m_uc) { Log("[!] HardReset: no UC context"); return; }
    Log("[*] HardReset: saving state...");

    // 1. Save full state from current UC
    uintptr_t saveSize = 0;
    void* pSave = SaveRunStateEnv(saveSize);
    if (!pSave || !saveSize) { Log("[!] HardReset: SaveRunStateEnv failed"); return; }
    Log("[*] HardReset: saved %zu bytes", (size_t)saveSize);

    // 2. Remove hooks and close engine (AsmRunner state untouched)
    if (m_hkCode) {
        uc_hook_del(m_uc, m_hkCode);
        m_hkCode = 0;
    }
    if (m_hkMem) {
        uc_hook_del(m_uc, m_hkMem);
        m_hkMem = 0;
    }
    for (auto& n : m_insnHooks) {
        if (n.hk) {
            uc_hook_del(m_uc, n.hk);
            n.hk = 0;
        } 
    }
    uc_close(m_uc);
    m_uc = nullptr;
    Log("[*] HardReset: old UC closed");

    // 3. Create fresh UC engine
    uc_mode mode = m_bX64 ? UC_MODE_64 : UC_MODE_32;
    uc_err err = uc_open(UC_ARCH_X86, mode, &m_uc);
    if (err != UC_ERR_OK) {
        Log("[!] HardReset: uc_open failed: %s", uc_strerror(err));
        free(pSave);
        return;
    }
    m_memMap.clear();
    m_bInitedStack = false;
    m_bInitedSehFS = false;
    m_modStart = 0;
    m_modEnd = 0;
    Log("[*] HardReset: new UC created");

    // 4. Restore all memory + registers (bRun=false, we run after hook re-install)
    LoadRunStateEnv(pSave, false);
    free(pSave);

    // 5. Re-install UC hooks on the new engine
    if (!m_hkCode) {
        err = uc_hook_add(m_uc, &m_hkCode, UC_HOOK_CODE,
            reinterpret_cast<void*>(HookCodeTrampoline), this, 1, 0);
        if (err != UC_ERR_OK) Log("[!] HardReset: hkCode: %s", uc_strerror(err));
    }
    if (!m_hkMem) {
        err = uc_hook_add(m_uc, &m_hkMem,
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE |
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_PROT |
            //UC_HOOK_MEM_READ_AFTER |
            //UC_HOOK_MEM_FETCH | // чтение самой инструкции, warn! old+unused
            UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT,
            reinterpret_cast<void*>(HookMemTrampoline), this, 1, 0);
        if (err != UC_ERR_OK) Log("[!] HardReset: hkMem: %s", uc_strerror(err));
    }
    for (auto& n : m_insnHooks) {
        if (!n.hk) {
            err = uc_hook_add(m_uc, &n.hk, UC_HOOK_INSN,
                reinterpret_cast<void*>(HookInsnTrampoline), &n, 1, 0, (int)n.nInsn);
            if (err != UC_ERR_OK)
                Log("[!] HardReset: insnHook nInsn=%zu: %s", (size_t)n.nInsn, uc_strerror(err));
        }
    }
    Log("[*] HardReset: hooks re-installed");

    // 6. Resume from saved PC with remaining steps
    uintptr_t pc = 0;
    if (m_bX64) uc_reg_read(m_uc, UC_X86_REG_RIP, &pc);
    else { uint32_t pc32 = 0; uc_reg_read(m_uc, UC_X86_REG_EIP, &pc32); pc = pc32; }
    uintptr_t remain = (m_nRunStepsDeep > m_instrCount) ? (m_nRunStepsDeep - m_instrCount) : 0;
    Log("[*] HardReset: resume PC=0x%p remain=%zu", (void*)pc, (size_t)remain);
    Log("[+] HardReset: complete");
    Run(pc, remain);
}

void AsmRunner::ResolveIATModule()
{
    if (!m_uc || !m_modStart || m_modEnd <= m_modStart)
        return;

    auto* base = reinterpret_cast<uint8_t*>(m_modStart);

    __try
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return;

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress || !dir.Size)
            return;

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
        const uintptr_t ptrSize = PointerSize();

        if (m_bLogRunner)
            Log("[*] ResolveIATModule: importRVA=0x%p size=0x%zx", (void*)dir.VirtualAddress, static_cast<size_t>(dir.Size));

        for (size_t dllIndex = 0; desc[dllIndex].Name != 0; ++dllIndex)
        {
            const char* dllName = reinterpret_cast<const char*>(base + desc[dllIndex].Name);
            if (!dllName || !*dllName)
                continue;

            HMODULE hDll = GetModuleHandleA(dllName);
            if (!hDll)
                hDll = LoadLibraryA(dllName); // Load!!

            uintptr_t* firstThunk = reinterpret_cast<uintptr_t*>(base + desc[dllIndex].FirstThunk);

            // INT для имён/ординалов, если есть.
            // Если OriginalFirstThunk == 0, используем FirstThunk как на диске.
            uintptr_t* origThunk = desc[dllIndex].OriginalFirstThunk
                ? reinterpret_cast<uintptr_t*>(base + desc[dllIndex].OriginalFirstThunk)
                : firstThunk;

            if (m_bLogRunner)
            {
                Log("[IAT] dll=%s hmod=0x%p OFT=0x%p FT=0x%p",
                    dllName, (void*)hDll,
                    (void*)desc[dllIndex].OriginalFirstThunk,
                    (void*)desc[dllIndex].FirstThunk);
            }

            for (size_t i = 0; ; ++i)
            {
                uintptr_t thunk = origThunk[i];
                if (thunk == 0)
                    break;

                void* resolved = nullptr;
                const char* funcName = nullptr;
                char ordBuf[32]{};

                if (thunk & IMAGE_ORDINAL_FLAG32)
                {
                    WORD ordinal = static_cast<WORD>(thunk & 0xFFFF);
                    resolved = reinterpret_cast<void*>(GetProcAddress(hDll, MAKEINTRESOURCEA(ordinal)));

                    std::snprintf(ordBuf, sizeof(ordBuf), "#%u", ordinal);
                    funcName = ordBuf;
                }
                else
                {
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + thunk);
                    funcName = reinterpret_cast<const char*>(ibn->Name);
                    resolved = reinterpret_cast<void*>(GetProcAddress(hDll, funcName));
                }

                const uintptr_t thunkAddr = reinterpret_cast<uintptr_t>(&firstThunk[i]);

                // Если адрес нашли — пишем его в IAT в Unicorn-памяти.
                // Если нет — оставляем 0, чтобы это было видно в emu.
                uintptr_t outValue = reinterpret_cast<uintptr_t>(resolved);

                uc_err err = UC_ERR_OK;
                if (ptrSize == 8)
                {
                    uint64_t v = static_cast<uint64_t>(outValue);
                    err = uc_mem_write(m_uc, thunkAddr, &v, sizeof(v));
                }
                else
                {
                    uint32_t v = static_cast<uint32_t>(outValue);
                    err = uc_mem_write(m_uc, thunkAddr, &v, sizeof(v));
                }

                if (m_bLogRunner)
                {
                    Log("[IAT] %s!%s -> %p  write@0x%p %s",
                        dllName,
                        funcName ? funcName : "?",
                        resolved,
                        (void*)thunkAddr,
                        (err == UC_ERR_OK) ? "OK" : uc_strerror(err));
                }
            }
        }

        m_bInitIAT = true;

        if (m_bLogRunner)
            Log("[*] ResolveIATModule done");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (m_bLogRunner)
            Log("[!] ResolveIATModule: exception while parsing PE image");
    }
}

uintptr_t AsmRunner::GetRandomEntryPoint()
{
    const uintptr_t align = 0x1000;

    uint64_t t = __rdtsc();
    t ^= (t << 13);
    t ^= (t >> 7);
    t ^= (t << 17);

    uintptr_t base = m_bX64 ? 0x0000000140000000ull : 0x00400000u;
    uintptr_t span = m_bX64 ? 0x0000000100000000ull : 0x70000000u;

    uintptr_t addr = base + (static_cast<uintptr_t>(t) % (span / align)) * align;
    return AlignUp(addr, align);
}

void AsmRunner::AddExecRegion(uintptr_t pStart, uintptr_t pEnd)
{
    if (pStart == 0 || pEnd == 0 || pEnd <= pStart)
        return;

    m_execRegions.push_back({ pStart, pEnd });
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
            n.funcRva = static_cast<uintptr_t>(rva);
            n.funcSize = 0;
            n.funcName = nm;
            n.moduleBase = m_modStart;
            n.moduleName = "";
            out.push_back(n);
        }
    }
    //__except (EXCEPTION_EXECUTE_HANDLER) { return false; }

    std::sort(out.begin(), out.end(), [](const tFuncNode& a, const tFuncNode& b) { return a.funcRva < b.funcRva; });
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
        if (_stricmp(exps[i].funcName.c_str(), szExportName) == 0) {
            return exps[i];
        }
    }

    return empty;
}

void AsmRunner::SetPCTrace(const char* szPCTraceFileOutPath, OnOpcodeCb cb, bool bRVA, uintptr_t pASLR, uintptr_t nICOffset, uint32_t nAnyJmpMode, bool bDisasm)
{
    if (!szPCTraceFileOutPath || !*szPCTraceFileOutPath) {
        if (m_bLogRunner)
            Log("[!] SetPCTrace: invalid file path");
        return;
    }

    if (m_rttrace.inited) {
        if (m_bLogRunner)
            Log("[!] SetPCTrace: trace already initialized");
        return;
    }

    if (m_rttrace.file.is_open())
        m_rttrace.file.close();

    m_rttrace.file.open(szPCTraceFileOutPath, std::ios::out | std::ios::trunc);
    if (!m_rttrace.file.is_open() && m_bLogRunner)
    {
        Log("[!] cannot open PC trace file: %s", szPCTraceFileOutPath);
        m_rttrace.inited = false;
        return;
    }

    m_rttrace.aslr = pASLR;
    m_rttrace.icoffset = nICOffset;
    m_rttrace.anyjmpmode = nAnyJmpMode;
    m_rttrace.cb = cb;
    m_rttrace.rva = bRVA;
    m_rttrace.disasm = bDisasm;
    m_rttrace.bin = false;

    m_rttrace.rwhistory.bUseRWHistory = false;
    m_rttrace.rwhistory.bRead = false;
    m_rttrace.rwhistory.bWrite = false;
    m_rttrace.rwhistory.bValNotice = false;
    m_rttrace.rwhistory.bSym = false;
    m_rttrace.rwhistory.bShortFmt = false;
    m_rttrace.rwhistory.bDisasm = false;

    if (m_bLogRunner) {
        Log("[*] PC trace opened: %s", szPCTraceFileOutPath);
        Log("[*] PC trace mode: %s%s", bRVA ? "RVA" : "PC", (bRVA && pASLR) ? " + custom ASLR" : "");
    }

    m_rttrace.inited = true;
}

//AsmRunner::SetPCTraceFull(
//    "trace.log",           // szPCTraceFileOutPath
//    nullptr,               // cb - OnOpcodeCb // \default/
//    true,                  // bRVA
//    0,                     // pASLR
//    0,                     // nICOffset
//    0,                     // nAnyJmpMode
//    true                   // bDisasm
//    true,                  // bRead
//    true,                  // bWrite
//    true,                  // bValNotice
//    true,                  // bSym
//    false,                 // bShortFmt
//    true,                  // bDisasmRW
//);
void AsmRunner::SetPCTraceFull(const char* szPCTraceFileOutPath, OnOpcodeCb cb, bool bRVA, uintptr_t pASLR, uintptr_t nICOffset, uint32_t nAnyJmpMode,
    bool bDisasm, bool bRead, bool bWrite, bool bValNotice, bool bSym, bool bShortFmt, bool bDisasmRW)
{
    if (m_rttrace.inited) {
        if (m_bLogRunner)
            Log("[!] SetPCTraceFull: trace already initialized");
        return;
    }

    SetPCTrace(szPCTraceFileOutPath, cb, bRVA, pASLR, nICOffset, nAnyJmpMode, bDisasm);
    m_rttrace.rwhistory.bUseRWHistory = true;
    m_rttrace.rwhistory.bRead = bRead;
    m_rttrace.rwhistory.bWrite = bWrite;
    m_rttrace.rwhistory.bValNotice = bValNotice;
    m_rttrace.rwhistory.bSym = bSym;
    m_rttrace.rwhistory.bShortFmt = bShortFmt;
    m_rttrace.rwhistory.bDisasm = bDisasmRW;

    m_rttrace.inited = true;
}

void AsmRunner::SetPCTraceBin(const char* szPCTraceFileOutPath, OnOpcodeCb cb, uintptr_t nICOffset)
{
    if (m_rttrace.inited) {
        if (m_bLogRunner)
            Log("[!] SetPCTraceBin: trace already initialized");
        return;
    }

    SetPCTrace(szPCTraceFileOutPath, cb, false, 0, nICOffset, 0, false);
    m_rttrace.bin = true;

    m_rttrace.inited = true;
}

void AsmRunner::ComparePCTrace(const char* szPCTraceA, const char* szPCTraceB, bool bAll, const char* szOutFileCompare)
{
    if (!szPCTraceA || !*szPCTraceA || !szPCTraceB || !*szPCTraceB)
    {
        Log("[!] ComparePCTrace: empty path");
        return;
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    bool haveConsole = (hConsole != INVALID_HANDLE_VALUE) && GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD oldAttr = haveConsole ? csbi.wAttributes : (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    const WORD kWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    const WORD kRed = FOREGROUND_RED;
    const WORD kGreen = FOREGROUND_GREEN;
    const WORD kYellow = FOREGROUND_RED | FOREGROUND_GREEN;

    std::ofstream outFile;
    std::ostream* out = &std::cout;
    const bool toFile = (szOutFileCompare && *szOutFileCompare);

    if (toFile)
    {
        outFile.open(szOutFileCompare, std::ios::out | std::ios::trunc);
        if (!outFile.is_open())
        {
            Log("[!] ComparePCTrace: cannot open output file: %s", szOutFileCompare);
            return;
        }
        out = &outFile;
    }

    auto setColor = [&](WORD c)
    {
        if (!toFile && haveConsole)
            SetConsoleTextAttribute(hConsole, c);
    };

    auto restoreColor = [&]()
    {
        if (!toFile && haveConsole)
            SetConsoleTextAttribute(hConsole, oldAttr);
    };

    auto writeLine = [&](WORD color, const std::string& s)
    {
        setColor(color);
        (*out) << s << '\n';
    };

    auto toHex = [](uintptr_t v) -> std::string
    {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << v;
        return ss.str();
    };

    std::ifstream fa(szPCTraceA);
    std::ifstream fb(szPCTraceB);

    if (!fa.is_open())
    {
        Log("[!] ComparePCTrace: cannot open A: %s", szPCTraceA);
        restoreColor();
        return;
    }
    if (!fb.is_open())
    {
        Log("[!] ComparePCTrace: cannot open B: %s", szPCTraceB);
        restoreColor();
        return;
    }

    auto trim = [](std::string& s)
    {
        auto issp = [](unsigned char c) { return std::isspace(c) != 0; };

        s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            [&](char c) { return !issp(static_cast<unsigned char>(c)); }));

        s.erase(std::find_if(s.rbegin(), s.rend(),
            [&](char c) { return !issp(static_cast<unsigned char>(c)); }).base(), s.end());
    };

    auto parseLine = [&](const std::string& line, uintptr_t& outPc) -> bool
    {
        std::string s = line;
        trim(s);
        if (s.empty())
            return false;
        if (s[0] == ';' || s[0] == '#')
            return false;

        size_t p = s.find("0x");
        const char* str = (p != std::string::npos) ? (s.c_str() + p + 2) : s.c_str();

        char* end = nullptr;
        unsigned long long v = std::strtoull(str, &end, 16);
        if (end == str)
            return false;

        outPc = static_cast<uintptr_t>(v);
        return true;
    };

    auto loadTrace = [&](std::ifstream& f, std::vector<uintptr_t>& outVec)
    {
        outVec.clear();
        std::string line;
        while (std::getline(f, line))
        {
            uintptr_t pc = 0;
            if (parseLine(line, pc))
                outVec.push_back(pc);
        }
    };

    std::vector<uintptr_t> a, b;
    loadTrace(fa, a);
    loadTrace(fb, b);

    if (m_bLogRunner)
    {
        writeLine(kWhite, "[*] ComparePCTrace");

        {
            std::ostringstream ss;
            ss << "[*] A: " << szPCTraceA << " (len=" << a.size() << ")";
            writeLine(kWhite, ss.str());
        }
        {
            std::ostringstream ss;
            ss << "[*] B: " << szPCTraceB << " (len=" << b.size() << ")";
            writeLine(kWhite, ss.str());
        }
    }

    if (a.empty() && b.empty())
    {
        writeLine(kGreen, "[=] both traces are empty");
        restoreColor();
        return;
    }

    const size_t minSz = std::min(a.size(), b.size());
    size_t firstDiff = minSz;

    for (size_t i = 0; i < minSz; ++i)
    {
        if (a[i] != b[i])
        {
            firstDiff = i;
            break;
        }
    }

    if (firstDiff == minSz)
    {
        writeLine(kGreen, "[=] traces match for first " + std::to_string(minSz) + " instruction(s)");

        if (a.size() == b.size())
        {
            writeLine(kGreen, "[=] eq, same length: " + std::to_string(a.size()));
        }
        else if (a.size() < b.size())
        {
            writeLine(kGreen, "[=] eq by shorter file: A ended first, B is longer by " +
                std::to_string(b.size() - a.size()) + " instruction(s)");
        }
        else
        {
            writeLine(kGreen, "[=] eq by shorter file: B ended first, A is longer by " +
                std::to_string(a.size() - b.size()) + " instruction(s)");
        }

        restoreColor();
        return;
    }

    if (bAll)
    {
        for (size_t i = 0; i < std::max(a.size(), b.size()); ++i)
        {
            const bool hasA = i < a.size();
            const bool hasB = i < b.size();
            const bool diff = (!hasA || !hasB || a[i] != b[i]);

            if (!diff)
                continue;

            std::ostringstream ss;
            ss << "[" << i << "] ";

            if (hasA)
                ss << "A " << toHex(a[i]);
            else
                ss << "A <EOF>";

            ss << " / ";

            if (hasB)
                ss << "B " << toHex(b[i]);
            else
                ss << "B <EOF>";

            writeLine(kRed, ss.str());
        }

        restoreColor();
        return;
    }

    const size_t begin = (firstDiff > 10) ? (firstDiff - 10) : 0;
    const size_t end = std::min(std::max(a.size(), b.size()), firstDiff + 11);

    {
        std::ostringstream ss;
        ss << "[!] first diff at instruction #" << firstDiff;
        writeLine(kYellow, ss.str());
    }

    for (size_t i = begin; i < end; ++i)
    {
        const bool hasA = i < a.size();
        const bool hasB = i < b.size();
        const bool eq = hasA && hasB && (a[i] == b[i]);

        WORD color = eq ? kGreen : kRed;
        if (i == firstDiff)
            color = kYellow;

        std::ostringstream ss;
        ss << "[" << i << "] ";

        if (hasA && hasB)
        {
            ss << "A " << toHex(a[i]) << " / B " << toHex(b[i]);
        }
        else if (hasA)
        {
            ss << "A " << toHex(a[i]) << " / B <EOF>";
        }
        else
        {
            ss << "A <EOF> / B " << toHex(b[i]);
        }

        if (i == firstDiff)
            ss << "  <== 1st diff";

        writeLine(color, ss.str());
    }

    if (a.size() != b.size())
    {
        if (a.size() < b.size())
        {
            writeLine(kYellow, "[!] A shorter by " + std::to_string(b.size() - a.size()) + " instruction(s)");
        }
        else
        {
            writeLine(kYellow, "[!] B shorter by " + std::to_string(a.size() - b.size()) + " instruction(s)");
        }
    }

    restoreColor();
}

bool AsmRunner::CompressDiffs(std::vector<std::string> files, std::string outFile)
{
    if (files.empty() || outFile.empty())
    {
        if (m_bLogRunner)
            Log("[!] CompressDiffs: invalid arguments");
        return false;
    }

    auto Load = [](const std::string& path, std::vector<std::string>& lines) -> bool
    {
        std::ifstream f(path);
        if (!f)
            return false;

        std::string s;
        while (std::getline(f, s))
            lines.emplace_back(std::move(s));
        return true;
    };

    std::vector<std::vector<std::string>> traces(files.size());
    size_t minLines = SIZE_MAX;

    for (size_t i = 0; i < files.size(); ++i)
    {
        if (!Load(files[i], traces[i]))
        {
            if (m_bLogRunner)
                Log("[!] CompressDiffs: failed to load '%s'", files[i].c_str());
            return false;
        }

        minLines = std::min(minLines, traces[i].size());
    }

    FILE* out = FileOpen(outFile.c_str(), "wb");
    if (!out)
    {
        if (m_bLogRunner)
            Log("[!] CompressDiffs: failed to create '%s'", outFile.c_str());
        return false;
    }

    for (size_t line = 0; line < minLines; ++line)
    {
        bool diff = false;
        for (size_t i = 1; i < traces.size(); ++i)
        {
            if (traces[i][line] != traces[0][line])
            {
                diff = true;
                break;
            }
        }

        if (!diff)
            continue;

        for (size_t i = 0; i < traces.size(); ++i)
            FileAdd(out, "[%zu:%c]%s", line + 1, 'A' + (char)i, traces[i][line].c_str());

        FileAdd(out, "");
    }

    FileClose(out);

    if (m_bLogRunner)
        Log("[*] CompressDiffs done");

    return true;
}

bool AsmRunner::RunCurrentPC(uintptr_t nStepsDeep, bool bSeh)
{
    if (!m_uc)
        return false;

    uintptr_t pc = 0;
    if (m_bX64) {
        uc_reg_read(m_uc, UC_X86_REG_RIP, &pc);
    }
    else {
        uint32_t pc32 = 0;
        uc_reg_read(m_uc, UC_X86_REG_EIP, &pc32);
        pc = pc32;
    }

    return Run(pc, nStepsDeep, bSeh);
}

bool AsmRunner::TryRun(uintptr_t pEntry, uintptr_t nStepsDeep, bool bSeh)
{
    try {
        return Run(pEntry, nStepsDeep, bSeh);
    }
    catch (const std::exception& e) {
        printf("std::exception: %s\n", e.what());
    }
    catch (...) {
        printf("Unknown C++ exception\n");
    }
    return false;
}

bool AsmRunner::Run(uintptr_t pEntry, uintptr_t nStepsDeep, bool bSeh)
{
    // todo m_RestartICPoints  (hardreset)
    if (bSeh) {
    // like RtlDispatchException // 
    // TODO: if(bSeh)while (!RunOnly) {log, performseh run (deep-ic)}
        return RunOnly(pEntry, nStepsDeep, bSeh); // tmp
    }
    else {
        return RunOnly(pEntry, nStepsDeep, bSeh);
    }
}

bool AsmRunner::RunOnly(uintptr_t pEntry, uintptr_t nStepsDeep, bool bSeh)
{
    if (!m_uc || m_modStart == 0 || m_modEnd == 0 || !m_bInitialised) {
        Log("[!] AsmRunner::Run ERROR: m_uc 0x%p, m_modStart 0x%p, m_modEnd 0x%p, m_bInitialised %d", m_uc, m_modStart, m_modEnd, m_bInitialised);
        return false;
    }

    uintptr_t pc = pEntry;
    if (!m_bX64) pc = static_cast<uint32_t>(pc);
    uc_reg_write(m_uc, PcReg(), &pc);

    if (!m_hkCode) {
        uc_err err = uc_hook_add(m_uc, &m_hkCode, UC_HOOK_CODE, reinterpret_cast<void*>(HookCodeTrampoline), this, 1, 0);
        if (err != UC_ERR_OK) {
            Log("[!] uc_hook_add CODE failed: %s", uc_strerror(err));
            return false;
        }
    }

    if (!m_hkMem) {
        uc_err err = uc_hook_add(m_uc, &m_hkMem,
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE |
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_PROT |
            //UC_HOOK_MEM_READ_AFTER |
            //UC_HOOK_MEM_FETCH | // чтение самой инструкции, warn! old+unused
            UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT,
            reinterpret_cast<void*>(HookMemTrampoline), this, 1, 0);
        if (err != UC_ERR_OK) {
            Log("[!] uc_hook_add MEM failed: %s", uc_strerror(err));
            return false;
        }
    }

    // TODO? UC_HOOK_INTR  // UC_HOOK_INSN(done)

    m_bPaused = false;
    m_bStopped = false;
    m_bSkipCBCallsWithNewPC = false;
    m_nRunStepsDeep = nStepsDeep;

    if (m_bLogRunner) {
        Log("[*] Entry = 0x%p", (void*)pc);
        Log("[*] Steps = %zu", static_cast<size_t>(nStepsDeep));
        Log("[*] Bounds = [0x%p - 0x%p]", (void*)m_modStart, (void*)m_modEnd);
    }

    uint64_t count = nStepsDeep ? static_cast<uint64_t>(nStepsDeep) : 0;
    uc_err err = uc_emu_start(m_uc, pc, m_modEnd ? m_modEnd : 0, 0, count);

    if (m_bLogRunner)
    {
        SetConsoleColor(1);
        DisassembleWithZydis(true);
        Log("[*] emu end, err=%s, IC instr=%zu", uc_strerror(err), static_cast<size_t>(m_instrCount));

        if (err != UC_ERR_OK)
        {
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
            DumpFlags();
            DumpSegmentRegisters();
            DumpStack(50);
            SetConsoleColor(6);

            return false;
        }
    }

    return true;
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

void AsmRunner::Restart()
{
    if (!m_uc) return;
    uc_emu_stop(m_uc);
    uintptr_t pc = CurrentPc(m_uc);
    uc_emu_start(m_uc, pc, m_modEnd ? m_modEnd : 0, 0, 0);
}

void AsmRunner::B(intptr_t nOps)
{
    if (!m_uc || nOps == 0) return;
    uintptr_t pc = CurrentPc(m_uc);
    uint64_t count = static_cast<uint64_t>(nOps > 0 ? nOps : -nOps);
    uc_emu_start(m_uc, pc, m_modEnd ? m_modEnd : 0, 0, count);
}

void AsmRunner::DumpRegisters(bool bFull)
{
    if (!m_uc) return;

    auto read = [&](uint32_t reg) -> uintptr_t {
        uintptr_t v = 0;
        uc_reg_read(m_uc, reg, &v);
        if (!m_bX64) v = static_cast<uint32_t>(v);
        return v;
    };

    const uintptr_t ax = read(AxReg());
    const uintptr_t bx = read(BxReg());
    const uintptr_t cx = read(CxReg());
    const uintptr_t dx = read(DxReg());
    const uintptr_t si = read(SiReg());
    const uintptr_t di = read(DiReg());
    const uintptr_t sp = read(SpReg());
    const uintptr_t bp = read(FpReg());
    const uintptr_t pc = read(PcReg());
    const uintptr_t fl = read(FlagsReg());

    auto valueTag = [&](uintptr_t v, bool bDec) -> std::string
    {
        std::ostringstream s;
        s << "[value " << PrintPtrAsciiTag(v, PointerSize(), bDec) << "]";
        return s.str();
    };

    auto readPtr = [&](uintptr_t addr, uintptr_t& out) -> bool
    {
        out = 0;
        if (!m_uc)
            return false;

        if (IsInAddr(addr, m_fsBase, m_fsBase + m_fsSize)) // skip fake tid
            return false;

        if (uc_mem_read(m_uc, addr, &out, static_cast<size_t>(PointerSize())) != UC_ERR_OK)
            return false;

        if (!m_bX64)
            out = static_cast<uint32_t>(out);

        return true;
    };

    auto printReg = [&](const char* regName, uintptr_t v)
    {
        printf("%-12s = 0x%p", regName, (void*)v);

        uintptr_t dref = 0;
        const uintptr_t stackLow = m_stackBase; // 0x00100000
        const uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000); // 0x00200000
        const bool isStack = IsInAddr(v, stackLow, stackHigh);
        const bool hasDref = readPtr(v, dref);
        tFuncNode* sym = FindSymbolByRuntime(v); // iat and symmap

        /*if (FindIATNode(v)) { // can have dummy memory for hooks in uc
            printf(" <- regptr iat %s", FindIATNode(v)->GetAbsoluteName().c_str());
        }
        else*/ if (isStack && hasDref) {
            printf(" <- regptr to stack %s", valueTag(dref, true).c_str());
        }
        else if (isStack && !hasDref) { // when is it? can't read value at stack range?
            printf(" <- regptr to stack [ERROR]");
        }
        else if (sym) { // can have dummy memory for hooks in uc
            printf(" <- regptr sym %s", sym->GetAbsoluteName().c_str());
        }
        else if (hasDref) {
            printf(" <- regptr to mem %s", valueTag(dref, true).c_str());
        }
        else {
            printf(" <- data %s", valueTag(v, true).c_str());
        }

        printf("\n");
    };

    // TODO? RegName
    if (bFull) {
        printf("=== REGISTERS ===\n");
        printReg(m_bX64 ? "RAX" : "EAX", ax);
        printReg(m_bX64 ? "RBX" : "EBX", bx);
        printReg(m_bX64 ? "RCX" : "ECX", cx);
        printReg(m_bX64 ? "RDX" : "EDX", dx);
        printReg(m_bX64 ? "RSI" : "ESI", si);
        printReg(m_bX64 ? "RDI" : "EDI", di);
        printReg(m_bX64 ? "RSP" : "ESP", sp);
        printReg(m_bX64 ? "RBP" : "EBP", bp);
        printReg(m_bX64 ? "RIP" : "EIP", pc);
    } else { // short fmt
        printf("=== REGISTERS ===\n");
        printf("EAX/RAX=%s EBX/RBX=%s ECX/RCX=%s EDX/RDX=%s\n", PrintValue(ax).c_str(), PrintValue(bx).c_str(), PrintValue(cx).c_str(), PrintValue(dx).c_str());
        printf("ESI/RSI=%s EDI/RDI=%s ESP/RSP=%s EBP/RBP=%s\n", PrintValue(si).c_str(), PrintValue(di).c_str(), PrintValue(sp).c_str(), PrintValue(bp).c_str());
        printf("%s=%s\n", m_bX64 ? "RIP" : "EIP", PrintValue(pc).c_str());
    }
}

void AsmRunner::DumpSegmentRegisters()
{
    if (!m_uc) return;

    uint16_t cs = 0, ds = 0, es = 0, ss = 0, fs_sel = 0, gs_sel = 0;
    uint64_t fs_base = 0, gs_base = 0;

    uc_reg_read(m_uc, UC_X86_REG_CS, &cs);
    uc_reg_read(m_uc, UC_X86_REG_DS, &ds);
    uc_reg_read(m_uc, UC_X86_REG_ES, &es);
    uc_reg_read(m_uc, UC_X86_REG_SS, &ss);
    uc_reg_read(m_uc, UC_X86_REG_FS, &fs_sel);
    uc_reg_read(m_uc, UC_X86_REG_GS, &gs_sel);

    printf("=== SEGMENT REGISTERS ===\n");
    printf("CS = 0x%04X  DS = 0x%04X  ES = 0x%04X  SS = 0x%04X  FS = 0x%04X  GS = 0x%04X\n",
        cs, ds, es, ss, fs_sel, gs_sel);

    if (!m_bX64) {
        uc_reg_read(m_uc, UC_X86_REG_FS_BASE, &fs_base);
        Log("FS_BASE = 0x%08X", (uint32_t)fs_base);
    }
    else {
        uc_reg_read(m_uc, UC_X86_REG_FS_BASE, &fs_base);
        uc_reg_read(m_uc, UC_X86_REG_GS_BASE, &gs_base);
        Log("FS_BASE = 0x%016llX", fs_base);
        Log("GS_BASE = 0x%016llX", gs_base);
    }

    if (!m_bX64) {
        const char* mode = "???";
        if (cs == 0x23) mode = "32-bit protected (user)";
        else if (cs == 0x1B) mode = "32-bit protected (kernel)";
        else if (cs == 0x08) mode = "16-bit protected";
        else if (cs == 0x10) mode = "16-bit protected (data)";
        else if (cs == 0x33) mode = "64-bit (long mode)"; // x64
        Log("Current mode (CS): %s", mode);
    }
    else {
        const char* mode = (cs == 0x33) ? "64-bit (long mode)" : "unknown";
        Log("Current mode (CS): %s", mode);
    }

    if (!m_bX64 && cs != 0x23 && cs != 0x1B) {
        Log("[!] WARNING: CS=0x%04X may cause 16-bit emulation. Expected 0x23 or 0x1B.", cs);
    }
}

void AsmRunner::DumpFlags()
{
    if (!m_uc) return;

    uintptr_t eflags = GetRegister(FlagsReg());

    auto flag_status = [&](uintptr_t mask) -> const char* {
        return (eflags & mask) ? "1" : "0";
    };

    auto flag_desc = [&](uintptr_t mask, const char* name, const char* desc_true, const char* desc_false) -> void {
        bool is_set = (eflags & mask) != 0;
        printf("%-4s %-32s %s (%s)\n",
            flag_status(mask),
            name,
            is_set ? desc_true : desc_false,
            is_set ? "Set" : "Clear");
    };

    printf("\n=== EFLAGS (0x%08X) ===\n", static_cast<uint32_t>(eflags));
    printf("%-4s %-32s %s\n", "Bit", "Flag", "Status");
    printf("%-4s %-32s %s\n", "---", "----", "------");

    // base flags
    flag_desc(eFlags::CARRY_FLAG, "CF (Carry Flag)", "Carry/Borrow occurred", "No carry/borrow");
    flag_desc(eFlags::PARITY_FLAG, "PF (Parity Flag)", "Low byte has even parity", "Low byte has odd parity");
    flag_desc(eFlags::AUXILIARY_FLAG, "AF (Auxiliary Carry Flag)", "Auxiliary carry occurred (BCD)", "No auxiliary carry");
    flag_desc(eFlags::ZERO_FLAG, "ZF (Zero Flag)", "Result is zero", "Result is non-zero");
    flag_desc(eFlags::SIGN_FLAG, "SF (Sign Flag)", "Result is negative", "Result is non-negative");
    flag_desc(eFlags::TRAP_FLAG, "TF (Trap Flag)", "Single-step mode enabled", "Single-step mode disabled");
    flag_desc(eFlags::INTERRUPT_FLAG, "IF (Interrupt Flag)", "Interrupts enabled", "Interrupts disabled");
    flag_desc(eFlags::DIRECTION_FLAG, "DF (Direction Flag)", "String operations decrement address", "String operations increment address");
    flag_desc(eFlags::OVERFLOW_FLAG, "OF (Overflow Flag)", "Signed overflow occurred", "No signed overflow");

    // extra
    printf("%-4s %-32s %s\n", "---", "----", "------");
    flag_desc(eFlags::NESTED_TASK,  "NT (Nested Task Flag)", "Nested task", "Not nested task");
    flag_desc(eFlags::RESUME_FLAG,  "RF (Resume Flag)", "Debug exception resume", "No debug resume");
    flag_desc(eFlags::VIRTUAL_8086, "VM (Virtual-8086 Mode)", "Virtual-8086 mode", "Not in Virtual-8086 mode");
    flag_desc(eFlags::ALIGNMENT_CHECK,  "AC (Alignment Check)", "Alignment check enabled", "Alignment check disabled");
    flag_desc(eFlags::VIRTUAL_INTERRUPT, "VIF (Virtual Interrupt Flag)", "Virtual interrupt pending", "No virtual interrupt");
    flag_desc(eFlags::VIRTUAL_INTERRUPT_PENDING, "VIP (Virtual Interrupt Pending)", "Virtual interrupt pending", "No virtual interrupt pending");
    flag_desc(eFlags::ID_FLAG,  "ID (ID Flag)", "CPUID supported", "CPUID not supported");

    uint32_t iopl = ((eflags & eFlags::IOPL_FLAG) >> 12);
    printf("%-4s %-32s %s\n", "---", "----", "------");
    const char* iopl_desc[] = { "Level 0 (Ring 0)", "Level 1", "Level 2", "Level 3 (Ring 3)" };
    printf("IOPL (I/O Privilege Level): %u - %s\n", iopl, iopl_desc[iopl]);

    printf("[FLAGS] ");
    printf("%c ", (eflags & eFlags::CARRY_FLAG) ? 'C' : '-');
    printf("%c ", (eflags & eFlags::PARITY_FLAG) ? 'P' : '-');
    printf("%c ", (eflags & eFlags::AUXILIARY_FLAG) ? 'A' : '-');
    printf("%c ", (eflags & eFlags::ZERO_FLAG) ? 'Z' : '-');
    printf("%c ", (eflags & eFlags::SIGN_FLAG) ? 'S' : '-');
    printf("%c ", (eflags & eFlags::TRAP_FLAG) ? 'T' : '-');
    printf("%c ", (eflags & eFlags::INTERRUPT_FLAG) ? 'I' : '-');
    printf("%c ", (eflags & eFlags::DIRECTION_FLAG) ? 'D' : '-');
    printf("%c ", (eflags & eFlags::OVERFLOW_FLAG) ? 'O' : '-');
    printf(" |  EXTRA: ");
    printf("%c ", (eflags & eFlags::NESTED_TASK) ? 'N' : '-');
    printf("%c ", (eflags & eFlags::RESUME_FLAG) ? 'R' : '-');
    printf("%c ", (eflags & eFlags::VIRTUAL_8086) ? 'V' : '-');
    printf("%c ", (eflags & eFlags::ALIGNMENT_CHECK) ? 'A' : '-');
    printf("%c ", (eflags & eFlags::VIRTUAL_INTERRUPT) ? 'i' : '-');
    printf("%c ", (eflags & eFlags::VIRTUAL_INTERRUPT_PENDING) ? 'p' : '-');
    printf("%c\n", (eflags & eFlags::ID_FLAG) ? 'I' : '-');
}

bool AsmRunner::GetFlag(eFlags flag)
{
    uint32_t eflags = GetRegister(FlagsReg());
    return (eflags & static_cast<uint32_t>(flag)) != 0;
}

void AsmRunner::SetFlag(eFlags flag, bool value)
{
    uint32_t eflags = GetRegister(FlagsReg());
    if (value)
        eflags |= static_cast<uint32_t>(flag);
    else
        eflags &= ~static_cast<uint32_t>(flag);
    SetRegister(FlagsReg(), eflags);
}

void AsmRunner::DumpStack(intptr_t nCount, bool bValNotice)
{
    if (!m_uc || !m_bInitedStack)
        return;

    const uintptr_t sp = CurrentSp(m_uc);
    const uintptr_t fp = GetRegister(FpReg());

    const uintptr_t ptrSize = PointerSize();
    const uintptr_t stackLow = m_stackBase; // 0x00100000
    const uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000); // 0x00200000

    const char* regNameSp = m_bX64 ? "rsp" : "esp";
    const char* regNameFp = m_bX64 ? "rbp" : "ebp";

    auto valueTag = [&](uintptr_t v, bool bDec) -> std::string
    {
        std::ostringstream s;
        s << "[value " << PrintPtrAsciiTag(v, PointerSize(), bDec) << "]";
        return s.str();
    };

    auto readPtr = [&](uintptr_t addr, uintptr_t& out) -> bool
    {
        out = 0;
        if (!m_uc)
            return false;

        if (IsInAddr(addr, m_fsBase, m_fsBase + m_fsSize)) // skip fake tid
            return false;

        if (uc_mem_read(m_uc, addr, &out, static_cast<size_t>(ptrSize)) != UC_ERR_OK)
            return false;

        if (!m_bX64)
            out = static_cast<uint32_t>(out);

        return true;
    };

    intptr_t idx = 0;
    uintptr_t addr = sp;
    printf("=== STACK [0x%p -> 0x%p] ===\n", stackHigh, stackLow);

    while (true)
    {
        if (nCount >= 0 && idx >= nCount)
            break;

        if (addr + ptrSize > stackHigh)
            break;

        uintptr_t val = 0;
        if (uc_mem_read(m_uc, addr, &val, ptrSize) != UC_ERR_OK)
            break;

        if (!m_bX64)
            val = static_cast<uint32_t>(val);

        printf("[%lld] 0x%p: 0x%p", static_cast<long long>(idx), (void*)addr, (void*)val);

        if (addr == sp)
            printf(" <- %s", regNameSp);

        if (nCount == -1 && fp != 0 && addr == fp)
            printf(" <- %s", regNameFp);

        if (bValNotice)
        {
            uintptr_t dref = 0;
            const bool isStack = IsInAddr(val, stackLow, stackHigh);
            const bool hasDref = readPtr(val, dref);
            tFuncNode* sym = FindSymbolByRuntime(val); // iat and symmap

            /*if (FindIATNode(val)) { // can have dummy memory for hooks in uc
                printf(" <- valptr iat %s", FindIATNode(val)->GetAbsoluteName().c_str());
            }
            else*/ if (isStack && hasDref) {
                printf(" <- valptr to stack %s", valueTag(dref, true).c_str());
            }
            else if (isStack && !hasDref) { // when is it? can't read value at stack range?
                printf(" <- valptr to stack [ERROR]");
            }
            else if (sym) { // can have dummy memory for hooks in uc
                printf(" <- valptr sym %s", sym->GetAbsoluteName().c_str());
            }
            else if (hasDref) {
                //printf(" <- possible memptr %s", valueTag(dref, true).c_str());
                printf(" <- valptr to mem %s", valueTag(dref, true).c_str());
            }
            else {
                printf(" <- data %s", valueTag(val, true).c_str());
            }
        }

        printf("\n");

        ++idx;
        addr += ptrSize;
    }
}

std::string AsmRunner::FormatRWHistoryLine(const AsmRunner::tRWHistory& h, bool bValNotice, bool bRVA, bool bSym, bool bShortFmt, bool bDisasm)
{
    const uintptr_t stackLow = m_stackBase;
    const uintptr_t stackHigh = m_stackBase + AlignUp(m_stackSize, 0x1000);

    auto valueTag = [&](uintptr_t v, bool bDec) -> std::string
    {
        std::ostringstream s;
        s << "[value " << PrintPtrAsciiTag(v, PointerSize(), bDec) << "]";
        return s.str();
    };

    auto readPtr = [&](uintptr_t addr, uintptr_t& out) -> bool
    {
        out = 0;
        if (!m_uc)
            return false;

        if (IsInAddr(addr, m_fsBase, m_fsBase + m_fsSize)) // skip fake tid
            return false;

        if (uc_mem_read(m_uc, addr, &out, static_cast<size_t>(PointerSize())) != UC_ERR_OK)
            return false;

        if (!m_bX64)
            out = static_cast<uint32_t>(out);

        return true;
    };

    uintptr_t adref = 0;
    uintptr_t vdref = 0;

    //tFuncNode* pVIatNode = FindIATNode(h.value);
    const bool isStackAddr = IsInAddr(h.addr, stackLow, stackHigh); // isStack операнд лежит в стеке
    const bool isStackValueAddr = IsInAddr(h.value, stackLow, stackHigh); // isStack операнд указывает на стеке
    const bool bIsMemPtr = (!isStackValueAddr && m_uc && h.size == PointerSize() && readPtr(h.value, vdref));
    tFuncNode* SymAddr = FindSymbolByRuntime(h.addr); // iat and symmap
    tFuncNode* SymVal = FindSymbolByRuntime(h.value); // iat and symmap

    // h.addr указатель, возможно на стек // то что где мы читали писали
    // h.value операнд истории, возможно указатель на стек или на память если читается

    std::ostringstream oss;

    if (bShortFmt)
    {
        // 10 77777777 W 0x17854123 0x123   0x233564546 0x10 16 '.' 1  // N IC RW PC PCRVA DATAPTR DATA16 DATA10 DATAASCII SIZE10
        // 12 93017871 R 0x629FA0B1 0x1AFA0B1 0x1EBE64  0x20000000 536870912 '... ' 4
        //oss << n << " " << h.ic << " " << (h.bRead ? 'R' : 'W') << " ";
        //oss << n << " " << formatWithSeparator(h.ic, m_DisasmSepGroup) << " " << (h.bRead ? 'R' : 'W') << " ";
        oss << formatWithSeparator(h.ic, m_DisasmSepGroup) << " " << (h.bRead ? 'R' : 'W') << " ";

        if (bRVA)
        {
            if (m_bDisasmRVA && m_DisasmCustomASLR == 0)
                oss << "0x" << std::hex << std::uppercase << (h.pc - m_modStart) << " ";
            else if (m_bDisasmRVA)
                oss << "0x" << std::hex << std::uppercase << CalcWithCASLR(h.pc) << " 0x" << (h.pc - m_modStart) << " ";
            else
                oss << "0x" << std::hex << std::uppercase << h.pc << " ";
        }
        else
            oss << "0x" << std::hex << std::uppercase << h.pc << " ";

        oss << "0x" << std::hex << std::uppercase << h.addr << " ";

        if (/*pVIatNode ||*/ SymVal || isStackValueAddr || bIsMemPtr)
            oss << PrintValue(h.value) << " "; // don't print dec and ascii for pointers
        else
            oss << PrintPtrAsciiTag(h.value, PointerSize(), true, false) << " ";

        oss << std::dec << h.size;
    }
    else
    {
        //oss << "[" << n << "] [" << h.ic << "] " << (h.bRead ? 'R' : 'W') << "  ";
        //oss << "[" << n << "] [" << formatWithSeparator(h.ic, m_DisasmSepGroup) << "] " << (h.bRead ? 'R' : 'W') << "  ";
        oss << "[" << formatWithSeparator(h.ic, m_DisasmSepGroup) << "] " << (h.bRead ? 'R' : 'W') << "  ";

        if (bRVA)
        {
            if (m_bDisasmRVA && m_DisasmCustomASLR == 0)
                oss << "PC 0x" << std::hex << std::uppercase << (h.pc - m_modStart) << ": ";
            else if (m_bDisasmRVA)
                oss << "PC 0x" << std::hex << std::uppercase << CalcWithCASLR(h.pc) << " ( +0x" << (h.pc - m_modStart) << "): ";
            else
                oss << "PC 0x" << std::hex << std::uppercase << h.pc << ": ";
        }
        else
            oss << "PC 0x" << std::hex << std::uppercase << h.pc << ": ";

        oss << "MEM 0x" << std::hex << std::uppercase << h.addr << " ->";

        if (/*pVIatNode ||*/ SymVal || isStackValueAddr || bIsMemPtr)
            oss << " value " << PrintValue(h.value); // don't print dec and ascii for pointers
        else
            oss << " value " << PrintPtrAsciiTag(h.value, PointerSize(), true);

        oss << " size: " << std::dec << h.size;

        if (bValNotice)
        {
            // метка характеристики где лежали данные
            if (isStackAddr) {
                //if (readPtr(h.addr, adref))
                //    oss << " <- haddr to stack, now its" << valueTag(adref); // h.addr лежит в стеке а там указатель да ещё и рабочий, читаем
                //else // when is it? error
                oss << " <- haddr to stack"; // h.addr просто лежит в стеке
            }
            else if (SymAddr) { // can have dummy memory for hooks in uc
                oss << " <- haddr sym " << SymAddr->GetAbsoluteName();
            }
            else {
                //oss << " <- haddr to mem"; // и так работаем с памятью в history
            }

            // метка характеристики самих данных которые читали
            /*if (pVIatNode) { // can have dummy memory for hooks in uc
                oss << " <- hvalptr iat " << pVIatNode->GetAbsoluteName();
            }
            else*/ if (isStackValueAddr) {
            //uintptr_t vdref = 0;
            //if (readPtr(h.value, vdref))
            //    oss << " <- hvalptr to stack, now its" << valueTag(vdref);
            //else // when is it? error
                oss << " <- hvalptr to stack";
            }
            else if (SymVal) { // can have dummy memory for hooks in uc
                oss << " <- hvalptr sym " << SymVal->GetAbsoluteName();
            }
            else if (bIsMemPtr) { // не в диапазоне стека, возможно указатель на память
                oss << " <- hvalptr to mem, now its" << valueTag(vdref, true);
            }
            else {
                //oss << " <- data"; // и так лог памяти, по умолчанию data
            }

            // символ pc
            if (bSym && IsSymMapInitialised()) {
                std::string sAddr = FormatCurrentSymbolSuffix(h.pc);
                if (!sAddr.empty())
                    oss << " (PC " << sAddr << ")";
            }
        }

        if (bDisasm && !h.disasm.empty())
            oss << " " << h.disasm;
    }

    return oss.str();
}

void AsmRunner::DumpRWHistory(uintptr_t nLimSize, bool bStartLim, bool bRead, bool bWrite, bool bValNotice, bool bRVA, bool bSym, bool bShortFmt, bool bDisasm)
{
    if (m_RWHistory.empty())
    {
        Log("[RW] history is empty");
        return;
    }

    const size_t total = m_RWHistory.size();
    size_t begin = 0;
    size_t end = total;

    if (nLimSize != 0 && nLimSize < total)
    {
        if (bStartLim)
        {
            begin = 0;
            end = static_cast<size_t>(nLimSize);
        }
        else
        {
            begin = total - static_cast<size_t>(nLimSize);
            end = total;
        }
    }

#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    bool bHaveConsole = (hConsole != INVALID_HANDLE_VALUE) &&
        (hConsole != nullptr) &&
        GetConsoleScreenBufferInfo(hConsole, &csbi);
    const WORD savedAttrs = bHaveConsole ? csbi.wAttributes : 0;
#endif

    auto setColor = [&](WORD attrs)
    {
#ifdef _WIN32
        if (bHaveConsole)
            SetConsoleTextAttribute(hConsole, attrs);
#else
        (void)attrs;
#endif
    };

    auto resetColor = [&]()
    {
#ifdef _WIN32
        if (bHaveConsole)
            SetConsoleTextAttribute(hConsole, savedAttrs);
#endif
    };

    for (size_t i = begin; i < end; ++i)
    {
        const auto& h = m_RWHistory[i];
        if ((h.bRead && !bRead) || (!h.bRead && !bWrite))
            continue;

#ifdef _WIN32
        if (h.bRead)
        {
            // жёлтый
            //setColor(isStack ? (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY) : (FOREGROUND_RED | FOREGROUND_GREEN));
            setColor(FOREGROUND_RED | FOREGROUND_GREEN);
        }
        else
        {
            // розовый / magenta
            //setColor(isStack ? (FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY) : (FOREGROUND_RED | FOREGROUND_BLUE));
            setColor(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        }
#endif

        Log("[%d] %s", i, FormatRWHistoryLine(h, bValNotice, bRVA, bSym, bShortFmt, bDisasm).c_str());
        if (bDisasm && !h.disasm.empty())
            Log(""); // \n
        resetColor();
    }

    resetColor();
}

void AsmRunner::DumpRWHistoryFile(std::string fName, uintptr_t nLimSize, bool bStartLim, bool bRead, bool bWrite, bool bValNotice, bool bRVA, bool bSym, bool bShortFmt, bool bDisasm)
{
    if (m_RWHistory.empty())
    {
        Log("[RW] history is empty");
        return;
    }

    std::string outName;
    if (bRead && bWrite)
        outName = fName + "_RW.txt";
    else if (bRead)
        outName = fName + "_R.txt";
    else if (bWrite)
        outName = fName + "_W.txt";
    else
        return;

    std::ofstream out(outName.c_str(), std::ios::out | std::ios::trunc);
    if (!out.is_open())
    {
        Log("[RW] cannot open file: %s", outName.c_str());
        return;
    }

    const size_t total = m_RWHistory.size();
    size_t begin = 0;
    size_t end = total;

    if (nLimSize != 0 && nLimSize < total)
    {
        if (bStartLim)
        {
            begin = 0;
            end = static_cast<size_t>(nLimSize);
        }
        else
        {
            begin = total - static_cast<size_t>(nLimSize);
            end = total;
        }
    }

    for (size_t i = begin; i < end; ++i)
    {
        const auto& h = m_RWHistory[i];
        if ((h.bRead && !bRead) || (!h.bRead && !bWrite))
            continue;

        out << "[" << i << "] " << FormatRWHistoryLine(h, bValNotice, bRVA, bSym, bShortFmt, bDisasm) << '\n';
        if (bDisasm && !h.disasm.empty())
            out << '\n';
    }
}

void AsmRunner::DumpRWHistorySelfModifying(uintptr_t pTextSec, uintptr_t pTextSecEnd)
{
    if (m_RWHistory.empty())
    {
        Log("[RW] history is empty");
        return;
    }

    // Count how many writes are within the specified range
    size_t count = 0;
    for (const auto& h : m_RWHistory)
    {
        if (!h.bRead && IsInAddr(h.addr, pTextSec, pTextSecEnd))
            count++;
    }

    if (count == 0)
    {
        Log("[RW] No self-modifying writes found in range [0x%p, 0x%p)", (void*)pTextSec, (void*)pTextSecEnd);
        return;
    }

    Log("[RW] Self-modifying writes in range [0x%p, 0x%p) (total: %zu)",
        (void*)pTextSec, (void*)pTextSecEnd, count);

#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    bool bHaveConsole = (hConsole != INVALID_HANDLE_VALUE) &&
        (hConsole != nullptr) &&
        GetConsoleScreenBufferInfo(hConsole, &csbi);
    const WORD savedAttrs = bHaveConsole ? csbi.wAttributes : 0;
#endif

    auto setColor = [&](WORD attrs)
    {
#ifdef _WIN32
        if (bHaveConsole)
            SetConsoleTextAttribute(hConsole, attrs);
#else
        (void)attrs;
#endif
    };

    auto resetColor = [&]()
    {
#ifdef _WIN32
        if (bHaveConsole)
            SetConsoleTextAttribute(hConsole, savedAttrs);
#endif
    };

    // Display each matching write with highlighting
    for (size_t i = 0; i < m_RWHistory.size(); ++i)
    {
        const auto& h = m_RWHistory[i];

        // Skip reads and writes outside the range
        if (h.bRead || !IsInAddr(h.addr, pTextSec, pTextSecEnd))
            continue;

        // Highlight self-modifying writes in red
#ifdef _WIN32
        setColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
#endif

        Log("[%zu] SELF-MOD: %s", i,
            FormatRWHistoryLine(h, true, false, true, false, true).c_str());

        if (!h.disasm.empty())
            Log("    disasm: %s\n", h.disasm.c_str());

        resetColor();
    }

    resetColor();
}

void AsmRunner::ClearRWHistory()
{
    m_RWHistory.clear();
}

void AsmRunner::AddDeadzoneIC(uintptr_t startIC, uintptr_t endIC, bool checkPC, bool showEnterMessage, bool skipAll, bool skipJmps, bool skipMem, bool skipOpcode, bool skipTrace, bool skipHistory)
{
    m_deadzonesIC.push_back({ startIC, endIC, checkPC, showEnterMessage, skipJmps, skipMem, skipOpcode, skipAll, skipTrace, skipHistory, false });

    std::sort(m_deadzonesIC.begin(), m_deadzonesIC.end(),
        [](const tDeadzoneIC& a, const tDeadzoneIC& b) { return a.startIC < b.startIC; });

    if (m_bLogRunner)
        Log("[*] DeadzoneIC added: 0x%p - 0x%p (skipAll=%d)", startIC, endIC, skipAll);
}

// try fix qemu сшивание TCG Translation Blocks tb_add_jump chaining translation blocks (TB chaining)  краш на SMC коде
void AsmRunner::InstallDangerNativeCoreFixes()
{ // native core patch for noncrash at SMC
#ifdef AR_NTCORE_PATCH

    if (m_bNativeCorePatchInstalled) {
        if (m_bLogRunner)
            Log("[*] InstallDangerNativeCoreFixes failed! Already Patched!");
        return;
    }

#define AR_COREPTR(pidb) (pidb - 0x56EE0000 + hModule)
        uintptr_t hModule = (uintptr_t)GetModuleHandleA("unicorn.dll");

        if (hModule == 0) {
            if (m_bLogRunner)
                Log("[*] InstallDangerNativeCoreFixes: Failed to find core library!");
            return;
        }

        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hModule;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dos->e_lfanew);
        DWORD moduleSize = nt->OptionalHeader.SizeOfImage;

        {
            if (sizeof(uintptr_t) != 4) {
                if (m_bLogRunner)
                    Log("[*] InstallDangerNativeCoreFixes: Failed to patch non x86!");
                return;
            }
        }

        // отключаем в tb_find tb_add_jump(краш tb_target_set_jmp_target), page_collection_lock page_collection_unlock бо крашит там, а в qemu они и сами это отключили

        // SMC crash (write to 0x0) tb_find -> tb_target_set_jmp_target/tb_set_jmp_target/tb_add_jump/tb_find/cpu_exec  // disable tb_add_jump (inlined), no TranslationBlock link
        //void* jz__tb_find__last_tb = (void*)AR_COREPTR(0x56F3D976); // if (last_tb) See if we can patch the calling TB. tb_add_jump
        void* jz__tb_find__last_tb = (void*)SearchPointerByPattern(hModule, moduleSize, "74 5D 8B 45 38 83 F8 02 72 1A 68");
        // near "n < (sizeof(tb->jmp_list_next) / sizeof(tb->jmp_list_next[0]))"

        //После того как QEMU сгенерировал новый TB(текущий блок), он пытается пропатчить
        //предыдущий TB(last_tb), чтобы тот сразу прыгал на этот новый блок, минуя диспетчер.
        //Это сильно ускоряет выполнение циклов и частых переходов.
        //Когда код пересекает границу страницы, возникает проблема с самомодифицирующимся кодом(SMC).
        //Если мы пропатчим предыдущий TB так, чтобы он прыгал на этот двухстраничный TB, а потом одна из этих страниц будет изменена
        //(например, код перезапишется), то прыжок станет невалидным — он будет указывать на старый, уже недействительный код.
        //Это приведёт к крашу или непредсказуемому поведению.
        //Поэтому разработчики QEMU приняли решение : если текущий TB занимает две страницы, мы не будем патчить предыдущий TB.
        //Вместо этого last_tb обнуляется, и прыжок не добавляется.Это защита от SMC - проблем, связанных с межстраничными блоками.
        //Ограничение размера Translation Block
        //Одна из ключевых проблем SMC в QEMU связана с тем, что один Translation Block(TB) может покрывать несколько страниц памяти.
        //Патчи, исправляющие эту проблему, есть в коде[translate - all.c].Чтобы минимизировать вероятность ошибки, можно принудительно уменьшить размер TB.
        //Где править : В файле accel / tcg / translate - all.c(в старых версиях translate - all.c).
        //Что править : Нужно найти место, где определяется максимальное количество инструкций в блоке(max_insns).
        //Обычно это внутри функции tb_gen_code.Можно попробовать жестко задать 1. // TCG_MAX_INSNS + TCG_MAX_TEMPS
        //TCG_MAX_TEMPS — максимальное количество временных переменных(регистров), которые TCG может использовать при генерации кода.
        //TCG_MAX_INSNS — максимальное количество инструкций гостя в одном Translation Block(TB).
        //Этот параметр определяет, сколько инструкций гостя будет скомпилировано в один блок.
        //Для "чистого runtime" тебе нужно, чтобы блоки были как можно меньше.
        //Если каждый TB содержит всего 1 инструкцию, то при модификации кода ты теряешь максимум 1 инструкцию из кэша.
        //Unicorn / QEMU будет перекомпилировать код каждый раз, когда встречает новую инструкцию.Кэширование практически перестает существовать.
        //Это дает тебе "чистый runtime" — каждая инструкция выполняется как будто в первый раз.
        if (!CheckNT<unsigned char>(jz__tb_find__last_tb, 0x74)) // jz
        {
            if (m_bLogRunner)
                Log("InstallDangerNativeCoreFixes failed! Could not find jump opcode.");
            MboxSTD("InstallDangerNativeCoreFixes failed! Could not find jump opcode.", AR_SNAME);
            return;
        }

        // Lets disable tb_add_jump in tb_find by if (last_tb) cond for prevent native crash in tb_set_jmp_target
        WriteNT<unsigned char>(jz__tb_find__last_tb, 0xEB); // jmp, never call crashly tb_add_jump


        // crash in page_collection_lock read 0xC0000005 page_collection_lock (disabled curr in qemu) // патч от самих qemu #if 0 отключили
        //void* page_collection_lock = (void*)AR_COREPTR(0x56EE99A0); // __cdecl
        void* page_collection_lock = (void*)SearchPointerByPattern(hModule, moduleSize, "83 EC 10 53 55 56 57 6A 08 E8");
        //void* page_collection_unlock = (void*)AR_COREPTR(0x56EE9BE0); // __cdecl
        void* page_collection_unlock = (void*)SearchPointerByPattern(hModule, moduleSize, "56 8B 74 24 08 FF 36 E8");
        // mov eax, 0; ret; // 0xB8 0x00 0x00 0x00 0x00; 0xC3
        // xor eax, eax; ret; // 0x31 0xC0; 0xC3
        // if stdcall like -> ret (sizeof(void*) * Nargs) // remove args from stack
        unsigned int patch_no_func_cdecl = 0x90'C3'C0'31; // little-endian xor eax, eax; ret; nop;

        if (!CheckNT<unsigned char>(page_collection_lock, 0x83)) // sub
        {
            if (m_bLogRunner)
                Log("InstallDangerNativeCoreFixes failed! Could not find page_collection_lock opcode.");
            MboxSTD("InstallDangerNativeCoreFixes failed! Could not find page_collection_lock opcode.", AR_SNAME);
            return;
        }

        WriteNT<unsigned int>(page_collection_lock, patch_no_func_cdecl);

        if (!CheckNT<unsigned char>(page_collection_unlock, 0x56)) // push
        {
            if (m_bLogRunner)
                Log("InstallDangerNativeCoreFixes failed! Could not find page_collection_unlock opcode.");
            MboxSTD("InstallDangerNativeCoreFixes failed! Could not find page_collection_unlock opcode.", AR_SNAME);
            return;
        }

        WriteNT<unsigned int>(page_collection_unlock, patch_no_func_cdecl);


        if (m_bLogRunner)
            Log("[*] InstallDangerNativeCoreFixes: Successfully patched.");

        m_bNativeCorePatchInstalled = true;

#undef AR_COREPTR
#endif
}

// TODO: others ntdll, ws
void AsmRunner::InstallDefaultHooks(HookNotifyCb cb)
{
    m_gstftBaseFt64 = 0;
    m_gstftBaseIc = 0;
    m_gstftSleepDelta = 0;
    m_gstftInited = false;

    const bool bBefore = false;

    // kernel32.dll
    LoadLibraryA("kernel32.dll");
    SetIAT(0, 0, false); // collect temp ENV

    SetAnyJmpHook(FindIATNode("VirtualAlloc", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        { // LPVOID __stdcall VirtualAllocStub(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) // b+8 b+C b+10 b+14
            cb(FindIATNode("VirtualAlloc", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            //printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u\n", (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic);

            // LPVOID VirtualAlloc(
            //   LPVOID lpAddress,         // x86: [ESP+4], x64: RCX
            //   SIZE_T dwSize,            // x86: [ESP+8], x64: RDX
            //   DWORD flAllocationType,   // x86: [ESP+12], x64: R8
            //   DWORD flProtect           // x86: [ESP+16], x64: R9
            // );
            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            uintptr_t lpAddress = 0;
            uintptr_t dwSize = 0;
            uintptr_t flAllocationType = 0;
            uintptr_t flProtect = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(lpAddress, 0, bShouldPopArgs_NoCdecl))        return false;
            if (!self->StackGetArg(dwSize, 1, bShouldPopArgs_NoCdecl))           return false;
            if (!self->StackGetArg(flAllocationType, 2, bShouldPopArgs_NoCdecl)) return false;
            if (!self->StackGetArg(flProtect, 3, bShouldPopArgs_NoCdecl))        return false;

            printf("[VirtualAlloc] lpAddress=0x%p dwSize=0x%p flAllocationType=0x%p flProtect=0x%p ret=0x%p\n",
                (void*)lpAddress, (void*)dwSize, (void*)flAllocationType, (void*)flProtect, (void*)retaddr);

            uintptr_t allocated = 0;

            if (dwSize == 0) {
                allocated = 0;
            }
            else {
                allocated = self->AddMemory(dwSize, UC_PROT_ALL, true);
                if (!allocated)
                {
                    printf("[VirtualAlloc] AddMemory failed for size 0x%p\n", (void*)dwSize);
                    self->SetRegister(self->AxReg(), 0);
                    self->UpdatePC(retaddr, true);
                    return true;
                }

                printf("[VirtualAlloc] allocated 0x%p bytes at 0x%p\n", (void*)dwSize, (void*)allocated);

                if (lpAddress != 0 && lpAddress != allocated)
                {
                    printf("[VirtualAlloc] WARNING: requested specific address 0x%p but allocated at 0x%p\n",
                        (void*)lpAddress, (void*)allocated);
                }
            }

            self->SetRegister(self->AxReg(), allocated);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("VirtualAlloc", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("VirtualFree", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("VirtualFree", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            //printf("[hook] VirtualFree hit: from=0x%p to=0x%p size=%u mnemonic=%u\n", (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic);

            // BOOL VirtualFree(
            //   LPVOID lpAddress,   // x86: [ESP+4], x64: RCX
            //   SIZE_T dwSize,      // x86: [ESP+8], x64: RDX  
            //   DWORD dwFreeType    // x86: [ESP+12], x64: R8
            // );
            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            uintptr_t lpAddress = 0;
            uintptr_t dwSize = 0;
            uintptr_t dwFreeType = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(lpAddress, 0, bShouldPopArgs_NoCdecl))     return false;
            if (!self->StackGetArg(dwSize, 1, bShouldPopArgs_NoCdecl))        return false;
            if (!self->StackGetArg(dwFreeType, 2, bShouldPopArgs_NoCdecl))    return false;

            printf("[VirtualFree] lpAddress=0x%p dwSize=0x%p dwFreeType=0x%p ret=0x%p\n", (void*)lpAddress, (void*)dwSize, (void*)dwFreeType, (void*)retaddr);

            BOOL result = TRUE; // или VirtualFreeStub((LPVOID)lpAddress, dwSize, dwFreeType);

            if (dwFreeType == MEM_RELEASE || dwFreeType == MEM_DECOMMIT)
            {
                if (lpAddress != 0)
                {
                    self->FreeMemory(lpAddress);
                    printf("[VirtualFree] Freeing memory at 0x%p\n", (void*)lpAddress);
                }
            }

            self->SetRegister(self->AxReg(), result);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("VirtualFree", "kernel32.dll")->GetAbsoluteName());

    // TODO: Replace with instruction-based time emulation (CalcTime) instead of caching real time (fake perfomance)
    SetAnyJmpHook(FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            //printf("[hook] GetSystemTimeAsFileTime hit: from=0x%p to=0x%p\n", (void*)from, (void*)to);
            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            uintptr_t lpSystemTimeAsFileTime = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(lpSystemTimeAsFileTime, 0, bShouldPopArgs_NoCdecl)) return false;

            printf("[GetSystemTimeAsFileTime] lpSystemTimeAsFileTime=0x%p\n", (void*)lpSystemTimeAsFileTime);

            FILETIME ft = { 0 };

            // 0 = всегда реальное
            // 1 = первый вызов реальное, дальше кешированное
            // 2 = первый вызов реальное, дальше пересчитанное от instruction count
#define AR_GSTFT_MODE 2
#if AR_GSTFT_MODE == 0
            // всегда реальное время
            GetSystemTimeAsFileTime(&ft);

#elif AR_GSTFT_MODE == 1
        // первый вызов реальное, дальше кешированное
            static FILETIME s_ft = {};
            static bool s_inited = false;

            if (!s_inited)
            {
                GetSystemTimeAsFileTime(&s_ft);
                s_inited = true;
                if (m_bLogRunner)
                    printf("[GetSystemTimeAsFileTime] Static time initialized: 0x%08X%08X\n",
                        s_ft.dwHighDateTime, s_ft.dwLowDateTime);
            }

            ft = s_ft;

#elif AR_GSTFT_MODE == 2
            if (!self->m_gstftInited)
            {
                FILETIME realFt{};
                GetSystemTimeAsFileTime(&realFt);

                ULARGE_INTEGER u{};
                u.LowPart = realFt.dwLowDateTime;
                u.HighPart = realFt.dwHighDateTime;

                self->m_gstftBaseFt64 = u.QuadPart;
                self->m_gstftBaseIc = static_cast<uint64_t>(self->GetInstructionCount());
                self->m_gstftSleepDelta = 0;
                self->m_gstftInited = true;
                if(m_bLogRunner)
                    printf("[GetSystemTimeAsFileTime] Static time initialized: 0x%08X%08X\n",
                        realFt.dwHighDateTime, realFt.dwLowDateTime);
            }

            const uint64_t curIc = static_cast<uint64_t>(self->GetInstructionCount());
            const uint64_t deltaIc = (curIc >= self->m_gstftBaseIc) ? (curIc - self->m_gstftBaseIc) : 0;

            uint64_t deltaFtFromIc = 0;
            if (self->GetInstructionsPerSecond() != 0)
                deltaFtFromIc = self->CalcTime(deltaIc);

            const uint64_t totalFt = self->m_gstftBaseFt64 + deltaFtFromIc + self->m_gstftSleepDelta;
            self->m_gstftSleepDelta = 0;

            ULARGE_INTEGER t{};
            t.QuadPart = totalFt;
            ft.dwLowDateTime = t.LowPart;
            ft.dwHighDateTime = t.HighPart;
#else
#   error "Define AR_GSTFT_MODE as 0, 1 or 2"
#endif

            printf("[GetSystemTimeAsFileTime] result: 0x%08X%08X\n", ft.dwHighDateTime, ft.dwLowDateTime);

            if (lpSystemTimeAsFileTime)
                self->CopyMemory(lpSystemTimeAsFileTime, (uintptr_t)&ft, sizeof(FILETIME));

            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("Sleep", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("Sleep", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            // Получаем аргументы
            uintptr_t dwMilliseconds = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(dwMilliseconds, 0, bShouldPopArgs_NoCdecl)) return false;

            // по идее ещё можно бустануть ic, но это сломает ic хуки
            if (dwMilliseconds != 0)
            {
                // 1 ms = 10,000 * 100ns
                self->m_gstftSleepDelta += static_cast<uint64_t>(dwMilliseconds) * 10'000ULL;
            }

            printf("[Sleep] dwMilliseconds=0x%X\n", dwMilliseconds);

            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("Sleep", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("GetCurrentThreadId", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("GetCurrentThreadId", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            // Получаем аргументы
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

#if 0
            uintptr_t tid = 0;
#else
            uintptr_t tid = static_cast<uintptr_t>(GetCurrentThreadId());
#endif

            self->SetRegister(self->AxReg(), tid);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("GetCurrentThreadId", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("GetProcessHeap", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("GetProcessHeap", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            // Один глобальный heap для процесса.
            static constexpr uintptr_t kFakeProcessHeap = 0x13370000;

            printf("[GetProcessHeap] returning 0x%p ret=0x%p\n",
                (void*)kFakeProcessHeap,
                (void*)retaddr);

            self->SetRegister(self->AxReg(), kFakeProcessHeap);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("GetProcessHeap", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("GetLastError", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("GetLastError", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            uintptr_t retaddr = 0;

            if (bBefore)
            {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr))
            {
                return false;
            }
            uintptr_t err = self->GetFSTEBLastError();
            printf("[GetLastError] -> %u (0x%08X)\n", err, err);

            self->SetRegister(self->AxReg(), err);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("GetLastError", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("SetLastError", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("SetLastError", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t dwErrCode = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(dwErrCode, 0, bShouldPopArgs_NoCdecl))
                return false;

            self->SetTebLastError(dwErrCode);

            printf("[SetLastError] Error=%u (0x%08X)\n", self->GetTebLastError(), self->GetTebLastError());

            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("SetLastError", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("HeapFree", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("HeapFree", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t hHeap = 0;
            uintptr_t dwFlags = 0;
            uintptr_t lpMem = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(hHeap, 0, bShouldPopArgs_NoCdecl))   return false;
            if (!self->StackGetArg(dwFlags, 1, bShouldPopArgs_NoCdecl)) return false;
            if (!self->StackGetArg(lpMem, 2, bShouldPopArgs_NoCdecl))   return false;

            printf("[HeapFree] Heap=0x%p Flags=0x%p Mem=0x%p ret=0x%p\n",
                (void*)hHeap,
                (void*)dwFlags,
                (void*)lpMem,
                (void*)retaddr);

            BOOL result = TRUE;

            if (lpMem)
            {
                self->FreeMemory(lpMem);
                printf("[HeapFree] Freed 0x%p\n", (void*)lpMem);
            }

            self->SetRegister(self->AxReg(), result);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("HeapFree", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("GetCurrentProcess", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("GetCurrentProcess", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

#ifdef _WIN64
            constexpr uintptr_t hProcess = static_cast<uintptr_t>(-1ll);
#else
            constexpr uintptr_t hProcess = static_cast<uintptr_t>(0xFFFFFFFFu);
#endif

            printf("[GetCurrentProcess] -> HANDLE=0x%p\n", (void*)hProcess);

            self->SetRegister(self->AxReg(), hProcess);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("GetCurrentProcess", "kernel32.dll")->GetAbsoluteName());
    
    // used in __report_gsfailure
    SetAnyJmpHook(FindIATNode("IsProcessorFeaturePresent", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("IsProcessorFeaturePresent", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t feature = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(feature, 0, bShouldPopArgs_NoCdecl))
                return false;

            BOOL result = FALSE;

            switch ((DWORD)feature)
            {
                case PF_FLOATING_POINT_PRECISION_ERRATA:
                case PF_FLOATING_POINT_EMULATED:
                    result = FALSE;
                    break;

                case PF_MMX_INSTRUCTIONS_AVAILABLE:
                case PF_XMMI_INSTRUCTIONS_AVAILABLE:        // SSE
                case PF_XMMI64_INSTRUCTIONS_AVAILABLE:      // SSE2
                case PF_SSE3_INSTRUCTIONS_AVAILABLE:
                case PF_COMPARE_EXCHANGE_DOUBLE:
                case PF_COMPARE_EXCHANGE128:
                case PF_RDTSC_INSTRUCTION_AVAILABLE:
                case PF_NX_ENABLED:
                case PF_FASTFAIL_AVAILABLE:
                    result = TRUE;
                    break;

                default:
                    result = FALSE;
                    break;
            }

            printf("[IsProcessorFeaturePresent] Feature=%u -> %d\n",
                (DWORD)feature, result);

            self->SetRegister(self->AxReg(), result);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("IsProcessorFeaturePresent", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("SetUnhandledExceptionFilter", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("SetUnhandledExceptionFilter", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t lpTopLevelExceptionFilter = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(lpTopLevelExceptionFilter, 0, bShouldPopArgs_NoCdecl))
                return false;

            uintptr_t previous = self->m_unhandledExceptionFilter;
            self->m_unhandledExceptionFilter = lpTopLevelExceptionFilter;

            printf("[SetUnhandledExceptionFilter] new=0x%p old=0x%p\n",
                (void*)lpTopLevelExceptionFilter,
                (void*)previous);

            self->SetRegister(self->AxReg(), previous);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("SetUnhandledExceptionFilter", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("UnhandledExceptionFilter", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("UnhandledExceptionFilter", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t pExceptionInfo = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(pExceptionInfo, 0, bShouldPopArgs_NoCdecl))
                return false;

            printf("[UnhandledExceptionFilter] ExceptionInfo=0x%p\n",
                (void*)pExceptionInfo);

#if 1
            if (self->GetUnhandledExceptionFilter())
            {
                uintptr_t handler = self->GetUnhandledExceptionFilter();

                self->StackPush(pExceptionInfo);
                self->StackPush(retaddr);
                self->UpdatePC(handler, true);

                return true;
            }
#else
            // Пока полноценный SEH не реализован.
            // Сообщаем вызывающему, что исключение обработано.
            self->SetRegister(self->AxReg(), EXCEPTION_EXECUTE_HANDLER);
#endif

            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("UnhandledExceptionFilter", "kernel32.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("TerminateProcess", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("TerminateProcess", "kernel32.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t hProcess = 0;
            uintptr_t uExitCode = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(hProcess, 0, bShouldPopArgs_NoCdecl))
                return false;

            if (!self->StackGetArg(uExitCode, 1, bShouldPopArgs_NoCdecl))
                return false;

            printf("[TerminateProcess] Process=0x%p ExitCode=0x%X\n",
                (void*)hProcess,
                (DWORD)uExitCode);

            //self->m_dwExitCode = static_cast<DWORD>(uExitCode);
            //self->m_bProcessTerminated = true;

            //self->ShutdownByHalt(uc);

            self->SetRegister(self->AxReg(), TRUE);

            return true;
        }, this, bBefore, false, FindIATNode("TerminateProcess", "kernel32.dll")->GetAbsoluteName());

    // TODO: SleepEx, NtDelayExecution, WaitForSingleObject


    // ntdll.dll
    LoadLibraryA("ntdll.dll");
    SetIAT(0, 0, false); // collect temp ENV

    SetAnyJmpHook(FindIATNode("RtlInitializeCriticalSection", "ntdll.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("RtlInitializeCriticalSection", "ntdll.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t pCs = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(pCs, 0, bShouldPopArgs_NoCdecl))
                return false;

            printf("[RtlInitializeCriticalSection] CriticalSection=0x%p ret=0x%p\n",
                (void*)pCs, (void*)retaddr);

            self->WriteMemory<uint32_t>(pCs + 0x0, 0);
            self->WriteMemory<int32_t>(pCs + 0x4, -1);
            self->WriteMemory<int32_t>(pCs + 0x8, 0);
            self->WriteMemory<uint32_t>(pCs + 0xC, 0);

            self->SetRegister(self->AxReg(), 0);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("RtlInitializeCriticalSection", "ntdll.dll")->GetAbsoluteName());


    SetAnyJmpHook(FindIATNode("RtlTryEnterCriticalSection", "ntdll.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("RtlTryEnterCriticalSection", "ntdll.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t pCs = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(pCs, 0, bShouldPopArgs_NoCdecl))
                return false;

            DWORD tid = GetCurrentThreadId();

            int32_t lockCount = self->ReadMemory<int32_t>(pCs + 4);
            uint32_t owner = self->ReadMemory<uint32_t>(pCs + 12);

            BOOL result = FALSE;

            if (lockCount == -1)
            {
                self->WriteMemory<int32_t>(pCs + 4, 0);
                self->WriteMemory<int32_t>(pCs + 8, 1);
                self->WriteMemory<uint32_t>(pCs + 12, tid);
                result = TRUE;
            }
            else if (owner == tid)
            {
                auto rec = self->ReadMemory<int32_t>(pCs + 8);
                self->WriteMemory<int32_t>(pCs + 8, rec + 1);
                result = TRUE;
            }

            printf("[RtlTryEnterCriticalSection] CriticalSection=0x%p lock=%d owner=0x%X tid=0x%X result=%d ret=0x%p\n",
                (void*)pCs,
                lockCount,
                owner,
                tid,
                result,
                (void*)retaddr);

            self->SetRegister(self->AxReg(), result);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("RtlTryEnterCriticalSection", "ntdll.dll")->GetAbsoluteName());


    SetAnyJmpHook(FindIATNode("RtlEnterCriticalSection", "ntdll.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("RtlEnterCriticalSection", "ntdll.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t pCs = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(pCs, 0, bShouldPopArgs_NoCdecl))
                return false;

            DWORD tid = GetCurrentThreadId();

            int32_t lockCount = self->ReadMemory<int32_t>(pCs + 4);
            uint32_t owner = self->ReadMemory<uint32_t>(pCs + 12);

            if (lockCount == -1)
            {
                self->WriteMemory<int32_t>(pCs + 4, 0);
                self->WriteMemory<int32_t>(pCs + 8, 1);
                self->WriteMemory<uint32_t>(pCs + 12, tid);
            }
            else if (owner == tid)
            {
                auto rec = self->ReadMemory<int32_t>(pCs + 8);
                self->WriteMemory<int32_t>(pCs + 8, rec + 1);
            }
            else
            {
                printf("[RtlEnterCriticalSection] contention detected, forcing ownership\n");

                self->WriteMemory<int32_t>(pCs + 4, 0);
                self->WriteMemory<int32_t>(pCs + 8, 1);
                self->WriteMemory<uint32_t>(pCs + 12, tid);
            }

            printf("[RtlEnterCriticalSection] CriticalSection=0x%p lock=%d owner=0x%X tid=0x%X ret=0x%p\n",
                (void*)pCs,
                lockCount,
                owner,
                tid,
                (void*)retaddr);

            self->SetRegister(self->AxReg(), 0);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("RtlEnterCriticalSection", "ntdll.dll")->GetAbsoluteName());


    SetAnyJmpHook(FindIATNode("RtlLeaveCriticalSection", "ntdll.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("RtlLeaveCriticalSection", "ntdll.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t pCs = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(pCs, 0, bShouldPopArgs_NoCdecl))
                return false;

            int32_t rec = self->ReadMemory<int32_t>(pCs + 8);

            printf("[RtlLeaveCriticalSection] CriticalSection=0x%p RecursionCount=%d ret=0x%p\n",
                (void*)pCs,
                rec,
                (void*)retaddr);

            if (rec > 1)
            {
                self->WriteMemory<int32_t>(pCs + 8, rec - 1);
            }
            else
            {
                self->WriteMemory<int32_t>(pCs + 8, 0);
                self->WriteMemory<uint32_t>(pCs + 12, 0);
                self->WriteMemory<int32_t>(pCs + 4, -1);
            }

            self->SetRegister(self->AxReg(), 0);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("RtlLeaveCriticalSection", "ntdll.dll")->GetAbsoluteName());


    SetAnyJmpHook(FindIATNode("RtlAllocateHeap", "ntdll.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("RtlAllocateHeap", "ntdll.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t hHeap = 0;
            uintptr_t dwFlags = 0;
            uintptr_t dwBytes = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
            {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr))
            {
                return false;
            }

            if (!self->StackGetArg(hHeap, 0, bShouldPopArgs_NoCdecl))   return false;
            if (!self->StackGetArg(dwFlags, 1, bShouldPopArgs_NoCdecl)) return false;
            if (!self->StackGetArg(dwBytes, 2, bShouldPopArgs_NoCdecl)) return false;

            printf("[RtlAllocateHeap] Heap=0x%p Flags=0x%p Size=0x%p ret=0x%p\n",
                (void*)hHeap,
                (void*)dwFlags,
                (void*)dwBytes,
                (void*)retaddr);

            uintptr_t result = 0;

            if (dwBytes != 0)
            {
                result = self->AddMemory(dwBytes, UC_PROT_ALL, true);

                if ((dwFlags & HEAP_ZERO_MEMORY) && result)
                {
                    std::vector<uint8_t> zero(dwBytes, 0);
                    self->CopyMemory(result, (uintptr_t)zero.data(), zero.size());
                }

                printf("[RtlAllocateHeap] Allocated %zu bytes -> 0x%p\n",
                    (size_t)dwBytes,
                    (void*)result);
            }

            self->SetRegister(self->AxReg(), result);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("RtlAllocateHeap", "ntdll.dll")->GetAbsoluteName());


    SetAnyJmpHook(FindIATNode("RtlFreeHeap", "ntdll.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("RtlFreeHeap", "ntdll.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t hHeap = 0;
            uintptr_t dwFlags = 0;
            uintptr_t lpMem = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
            {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr))
            {
                return false;
            }

            if (!self->StackGetArg(hHeap, 0, bShouldPopArgs_NoCdecl))   return false;
            if (!self->StackGetArg(dwFlags, 1, bShouldPopArgs_NoCdecl)) return false;
            if (!self->StackGetArg(lpMem, 2, bShouldPopArgs_NoCdecl))   return false;

            printf("[RtlFreeHeap] Heap=0x%p Flags=0x%p Mem=0x%p ret=0x%p\n",
                (void*)hHeap,
                (void*)dwFlags,
                (void*)lpMem,
                (void*)retaddr);

            BOOLEAN result = TRUE;

            if (lpMem)
            {
                self->FreeMemory(lpMem);
                printf("[RtlFreeHeap] Freed 0x%p\n", (void*)lpMem);
            }

            self->SetRegister(self->AxReg(), result);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("RtlFreeHeap", "ntdll.dll")->GetAbsoluteName());


    SetAnyJmpHook(FindIATNode("RtlEncodePointer", "ntdll.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("RtlEncodePointer", "ntdll.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t ptr = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(ptr, 0, bShouldPopArgs_NoCdecl))
                return false;

            static auto RtlEncodePointer = reinterpret_cast<PVOID(*)(PVOID)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEncodePointer"));
            uintptr_t encoded = ptr;
            if (RtlEncodePointer)
            {
                encoded = reinterpret_cast<uintptr_t>(RtlEncodePointer(reinterpret_cast<PVOID>(ptr)));
                printf("[RtlEncodePointer] Ptr=0x%p -> 0x%p\n", (void*)ptr, (void*)encoded);
            }
            else {
                printf("[RtlEncodePointer] Function not found, leaving ptr=0x%p\n", (void*)ptr);
            }

            self->SetRegister(self->AxReg(), encoded);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("RtlEncodePointer", "ntdll.dll")->GetAbsoluteName());


    SetAnyJmpHook(FindIATNode("RtlDecodePointer", "ntdll.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("RtlDecodePointer", "ntdll.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t ptr = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(ptr, 0, bShouldPopArgs_NoCdecl))
                return false;

            static auto RtlDecodePointer = reinterpret_cast<PVOID(*)(PVOID)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDecodePointer"));
            uintptr_t decoded = ptr;
            if (RtlDecodePointer)
            {
                decoded = reinterpret_cast<uintptr_t>(RtlDecodePointer(reinterpret_cast<PVOID>(ptr)));
                printf("[RtlDecodePointer] Ptr=0x%p -> 0x%p\n", (void*)ptr, (void*)decoded);
            }
            else {
                printf("[RtlDecodePointer] Function not found, leaving ptr=0x%p\n", (void*)ptr);
            }

            self->SetRegister(self->AxReg(), decoded);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("RtlDecodePointer", "ntdll.dll")->GetAbsoluteName());



    // kernelbase.dll
    LoadLibraryA("kernelbase.dll");
    SetIAT(0, 0, false); // collect temp ENV

    SetAnyJmpHook(FindIATNode("FlsGetValue", "kernelbase.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("FlsGetValue", "kernelbase.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t dwFlsIndex = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(dwFlsIndex, 0, bShouldPopArgs_NoCdecl))
                return false;

            uintptr_t value = self->GetFlsValue(dwFlsIndex);

            printf("[FlsGetValue] Index=%u -> 0x%p\n",
                (DWORD)dwFlsIndex,
                (void*)value);

            self->SetRegister(self->AxReg(), value);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("FlsGetValue", "kernelbase.dll")->GetAbsoluteName());

    SetAnyJmpHook(FindIATNode("FlsSetValue", "kernelbase.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            cb(FindIATNode("FlsSetValue", "kernelbase.dll"));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t dwFlsIndex = 0;
            uintptr_t lpFlsData = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(dwFlsIndex, 0, bShouldPopArgs_NoCdecl))
                return false;

            if (!self->StackGetArg(lpFlsData, 1, bShouldPopArgs_NoCdecl))
                return false;

            self->SetFlsValue(dwFlsIndex, lpFlsData);

            printf("[FlsSetValue] Index=%u Value=0x%p\n",
                (DWORD)dwFlsIndex,
                (void*)lpFlsData);

            self->SetRegister(self->AxReg(), TRUE);
            self->UpdatePC(retaddr, true);

            return true;
        }, this, bBefore, false, FindIATNode("FlsSetValue", "kernelbase.dll")->GetAbsoluteName());



    // Insn
    SetInsnCB(UC_X86_INS_CPUID,
        [&](uc_engine* uc, uintptr_t address, uint32_t size, uintptr_t nUcInsn, ZydisMnemonic mnemonic, void* user_data) -> bool
        {
            (void)address;
            (void)size;
            (void)nUcInsn;
            (void)mnemonic;

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self || !uc)
                return true;

            MboxSTD("Warn! UC_X86_INS_CPUID", AR_SNAME);

            const uint32_t leaf = static_cast<uint32_t>(self->GetRegister(self->AxReg())); // main function ID (leaf)
            const uint32_t subleaf = static_cast<uint32_t>(self->GetRegister(self->CxReg())); // subfunction ID(subleaf)

            uint32_t outEax = 0; // CPUID leaf / return value
            uint32_t outEbx = 0; // "Genu" part of "GenuineIntel"
            uint32_t outEcx = 0; // feature flags or vendor string part 3
            uint32_t outEdx = 0; // feature flags or vendor string part 1

#if defined(_MSC_VER)
            int cpuInfo[4] = {};
            __cpuidex(cpuInfo, static_cast<int>(leaf), static_cast<int>(subleaf));
            outEax = static_cast<uint32_t>(cpuInfo[0]);
            outEbx = static_cast<uint32_t>(cpuInfo[1]);
            outEcx = static_cast<uint32_t>(cpuInfo[2]);
            outEdx = static_cast<uint32_t>(cpuInfo[3]);
#elif defined(__GNUC__) || defined(__clang__)
            unsigned int a = 0, b = 0, c = 0, d = 0;
            __cpuid_count(leaf, subleaf, a, b, c, d);
            outEax = a;
            outEbx = b;
            outEcx = c;
            outEdx = d;
#else
#   error "CPUID hook requires __cpuidex or __cpuid_count"
#endif

            self->SetRegister(self->AxReg(), static_cast<uintptr_t>(outEax));
            self->SetRegister(self->BxReg(), static_cast<uintptr_t>(outEbx));
            self->SetRegister(self->CxReg(), static_cast<uintptr_t>(outEcx));
            self->SetRegister(self->DxReg(), static_cast<uintptr_t>(outEdx));

            // Skip original CPUID execution and move to next instruction.
            self->UpdatePC(address + size, true);

            if (self->m_bLogRunner)
            {
                printf("[CPUID] leaf=0x%08X subleaf=0x%08X -> "
                    "EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\n",
                    leaf, subleaf, outEax, outEbx, outEcx, outEdx);
            }

            return true;
        }, this);
}

bool AsmRunner::ParseModuleSections()
{
    m_sections.clear();

    if (m_modStart == 0)
        return false;

    //__try
    {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_modStart);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_modStart + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        const WORD count = nt->FileHeader.NumberOfSections;

        m_sections.reserve(count);

        for (WORD i = 0; i < count; ++i, ++sec)
        {
            tSection s;

            char nameBuf[IMAGE_SIZEOF_SHORT_NAME + 1]{};
            memcpy(nameBuf, sec->Name, IMAGE_SIZEOF_SHORT_NAME);
            s.name = nameBuf;
            while (!s.name.empty() && s.name.back() == '\0')
                s.name.pop_back();

            s.rva = sec->VirtualAddress;
            s.va = m_modStart + sec->VirtualAddress;
            s.virtualSize = sec->Misc.VirtualSize;
            s.rawSize = sec->SizeOfRawData;
            s.rawPtr = sec->PointerToRawData;
            s.characteristics = sec->Characteristics;

            s.readable = (sec->Characteristics & IMAGE_SCN_MEM_READ) != 0;
            s.writable = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            s.executable = (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

            m_sections.push_back(std::move(s));
        }

        std::sort(m_sections.begin(), m_sections.end(),
            [](const tSection& a, const tSection& b)
            {
                return a.rva < b.rva;
            });
    }
    //__except (EXCEPTION_EXECUTE_HANDLER)
    //{
    //    m_sections.clear();
    //    return false;
    //}

    return !m_sections.empty();
}

void AsmRunner::Dump()
{
    DumpRegisters();
    DumpFlags();
    DumpSegmentRegisters();
    DumpStack(20);
    DisassembleWithZydis(true);
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
        Log("[!] Can't open map: %s", szPath);
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
        e.funcRva = ptr - nSymASLR;
        e.funcSize = sizeVal;
        e.funcName = sName;
        e.moduleBase = m_modStart; // can be 0 when load sym before module
        e.moduleName = m_modName; // can be "" when load sym before module
        m_sym.push_back(e);
    }

    std::sort(m_sym.begin(), m_sym.end(), [](const tFuncNode& a, const tFuncNode& b) { return a.funcRva < b.funcRva; });
    Log("[+] loaded symbols: %zu", m_sym.size());
}

tFuncNode* AsmRunner::GetSymByName(const char* szName)
{
    if (!szName || !*szName) return nullptr;
    for (size_t i = 0; i < m_sym.size(); ++i) {
        if (_stricmp(m_sym[i].funcName.c_str(), szName) == 0) return &m_sym[i];
    }
    return nullptr;
}

tFuncNode* AsmRunner::GetSymByAddr(uintptr_t pAddr) // wrapper
{
    return FindSymbolByRuntime(pAddr);
}

void AsmRunner::SetBreakpointCode(uintptr_t pAddr, OnOpcodeCb cb, void* data, uint32_t size)
{
    if (size == 0 || !cb)
    {
        if (m_bLogRunner)
            Log("[!] SetBreakpointCode: invalid args (addr=0x%p size=%u)", (void*)pAddr, size);
        return;
    }

    uintptr_t existingBpAddr;
    tBpInfo* existingBp = FindBreakpoint(pAddr, true, existingBpAddr);
    if (existingBp && m_bLogRunner) {
        Log("[!] Warning: Breakpoint at 0x%llx overlaps with existing breakpoint at 0x%p (size: %u)", (void*)pAddr, existingBpAddr, existingBp->size);
    }

    if (size != 1 && !m_bUsingBpCodeSizeRange) {
        SetUsingBpCodeSizeRange(true);
        if (m_bLogRunner)
            Log("[*] SetBreakpointCode with wider range, toggle on code bp range check");
    }

    tBpInfo& bp = m_breakpoints[pAddr];
    bp.size = size ? size : 1;
    bp.type = BP_CODE;
    bp.opcodeCb = std::move(cb);
    bp.memCb = nullptr;
    bp.data = data;
    m_bUsingBp = true;
}

#ifdef AR_BP_RANGE
void AsmRunner::SetBreakpointRangeCode(uintptr_t pStart, uintptr_t pEnd, OnOpcodeCb cb, void* data/*, uint32_t size*/)
{
    if (/*pStart == 0 ||*/ pEnd == 0 || pEnd <= pStart || !cb)
    {
        if (m_bLogRunner)
            Log("[!] SetBreakpointRangeCode: invalid args (start=0x%p end=0x%p)", (void*)pStart, (void*)pEnd);
        return;
    }

    //for (uintptr_t addr = pStart; addr <= pEnd; addr += (size ? size : 1))
    for (uintptr_t addr = pStart; addr < pEnd; ++addr)
        SetBreakpointCode(addr, cb, data/*, size*/);
}
#endif

void AsmRunner::SetBreakpointMem(uintptr_t pAddr, uint32_t size, eBpType type, OnMemCb cb, void* data)
{
    if (size == 0 || !cb)
    {
        if (m_bLogRunner)
            Log("[!] SetBreakpointMem: invalid args (addr=0x%p size=%u)", (void*)pAddr, size);
        return;
    }

    if (type != BP_MEM_READ && type != BP_MEM_WRITE && type != BP_MEM_RW)
    {
        if (m_bLogRunner)
            Log("[!] SetBreakpointMem: invalid type=%u at addr=0x%p", (uint32_t)type, (void*)pAddr);
        return;
    }

    uintptr_t existingBpAddr;
    tBpInfo* existingBp = FindBreakpoint(pAddr, true, existingBpAddr);
    if (existingBp && m_bLogRunner) {
        Log("[!] Warning: Memory breakpoint at 0x%p (size: %u) overlaps with existing breakpoint at 0x%p (size: %u)", (void*)pAddr, size, (void*)existingBpAddr, existingBp->size);
    }

    tBpInfo& bp = m_breakpoints[pAddr];
    bp.size = size;
    bp.type = type;
    bp.opcodeCb = nullptr;
    bp.memCb = std::move(cb);
    bp.data = data;
    m_bUsingBp = true;
}

#ifdef AR_BP_RANGE
void AsmRunner::SetBreakpointRangeMem(uintptr_t pStart, uintptr_t pEnd, uint32_t size, eBpType type, OnMemCb cb, void* data)
{
    if (/*pStart == 0 ||*/ pEnd == 0 || pEnd <= pStart || size == 0 || !cb)
    {
        if (m_bLogRunner)
            Log("[!] SetBreakpointRangeMem: invalid args (start=0x%p end=0x%p size=%u)", (void*)pStart, (void*)pEnd, size);
        return;
    }

    if (type != BP_MEM_READ && type != BP_MEM_WRITE && type != BP_MEM_RW)
    {
        if (m_bLogRunner)
            Log("[!] SetBreakpointRangeMem: invalid type=%u (start=0x%p end=0x%p)", (uint32_t)type, (void*)pStart, (void*)pEnd);
        return;
    }

    const uintptr_t step = size ? size : 1;
    for (uintptr_t addr = pStart; addr < pEnd; addr += step)
        SetBreakpointMem(addr, size, type, cb, data);
}
#endif

void AsmRunner::RemoveBreakpoint(uintptr_t pAddr)
{
    m_breakpoints.erase(pAddr);
    if (m_breakpoints.size() == 0)
        m_bUsingBp = false;
}

AsmRunner::tBpInfo* AsmRunner::FindBreakpoint(uintptr_t pAddr, bool bCheckRange, uintptr_t& outBpAddr)
{
    outBpAddr = 0;
    if (!m_bUsingBp)
        return nullptr;

    if (bCheckRange) {
        auto it = m_breakpoints.upper_bound(pAddr); // первый > pAddr
        if (it != m_breakpoints.begin()) {
            --it;
            if (pAddr >= it->first && pAddr - it->first < it->second.size) {
                outBpAddr = it->first;
                return &it->second;
            }
        }
        return nullptr;
    }

    auto it = m_breakpoints.find(pAddr);
    if (it != m_breakpoints.end()) {
        outBpAddr = it->first;
        return &it->second;
    }

    return nullptr;
}

// we set big range(size) for bp to capture ~exec flow, when trigger bp we know 1st priority addr, dupl can be removed // antispam
bool AsmRunner::AdjustBreakpointCodeRangeAt(uintptr_t pAtRt)
{
    uintptr_t bpBase = 0;
    tBpInfo* bp = FindBreakpoint(pAtRt, true, bpBase);
    if (!bp || bp->type != BP_CODE || !bp->UseRange()) return false; // !UseRange its direct bp
    if (bpBase == pAtRt) { // trimEnd
        // Case 1: Trigger is exactly at the base address
        // Just trim the size to 1 (single instruction)
        if (m_bLogRunner) {
            Log("[*] Resized breakpoint at 0x%p from range (+0x%X) to single instruction", (void*)bpBase, bp->size);
        }
        bp->size = 1;
        return true;
    }
    else {
        // Case 2: Trigger is somewhere inside the range (offset > 0)
        // Need to rebase: remove old breakpoint, create new one at exact trigger address

        // Save callback and data before removing
        auto opcodeCb = std::move(bp->opcodeCb);
        uint32_t nOldSize = bp->size;
        void* data = bp->data;

        // Remove the old range breakpoint
        RemoveBreakpoint(bpBase);

        // Create new precise breakpoint at the actual trigger address
        SetBreakpointCode(pAtRt, std::move(opcodeCb), data);

        if (m_bLogRunner) {
            Log("[*] Resized breakpoint: moved from range [0x%p +0x%X] to precise address 0x%p (+0x%p)",
                (void*)bpBase, nOldSize, (void*)pAtRt, (void*)(pAtRt - m_modStart));
        }

        return true;
    }

    return false;
}

void AsmRunner::DumpAllBreakpoints(void)
{
    printf("=== Breakpoints Dump ===\n");
    printf("Total breakpoints: %d\n", m_breakpoints.size());
    printf("m_bUsingBp: %s\n", m_bUsingBp ? "true" : "false");
    printf("m_bUsingBpCodeSizeRange: %s\n", m_bUsingBpCodeSizeRange ? "true" : "false");
    printf("\n");

    for (const auto& pair : m_breakpoints)
    {
        uintptr_t addr = pair.first;
        const tBpInfo& bp = pair.second;

        const char* typeStr = "UNKNOWN";
        switch (bp.type)
        {
        case BP_CODE: typeStr = "CODE"; break;
        case BP_MEM_READ: typeStr = "MEM_READ"; break;
        case BP_MEM_WRITE: typeStr = "MEM_WRITE"; break;
        case BP_MEM_RW: typeStr = "MEM_RW"; break;
        }

        printf("Addr: 0x%p | Type: %s | Size: %u | Data: 0x%p | ", (void*)addr, typeStr, bp.size, bp.data);

        if (bp.opcodeCb)
            printf("OpcodeCb: 0x%p", (void*)(uintptr_t)bp.opcodeCb.target<void(*)()>());
        else if (bp.memCb)
            printf("MemCb: 0x%p", (void*)(uintptr_t)bp.memCb.target<void(*)()>());
        else
            printf("Cb: nullptr");

        printf("\n");
    }
}

void AsmRunner::TraceWriteLine(const std::string& s)
{
    if (!m_trace.file.is_open()) return;
    m_trace.file << s << '\n';
}

void AsmRunner::TraceInstruction(const char* szTraceFileOutPath, uintptr_t pStart, uint32_t nMaxCount, TraceCb cb, bool bPCArray)
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
    m_trace.PCArray = bPCArray;
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

#ifdef AR_IDA_WS

#if 1 // async
bool AsmRunner::InitIDAWS(const std::string& host, uint16_t port)
{
    CloseIDAWS();

    m_ws.bind_addr = host.empty() ? "127.0.0.1" : host;
    m_ws.port = port ? static_cast<int32_t>(port) : 27310;
    m_ws.listen_sock = static_cast<uintptr_t>(INVALID_SOCKET);
    m_ws.client_sock = static_cast<uintptr_t>(INVALID_SOCKET);
    m_ws.running.store(false);
    m_ws.wsa_started = false;

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return false;
    m_ws.wsa_started = true;
#endif

    SOCKET listenSock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET)
    {
        CloseIDAWS();
        return false;
    }
    m_ws.listen_sock = static_cast<uintptr_t>(listenSock);

    int opt = 1;
    ::setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(m_ws.port));

    if (m_ws.bind_addr.empty() || m_ws.bind_addr == "0.0.0.0")
    {
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
        if (inet_pton(AF_INET, m_ws.bind_addr.c_str(), &addr.sin_addr) != 1)
        {
            CloseIDAWS();
            return false;
        }
    }

    if (bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        CloseIDAWS();
        return false;
    }

    if (listen(listenSock, 1) != 0)
    {
        CloseIDAWS();
        return false;
    }

    m_ws.running.store(true);

    m_ws.accept_thread = std::thread([this]()
        {
            auto close_client_locked = [this]()
            {
                if (m_ws.client_sock != static_cast<uintptr_t>(INVALID_SOCKET))
                {
                    SOCKET s = static_cast<SOCKET>(m_ws.client_sock);
                    ::shutdown(s, SD_BOTH);
                    ::closesocket(s);
                    m_ws.client_sock = static_cast<uintptr_t>(INVALID_SOCKET);
                }
            };

            while (m_ws.running.load())
            {
                sockaddr_in clientAddr{};
#ifdef _WIN32
                int clientLen = static_cast<int>(sizeof(clientAddr));
#else
                socklen_t clientLen = static_cast<socklen_t>(sizeof(clientAddr));
#endif
                SOCKET client = ::accept(static_cast<SOCKET>(m_ws.listen_sock),
                    reinterpret_cast<sockaddr*>(&clientAddr),
                    &clientLen);

                if (!m_ws.running.load())
                    break;

                if (client == INVALID_SOCKET)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }

#ifdef _WIN32
                u_long nonBlocking = 1;
                ioctlsocket(client, FIONBIO, &nonBlocking);
#endif

                {
                    std::lock_guard<std::mutex> lk(m_ws.client_mutex);
                    close_client_locked();
                    m_ws.client_sock = static_cast<uintptr_t>(client);
                }

                while (m_ws.running.load())
                {
                    char tmp = 0;
                    int r = ::recv(client, &tmp, 1, MSG_PEEK);

                    if (r == 0)
                        break;

                    if (r < 0)
                    {
#ifdef _WIN32
                        const int err = WSAGetLastError();
                        if (err == WSAEWOULDBLOCK || err == WSAEINTR)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(200));
                            continue;
                        }
#else
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(200));
                            continue;
                        }
#endif
                        break;
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }

                {
                    std::lock_guard<std::mutex> lk(m_ws.client_mutex);
                    if (m_ws.client_sock == static_cast<uintptr_t>(client))
                        close_client_locked();
                    else
                        ::closesocket(client);
                }
            }
        });

    return true;
}

bool AsmRunner::IsIDAWSConnected() const
{
    return m_ws.client_sock != static_cast<uintptr_t>(INVALID_SOCKET);
}

void AsmRunner::WaitIDAWSConnection() const
{
    // Wait until we have a connected client
    while (!IsIDAWSConnected())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Optional: add a small delay after connection is detected
    // to ensure the client is fully ready
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

bool AsmRunner::SendIDAAddr(uintptr_t addr)
{
    if (!IsIDAWSConnected())
        return false;

    SOCKET client = static_cast<SOCKET>(m_ws.client_sock);

    const uint8_t addrSize = static_cast<uint8_t>(sizeof(uintptr_t));
    std::array<uint8_t, 2 + sizeof(uintptr_t)> packet{};
    packet[0] = 'A';
    packet[1] = addrSize;

    for (uint8_t i = 0; i < addrSize; ++i)
        packet[2 + i] = static_cast<uint8_t>((addr >> (i * 8)) & 0xFF);

    size_t sent = 0;
    while (sent < packet.size())
    {
        int s = ::send(client,
            reinterpret_cast<const char*>(packet.data() + sent),
            static_cast<int>(packet.size() - sent),
            0);
        if (s <= 0)
        {
            CloseIDAWS();
            return false;
        }
        sent += static_cast<size_t>(s);
    }

    return true;
}

bool AsmRunner::SendIDAIdcBuff(const std::string& idcBuff)
{
    if (!IsIDAWSConnected())
        return false;

    SOCKET client = static_cast<SOCKET>(m_ws.client_sock);

    const uint32_t len = static_cast<uint32_t>(idcBuff.size());
    std::vector<uint8_t> packet;
    packet.reserve(1 + 4 + len);
    packet.push_back('I');
    packet.push_back(static_cast<uint8_t>(len & 0xFF));
    packet.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    packet.insert(packet.end(), idcBuff.begin(), idcBuff.end());

    size_t sent = 0;
    while (sent < packet.size())
    {
        int s = ::send(client,
            reinterpret_cast<const char*>(packet.data() + sent),
            static_cast<int>(packet.size() - sent),
            0);
        if (s <= 0)
        {
            CloseIDAWS();
            return false;
        }
        sent += static_cast<size_t>(s);
    }

    return true;
}

void AsmRunner::CloseIDAWS()
{
    m_ws.running.store(false);

    if (m_ws.listen_sock != static_cast<uintptr_t>(INVALID_SOCKET))
    {
        SOCKET s = static_cast<SOCKET>(m_ws.listen_sock);
        ::shutdown(s, SD_BOTH);
        ::closesocket(s);
        m_ws.listen_sock = static_cast<uintptr_t>(INVALID_SOCKET);
    }

    {
        std::lock_guard<std::mutex> lk(m_ws.client_mutex);
        if (m_ws.client_sock != static_cast<uintptr_t>(INVALID_SOCKET))
        {
            SOCKET s = static_cast<SOCKET>(m_ws.client_sock);
            ::shutdown(s, SD_BOTH);
            ::closesocket(s);
            m_ws.client_sock = static_cast<uintptr_t>(INVALID_SOCKET);
        }
    }

    if (m_ws.accept_thread.joinable() &&
        m_ws.accept_thread.get_id() != std::this_thread::get_id())
    {
        m_ws.accept_thread.join();
    }

#ifdef _WIN32
    if (m_ws.wsa_started)
    {
        WSACleanup();
        m_ws.wsa_started = false;
    }
#endif
}
#else
bool AsmRunner::InitIDAWS(const std::string& host, uint16_t port)
{
    CloseIDAWS();

    m_ws.bind_addr = host.empty() ? "127.0.0.1" : host;
    m_ws.port = port ? static_cast<int32_t>(port) : 27310;
    m_ws.listen_sock = static_cast<uintptr_t>(INVALID_SOCKET);
    m_ws.client_sock = static_cast<uintptr_t>(INVALID_SOCKET);
    m_ws.running.store(false);
    m_ws.wsa_started = false;

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return false;
    m_ws.wsa_started = true;
#endif

    SOCKET listenSock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET)
    {
        CloseIDAWS();
        return false;
    }
    m_ws.listen_sock = static_cast<uintptr_t>(listenSock);

    int opt = 1;
    ::setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(m_ws.port));

    if (m_ws.bind_addr.empty() || m_ws.bind_addr == "0.0.0.0")
    {
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
        if (inet_pton(AF_INET, m_ws.bind_addr.c_str(), &addr.sin_addr) != 1)
        {
            CloseIDAWS();
            return false;
        }
    }

    if (bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        CloseIDAWS();
        return false;
    }

    if (listen(listenSock, 1) != 0)
    {
        CloseIDAWS();
        return false;
    }

    m_ws.running.store(true);

    m_ws.accept_thread = std::thread([this]()
        {
            auto close_client_locked = [this]()
            {
                if (m_ws.client_sock != static_cast<uintptr_t>(INVALID_SOCKET))
                {
                    SOCKET s = static_cast<SOCKET>(m_ws.client_sock);
                    ::shutdown(s, SD_BOTH);
                    ::closesocket(s);
                    m_ws.client_sock = static_cast<uintptr_t>(INVALID_SOCKET);
                }
            };

            while (m_ws.running.load())
            {
                sockaddr_in clientAddr{};
#ifdef _WIN32
                int clientLen = static_cast<int>(sizeof(clientAddr));
#else
                socklen_t clientLen = static_cast<socklen_t>(sizeof(clientAddr));
#endif
                SOCKET client = ::accept(static_cast<SOCKET>(m_ws.listen_sock),
                    reinterpret_cast<sockaddr*>(&clientAddr),
                    &clientLen);

                if (!m_ws.running.load())
                    break;

                if (client == INVALID_SOCKET)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    continue;
                }

#ifdef _WIN32
                u_long nonBlocking = 1;
                ioctlsocket(client, FIONBIO, &nonBlocking);
#endif

                {
                    std::lock_guard<std::mutex> lk(m_ws.client_mutex);
                    close_client_locked();
                    m_ws.client_sock = static_cast<uintptr_t>(client);
                }

                while (m_ws.running.load())
                {
                    char tmp = 0;
                    int r = ::recv(client, &tmp, 1, MSG_PEEK);

                    if (r == 0)
                        break;

                    if (r < 0)
                    {
#ifdef _WIN32
                        const int err = WSAGetLastError();
                        if (err == WSAEWOULDBLOCK || err == WSAEINTR)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(20));
                            continue;
                        }
#else
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(20));
                            continue;
                        }
#endif
                        break;
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }

                {
                    std::lock_guard<std::mutex> lk(m_ws.client_mutex);
                    if (m_ws.client_sock == static_cast<uintptr_t>(client))
                        close_client_locked();
                    else
                        ::closesocket(client);
                }
            }
        });

    // Ждём, пока new_listener.py реально подключится.
    // После возврата отсюда SendIdcBuff / SendAddr уже можно вызывать сразу.
    constexpr auto kWaitTimeout = std::chrono::seconds(5);
    const auto deadline = std::chrono::steady_clock::now() + kWaitTimeout;

    while (std::chrono::steady_clock::now() < deadline)
    {
        {
            std::lock_guard<std::mutex> lk(m_ws.client_mutex);
            if (m_ws.client_sock != static_cast<uintptr_t>(INVALID_SOCKET))
                return true;
        }

        if (!m_ws.running.load())
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    CloseIDAWS();
    return false;
}

bool AsmRunner::IsIDAWSConnected() const
{
    std::lock_guard<std::mutex> lk(const_cast<std::mutex&>(m_ws.client_mutex));
    return m_ws.client_sock != static_cast<uintptr_t>(INVALID_SOCKET);
}

void AsmRunner::WaitIDAWSConnection() const
{
    // Wait until we have a connected client
    while (!IsIDAWSConnected())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Optional: add a small delay after connection is detected
    // to ensure the client is fully ready
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

bool AsmRunner::SendIDAAddr(uintptr_t addr)
{
    SOCKET client = INVALID_SOCKET;
    {
        std::lock_guard<std::mutex> lk(m_ws.client_mutex);
        if (m_ws.client_sock == static_cast<uintptr_t>(INVALID_SOCKET))
            return false;
        client = static_cast<SOCKET>(m_ws.client_sock);
    }

    const uint8_t addrSize = static_cast<uint8_t>(sizeof(uintptr_t));
    std::array<uint8_t, 2 + sizeof(uintptr_t)> packet{};
    packet[0] = 'A';
    packet[1] = addrSize;

    for (uint8_t i = 0; i < addrSize; ++i)
        packet[2 + i] = static_cast<uint8_t>((addr >> (i * 8)) & 0xFF);

    size_t sent = 0;
    while (sent < packet.size())
    {
        int s = ::send(client,
            reinterpret_cast<const char*>(packet.data() + sent),
            static_cast<int>(packet.size() - sent),
            0);
        if (s <= 0)
        {
            CloseIDAWS();
            return false;
        }
        sent += static_cast<size_t>(s);
    }

    return true;
}

bool AsmRunner::SendIDAIdcBuff(const std::string& idcBuff)
{
    SOCKET client = INVALID_SOCKET;
    {
        std::lock_guard<std::mutex> lk(m_ws.client_mutex);
        if (m_ws.client_sock == static_cast<uintptr_t>(INVALID_SOCKET))
            return false;
        client = static_cast<SOCKET>(m_ws.client_sock);
    }

    const uint32_t len = static_cast<uint32_t>(idcBuff.size());
    std::vector<uint8_t> packet;
    packet.reserve(1 + 4 + len);

    packet.push_back('I');
    packet.push_back(static_cast<uint8_t>(len & 0xFF));
    packet.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    packet.insert(packet.end(), idcBuff.begin(), idcBuff.end());

    size_t sent = 0;
    while (sent < packet.size())
    {
        int s = ::send(client,
            reinterpret_cast<const char*>(packet.data() + sent),
            static_cast<int>(packet.size() - sent),
            0);
        if (s <= 0)
        {
            CloseIDAWS();
            return false;
        }
        sent += static_cast<size_t>(s);
    }

    return true;
}

void AsmRunner::CloseIDAWS()
{
    m_ws.running.store(false);

    if (m_ws.listen_sock != static_cast<uintptr_t>(INVALID_SOCKET))
    {
        SOCKET s = static_cast<SOCKET>(m_ws.listen_sock);
        ::shutdown(s, SD_BOTH);
        ::closesocket(s);
        m_ws.listen_sock = static_cast<uintptr_t>(INVALID_SOCKET);
    }

    {
        std::lock_guard<std::mutex> lk(m_ws.client_mutex);
        if (m_ws.client_sock != static_cast<uintptr_t>(INVALID_SOCKET))
        {
            SOCKET s = static_cast<SOCKET>(m_ws.client_sock);
            ::shutdown(s, SD_BOTH);
            ::closesocket(s);
            m_ws.client_sock = static_cast<uintptr_t>(INVALID_SOCKET);
        }
    }

    if (m_ws.accept_thread.joinable() &&
        m_ws.accept_thread.get_id() != std::this_thread::get_id())
    {
        m_ws.accept_thread.join();
    }

#ifdef _WIN32
    if (m_ws.wsa_started)
    {
        WSACleanup();
        m_ws.wsa_started = false;
    }
#endif
}
#endif

#endif

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

size_t AsmRunner::FileSize(FILE* file)
{
    if (!file) return 0;

    long currentPos = ftell(file);
    if (currentPos == -1) return 0;

    if (fseek(file, 0, SEEK_END) != 0) return 0;
    long size = ftell(file);
    if (size == -1) return 0;

    fseek(file, currentPos, SEEK_SET);
    return static_cast<size_t>(size);
}

size_t AsmRunner::FileRead(FILE* file, void* pb, size_t sz)
{
    if (!file || !pb || sz == 0) return 0;

    return fread(pb, 1, sz, file);
}

void AsmRunner::FileWrite(FILE* file, void* pb, size_t sz)
{
    if (!file || !pb || sz == 0) return;

    fwrite(pb, 1, sz, file);
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

bool AsmRunner::SaveBuffer(const char* filename, uintptr_t pBuff, uintptr_t size)
{
    if (!filename || !pBuff || size == 0) return false;

    FILE* file = FileOpen(filename, "wb");
    if (!file) return false;

    bool success = true;
    size_t written = fwrite(reinterpret_cast<const void*>(pBuff), 1, size, file);

    if (written != size) {
        success = false;
    }

    FileClose(file);
    return success;
}

void* AsmRunner::LoadBuffer(const char* filename, uintptr_t& size)
{
    if (!filename) return nullptr;
    FILE* file = FileOpen(filename, "rb");
    if (!file) return nullptr;
    size = FileSize(file);
    char* buffer = (char*)malloc(size);
    size_t bytesRead = FileRead(file, buffer, size);
    FileClose(file);
    return buffer;
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

    const size_t cmpSize = std::min(a.data.size(), b.data.size());

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

#ifdef AR_DFT
// -----------------------------------------------------------------------
// Data trace — tree-based data-flow tracker
// -----------------------------------------------------------------------

AsmRunner::tDataTrace* AsmRunner::_FindDataTrace(DataTraceHandle h)
{
    for (auto& dt : m_dataTraces)
        if (dt.id == h) return &dt;
    return nullptr;
}

AsmRunner::tDataTraceNode* AsmRunner::_AllocNode(tDataTrace& dt, tDataTraceNode* parent)
{
    auto up = std::make_unique<tDataTraceNode>();
    tDataTraceNode* raw = up.get();
    raw->parent = parent;
    if (parent)
        parent->children.push_back(raw);
    dt.pool.push_back(std::move(up));
    return raw;
}

bool AsmRunner::_ReadNodeCurrentValue(uc_engine* uc, const tDataTraceNode* node,
    uintptr_t& outVal, std::vector<uint8_t>* outBytes) const
{
    outVal = 0;
    if (!uc || !node) return false;

    if (node->kind == tDataTraceNode::eKind::Reg)
    {
        return ReadZydisRegisterValue(uc, node->reg, outVal);
    }
    else // Mem
    {
        if (node->opSz == 0) return false;
        std::vector<uint8_t> bytes;
        if (!ReadBytes(uc, static_cast<uint64_t>(node->ptr), node->opSz, bytes)) return false;
        const uint32_t lim = std::min((uint32_t)bytes.size(), (uint32_t)sizeof(uintptr_t));
        for (uint32_t i = 0; i < lim; ++i)
            outVal |= (uintptr_t)bytes[i] << (i * 8);
        if (outBytes) *outBytes = std::move(bytes);
        return true;
    }
}

void AsmRunner::_FillPendingAfterValues(uc_engine* uc)
{
    for (auto* node : m_pendingAfterNodes)
    {
        node->bNeedAfter = false;
        _ReadNodeCurrentValue(uc, node, node->valAfter, &node->dataBytesAfter);
    }
    m_pendingAfterNodes.clear();
}

// -----------------------------------------------------------------------

AsmRunner::DataTraceHandle AsmRunner::StartDataTrace(uint32_t reg)
{
    const ZydisRegister canonical = _CanonicalReg(static_cast<ZydisRegister>(reg));

    tDataTrace dt;
    dt.id = m_nextDataTraceId++;
    dt.active = true;

    tDataTraceNode* root = _AllocNode(dt, nullptr);
    root->kind = tDataTraceNode::eKind::Reg;
    root->reg = canonical;
    root->opSz = m_bX64 ? 8u : 4u;
    root->bActive = true;
    if (m_uc) ReadZydisRegisterValue(m_uc, canonical, root->valBefore);

    dt.root = root;
    dt.activeLeaves.push_back(root);

    m_dataTraces.push_back(std::move(dt));
    return m_dataTraces.back().id;
}

AsmRunner::DataTraceHandle AsmRunner::StartDataTrace(uintptr_t ptr, uintptr_t size)
{
    tDataTrace dt;
    dt.id = m_nextDataTraceId++;
    dt.active = true;

    tDataTraceNode* root = _AllocNode(dt, nullptr);
    root->kind = tDataTraceNode::eKind::Mem;
    root->ptr = ptr;
    root->opSz = static_cast<uint32_t>(size);
    root->bActive = true;
    if (m_uc)
        _ReadNodeCurrentValue(m_uc, root, root->valBefore, &root->dataBytesBefore);

    dt.root = root;
    dt.activeLeaves.push_back(root);

    m_dataTraces.push_back(std::move(dt));
    return m_dataTraces.back().id;
}

// -----------------------------------------------------------------------

void AsmRunner::_CollectBranches(tDataTraceNode* node,
    std::vector<tDataTraceNode*>& cur,
    std::vector<std::vector<tDataTraceNode*>>& out)
{
    if (!node) return;
    cur.push_back(node);
    if (node->children.empty())
        out.push_back(cur);
    else
        for (auto* child : node->children)
            _CollectBranches(child, cur, out);
    cur.pop_back();
}

void AsmRunner::_SaveBranch(FILE* f, const std::vector<tDataTraceNode*>& path) const
{
    for (size_t i = 0; i < path.size(); ++i)
    {
        const auto* n = path[i];
        std::ostringstream oss;
        oss << "[" << i << "] ";

        if (n->kind == tDataTraceNode::eKind::Reg)
        {
            const char* rn = ZydisRegisterGetString(n->reg);
            oss << (rn ? rn : "?REG");
        }
        else
        {
            oss << "[0x" << std::hex << std::uppercase << n->ptr
                << "+" << std::dec << n->opSz << "b]";
        }

        if (!n->disasm.empty())
            oss << " | ic=" << n->ic
            << " 0x" << std::hex << std::uppercase << n->instrAddr
            << " " << n->disasm;

        oss << " | before=0x" << std::hex << std::uppercase << n->valBefore
            << " after=0x" << n->valAfter;

        if (!n->bActive)    oss << " [TERMINATED]";
        if (n->bNeedAfter)  oss << " [PENDING_AFTER]";

        FileAdd(f, "%s\n", oss.str().c_str());
    }
}

void AsmRunner::SaveDataTrace(DataTraceHandle h, const char* dir)
{
    SaveDataTrace(h, dir, nullptr, false);
}

void AsmRunner::SaveDataTrace(DataTraceHandle h, const char* dir, DTCompCB cb, bool bEndsWith)
{
    tDataTrace* dt = _FindDataTrace(h);
    if (!dt) { Log("SaveDataTrace: handle %u not found", h); return; }
    if (!dt->root) { Log("SaveDataTrace: handle %u has no root", h); return; }

    CreateDirectoryA(dir, nullptr);

    std::string dirStr = dir;
    if (!dirStr.empty() && dirStr.back() != '\\' && dirStr.back() != '/')
        dirStr += '\\';

    std::vector<tDataTraceNode*> cur;
    std::vector<std::vector<tDataTraceNode*>> branches;
    _CollectBranches(dt->root, cur, branches);

    size_t saved = 0;
    for (const auto& path : branches)
    {
        if (path.empty()) continue;

        bool match = true;
        if (cb)
        {
            match = false;
            if (bEndsWith)
            {
                match = cb(path.back());
            }
            else
            {
                for (const auto* n : path)
                    if (cb(n)) { match = true; break; }
            }
        }

        if (!match) continue;

        std::string fname = dirStr + "branch_" + std::to_string(saved++) + ".txt";
        FILE* f = FileOpen(fname.c_str());
        if (!f) { Log("SaveDataTrace: cannot open %s", fname.c_str()); continue; }
        _SaveBranch(f, path);
        FileClose(f);
    }

    Log("SaveDataTrace[%u]: %zu/%zu branches -> %s", h, saved, branches.size(), dir);
}

void AsmRunner::RemoveDataTrace(DataTraceHandle h)
{
    auto it = std::find_if(m_dataTraces.begin(), m_dataTraces.end(),
        [h](const tDataTrace& d) { return d.id == h; });
    if (it == m_dataTraces.end()) { Log("RemoveDataTrace: handle %u not found", h); return; }

    // Remove pending fill entries that belong to this trace's pool
    const auto& pool = it->pool;
    m_pendingAfterNodes.erase(
        std::remove_if(m_pendingAfterNodes.begin(), m_pendingAfterNodes.end(),
            [&pool](const tDataTraceNode* n) {
                for (const auto& up : pool)
                    if (up.get() == n) return true;
                return false;
            }),
        m_pendingAfterNodes.end());

    m_dataTraces.erase(it);
}

// -----------------------------------------------------------------------

void AsmRunner::_OnOpcodeOperands(uc_engine* uc, uintptr_t curPc, uint64_t ic,
    const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* operands,
    const std::vector<tDTResolvedOp>& dst, const std::vector<tDTResolvedOp>& src,
    const std::string& disasm)
{
    for (auto& dt : m_dataTraces)
    {
        if (!dt.active) continue;

        // Snapshot the leaf list — we mutate it below
        std::vector<tDataTraceNode*> leaves = dt.activeLeaves;
        std::vector<tDataTraceNode*> toRemove, toAdd;

        for (auto* leaf : leaves)
        {
            if (!leaf->bActive) continue;

            // -- Determine if this leaf's operand appears in src / dst --

            auto matchesLeaf = [&](const tDTResolvedOp& op) -> bool {
                if (leaf->kind == tDataTraceNode::eKind::Reg)
                    return op.type == ZYDIS_OPERAND_TYPE_REGISTER && op.reg == leaf->reg;
                // Mem: any byte of the access overlaps our tracked range
                if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) return false;
                const uintptr_t opEnd = op.addr + op.sz;
                const uintptr_t leafEnd = leaf->ptr + leaf->opSz;
                return op.addr < leafEnd&& opEnd > leaf->ptr;
            };

            bool leafInSrc = false;
            bool leafInDst = false;
            for (const auto& op : src) if (matchesLeaf(op)) { leafInSrc = true; break; }
            for (const auto& op : dst) if (matchesLeaf(op)) { leafInDst = true; break; }

            // Heuristic: tracked reg used as base/index in a memory operand (implicit read).
            // Covers:  movzx eax, byte ptr [sbox + eax]
            //          mov eax, [table + eax*4]
            bool leafAsAddrIdx = false;
            if (leaf->kind == tDataTraceNode::eKind::Reg && !leafInSrc)
            {
                for (uint8_t i = 0; i < instr.operand_count_visible && !leafAsAddrIdx; ++i)
                {
                    const auto& op = operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                    {
                        if (_CanonicalReg(op.mem.base) == leaf->reg) leafAsAddrIdx = true;
                        if (_CanonicalReg(op.mem.index) == leaf->reg) leafAsAddrIdx = true;
                    }
                }
            }

            const bool effectiveRead = leafInSrc || leafAsAddrIdx;

            if (!effectiveRead && !leafInDst)
                continue; // instruction doesn't touch this tracked operand

            // ------------------------------------------------------------------
            // Case A: self-modify  (add eax, k; xor eax, k; inc eax; sbox load)
            // The operand is both read (or used as addr-index) AND written.
            // Branch continues with a new child for the same operand after exec.
            // ------------------------------------------------------------------
            if (effectiveRead && leafInDst)
            {
                tDataTraceNode* child = _AllocNode(dt, leaf);
                child->kind = leaf->kind;
                child->reg = leaf->reg;
                child->ptr = leaf->ptr;
                child->opSz = leaf->opSz;
                child->disasm = disasm;
                child->instrAddr = curPc;
                child->ic = ic;
                child->bActive = true;
                child->bNeedAfter = true;
                _ReadNodeCurrentValue(uc, child, child->valBefore, &child->dataBytesBefore);

                leaf->bActive = false;
                toRemove.push_back(leaf);
                toAdd.push_back(child);
                m_pendingAfterNodes.push_back(child);
            }
            // ------------------------------------------------------------------
            // Case B: pure read — value flows to destination(s).
            // e.g.  mov ecx, eax   /  mov [out], eax  /  push eax
            // The source leaf is unchanged; spawn child branches for each dst.
            // ------------------------------------------------------------------
            else if (effectiveRead && !leafInDst)
            {
                for (const auto& dop : dst)
                {
                    if (dop.type != ZYDIS_OPERAND_TYPE_REGISTER &&
                        dop.type != ZYDIS_OPERAND_TYPE_MEMORY)
                        continue;
                    if (matchesLeaf(dop)) continue; // dst == src (already handled)

                    tDataTraceNode* child = _AllocNode(dt, leaf);
                    if (dop.type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        child->kind = tDataTraceNode::eKind::Reg;
                        child->reg = dop.reg;
                        child->opSz = dop.sz;
                    }
                    else
                    {
                        child->kind = tDataTraceNode::eKind::Mem;
                        child->ptr = dop.addr;
                        child->opSz = dop.sz;
                    }
                    child->disasm = disasm;
                    child->instrAddr = curPc;
                    child->ic = ic;
                    child->bActive = true;
                    child->bNeedAfter = true;
                    child->valBefore = dop.val;
                    if (!dop.bytes.empty()) child->dataBytesBefore = dop.bytes;

                    toAdd.push_back(child);
                    m_pendingAfterNodes.push_back(child);
                }
                // Source leaf stays active — its location and value are unchanged.
            }
            // ------------------------------------------------------------------
            // Case C: pure overwrite — mov eax, imm / mov eax, [unrelated_ptr].
            // The original value is gone. Branch terminates.
            // We still record the node so valAfter shows what was written.
            // ------------------------------------------------------------------
            else // !effectiveRead && leafInDst
            {
                tDataTraceNode* child = _AllocNode(dt, leaf);
                child->kind = leaf->kind;
                child->reg = leaf->reg;
                child->ptr = leaf->ptr;
                child->opSz = leaf->opSz;
                child->disasm = disasm;
                child->instrAddr = curPc;
                child->ic = ic;
                child->bActive = false; // BRANCH TERMINATED
                child->bNeedAfter = true;
                _ReadNodeCurrentValue(uc, child, child->valBefore, &child->dataBytesBefore);

                leaf->bActive = false;
                toRemove.push_back(leaf);
                m_pendingAfterNodes.push_back(child);
                // child NOT added to activeLeaves
            }
        } // for each leaf

        // Apply list mutations
        for (auto* r : toRemove)
        {
            auto it = std::find(dt.activeLeaves.begin(), dt.activeLeaves.end(), r);
            if (it != dt.activeLeaves.end()) dt.activeLeaves.erase(it);
        }
        for (auto* a : toAdd)
            dt.activeLeaves.push_back(a);
    }
}
#endif

std::vector<AsmRunner::tScanWindowResult> AsmRunner::ScanWindow(uintptr_t pStart, uintptr_t pEnd, std::vector<AsmRunner::tScanPatternNode> patterns,
    const std::vector<AsmRunner::tScanNeed>& need, uintptr_t nWindowSize, bool bAdjustWindow, bool bDisplayProgress)
{
    std::vector<tScanWindowResult> result;

    if (pStart == 0 || pEnd == 0 || pStart >= pEnd || nWindowSize == 0)
        return result;

    if ((pEnd - pStart + 1) < nWindowSize)
        return result;

    std::sort(patterns.begin(), patterns.end(),
        [](const tScanPatternNode& a, const tScanPatternNode& b)
        {
            return a.bytesAsm < b.bytesAsm;
        });

    auto last = std::unique(patterns.begin(), patterns.end(),
        [](const tScanPatternNode& a, const tScanPatternNode& b)
        {
            return a.bytesAsm == b.bytesAsm;
        });
    patterns.erase(last, patterns.end());

    size_t kindCount = 0;
    for (const auto& p : patterns)
    {
        if (p.type >= 0)
            kindCount = std::max(kindCount, (size_t)p.type + 1);
    }
    for (const auto& req : need)
    {
        if (req.type >= 0)
            kindCount = std::max(kindCount, (size_t)req.type + 1);
    }

    if (kindCount == 0)
        return result;

    std::vector<std::vector<const tScanPatternNode*>> byType(kindCount);
    for (const auto& p : patterns)
    {
        if (p.type >= 0 && (size_t)p.type < kindCount)
            byType[(size_t)p.type].push_back(&p);
    }

    auto ValidateWindow =
        [&](uintptr_t ws, uintptr_t we, uintptr_t& firstHit, uintptr_t& advanceTo, std::vector<size_t>& foundCounts) -> bool
    {
        foundCounts.assign(kindCount, 0);
        firstHit = 0;
        advanceTo = ws + 1;

        uintptr_t minPos = std::numeric_limits<uintptr_t>::max();

        for (const auto& req : need)
        {
            if (req.type < 0 || (size_t)req.type >= kindCount)
                continue;

            const size_t t = (size_t)req.type;
            std::vector<uintptr_t> ends;

            for (const auto* pat : byType[t])
            {
                auto hits = ScanBytes(ws, we, pat->bytesAsm);
                if (hits.empty())
                    continue;

                foundCounts[t] += hits.size();

                for (uintptr_t h : hits)
                {
                    if (h < minPos)
                        minPos = h;

                    ends.push_back(h + pat->bytesAsm.size());
                }
            }

            if (foundCounts[t] < req.count)
                return false;

            std::sort(ends.begin(), ends.end());

            // конец последнего обязательного совпадения для этого type
            const uintptr_t typeAdvanceTo = ends[req.count - 1];
            if (typeAdvanceTo > advanceTo)
                advanceTo = typeAdvanceTo;
        }

        firstHit = (minPos == std::numeric_limits<uintptr_t>::max()) ? ws : minPos;
        return true;
    };

    auto UpdateProgress = [](uintptr_t winStart, uintptr_t scanned, uintptr_t total, uintptr_t found, bool force = false)
    {
        static uintptr_t lastUpdate = 0;

        if (total == 0)
            return;

        if (scanned < lastUpdate)
            lastUpdate = 0;

        if (!force && (scanned - lastUpdate) < 1000 && scanned < total)
            return;

        lastUpdate = scanned;
        int percent = (int)((scanned * 100) / total);
        int barWidth = 50;
        int pos = (barWidth * percent) / 100;

        printf("\r[");
        for (int i = 0; i < barWidth; ++i)
        {
            if (i < pos) printf("=");
            else if (i == pos && percent < 100) printf(">");
            else printf(" ");
        }
        printf("] %d%% 0x%p (%zu / %zu windows, found: %zu)", percent, winStart, (size_t)scanned, (size_t)total, (size_t)found);
        fflush(stdout);
    };

    uintptr_t totalWindows = 0;
    uintptr_t scannedWindows = 0;
    uintptr_t foundWindows = 0;

    const uintptr_t lastStart = pEnd - nWindowSize + 1;
    totalWindows = (lastStart - pStart + 1);

    for (uintptr_t winStart = pStart; winStart <= lastStart; )
    {
        const uintptr_t winEnd = winStart + nWindowSize - 1;

        uintptr_t firstHit = 0;
        uintptr_t advanceTo = 0;
        std::vector<size_t> foundCounts;

        if (ValidateWindow(winStart, winEnd, firstHit, advanceTo, foundCounts))
        {
            foundWindows++;

            tScanWindowResult r;
            r.address = bAdjustWindow ? firstHit : winStart;
            r.counts = foundCounts;
            result.push_back(r);

            if (bAdjustWindow)
                winStart = (advanceTo > winStart) ? advanceTo : (winStart + 1);
            else
                winStart += nWindowSize;
        }
        else
        {
            ++winStart;
        }

        scannedWindows++;

        if (bDisplayProgress)
            UpdateProgress(winStart, scannedWindows, totalWindows, foundWindows);
    }

    if (bDisplayProgress)
    {
        UpdateProgress(lastStart, totalWindows, totalWindows, foundWindows, true);
        printf("\n");
    }

    return result;
}

#if 0 // big log
std::vector<AsmRunner::tScanWindowResult> AsmRunner::ScanWindow(uintptr_t pStart, uintptr_t pEnd, std::vector<AsmRunner::tScanPatternNode> patterns,
    const std::vector<AsmRunner::tScanNeed>& need, uintptr_t nWindowSize, bool bAdjustWindow, bool bDisplayProgress)
{
    std::vector<tScanWindowResult> result;

    if (pStart == 0 || pEnd == 0 || pStart >= pEnd || nWindowSize == 0)
        return result;

    if ((pEnd - pStart + 1) < nWindowSize)
        return result;

    // Открываем файл для записи
    std::ofstream logFile("scan_log.txt", std::ios::out | std::ios::trunc);
    logFile << "SCAN RANGE start=0x" << std::hex << pStart
        << " end=0x" << pEnd
        << " size=0x" << (pEnd - pStart)
        << " lastStart=0x" << (pEnd - nWindowSize + 1)
        << " winSize=0x" << nWindowSize
        << "\n";

    std::sort(patterns.begin(), patterns.end(),
        [](const tScanPatternNode& a, const tScanPatternNode& b)
        {
            return a.bytesAsm < b.bytesAsm;
        });

    auto last = std::unique(patterns.begin(), patterns.end(),
        [](const tScanPatternNode& a, const tScanPatternNode& b)
        {
            return a.bytesAsm == b.bytesAsm;
        });
    patterns.erase(last, patterns.end());

    size_t kindCount = 0;
    for (const auto& p : patterns)
    {
        if (p.type >= 0)
            kindCount = std::max(kindCount, (size_t)p.type + 1);
    }
    for (const auto& req : need)
    {
        if (req.type >= 0)
            kindCount = std::max(kindCount, (size_t)req.type + 1);
    }

    if (kindCount == 0)
        return result;

    std::vector<std::vector<const tScanPatternNode*>> byType(kindCount);
    for (const auto& p : patterns)
    {
        if (p.type >= 0 && (size_t)p.type < kindCount)
            byType[(size_t)p.type].push_back(&p);
    }

    auto ValidateWindow =
        [&](uintptr_t ws, uintptr_t we, uintptr_t& firstHit, uintptr_t& advanceTo, std::vector<size_t>& foundCounts) -> bool
    {
        foundCounts.assign(kindCount, 0);
        firstHit = 0;
        advanceTo = ws + 1;

        uintptr_t minPos = std::numeric_limits<uintptr_t>::max();

        for (const auto& req : need)
        {
            if (req.type < 0 || (size_t)req.type >= kindCount)
                continue;

            const size_t t = (size_t)req.type;
            std::vector<uintptr_t> ends;

            for (const auto* pat : byType[t])
            {
                auto hits = ScanBytes(ws, we, pat->bytesAsm);
                if (hits.empty())
                    continue;

                foundCounts[t] += hits.size();

                for (uintptr_t h : hits)
                {
                    if (h < minPos)
                        minPos = h;

                    ends.push_back(h + pat->bytesAsm.size());
                }
            }

            if (foundCounts[t] < req.count)
                return false;

            std::sort(ends.begin(), ends.end());

            // конец последнего обязательного совпадения для этого type
            const uintptr_t typeAdvanceTo = ends[req.count - 1];
            if (typeAdvanceTo > advanceTo)
                advanceTo = typeAdvanceTo;
        }

        firstHit = (minPos == std::numeric_limits<uintptr_t>::max()) ? ws : minPos;
        return true;
    };

    auto UpdateProgress = [](uintptr_t winStart, uintptr_t scanned, uintptr_t total, uintptr_t found, bool force = false)
    {
        static uintptr_t lastUpdate = 0;

        if (total == 0)
            return;

        if (scanned < lastUpdate)
            lastUpdate = 0;

        if (!force && (scanned - lastUpdate) < 1000 && scanned < total)
            return;

        lastUpdate = scanned;
        int percent = (int)((scanned * 100) / total);
        int barWidth = 50;
        int pos = (barWidth * percent) / 100;

        printf("\r[");
        for (int i = 0; i < barWidth; ++i)
        {
            if (i < pos) printf("=");
            else if (i == pos && percent < 100) printf(">");
            else printf(" ");
        }
        printf("] %d%% 0x%p (%zu / %zu windows, found: %zu)", percent, winStart, (size_t)scanned, (size_t)total, (size_t)found);
        fflush(stdout);
    };

    uintptr_t totalWindows = 0;
    uintptr_t scannedWindows = 0;
    uintptr_t foundWindows = 0;

    const uintptr_t lastStart = pEnd - nWindowSize + 1;
    totalWindows = (lastStart - pStart + 1);

    uintptr_t lastProcessedEnd = pStart;

    for (uintptr_t winStart = pStart; winStart <= lastStart; )
    {
        const uintptr_t winEnd = winStart + nWindowSize - 1;

        uintptr_t firstHit = 0;
        uintptr_t advanceTo = 0;
        std::vector<size_t> foundCounts;

        if (ValidateWindow(winStart, winEnd, firstHit, advanceTo, foundCounts))
        {
            foundWindows++;

            tScanWindowResult r;
            r.address = bAdjustWindow ? firstHit : winStart;
            r.counts = foundCounts;
            result.push_back(r);

            // Записываем найденное окно с информацией о найденных/нужных
            if (logFile.is_open())
            {
                logFile << "0x" << std::hex << 0x629D5000 + (r.address - pStart) << " found (";
                for (size_t i = 0; i < foundCounts.size(); ++i)
                {
                    if (i > 0) logFile << " ";
                    // Находим сколько нужно для этого типа
                    size_t needed = 0;
                    for (const auto& req : need)
                    {
                        if (req.type >= 0 && (size_t)req.type == i)
                        {
                            needed = req.count;
                            break;
                        }
                    }
                    logFile << std::dec << foundCounts[i] << "/" << needed;
                }
                logFile << " 0x" << std::hex << winStart << "-0x" << winEnd << ")\n";
            }

            if (bAdjustWindow)
                winStart = (advanceTo > winStart) ? advanceTo : (winStart + 1);
            else
                winStart += nWindowSize;
        }
        else
        {
            // Записываем пропущенное окно с инфо сколько нашли и сколько нужно
            if (logFile.is_open())
            {
                logFile << "0x" << std::hex << 0x629D5000 + (winStart - pStart) << " (not found";
                for (size_t i = 0; i < foundCounts.size(); ++i)
                {
                    if (i == 0) logFile << " ";
                    // Находим сколько нужно для этого типа
                    size_t needed = 0;
                    for (const auto& req : need)
                    {
                        if (req.type >= 0 && (size_t)req.type == i)
                        {
                            needed = req.count;
                            break;
                        }
                    }
                    logFile << std::dec << foundCounts[i] << "/" << needed;
                    if (i < foundCounts.size() - 1) logFile << " ";
                }
                logFile << ")\n";
            }
            ++winStart;
        }

        scannedWindows++;

        if (bDisplayProgress)
            UpdateProgress(winStart, scannedWindows, totalWindows, foundWindows);
    }

    if (logFile.is_open())
    {
        logFile.close();
    }

    if (bDisplayProgress)
    {
        UpdateProgress(lastStart, totalWindows, totalWindows, foundWindows, true);
        printf("\n");
    }

    return result;
}
#endif

#if 0
// Any pair
void AsmRunner::TestScanA(uintptr_t pStart, uintptr_t pEnd, uintptr_t pOffset)
{
    using namespace ArAsmCode;

    // Themida jcc >>11 >>7
    std::vector<ZydisRegister> anyRegs = {
        ZYDIS_REGISTER_EAX,
        ZYDIS_REGISTER_ECX,
        ZYDIS_REGISTER_EDX,
        ZYDIS_REGISTER_EBX,
        ZYDIS_REGISTER_ESP,
        ZYDIS_REGISTER_EBP,
        ZYDIS_REGISTER_ESI,
        ZYDIS_REGISTER_EDI,
        //ZYDIS_REGISTER_R8D,
        //ZYDIS_REGISTER_R9D,
        //ZYDIS_REGISTER_R10D,
        //ZYDIS_REGISTER_R11D,
        //ZYDIS_REGISTER_R12D,
        //ZYDIS_REGISTER_R13D,
        //ZYDIS_REGISTER_R14D,
        //ZYDIS_REGISTER_R15D,
    };

    // Scan // зависимости: 1.размер окна 2.один регистр на пару and+shr // результат ~/4 в одном jcc 4 пары shr 11 и 4 пары shr 7 total: 4 окна (1 окно 11 и 7)
    // themida: на 1 jcc 2 рандомных регистра (1 для >>11, 1 для >>7), в 1 jcc 4 >>11 и 4 >>7
    uintptr_t nWindowSize = 250;

    struct RegHits
    {
        std::vector<uintptr_t> and11;
        std::vector<uintptr_t> shr11;
        std::vector<uintptr_t> and7;
        std::vector<uintptr_t> shr7;
    };

    std::map<ZydisRegister, RegHits> hits;

    auto ScanPattern = [&](const std::vector<uint8_t>& pat) -> std::vector<uintptr_t>
    {
        return ScanBytes(pStart, pEnd, pat);
    };

    // Собираем все совпадения по каждому регистру отдельно
    for (size_t i = 0; i < anyRegs.size(); ++i)
    {
        ZydisRegister reg = anyRegs[i];

        // >>11 // v1 & 0x800) >> 11;
        {
            std::vector<uint8_t> buf;
            BuildAsm86Op2(buf, ZYDIS_MNEMONIC_AND, Operand::Reg(reg), Operand::Imm(0x800));
            hits[reg].and11 = ScanPattern(buf);
        }
        {
            std::vector<uint8_t> buf;
            BuildAsm86Op2(buf, ZYDIS_MNEMONIC_SHR, Operand::Reg(reg), Operand::Imm(0x0B));
            hits[reg].shr11 = ScanPattern(buf);
        }
        // >>7 // v1 & 0x80) >> 7;
        {
            std::vector<uint8_t> buf;
            BuildAsm86Op2(buf, ZYDIS_MNEMONIC_AND, Operand::Reg(reg), Operand::Imm(0x80));
            hits[reg].and7 = ScanPattern(buf);
        }
        {
            std::vector<uint8_t> buf;
            BuildAsm86Op2(buf, ZYDIS_MNEMONIC_SHR, Operand::Reg(reg), Operand::Imm(0x07));
            hits[reg].shr7 = ScanPattern(buf);
        }
    }

    auto InWindow = [&](const std::vector<uintptr_t>& v, uintptr_t begin, uintptr_t end) -> bool
    {
        for (size_t i = 0; i < v.size(); ++i)
        {
            uintptr_t a = v[i];
            if (a >= begin && a < end)
                return true;
        }
        return false;
    };

    auto FirstInWindow = [&](const std::vector<uintptr_t>& v, uintptr_t begin, uintptr_t end) -> uintptr_t
    {
        uintptr_t best = 0;
        for (size_t i = 0; i < v.size(); ++i)
        {
            uintptr_t a = v[i];
            if (a >= begin && a < end)
            {
                if (best == 0 || a < best)
                    best = a;
            }
        }
        return best;
    };

    std::vector<uintptr_t> anchors;
    anchors.reserve(4096);

    for (std::map<ZydisRegister, RegHits>::iterator it = hits.begin(); it != hits.end(); ++it)
    {
        RegHits& h = it->second;
        anchors.insert(anchors.end(), h.and11.begin(), h.and11.end());
        anchors.insert(anchors.end(), h.shr11.begin(), h.shr11.end());
        anchors.insert(anchors.end(), h.and7.begin(), h.and7.end());
        anchors.insert(anchors.end(), h.shr7.begin(), h.shr7.end());
    }

    std::sort(anchors.begin(), anchors.end());
    anchors.erase(std::unique(anchors.begin(), anchors.end()), anchors.end());

    for (size_t ai = 0; ai < anchors.size(); ++ai)
    {
        uintptr_t windowStart = anchors[ai];
        uintptr_t windowEnd = windowStart + nWindowSize;

        for (size_t r1 = 0; r1 < anyRegs.size(); ++r1)
        {
            ZydisRegister reg11 = anyRegs[r1];
            RegHits& h11 = hits[reg11];

            if (!InWindow(h11.and11, windowStart, windowEnd))
                continue;
            if (!InWindow(h11.shr11, windowStart, windowEnd))
                continue;

            uintptr_t and11Addr = FirstInWindow(h11.and11, windowStart, windowEnd);
            uintptr_t shr11Addr = FirstInWindow(h11.shr11, windowStart, windowEnd);

            for (size_t r2 = 0; r2 < anyRegs.size(); ++r2)
            {
                ZydisRegister reg7 = anyRegs[r2];
                RegHits& h7 = hits[reg7];

                if (!InWindow(h7.and7, windowStart, windowEnd))
                    continue;
                if (!InWindow(h7.shr7, windowStart, windowEnd))
                    continue;

                uintptr_t and7Addr = FirstInWindow(h7.and7, windowStart, windowEnd);
                uintptr_t shr7Addr = FirstInWindow(h7.shr7, windowStart, windowEnd);

                printf("Window found at: 0x%p\n", (void*)(windowStart - pOffset));
#if 0
                printf("  reg11 = %u\n", (unsigned)reg11);
                printf("    AND11 at: 0x%p\n", (void*)(and11Addr - pOffset));
                printf("    SHR11 at: 0x%p\n", (void*)(shr11Addr - pOffset));

                printf("  reg7  = %u\n", (unsigned)reg7);
                printf("    AND7  at: 0x%p\n", (void*)(and7Addr - pOffset));
                printf("    SHR7  at: 0x%p\n", (void*)(shr7Addr - pOffset));
                //printf("\n");
#endif
            }
        }
    }
}

// Linear asm
void AsmRunner::TestScanB(uintptr_t pStart, uintptr_t pEnd, uintptr_t pOffset)
{
    using namespace ArAsmCode;

    // Themida jcc >>11 >>7
    std::vector<std::pair<ZydisRegister, std::string>> anyRegs = {
        { ZYDIS_REGISTER_EAX, "EAX" },
        { ZYDIS_REGISTER_ECX, "ECX" },
        { ZYDIS_REGISTER_EDX, "EDX" },
        { ZYDIS_REGISTER_EBX, "EBX" },
        { ZYDIS_REGISTER_ESP, "ESP" },
        { ZYDIS_REGISTER_EBP, "EBP" },
        { ZYDIS_REGISTER_ESI, "ESI" },
        { ZYDIS_REGISTER_EDI, "EDI" },

        //{ ZYDIS_REGISTER_R8D, "R8D" },
        //{ ZYDIS_REGISTER_R9D, "R9D" },
        //{ ZYDIS_REGISTER_R10D, "R10D" },
        //{ ZYDIS_REGISTER_R11D, "R11D" },
        //{ ZYDIS_REGISTER_R12D, "R12D" },
        //{ ZYDIS_REGISTER_R13D, "R13D" },
        //{ ZYDIS_REGISTER_R14D, "R14D" },
        //{ ZYDIS_REGISTER_R15D, "R15D" },
    };

    enum eOpType
    {
        AND = 0, // 0x40 R1
        AND_11, // 0x800 R1
        SHR_11, // 0xB R1
        AND_7, // 0x80 R2
        SHR_7, // 0x7 R2
    };

    struct tDecodeNode {
        uintptr_t addr;
        eOpType type;
        std::string str;
        std::string reg;
        ZydisRegister r;
    };
    std::vector<tDecodeNode> scanres;

    struct tPatternNode {
        std::vector<uint8_t> bytesAsm;
        eOpType type;
        std::string str;
        std::string reg;
        ZydisRegister r;
    };
    std::vector<tPatternNode> patterns;

    auto AddPattern = [&](ZydisMnemonic mnemonic,
        const Operand& dst,
        const Operand& src,
        eOpType type,
        const std::string& desc,
        const std::string& regName,
        ZydisRegister r,
        const BuildOptions& opts = BuildOptions{}) {
            std::vector<uint8_t> buffer;
            if (BuildAsm86Op2(buffer, mnemonic, dst, src, opts)) {
                patterns.push_back({ buffer, type, desc, regName, r });
            }
    };

    for (auto reg : anyRegs)
    {
        BuildOptions opts8, opts16, opts32;
        opts8.force_imm_width = ImmWidth::I8;
        opts16.force_imm_width = ImmWidth::I16;
        opts32.force_imm_width = ImmWidth::I32;

        //// ========== AND 0x40 (64) ==========
        //// Вариант 1: 83 /0 ib (signed 8-bit)
        //AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm8(0x40),
        //    AND, "v2 & 0x40 [83/s8]", reg.second, reg.first, opts8);

        //// Вариант 2: 81 /0 id (32-bit)
        //AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm32(0x40),
        //    AND, "v2 & 0x40 [81/s32]", reg.second, reg.first, opts32);

        //// Вариант 3: Unsigned 8-bit (для полноты)
        //AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::UImm8(0x40),
        //    AND, "v2 & 0x40 [83/u8]", reg.second, reg.first, opts8);


        // ========== AND 0x800 (2048) ==========
        // Только 32-бит (не влезает в 8/16)
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm32(0x800),
            AND_11, "v1 & 0x800) >> 11 [81]", reg.second, reg.first, opts32);

        // Unsigned 32-bit
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::UImm32(0x800),
            AND_11, "v1 & 0x800) >> 11 [81/u]", reg.second, reg.first, opts32);


        // ========== SHR 0x0B (11) ==========
        // SHR всегда использует 8-битный immediate
        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::Imm8(0x0B),
            SHR_11, ">> v1 & 0x800) >> 11 [C1]", reg.second, reg.first, opts8);

        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::UImm8(0x0B),
            SHR_11, ">> v1 & 0x800) >> 11 [C1/u]", reg.second, reg.first, opts8);


        // ========== AND 0x80 (128) ==========
        BuildOptions opts8signed;
        opts8signed.force_imm_width = ImmWidth::I8;
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm8(0x80),
            AND_7, "v1 & 0x80) >> 7 [83/s8-fail]", reg.second, reg.first, opts8signed);

        // Unsigned 8-bit
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::UImm8(0x80),
            AND_7, "v1 & 0x80) >> 7 [83/u8]", reg.second, reg.first, opts8);

        // 32-bit
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm32(0x80),
            AND_7, "v1 & 0x80) >> 7 [81/s32]", reg.second, reg.first, opts32);

        // 16-bit
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm16(0x80),
            AND_7, "v1 & 0x80) >> 7 [81/s16]", reg.second, reg.first, opts16);


        // ========== SHR 0x07 (7) ==========
        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::Imm8(0x07),
            SHR_7, ">> v1 & 0x80) >> 7 [C1/s8]", reg.second, reg.first, opts8);

        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::UImm8(0x07),
            SHR_7, ">> v1 & 0x80) >> 7 [C1/u8]", reg.second, reg.first, opts8);

        // SHR с 32-бит imm (редко, но бывает)
        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::Imm32(0x07),
            SHR_7, ">> v1 & 0x80) >> 7 [C1/s32]", reg.second, reg.first, opts32);
    }
    //{
    //    std::vector<uint8_t> buffer;

    //    BuildAsm86Op2(buffer, ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm(0x40));
    //    patterns.push_back({ buffer, AND, "v2 & 0x40", reg.second });
    //    buffer.clear();

    //    BuildAsm86Op2(buffer, ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm(0x800));
    //    patterns.push_back({ buffer, AND_11, "& v1 & 0x800) >> 11", reg.second });
    //    buffer.clear();

    //    BuildAsm86Op2(buffer, ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::Imm(0x0B));
    //    patterns.push_back({ buffer, SHR_11, ">> v1 & 0x800) >> 11", reg.second });
    //    buffer.clear();

    //    BuildAsm86Op2(buffer, ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm(0x80));
    //    patterns.push_back({ buffer, AND_7, "& v1 & 0x80) >> 7", reg.second });
    //    buffer.clear();

    //    BuildAsm86Op2(buffer, ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::Imm(0x07));
    //    patterns.push_back({ buffer, SHR_7, ">> v1 & 0x80) >> 7", reg.second });
    //    buffer.clear();
    //}

    // Сортируем для уникализации
    std::sort(patterns.begin(), patterns.end(),
        [](const tPatternNode& a, const tPatternNode& b) {
            return a.bytesAsm < b.bytesAsm;
        });

    // Удаляем дубликаты
    auto last = std::unique(patterns.begin(), patterns.end(),
        [](const tPatternNode& a, const tPatternNode& b) {
            return a.bytesAsm == b.bytesAsm;
        });
    patterns.erase(last, patterns.end());

//#define TEST_SCAN_LOG
#ifdef TEST_SCAN_LOG
    printf("=== Patterns ===\n");
    for (const auto& pattern : patterns) {
        printf("Pattern: %-20s Reg: %-5s Bytes: ", pattern.str.c_str(), pattern.reg.c_str());

        for (size_t i = 0; i < pattern.bytesAsm.size(); i++) {
            printf("%02X ", pattern.bytesAsm[i]);
        }

        printf(" [");
        for (size_t i = 0; i < pattern.bytesAsm.size(); i++) {
            if (isprint(pattern.bytesAsm[i])) {
                printf("%c", pattern.bytesAsm[i]);
            }
            else {
                printf(".");
            }
        }
        printf("]\n");
    }
    printf("========================\n\n");
#endif

    //for (const auto& pattern : patterns) {
    //    printf("%s %s\n", pattern.str.c_str(), pattern.reg.c_str());
    //}

    // Сканируем все паттерны и заполняем scanres
    for (const auto& pattern : patterns) {
        std::vector<uintptr_t> found = ScanBytes(pStart, pEnd, pattern.bytesAsm);

        for (auto addr : found) {
            scanres.push_back({ addr, pattern.type, pattern.str, pattern.reg, pattern.r });
        }
    }

    // Сортируем scanres по адресу
    std::sort(scanres.begin(), scanres.end(),
        [](const tDecodeNode& a, const tDecodeNode& b) {
            return a.addr < b.addr;
        });

    //// Инициализация/обработка результатов
    //for (const auto& node : scanres) {
    //    printf("Addr: 0x%p -> Final: 0x%p | %s\n", (void*)node.addr, (void*)(node.addr - pOffset), node.str.c_str());
    //}

    //printf("Total found nodes: %zu\n", scanres.size()); // 8372

    // Строгая 16-инструкционная цепочка:
    // AND_11, SHR_11, AND_7, SHR_7  x4
    static constexpr eOpType kNeedle[] = {
        AND_11, SHR_11, AND_7, SHR_7,
        AND_11, SHR_11, AND_7, SHR_7,
        AND_11, SHR_11, AND_7, SHR_7,
        AND_11, SHR_11, AND_7, SHR_7
    };
    constexpr size_t kNeedleLen = sizeof(kNeedle) / sizeof(kNeedle[0]);

    // Лямбда-компаратор: проверяет потенциальный блок по позиции pos
    auto IsPotentialBlock = [&](size_t pos) -> bool
    {
        if (pos + kNeedleLen > scanres.size())
            return false;

        for (size_t i = 0; i < kNeedleLen; ++i)
        {
            const auto& cur = scanres[pos + i];

            // Проверяем тип в строгом порядке
            if (cur.type != kNeedle[i])
                return false;

            // Проверяем, что адреса идут линейно
            if (i > 0 && cur.addr <= scanres[pos + i - 1].addr)
                return false;
        }

        // Если нужно жестко требовать, чтобы каждая пара работала на одном регистре:
        for (size_t i = 0; i < kNeedleLen; i += 4)
        {
            if (scanres[pos + i + 0].r != scanres[pos + i + 1].r)
                return false; // AND_11 / SHR_11 на одном регистре

            if (scanres[pos + i + 2].r != scanres[pos + i + 3].r)
                return false; // AND_7 / SHR_7 на одном регистре
        }

        // Если хочешь еще жестче:
        // return scanres[pos + 0].r == scanres[pos + 1].r &&
        //        scanres[pos + 0].r == scanres[pos + 2].r &&
        //        scanres[pos + 0].r == scanres[pos + 3].r &&
        //        ... и т.д.

        return true;
    };

    // Ищем блоки
    std::vector<size_t> blocks;
    for (size_t i = 0; i + kNeedleLen <= scanres.size(); )
    {
        if (IsPotentialBlock(i))
        {
            blocks.push_back(i);
            i += kNeedleLen; // не пересекать найденный блок
        }
        else
        {
            ++i;
        }
    }

    // Вывод всех найденных блоков
    printf("=== Blocks ===\n");
    for (size_t b : blocks)
    {
        const auto& first = scanres[b];
        const auto& last = scanres[b + kNeedleLen - 1];

        printf("BLOCK: start=0x%p end=0x%p | firstReg=%s | lastReg=%s\n",
            (void*)(first.addr - pOffset),
            (void*)(last.addr - pOffset),
            first.reg.c_str(),
            last.reg.c_str());

#ifdef TEST_SCAN_LOG
        for (size_t i = 0; i < kNeedleLen; ++i)
        {
            const auto& n = scanres[b + i];
            printf("  [%02zu] Addr=0x%p | Type=%d | Reg=%-5s | %s\n",
                i,
                (void*)n.addr,
                (int)n.type,
                n.reg.c_str(),
                n.str.c_str());
        }
#endif
    }
    printf("Total blocks found: %zu\n", blocks.size());
}
#endif

// By Window (the best)
//https://back.engineering/blog/09/05/2026/
std::vector<uintptr_t> AsmRunner::TestScanC(uintptr_t pStart, uintptr_t pEnd, uintptr_t pOffset)
{
    using namespace ArAsmCode;

    // Themida jcc >>11 >>7
    std::vector<std::pair<ZydisRegister, std::string>> anyRegs = {
        { ZYDIS_REGISTER_EAX, "EAX" },
        { ZYDIS_REGISTER_ECX, "ECX" },
        { ZYDIS_REGISTER_EDX, "EDX" },
        { ZYDIS_REGISTER_EBX, "EBX" },
        { ZYDIS_REGISTER_ESP, "ESP" },
        { ZYDIS_REGISTER_EBP, "EBP" },
        { ZYDIS_REGISTER_ESI, "ESI" },
        { ZYDIS_REGISTER_EDI, "EDI" },

        //{ ZYDIS_REGISTER_R8D, "R8D" },
        //{ ZYDIS_REGISTER_R9D, "R9D" },
        //{ ZYDIS_REGISTER_R10D, "R10D" },
        //{ ZYDIS_REGISTER_R11D, "R11D" },
        //{ ZYDIS_REGISTER_R12D, "R12D" },
        //{ ZYDIS_REGISTER_R13D, "R13D" },
        //{ ZYDIS_REGISTER_R14D, "R14D" },
        //{ ZYDIS_REGISTER_R15D, "R15D" },
    };

    enum eOpType
    {
        AND = 0, // 0x40 R1
        AND_11, // 0x800 R1
        SHR_11, // 0xB R1
        AND_7, // 0x80 R2
        SHR_7, // 0x7 R2
    };

    std::vector<AsmRunner::tScanPatternNode> patterns;

    auto AddPattern = [&](ZydisMnemonic mnemonic,
        const Operand& dst,
        const Operand& src,
        eOpType type,
        const std::string& desc,
        const std::string& regName,
        const BuildOptions& opts = BuildOptions{})
    {
        std::vector<uint8_t> buffer;
        if (BuildAsm86Op2(buffer, mnemonic, dst, src, opts)) {
            patterns.push_back({ buffer, (int32_t)type });
            {
                printf("[%s] %s: ", regName.c_str(), desc.c_str());
                for (uint8_t b : buffer) printf("%02X ", b);
                printf("\n");
            }
        }
    };

    for (auto reg : anyRegs)
    {
        BuildOptions opts8, opts16, opts32;
        opts8.force_imm_width = ImmWidth::I8;
        opts16.force_imm_width = ImmWidth::I16;
        opts32.force_imm_width = ImmWidth::I32;
        BuildOptions opts8signed;
        opts8signed.force_imm_width = ImmWidth::I8;

        // ===== accumulator-only coverage =====
        // EAX short opcodes (this is the window you hit manually: 25 00 08 00 00)
        if (reg.first == ZYDIS_REGISTER_EAX)
        {
            AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm32(0x40),
                AND, "v2 & 0x40 [acc 25/s32]", reg.second, opts32);
            AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::UImm32(0x40),
                AND, "v2 & 0x40 [acc 25/u32]", reg.second, opts32);

            AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm32(0x800),
                AND_11, "v1 & 0x800) >> 11 [acc 25/s32]", reg.second, opts32);
            AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::UImm32(0x800),
                AND_11, "v1 & 0x800) >> 11 [acc 25/u32]", reg.second, opts32);

            // Optional 16-bit form (66 25 iw), useful when the target uses AX-style encoding.
            AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(ZYDIS_REGISTER_AX), Operand::Imm16(0x40),
                AND, "v2 & 0x40 [AX 66/25]", "AX", opts16);
            AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(ZYDIS_REGISTER_AX), Operand::Imm16(0x800),
                AND_11, "v1 & 0x800) >> 11 [AX 66/25]", "AX", opts16);

            // Optional 8-bit accumulator form (24/0C/14 etc. if you later extend the mnemonic table)
            AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(ZYDIS_REGISTER_AL), Operand::Imm8(0x40),
                AND, "v2 & 0x40 [AL 24]", "AL", opts8);
            AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(ZYDIS_REGISTER_AL), Operand::Imm8(0x80),
                AND_7, "v1 & 0x80) >> 7 [AL 24]", "AL", opts8);
        }

        // ========== AND 0x40 (64) ==========
        // Вариант 1: 83 /0 ib (signed 8-bit)
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm8(0x40),
            AND, "v2 & 0x40 [83/s8]", reg.second, opts8);

        // Вариант 2: 81 /0 id (32-bit)
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm32(0x40),
            AND, "v2 & 0x40 [81/s32]", reg.second, opts32);

        // Вариант 3: Unsigned 8-bit (для полноты)
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::UImm8(0x40),
            AND, "v2 & 0x40 [83/u8]", reg.second, opts8);


        // ========== AND 0x800 (2048) ==========
        // Только 32-бит (не влезает в 8/16)
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm32(0x800),
            AND_11, "v1 & 0x800) >> 11 [81]", reg.second, opts32);

        // Unsigned 32-bit
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::UImm32(0x800),
            AND_11, "v1 & 0x800) >> 11 [81/u]", reg.second, opts32);


        // ========== SHR 0x0B (11) ==========
        // SHR всегда использует 8-битный immediate
        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::Imm8(0x0B),
            SHR_11, ">> v1 & 0x800) >> 11 [C1]", reg.second, opts8);

        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::UImm8(0x0B),
            SHR_11, ">> v1 & 0x800) >> 11 [C1/u]", reg.second, opts8);


        // ========== AND 0x80 (128) ==========
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm8(0x80),
            AND_7, "v1 & 0x80) >> 7 [83/s8-fail]", reg.second, opts8signed);

        // Unsigned 8-bit
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::UImm8(0x80),
            AND_7, "v1 & 0x80) >> 7 [83/u8]", reg.second, opts8);

        // 32-bit
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm32(0x80),
            AND_7, "v1 & 0x80) >> 7 [81/s32]", reg.second, opts32);

        // 16-bit
        AddPattern(ZYDIS_MNEMONIC_AND, Operand::Reg(reg.first), Operand::Imm16(0x80),
            AND_7, "v1 & 0x80) >> 7 [81/s16]", reg.second, opts16);


        // ========== SHR 0x07 (7) ==========
        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::Imm8(0x07),
            SHR_7, ">> v1 & 0x80) >> 7 [C1/s8]", reg.second, opts8);

        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::UImm8(0x07),
            SHR_7, ">> v1 & 0x80) >> 7 [C1/u8]", reg.second, opts8);

        // SHR с 32-бит imm (редко, но бывает)
        AddPattern(ZYDIS_MNEMONIC_SHR, Operand::Reg(reg.first), Operand::Imm32(0x07),
            SHR_7, ">> v1 & 0x80) >> 7 [C1/s32]", reg.second, opts32);
    }

    // Settings
    const std::vector<AsmRunner::tScanNeed> need = {
        { AND,    1 },
        { AND_11, 3 }, // 4 default // с 3 окно может высоко и поймать только нужные 3, при 4 окно base будет ниже, 3 на всякий из за оптимизаций jmp reuse?
        { SHR_11, 3 }, // 4 default
        { AND_7,  3 }, // 4 default
        { SHR_7,  3 }, // 4 default
    };

    uintptr_t nWindowSize = 800; // окно, максимум что встречал 597 от 11 до 7 // больше окно - дольше поиск
    bool bAdjustWindow = true;   // true -> добавлять первый матч в окне, false -> добавлять winStart
    bool bDisplayProgress = true;

    std::vector<AsmRunner::tScanWindowResult> result = ScanWindow(pStart, pEnd, patterns, need, nWindowSize, bAdjustWindow, bDisplayProgress);

    std::vector<uintptr_t> outRes; // you can set bp for this by (range! linear code flow not equal pWindow) to capture if branch at runtime

    for (uint32_t i = 0; i < result.size(); ++i) {
        outRes.push_back(result[i].address);

        //printf("Window %d: start=0x%p\n", (i + 1), (void*)(result[i].address - pOffset));
        printf("Window %d: start=0x%p | entries: AND=%d, AND_11=%d, SHR_11=%d, AND_7=%d, SHR_7=%d\n",
            (i + 1),
            (void*)(result[i].address - pOffset),
            result[i].counts[AND],
            result[i].counts[AND_11],
            result[i].counts[SHR_11],
            result[i].counts[AND_7],
            result[i].counts[SHR_7]);
    }

    FILE* f = FileOpen("scan_results.txt", "w");
    if (f) {
        for (auto& r : result)
            FileAdd(f, "0x%p 0x%p", (void*)r.address, (void*)(r.address - pOffset));

        FileClose(f);
        printf("Saved: %zu blocks to scan_results.txt\n", result.size());
    }

    return outRes;
}

void AsmRunner::TestScanD(uintptr_t pStart, uintptr_t pEnd, uintptr_t pOffset, std::vector<uintptr_t>& outVMEntries, std::vector<uintptr_t>& outVMExits)
{
    using namespace ArAsmCode;

    //outVMEntries
    //  pushf + push any reg x6 count
    //outVMExits
    //  popf + pop any reg x6 count

    outVMEntries.clear();
    outVMExits.clear();

    std::vector<std::pair<ZydisRegister, std::string>> anyRegs = {
        { ZYDIS_REGISTER_EAX, "EAX" },
        { ZYDIS_REGISTER_ECX, "ECX" },
        { ZYDIS_REGISTER_EDX, "EDX" },
        { ZYDIS_REGISTER_EBX, "EBX" },
        { ZYDIS_REGISTER_ESP, "ESP" },
        { ZYDIS_REGISTER_EBP, "EBP" },
        { ZYDIS_REGISTER_ESI, "ESI" },
        { ZYDIS_REGISTER_EDI, "EDI" },

        //{ ZYDIS_REGISTER_R8D, "R8D" },
        //{ ZYDIS_REGISTER_R9D, "R9D" },
        //{ ZYDIS_REGISTER_R10D, "R10D" },
        //{ ZYDIS_REGISTER_R11D, "R11D" },
        //{ ZYDIS_REGISTER_R12D, "R12D" },
        //{ ZYDIS_REGISTER_R13D, "R13D" },
        //{ ZYDIS_REGISTER_R14D, "R14D" },
        //{ ZYDIS_REGISTER_R15D, "R15D" },
    };

    auto RunPass = [&](bool bEntries, std::vector<uintptr_t>& outVec)
    {
        enum eOpType
        {
            HEAD = 0,
            ANY_REG = 1,
        };

        std::vector<AsmRunner::tScanPatternNode> patterns;

        auto AddPattern0 = [&](ZydisMnemonic mnemonic, eOpType type)
        {
            std::vector<uint8_t> buffer;
            if (BuildAsm86Op0(buffer, mnemonic))
                patterns.push_back({ buffer, (int32_t)type });
        };

        auto AddPattern1 = [&](ZydisMnemonic mnemonic, ZydisRegister reg, eOpType type)
        {
            std::vector<uint8_t> buffer;
            if (BuildAsm86Op1(buffer, mnemonic, Operand::Reg(reg)))
                patterns.push_back({ buffer, (int32_t)type });
        };

        if (bEntries)
        {
            AddPattern0(ZYDIS_MNEMONIC_PUSHFD, HEAD);

            for (auto reg : anyRegs)
                AddPattern1(ZYDIS_MNEMONIC_PUSH, reg.first, ANY_REG);
        }
        else
        {
            AddPattern0(ZYDIS_MNEMONIC_POPFD, HEAD);

            for (auto reg : anyRegs)
                AddPattern1(ZYDIS_MNEMONIC_POP, reg.first, ANY_REG);
        }

        std::vector<AsmRunner::tScanNeed> need = {
            { HEAD, 1 },
            { ANY_REG, 6 },
        };

        uintptr_t nWindowSize = 100; // adj it
        bool bAdjustWindow = true;
        bool bDisplayProgress = true;

        std::vector<AsmRunner::tScanWindowResult> result = ScanWindow(
            pStart,
            pEnd,
            patterns,
            need,
            nWindowSize,
            bAdjustWindow,
            bDisplayProgress);

        for (const auto& r : result)
            outVec.push_back(r.address);
    };

    RunPass(true, outVMEntries);
    RunPass(false, outVMExits);

    printf("\n=== TestScanD Results ===\n");
    printf("VMEntries found: %zu\n", outVMEntries.size());
    for (uint32_t i = 0; i < outVMEntries.size(); ++i) {
        printf("Entry %d: 0x%p (0x%p)\n", (i + 1), (void*)outVMEntries[i], (void*)(outVMEntries[i] - pOffset));
    }
    FILE* f = FileOpen("vm_entries.txt", "w");
    if (f) {
        for (auto& addr : outVMEntries)
            FileAdd(f, "0x%p 0x%p", (void*)addr, (void*)(addr - pOffset));
        FileClose(f);
        f = nullptr;
        printf("Saved: %zu VM entries to vm_entries.txt\n", outVMEntries.size());
    }

    printf("\nVMExits found: %zu\n", outVMExits.size());
    for (uint32_t i = 0; i < outVMExits.size(); ++i) {
        printf("Exit %d: 0x%p (0x%p)\n", (i + 1), (void*)outVMExits[i], (void*)(outVMExits[i] - pOffset));
    }
    f = FileOpen("vm_exits.txt", "w");
    if (f) {
        for (auto& addr : outVMExits)
            FileAdd(f, "0x%p 0x%p", (void*)addr, (void*)(addr - pOffset));
        FileClose(f);
        f = nullptr;
        printf("Saved: %zu VM exits to vm_exits.txt\n", outVMExits.size());
    }
}

namespace ArAsmCode
{
	namespace detail
	{
		static void EmitU8(std::vector<uint8_t>& out, uint8_t v) { out.push_back(v); }
		static void EmitU16(std::vector<uint8_t>& out, uint16_t v)
		{
			out.push_back(static_cast<uint8_t>(v & 0xFF));
			out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
		}
		static void EmitU32(std::vector<uint8_t>& out, uint32_t v)
		{
			out.push_back(static_cast<uint8_t>(v & 0xFF));
			out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
			out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
			out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
		}

		static bool FitsSigned8(ZyanI64 v)  { return v >= -128 && v <= 127; }
		static bool FitsSigned16(ZyanI64 v) { return v >= -32768 && v <= 32767; }
		static bool FitsSigned32(ZyanI64 v) { return v >= INT32_MIN && v <= INT32_MAX; }
		static bool FitsUnsigned8(ZyanU64 v)  { return v <= 0xFFull; }
		static bool FitsUnsigned16(ZyanU64 v) { return v <= 0xFFFFull; }
		static bool FitsUnsigned32(ZyanU64 v) { return v <= 0xFFFFFFFFull; }

		static bool CanEmitImmWidth(const Operand::ImmOp& imm, ImmWidth w)
		{
			switch (w)
			{
			    case ImmWidth::I8:
				    return imm.signedValue ? FitsSigned8(imm.s) : FitsUnsigned8(imm.u);
			    case ImmWidth::I16:
				    return imm.signedValue ? FitsSigned16(imm.s) : FitsUnsigned16(imm.u);
			    case ImmWidth::I32:
				    return imm.signedValue ? FitsSigned32(imm.s) : FitsUnsigned32(imm.u);
			    default:
				    return false;
			}
		}

		struct GpRegInfo
		{
			uint8_t bits = 0;
			uint8_t code = 0;
			bool rex = false;
			bool high8 = false;
		};

		static bool TryGetGpRegInfo(ZydisRegister reg, GpRegInfo& out)
		{
			switch (reg)
			{
			    case ZYDIS_REGISTER_AL:  out = { 8, 0, false, false }; return true;
			    case ZYDIS_REGISTER_CL:  out = { 8, 1, false, false }; return true;
			    case ZYDIS_REGISTER_DL:  out = { 8, 2, false, false }; return true;
			    case ZYDIS_REGISTER_BL:  out = { 8, 3, false, false }; return true;
			    case ZYDIS_REGISTER_AH:  out = { 8, 4, false, true  }; return true;
			    case ZYDIS_REGISTER_CH:  out = { 8, 5, false, true  }; return true;
			    case ZYDIS_REGISTER_DH:  out = { 8, 6, false, true  }; return true;
			    case ZYDIS_REGISTER_BH:  out = { 8, 7, false, true  }; return true;

			    case ZYDIS_REGISTER_SPL: out = { 8, 4, true,  false }; return true;
			    case ZYDIS_REGISTER_BPL: out = { 8, 5, true,  false }; return true;
			    case ZYDIS_REGISTER_SIL: out = { 8, 6, true,  false }; return true;
			    case ZYDIS_REGISTER_DIL: out = { 8, 7, true,  false }; return true;

			    case ZYDIS_REGISTER_R8B:  out = { 8, 0, true, false }; return true;
			    case ZYDIS_REGISTER_R9B:  out = { 8, 1, true, false }; return true;
			    case ZYDIS_REGISTER_R10B: out = { 8, 2, true, false }; return true;
			    case ZYDIS_REGISTER_R11B: out = { 8, 3, true, false }; return true;
			    case ZYDIS_REGISTER_R12B: out = { 8, 4, true, false }; return true;
			    case ZYDIS_REGISTER_R13B: out = { 8, 5, true, false }; return true;
			    case ZYDIS_REGISTER_R14B: out = { 8, 6, true, false }; return true;
			    case ZYDIS_REGISTER_R15B: out = { 8, 7, true, false }; return true;

			    case ZYDIS_REGISTER_AX:   out = { 16, 0, false, false }; return true;
			    case ZYDIS_REGISTER_CX:   out = { 16, 1, false, false }; return true;
			    case ZYDIS_REGISTER_DX:   out = { 16, 2, false, false }; return true;
			    case ZYDIS_REGISTER_BX:   out = { 16, 3, false, false }; return true;
			    case ZYDIS_REGISTER_SP:   out = { 16, 4, false, false }; return true;
			    case ZYDIS_REGISTER_BP:   out = { 16, 5, false, false }; return true;
			    case ZYDIS_REGISTER_SI:   out = { 16, 6, false, false }; return true;
			    case ZYDIS_REGISTER_DI:   out = { 16, 7, false, false }; return true;

			    case ZYDIS_REGISTER_R8W:  out = { 16, 0, true, false }; return true;
			    case ZYDIS_REGISTER_R9W:  out = { 16, 1, true, false }; return true;
			    case ZYDIS_REGISTER_R10W: out = { 16, 2, true, false }; return true;
			    case ZYDIS_REGISTER_R11W: out = { 16, 3, true, false }; return true;
			    case ZYDIS_REGISTER_R12W: out = { 16, 4, true, false }; return true;
			    case ZYDIS_REGISTER_R13W: out = { 16, 5, true, false }; return true;
			    case ZYDIS_REGISTER_R14W: out = { 16, 6, true, false }; return true;
			    case ZYDIS_REGISTER_R15W: out = { 16, 7, true, false }; return true;

			    case ZYDIS_REGISTER_EAX:   out = { 32, 0, false, false }; return true;
			    case ZYDIS_REGISTER_ECX:   out = { 32, 1, false, false }; return true;
			    case ZYDIS_REGISTER_EDX:   out = { 32, 2, false, false }; return true;
			    case ZYDIS_REGISTER_EBX:   out = { 32, 3, false, false }; return true;
			    case ZYDIS_REGISTER_ESP:   out = { 32, 4, false, false }; return true;
			    case ZYDIS_REGISTER_EBP:   out = { 32, 5, false, false }; return true;
			    case ZYDIS_REGISTER_ESI:   out = { 32, 6, false, false }; return true;
			    case ZYDIS_REGISTER_EDI:   out = { 32, 7, false, false }; return true;

			    case ZYDIS_REGISTER_R8D:  out = { 32, 0, true, false }; return true;
			    case ZYDIS_REGISTER_R9D:  out = { 32, 1, true, false }; return true;
			    case ZYDIS_REGISTER_R10D: out = { 32, 2, true, false }; return true;
			    case ZYDIS_REGISTER_R11D: out = { 32, 3, true, false }; return true;
			    case ZYDIS_REGISTER_R12D: out = { 32, 4, true, false }; return true;
			    case ZYDIS_REGISTER_R13D: out = { 32, 5, true, false }; return true;
			    case ZYDIS_REGISTER_R14D: out = { 32, 6, true, false }; return true;
			    case ZYDIS_REGISTER_R15D: out = { 32, 7, true, false }; return true;

			    case ZYDIS_REGISTER_RAX:   out = { 64, 0, false, false }; return true;
			    case ZYDIS_REGISTER_RCX:   out = { 64, 1, false, false }; return true;
			    case ZYDIS_REGISTER_RDX:   out = { 64, 2, false, false }; return true;
			    case ZYDIS_REGISTER_RBX:   out = { 64, 3, false, false }; return true;
			    case ZYDIS_REGISTER_RSP:   out = { 64, 4, false, false }; return true;
			    case ZYDIS_REGISTER_RBP:   out = { 64, 5, false, false }; return true;
			    case ZYDIS_REGISTER_RSI:   out = { 64, 6, false, false }; return true;
			    case ZYDIS_REGISTER_RDI:   out = { 64, 7, false, false }; return true;

			    case ZYDIS_REGISTER_R8:  out = { 64, 0, true, false }; return true;
			    case ZYDIS_REGISTER_R9:  out = { 64, 1, true, false }; return true;
			    case ZYDIS_REGISTER_R10: out = { 64, 2, true, false }; return true;
			    case ZYDIS_REGISTER_R11: out = { 64, 3, true, false }; return true;
			    case ZYDIS_REGISTER_R12: out = { 64, 4, true, false }; return true;
			    case ZYDIS_REGISTER_R13: out = { 64, 5, true, false }; return true;
			    case ZYDIS_REGISTER_R14: out = { 64, 6, true, false }; return true;
			    case ZYDIS_REGISTER_R15: out = { 64, 7, true, false }; return true;

			    default:
				    return false;
			}
		}

		static bool IsGroup1Mnemonic(ZydisMnemonic m, uint8_t& ext)
		{
			switch (m)
			{
			    case ZYDIS_MNEMONIC_ADD: ext = 0; return true;
			    case ZYDIS_MNEMONIC_OR:  ext = 1; return true;
			    case ZYDIS_MNEMONIC_ADC: ext = 2; return true;
			    case ZYDIS_MNEMONIC_SBB: ext = 3; return true;
			    case ZYDIS_MNEMONIC_AND: ext = 4; return true;
			    case ZYDIS_MNEMONIC_SUB: ext = 5; return true;
			    case ZYDIS_MNEMONIC_XOR: ext = 6; return true;
			    case ZYDIS_MNEMONIC_CMP: ext = 7; return true;
			    default: return false;
			}
		}

		static bool IsTestMnemonic(ZydisMnemonic m)
		{
			return m == ZYDIS_MNEMONIC_TEST;
		}

		static ImmWidth NormalizeImmWidth(ImmWidth w)
		{
			return w == ImmWidth::I64 ? ImmWidth::I32 : w;
		}

		static ImmWidth SelectImmWidth(const Operand::ImmOp& imm, const BuildOptions& options)
		{
			if (imm.width != ImmWidth::Auto)
				return NormalizeImmWidth(imm.width);
			return NormalizeImmWidth(options.force_imm_width);
		}

		static ZyanI64 ImmAsSigned(const Operand::ImmOp& imm)
		{
			return imm.signedValue ? imm.s : static_cast<ZyanI64>(imm.u);
		}

		static ZyanU64 ImmAsUnsigned(const Operand::ImmOp& imm)
		{
			return imm.signedValue ? static_cast<ZyanU64>(imm.s) : imm.u;
		}

		static void EmitImmediate(std::vector<uint8_t>& out, const Operand::ImmOp& imm, ImmWidth w)
		{
			const ZyanU64 u = ImmAsUnsigned(imm);
			switch (w)
			{
			    case ImmWidth::I8:  EmitU8(out, static_cast<uint8_t>(u)); break;
			    case ImmWidth::I16: EmitU16(out, static_cast<uint16_t>(u)); break;
			    case ImmWidth::I32: EmitU32(out, static_cast<uint32_t>(u)); break;
			    default: break;
			}
		}

		static bool EncodeModRmSibDisp(std::vector<uint8_t>& tail,
			ZydisMachineMode mode,
			const Operand::MemOp& mem,
			uint8_t regField,
			uint8_t& rex)
		{
			tail.clear();

			GpRegInfo baseInfo{};
			GpRegInfo indexInfo{};
			const bool hasBase = mem.base != ZYDIS_REGISTER_NONE;
			const bool hasIndex = mem.index != ZYDIS_REGISTER_NONE;

			if (hasBase && !TryGetGpRegInfo(mem.base, baseInfo)) return false;
			if (hasIndex && !TryGetGpRegInfo(mem.index, indexInfo)) return false;
			if (hasIndex && indexInfo.bits == 8) return false;
			if (mem.scale != 1 && mem.scale != 2 && mem.scale != 4 && mem.scale != 8) return false;

			if (mode != ZYDIS_MACHINE_MODE_LONG_64)
			{
				if ((hasBase && baseInfo.rex) || (hasIndex && indexInfo.rex)) return false;
			}

			const ZyanI64 disp = mem.displacement;
			const bool dispFits8 = (disp >= -128 && disp <= 127);
			const bool dispFits32 = (disp >= INT32_MIN && disp <= INT32_MAX);
			if (!dispFits32) return false;

			rex = 0;
			if (mode == ZYDIS_MACHINE_MODE_LONG_64)
			{
				if (hasBase && baseInfo.rex) rex |= 0x01;
				if (hasIndex && indexInfo.rex) rex |= 0x02;
			}

			uint8_t mod = 0;
			uint8_t rm = 0;
			bool emitDisp8 = false;
			bool emitDisp32 = false;
			ZyanI32 disp32 = static_cast<ZyanI32>(disp);
			uint8_t sib = 0;
			bool useSib = false;

			if (!hasBase)
			{
				mod = 0;
				if (mode == ZYDIS_MACHINE_MODE_LONG_64)
				{
					useSib = true;
					rm = 4;
					const uint8_t scaleBits = (mem.scale == 1) ? 0 : (mem.scale == 2) ? 1 : (mem.scale == 4) ? 2 : 3;
					const uint8_t indexBits = hasIndex ? indexInfo.code : 4;
					sib = static_cast<uint8_t>((scaleBits << 6) | (indexBits << 3) | 5);
					emitDisp32 = true;
				}
				else
				{
					rm = 5;
					emitDisp32 = true;
				}
			}
			else
			{
				if (disp == 0 && baseInfo.code != 5)
					mod = 0;
				else if (dispFits8)
				{
					mod = 1;
					emitDisp8 = true;
				}
				else
				{
					mod = 2;
					emitDisp32 = true;
				}

				if (baseInfo.code == 5 && mod == 0)
				{
					mod = 1;
					emitDisp8 = true;
					disp32 = 0;
				}

				const bool needSib = hasIndex || baseInfo.code == 4;
				if (needSib)
				{
					useSib = true;
					rm = 4;
					if (hasIndex && indexInfo.code == 4) return false;
					const uint8_t scaleBits = (mem.scale == 1) ? 0 : (mem.scale == 2) ? 1 : (mem.scale == 4) ? 2 : 3;
					const uint8_t indexBits = hasIndex ? indexInfo.code : 4;
					const uint8_t baseBits = baseInfo.code;
					sib = static_cast<uint8_t>((scaleBits << 6) | (indexBits << 3) | baseBits);
				}
				else
				{
					rm = baseInfo.code;
				}
			}

			tail.push_back(static_cast<uint8_t>((mod << 6) | ((regField & 7) << 3) | (rm & 7)));
			if (useSib) tail.push_back(sib);
			if (emitDisp8) tail.push_back(static_cast<uint8_t>(disp32 & 0xFF));
			else if (emitDisp32) EmitU32(tail, static_cast<uint32_t>(disp32));
			return true;
		}

        static bool EncodeAluImm(std::vector<uint8_t>& out,
            ZydisMachineMode mode,
            ZydisMnemonic mnemonic,
            const Operand& dst,
            const Operand::ImmOp& srcImm,
            ImmWidth requestedWidth)
        {
            const ImmWidth req = NormalizeImmWidth(requestedWidth);
            uint8_t groupExt = 0;
            const bool isGroup1 = IsGroup1Mnemonic(mnemonic, groupExt);
            const bool isTest = IsTestMnemonic(mnemonic);
            if (!isGroup1 && !isTest)
                return false;

            if (dst.kind == Operand::Kind::Reg)
            {
                GpRegInfo r{};
                if (!TryGetGpRegInfo(dst.reg, r)) return false;
                if (mode != ZYDIS_MACHINE_MODE_LONG_64 && r.rex) return false;

                const bool need66 = (r.bits == 16);
                const bool needREXW = (r.bits == 64);
                const bool needREX = (mode == ZYDIS_MACHINE_MODE_LONG_64 && r.rex);
                if (r.high8 && (mode == ZYDIS_MACHINE_MODE_LONG_64 && needREX)) return false;

                auto emitAcc = [&](uint8_t opcode, ImmWidth immW) -> bool
                {
                    if (!CanEmitImmWidth(srcImm, immW)) return false;
                    if (immW == ImmWidth::I64) return false;

                    out.clear();
                    if (need66) EmitU8(out, 0x66);
                    if (mode == ZYDIS_MACHINE_MODE_LONG_64 && (needREXW || needREX))
                    {
                        uint8_t rex = 0x40;
                        if (needREXW) rex |= 0x08;
                        if (needREX)  rex |= 0x01;
                        EmitU8(out, rex);
                    }
                    EmitU8(out, opcode);
                    EmitImmediate(out, srcImm, immW);
                    return true;
                };

                // AL / AX / EAX / RAX accumulator forms.
                // Prefer them when the width is explicitly requested or when the immediate does not fit imm8.
                const bool wantAcc =
                    (r.code == 0) &&
                    (isTest || req != ImmWidth::Auto || !FitsSigned8(ImmAsSigned(srcImm)) || r.bits == 8);

                if (wantAcc)
                {
                    switch (mnemonic)
                    {
                        case ZYDIS_MNEMONIC_ADD: if (r.bits == 8) return emitAcc(0x04, ImmWidth::I8); else return emitAcc(0x05, (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32);
                        case ZYDIS_MNEMONIC_OR:  if (r.bits == 8) return emitAcc(0x0C, ImmWidth::I8); else return emitAcc(0x0D, (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32);
                        case ZYDIS_MNEMONIC_ADC: if (r.bits == 8) return emitAcc(0x14, ImmWidth::I8); else return emitAcc(0x15, (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32);
                        case ZYDIS_MNEMONIC_SBB: if (r.bits == 8) return emitAcc(0x1C, ImmWidth::I8); else return emitAcc(0x1D, (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32);
                        case ZYDIS_MNEMONIC_AND: if (r.bits == 8) return emitAcc(0x24, ImmWidth::I8); else return emitAcc(0x25, (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32);
                        case ZYDIS_MNEMONIC_SUB: if (r.bits == 8) return emitAcc(0x2C, ImmWidth::I8); else return emitAcc(0x2D, (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32);
                        case ZYDIS_MNEMONIC_XOR: if (r.bits == 8) return emitAcc(0x34, ImmWidth::I8); else return emitAcc(0x35, (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32);
                        case ZYDIS_MNEMONIC_CMP: if (r.bits == 8) return emitAcc(0x3C, ImmWidth::I8); else return emitAcc(0x3D, (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32);
                        case ZYDIS_MNEMONIC_TEST:
                            if (r.bits == 8)  return emitAcc(0xA8, ImmWidth::I8);
                            if (r.bits == 16) return emitAcc(0xA9, ImmWidth::I16);
                            if (r.bits == 32) return emitAcc(0xA9, ImmWidth::I32);
                            if (r.bits == 64) return emitAcc(0xA9, ImmWidth::I32);
                            break;
                        default:
                            break;
                    }
                }

                // Existing ModRM form (unchanged semantics).
                uint8_t opcode = 0;
                ImmWidth immWidth = ImmWidth::Auto;

                if (isTest)
                {
                    if (r.bits == 8) { opcode = 0xF6; immWidth = ImmWidth::I8; }
                    else if (r.bits == 16) { opcode = 0xF7; immWidth = ImmWidth::I16; }
                    else if (r.bits == 32) { opcode = 0xF7; immWidth = ImmWidth::I32; }
                    else if (r.bits == 64) { opcode = 0xF7; immWidth = ImmWidth::I32; }
                    else return false;

                    if (req != ImmWidth::Auto)
                        immWidth = (req == ImmWidth::I64) ? ImmWidth::I32 : req;

                    if (!CanEmitImmWidth(srcImm, immWidth) || immWidth == ImmWidth::I64) return false;

                    out.clear();
                    if (need66) EmitU8(out, 0x66);
                    if (mode == ZYDIS_MACHINE_MODE_LONG_64 && (needREXW || needREX))
                    {
                        uint8_t rex = 0x40;
                        if (needREXW) rex |= 0x08;
                        if (needREX)  rex |= 0x01;
                        EmitU8(out, rex);
                    }
                    EmitU8(out, opcode);
                    EmitU8(out, static_cast<uint8_t>(0xC0 | (0 << 3) | (r.code & 7)));
                    EmitImmediate(out, srcImm, immWidth);
                    return true;
                }

                if (r.bits == 8)
                {
                    opcode = 0x80;
                    immWidth = ImmWidth::I8;
                    if (req == ImmWidth::I16 || req == ImmWidth::I32 || req == ImmWidth::I64) return false;
                }
                else
                {
                    if (req == ImmWidth::I8)
                    {
                        opcode = 0x83;
                        immWidth = ImmWidth::I8;
                    }
                    else if (req == ImmWidth::I16)
                    {
                        if (r.bits != 16) return false;
                        opcode = 0x81;
                        immWidth = ImmWidth::I16;
                    }
                    else if (req == ImmWidth::I32)
                    {
                        if (r.bits == 16) return false;
                        opcode = 0x81;
                        immWidth = ImmWidth::I32;
                    }
                    else if (req == ImmWidth::I64)
                    {
                        if (r.bits != 64) return false;
                        opcode = 0x81;
                        immWidth = ImmWidth::I32;
                    }
                    else
                    {
                        const ZyanI64 v = ImmAsSigned(srcImm);
                        if (FitsSigned8(v))
                        {
                            opcode = 0x83;
                            immWidth = ImmWidth::I8;
                        }
                        else
                        {
                            opcode = 0x81;
                            immWidth = (r.bits == 16) ? ImmWidth::I16 : ImmWidth::I32;
                        }
                    }
                }

                if (!CanEmitImmWidth(srcImm, immWidth)) return false;

                out.clear();
                if (need66) EmitU8(out, 0x66);
                if (mode == ZYDIS_MACHINE_MODE_LONG_64 && (needREXW || needREX))
                {
                    uint8_t rex = 0x40;
                    if (needREXW) rex |= 0x08;
                    if (needREX)  rex |= 0x01;
                    EmitU8(out, rex);
                }
                EmitU8(out, opcode);
                EmitU8(out, static_cast<uint8_t>(0xC0 | ((groupExt & 7) << 3) | (r.code & 7)));
                EmitImmediate(out, srcImm, immWidth);
                return true;
            }

            if (dst.kind == Operand::Kind::Mem)
            {
                if (dst.mem.size != 1 && dst.mem.size != 2 && dst.mem.size != 4 && dst.mem.size != 8) return false;

                uint8_t opcode = 0;
                ImmWidth immWidth = ImmWidth::Auto;
                if (isTest)
                {
                    opcode = (dst.mem.size == 1) ? 0xF6 : 0xF7;
                    immWidth = (dst.mem.size == 1) ? ImmWidth::I8 : (dst.mem.size == 2) ? ImmWidth::I16 : ImmWidth::I32;
                    if (req != ImmWidth::Auto) immWidth = (req == ImmWidth::I64) ? ImmWidth::I32 : req;
                }
                else
                {
                    if (dst.mem.size == 1)
                    {
                        opcode = 0x80;
                        immWidth = ImmWidth::I8;
                    }
                    else if (req == ImmWidth::I16)
                    {
                        if (dst.mem.size != 2) return false;
                        opcode = 0x81;
                        immWidth = ImmWidth::I16;
                    }
                    else if (req == ImmWidth::I32 || req == ImmWidth::I64)
                    {
                        if (dst.mem.size == 2) return false;
                        opcode = 0x81;
                        immWidth = ImmWidth::I32;
                    }
                    else
                    {
                        const ZyanI64 v = ImmAsSigned(srcImm);
                        if (FitsSigned8(v)) { opcode = 0x83; immWidth = ImmWidth::I8; }
                        else { opcode = 0x81; immWidth = (dst.mem.size == 2) ? ImmWidth::I16 : ImmWidth::I32; }
                    }
                }

                if (!CanEmitImmWidth(srcImm, immWidth)) return false;

                out.clear();
                if (dst.mem.size == 2) EmitU8(out, 0x66);

                std::vector<uint8_t> tail;
                uint8_t rex = 0;
                if (!EncodeModRmSibDisp(tail, mode, dst.mem, isTest ? 0 : groupExt, rex)) return false;

                if (dst.mem.size == 8)
                    rex |= 0x08;

                if (mode == ZYDIS_MACHINE_MODE_LONG_64 && rex != 0)
                    EmitU8(out, static_cast<uint8_t>(0x40 | rex));

                EmitU8(out, opcode);
                out.insert(out.end(), tail.begin(), tail.end());
                EmitImmediate(out, srcImm, immWidth);
                return true;
            }

            return false;
        }

		static bool TryExactEncodeLegacyImm(std::vector<uint8_t>& out,
			ZydisMachineMode mode,
			ZydisMnemonic mnemonic,
			std::initializer_list<Operand> ops,
			const BuildOptions& options)
		{
			if (ops.size() != 2)
				return false;

			auto it = ops.begin();
			const Operand& a = *it++;
			const Operand& b = *it;
			if (b.kind != Operand::Kind::Imm)
				return false;

			ImmWidth requested = b.imm.width != ImmWidth::Auto ? b.imm.width : options.force_imm_width;
			return EncodeAluImm(out, mode, mnemonic, a, b.imm, requested);
		}

		static void FillOperand(ZydisEncoderOperand& dst, const Operand& src)
		{
			dst = {};
			switch (src.kind)
			{
			    case Operand::Kind::Reg:
				    dst.type = ZYDIS_OPERAND_TYPE_REGISTER;
				    dst.reg.value = src.reg;
				    break;
			    case Operand::Kind::Imm:
				    dst.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
				    if (src.imm.signedValue) dst.imm.s = src.imm.s;
				    else dst.imm.u = src.imm.u;
				    break;
			    case Operand::Kind::Mem:
				    dst.type = ZYDIS_OPERAND_TYPE_MEMORY;
				    dst.mem.base = src.mem.base;
				    dst.mem.index = src.mem.index;
				    dst.mem.scale = src.mem.scale;
				    dst.mem.displacement = src.mem.displacement;
				    dst.mem.size = src.mem.size;
				    break;
			    case Operand::Kind::Ptr:
				    dst.type = ZYDIS_OPERAND_TYPE_POINTER;
				    dst.ptr.segment = src.ptr.segment;
				    dst.ptr.offset = src.ptr.offset;
				    break;
			}
		}
	}

	Operand Operand::Reg(ZydisRegister r)
	{
		Operand o;
		o.kind = Kind::Reg;
		o.reg = r;
		return o;
	}

	Operand Operand::Mem(ZydisRegister base, ZydisRegister index, ZyanU8 scale, ZyanI64 displacement, ZyanU16 size)
	{
		Operand o;
		o.kind = Kind::Mem;
		o.mem.base = base;
		o.mem.index = index;
		o.mem.scale = scale;
		o.mem.displacement = displacement;
		o.mem.size = size;
		return o;
	}

	Operand Operand::Ptr(ZyanU16 segment, ZyanU32 offset)
	{
		Operand o;
		o.kind = Kind::Ptr;
		o.ptr.segment = segment;
		o.ptr.offset = offset;
		return o;
	}

	bool BuildAsm(std::vector<uint8_t>& bytes,
		ZydisMachineMode mode,
		ZydisMnemonic mnemonic,
		std::initializer_list<Operand> ops,
		const BuildOptions& options,
		ZyanU64 runtimeAddress)
	{
		bytes.clear();

		if (detail::TryExactEncodeLegacyImm(bytes, mode, mnemonic, ops, options))
			return true;

		if (ops.size() > ZYDIS_ENCODER_MAX_OPERANDS)
			return false;

		ZydisEncoderRequest req{};
		req.machine_mode = mode;
		req.mnemonic = mnemonic;
		req.allowed_encodings = options.allowed_encodings;
		req.prefixes = options.prefixes;
		req.branch_type = options.branch_type;
		req.branch_width = options.branch_width;
		req.address_size_hint = options.address_size_hint;
		req.operand_size_hint = options.operand_size_hint;
		req.operand_count = static_cast<ZyanU8>(ops.size());

		std::size_t i = 0;
		for (const auto& op : ops)
			detail::FillOperand(req.operands[i++], op);

		std::array<ZyanU8, ZYDIS_MAX_INSTRUCTION_LENGTH> buffer{};
		ZyanUSize length = buffer.size();
		const ZyanStatus st = (runtimeAddress != 0)
			? ZydisEncoderEncodeInstructionAbsolute(&req, buffer.data(), &length, runtimeAddress)
			: ZydisEncoderEncodeInstruction(&req, buffer.data(), &length);

		if (!ZYAN_SUCCESS(st))
			return false;

		bytes.assign(buffer.begin(), buffer.begin() + static_cast<std::size_t>(length));
		return true;
	}
}


#if 0
void TestArBuilder()
{
    std::vector<uint8_t> bytes1;
    ArAsmCode::BuildAsm86(
        bytes1,
        ZYDIS_MNEMONIC_SHR,
        {
            ArAsmCode::Operand::Reg(ZYDIS_REGISTER_ECX),
            ArAsmCode::Operand::Imm(7)
        }
    );

    // shr ecx, ecx -> в x86 shift-by-register нужен CL
    std::vector<uint8_t> bytes2;
    ArAsmCode::BuildAsm86(
        bytes2,
        ZYDIS_MNEMONIC_SHR,
        {
            ArAsmCode::Operand::Reg(ZYDIS_REGISTER_ECX),
            ArAsmCode::Operand::Reg(ZYDIS_REGISTER_CL)
        }
    );

    {
        using namespace ArAsmCode;
        std::vector<uint8_t> bytes;

        // ==============================================
        // shr ecx, 7
        // ==============================================
        if (BuildAsm86Op2(bytes, ZYDIS_MNEMONIC_SHR, Operand::Reg(ZYDIS_REGISTER_ECX), Operand::Imm(7)))
        {
            printf("SHR ECX, 7: ");
            for (uint8_t b : bytes)
                printf("%02X ", b);
            printf(" (%zu байт)\n", bytes.size());
        }

        // ==============================================
        // shr ecx, cl
        // ==============================================
        if (BuildAsm86Op2(bytes, ZYDIS_MNEMONIC_SHR, Operand::Reg(ZYDIS_REGISTER_ECX), Operand::Reg(ZYDIS_REGISTER_CL)))
        {
            printf("SHR ECX, CL: ");
            for (uint8_t b : bytes)
                printf("%02X ", b);
            printf(" (%zu байт)\n", bytes.size());
        }

        // ==============================================
        // mov [eax + ecx*4 + 8], 0x1234
        // ==============================================
        if (BuildAsm86Op2(bytes, ZYDIS_MNEMONIC_MOV,
            Operand::Mem(ZYDIS_REGISTER_EAX,   // base
                ZYDIS_REGISTER_ECX,   // index
                4,                    // scale
                8,                    // displacement
                4),                   // size (DWORD)
            Operand::Imm(0x1234)))
        {
            printf("MOV DWORD [EAX+ECX*4+8], 0x1234: ");
            for (uint8_t b : bytes) printf("%02X ", b);
            printf("\n");
        }

        // ==============================================
        // call 0x12345678 (32-битный режим)
        // ==============================================
        if (BuildAsm86At(bytes, ZYDIS_MNEMONIC_CALL,
            { Operand::Imm(0x12345678) },  // Абсолютный адрес
            0x13371337))                   // Текущий адрес инструкции
        {
            printf("CALL 0x12345678: ");
            for (uint8_t b : bytes)
                printf("%02X ", b);
            printf(" (%zu байт)\n", bytes.size());
        }
    }
}
#endif

#if 0
void IatTestUC()
{
    AsmRunner runner(false);
    void* pEntry = addr(0x62E4686F);

    MboxSTD("VMENTRY_UT_HK", "hold");

    //uintptr_t pStart = 0;
    //uintptr_t pEnd = 0;
    //uintptr_t nSize = 0;
    //runner.GetMappedModuleBounds(STEAM_LIB, pStart, pEnd, nSize);

    //if (nSize == 0 || pStart == 0)
    //{
    //	MboxSTD("VMENTRY_UT_HK", "module not found");
    //	return;
    //}

    //printf("[%s] base=0x%p end=0x%p size=0x%zx\n", STEAM_LIB, (void*)pStart, (void*)pEnd, (size_t)nSize);

    auto OpcodeCb = [](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        printf("OpcodeCb 0x%p (%d)\n", (void*)address, mnemonic);

        //std::vector<uint8_t> bytes(size);
        //if (uc_mem_read(uc, address, bytes.data(), size) != UC_ERR_OK) {
        //	printf("[!] Failed to read bytes at 0x%p\n", (void*)address);
        //	return true; // продолжаем, но логируем ошибку
        //}

        //if (bytes[0] == 0xC3) { // tmp
        //	printf("[RET] at 0x%p\n", (void*)address);
        //	return false; // если хочешь остановиться на RET
        //}

        // Ничего не делаем, просто возвращаем true (продолжаем выполнение)
        return true;
    };

    auto MemCb = [](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
        //printf("MemCb 0x%p\n", (void*)address);

        return true;
    };

    auto JmpCb = [](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);

        printf("JmpCb 0x%p %d\n", (void*)to, mnemonic);

        if (!self->IsPCNormal(to)) {
            MboxSTD("module escape", "asm runner");
            return false;
        }

        return true;
    };

    runner.Initialise(true, false, false, true);      // disasm + memrw + runner logs
    runner.InitialiseSymMap("idasym.txt", 0x60F00000); // IDB base -> RVA map
    //runner.CopyModule(pStart, nSize);         // копируем модуль в Unicorn по тому же base
    runner.CopyModule(STEAM_LIB);
    runner.SetCallbacks(OpcodeCb, &runner, MemCb, &runner, JmpCb, &runner);
    //runner.TraceInstruction("C:\\trace.txt", reinterpret_cast<uintptr_t>(pEntry), 300); return; // автостарт

    // Пример бряка по адресу
    // runner.SetBreakpoint(reinterpret_cast<uintptr_t>(pEntry), [](AsmRunner*, uint64_t a){ printf("BP hit 0x%llx\n", (unsigned long long)a); }, true);

    printf("[*] entry=0x%p\n", pEntry);

    runner.Run(reinterpret_cast<uintptr_t>(pEntry), 300); // 0 = без лимита по шагам
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
    auto OpcodeCb = [](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        //printf("OpcodeCb 0x%p (%d)\n", (void*)address, mnemonic);
        self->DumpRegisters(true);
        return true;
    };

    auto MemCb = [](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
        //printf("MemCb 0x%p\n", (void*)address);
        return true;
    };

    auto JmpCb = [](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);

        printf("JmpCb 0x%p %d\n", (void*)to, mnemonic);

        if (!self->IsPCNormal(to)) {
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
    uintptr_t pEntryArg2 = runner.AddMemory(strlen(pArg) + 1, UC_PROT_READ | UC_PROT_WRITE, true);
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

void TestInsnHookCpuid()
{
    AsmRunner runner(false);
    runner.Initialise(true, false, false, true);  // disasm + memrw + runner logs

    // xor eax,eax; xor ecx,ecx; cpuid; nop; ret
    static const uint8_t code[] = {
        0x31, 0xC0,       // xor eax, eax
        0x31, 0xC9,       // xor ecx, ecx
        0x0F, 0xA2,       // cpuid
        0x90,             // nop
        0xC3              // ret
    };
    uintptr_t pVEntry = runner.GetRandomEntryPoint();
    runner.CopyModule(pVEntry, (uintptr_t)code, sizeof(code));

    auto OpcodeCb = [](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        printf("[OPCODE] pc=0x%p size=%u mn=%d\n", (void*)address, (unsigned)size, (int)mnemonic);
        return true;
    };

    //runner.SetInsnCB(
    //	UC_X86_INS_CPUID,
    //	[](uc_engine* uc, uintptr_t address, uint32_t size, uintptr_t nUcInsn, ZydisMnemonic mnemonic, void* user_data) -> bool {
    //		auto* self = static_cast<AsmRunner*>(user_data);
    //		if (!self || !uc)
    //			return true;

    //		MboxSTD("CPUID hook hit!", "TestInsnHookCpuid");
    //		printf("[INSN] CPUID hit: pc=0x%p size=%u insn=%zu mn=%d\n",
    //			(void*)address, (unsigned)size, (size_t)nUcInsn, (int)mnemonic);

    //		// Опционально: подставить фейковые значения в регистры
    //		// self->SetRegister(UC_X86_REG_EAX, 0x00000F43); // Vendor: GenuineIntel
    //		// self->SetRegister(UC_X86_REG_EBX, 0x756E6547); // "Genu"
    //		// self->SetRegister(UC_X86_REG_ECX, 0x6C65746E); // "inel"
    //		// self->SetRegister(UC_X86_REG_EDX, 0x49656E69); // "Ieni"

    //		// Пропускаем инструкцию CPUID (переходим к следующей)
    //		self->UpdatePC(address + size, true);
    //		return true; // continue execution
    //	},
    //	&runner);

    runner.SetAllInsnCB(
        [&](uc_engine* uc, uintptr_t address, uint32_t size, uintptr_t nUcInsn, ZydisMnemonic mnemonic, void* user_data) -> bool {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            MboxSTD("Warn! UC_HOOK_INSN SetAllInsnCB!!!!", AR_SNAME);
            return true;
        },
        &runner);

    auto MemCb = [](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d\n", (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic);
        return true;
    };

    auto JmpCb = [](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        printf("[JMP] from 0x%p to 0x%p\n", (void*)from, (void*)to);
        return true;
    };

    runner.SetCallbacks(OpcodeCb, &runner, MemCb, &runner, JmpCb, &runner);

    printf("[*] CPUID test entry point: 0x%p\n", (void*)pVEntry);
    printf("[*] Expected execution: XOR EAX,EAX -> XOR ECX,ECX -> CPUID (hook) -> NOP -> RET\n");
    uc_engine* uc = runner.GetCTX();

    // old and wrong test fs/base behav
    //{
    //	// ============ FS (селектор) ============
    //	// 1. Чтение FS
    //	uint16_t fs_selector;
    //	auto err = uc_reg_read(uc, UC_X86_REG_FS, &fs_selector);
    //	if (!err) {
    //		printf("[READ] FS selector = 0x%04x\n", fs_selector);
    //	}
    //	else {
    //		printf("[READ] FS selector ERROR: %s\n", uc_strerror(err));
    //	}

    //	// 2. Запись FS
    //	uint16_t new_fs = (0x003B*0)+4;  // 32-bit селектор
    //	err = uc_reg_write(uc, UC_X86_REG_FS, &new_fs);
    //	if (!err) {
    //		printf("[WRITE] FS selector set to 0x%04x\n", new_fs);
    //	}
    //	else {
    //		printf("[WRITE] FS selector ERROR: %s\n", uc_strerror(err));
    //	}

    //	// 3. Чтение FS после записи
    //	uint16_t fs_after;
    //	err = uc_reg_read(uc, UC_X86_REG_FS, &fs_after);
    //	if (!err) {
    //		printf("[READ AGAIN] FS selector = 0x%04x\n", fs_after);
    //	}
    //	else {
    //		printf("[READ AGAIN] FS selector ERROR: %s\n", uc_strerror(err));
    //	}

    //	// ============ FS_BASE (скрытая часть) ============
    //	// 4. Чтение FS_BASE
    //	uint64_t fs_base;
    //	err = uc_reg_read(uc, UC_X86_REG_FS_BASE, &fs_base);
    //	if (!err) {
    //		printf("[READ] FS_BASE = 0x%016llx\n", (unsigned long long)fs_base);
    //	}
    //	else {
    //		printf("[READ] FS_BASE ERROR: %s\n", uc_strerror(err));
    //	}

    //	// 5. Запись FS_BASE
    //	uint64_t new_fs_base = 0x7ffdf000;  // TEB
    //	err = uc_reg_write(uc, UC_X86_REG_FS_BASE, &new_fs_base);
    //	if (!err) {
    //		printf("[WRITE] FS_BASE set to 0x%016llx\n", (unsigned long long)new_fs_base);
    //	}
    //	else {
    //		printf("[WRITE] FS_BASE ERROR: %s\n", uc_strerror(err));
    //	}

    //	// 6. Чтение FS_BASE после записи
    //	uint64_t fs_base_after;
    //	err = uc_reg_read(uc, UC_X86_REG_FS_BASE, &fs_base_after);
    //	if (!err) {
    //		printf("[READ AGAIN] FS_BASE = 0x%016llx\n", (unsigned long long)fs_base_after);
    //	}
    //	else {
    //		printf("[READ AGAIN] FS_BASE ERROR: %s\n", uc_strerror(err));
    //	}
    //}


    runner.Run(pVEntry, 0);
    runner.Shutdown();
    MboxSTD("Test completed", "TestInsnHookCpuid");
}

void TESTA()
{
    //AsmRunner::DumpModuleToFile((uintptr_t)gpSteamCRCDUPL, "MOD.DLL");
#define T93

#ifdef T93
#define _TADDR(_p) (_p - 0x12290000 + 0x13260000)
    static const char* szMod = "ardump_0x13260000_steamclient.dll";
    static const char* szModIAT = "ENV_ardump_0x13260000_steamclient.txt";
    static uintptr_t pModBase = _TADDR(0x12290000);
    static uintptr_t pEntry = _TADDR(0x12347700);
    static uintptr_t pEntryArg = _TADDR(0x126190F8);
    static uintptr_t pRedLogStart = _TADDR(0x13960000);
    static uintptr_t pRedLogEnd = _TADDR(0x14194000);
    static uintptr_t pPostSend = _TADDR(0x12346020); // f
    static uintptr_t pMd5 = _TADDR(0x12400D70); // f
    static uintptr_t pMemcpy = _TADDR(0x1250A700); // f
    static uintptr_t pRand = _TADDR(0x12520A97); // f // by vc32 flirt sig
    static uintptr_t pAes128E = _TADDR(0x123FDC90); //f EVP_EncryptInit_ex
    static uintptr_t pAes128U = _TADDR(0x123FDCB0); //f _EVP_EncryptUpdate
    static uintptr_t pMd5Buff = _TADDR(0x12609700);
    static uintptr_t pnSteamID_SHL1 = _TADDR(0x126193AC); // 0x0E8B0D6C6 // 3903903430 // 1951951715*2
#else
#define _TADDR(_p) (_p - 0x60F00000 + 0x60F00000)
    //static const char* szMod = "steamclient_dump_0x60F00000.dll";
    static const char* szMod = "MOD.DLL";
    static uintptr_t pModBase = _TADDR(0x60F00000);
    static uintptr_t pEntry = _TADDR(0x60F2F0C0);
    static uintptr_t pEntryArg = _TADDR(0x615CDB58);
    static uintptr_t pRedLogStart = _TADDR(0x629D5000);
    static uintptr_t pRedLogEnd = _TADDR(0x630DD000); // size: 0x708000
#endif
    const bool bBefore = false;
    const bool bFromState = true;
    AsmRunner runner(false);

    runner.Initialise(true, false, false, true, !bFromState);
    //runner.DumpRegisters();
#ifdef T93
    runner.LoadIATEnv(szModIAT);
#else
    runner.SetIAT(0, 0, false); // collect temp ENV
#endif
    //runner.CompressDiffs({ "trace_0.txt", "trace_1.txt", "trace_2.txt" }, "trace_cmp3.txt");
    //runner.CompressDiffs({ "trace_0.txt", "trace_1.txt" }, "trace_cmp2.txt");
    //MboxSTD("CompressDiffs", "CompressDiffs");

    if (!bFromState)
    {
        //runner.CopyModule(szMod); // from nt
        FILE* f = runner.FileOpen(szMod, "rb");
        if (f) {
            uintptr_t sz = (uintptr_t)runner.FileSize(f);
            char* buf = (char*)malloc(sz);
            runner.FileRead(f, buf, sz);
            runner.FileClose(f);
            runner.CopyModule(pModBase, (uintptr_t)buf, sz);
            free(buf);
        }
    }
    else {
        runner.LoadRunStateEnvFile("1-800-000.bin", false); // try avoid fakin crash smc code with broken tcg qemu
    }

    //pEntry = _TADDR(0x123BD890);
    //pEntryArg = runner.AddMemory(0x1A0, UC_PROT_ALL, true);
    //runner.WriteMemory<uint32_t>(_TADDR(0x1260F444), 440);
    runner.MemSet(_TADDR(0x12347891), 0x90, 5); // vmentry build post args
    //runner.SetRWHistory(true);
    //1'953'613
    //[9'160'676] BFCB 0x139BBC25 ( +0x172BC25): ret 0x00 ; [0xC2 0x00 0x00]

    auto OpcodeCb = [&](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        //printf("OpcodeCb 0x%p (%d)\n", (void*)address, mnemonic);
        //self->DumpRegisters(true);
        //self->DumpSegmentRegisters();
        if (self->IsInAddr(address, pRedLogStart, pRedLogEnd)) {
            SetConsoleColor(0); // red
        }
        else {
            SetConsoleColor(1);
        }

        //if (self->GetInstructionCount() > 1'953'610)
        if (self->GetInstructionCount() > 1'825'000) // 1'825'433
        {
            //self->SetLogDisasm(true);
            //self->DumpStack(10);
            //self->DumpRegisters();
            //printf("OpcodeCb 0x%p (%d)\n", (void*)address, mnemonic);
            //MboxSTD("GetInstructionCount", "OpcodeCb");
        }
        else {
            self->SetLogDisasm(false);
            //self->SetRWHistory(true);
        }

        if (self->GetInstructionCount() == 1'800'000 && !bFromState) {
            self->Dump();
            printf("s 0x%p %d\n", address, size);
            self->DumpMemory(address, size);
            self->SaveRunStateEnvFile("1-800-000.bin");
            MboxSTD("saved", "OpcodeCb");
        }

        //if (self->GetInstructionCount() == 1'825'433)
        if (self->GetInstructionCount() > 1'825'425)
        {
            //self->Pause();
            //self->Resume();
            //if(!self->IsLogDisasm()) self->SaveRunStateEnvFile("1-825-425.bin");
            self->SetLogDisasm(true);
            //self->DumpRWHistorySelfModifying(_TADDR(0x13960000), _TADDR(0x14194000));
            //self->UpdatePC(_TADDR(0x13B54BFA), true); // это пиздец, крашит прыжок tb_add_jump
            MboxSTD("warnnn", "OpcodeCb");
            //self->RequestShutdown(true);
            //self->RemapModule();
            //self->HardReset();
            //self->DumpRegisters();
            return true;
        }
        // todo env save+load, allocfreemap

        //if (address == _TADDR(0x12520AB8)) { // srand
        //	self->DumpStack(10);
        //	MboxSTD("bp", "OpcodeCb");
        //}
        //if (address == _TADDR(0x123BD8CE)) { // srand
        //	self->DumpRegisters();
        //	MboxSTD("bpr", "OpcodeCb");
        //}
        //if (address == _TADDR(0x12512CCE)) { // srand
        //	self->DumpRegisters();
        //	MboxSTD("bpr02", "OpcodeCb");
        //}

        // 4'304'724 // memset0 stack 0x001F0D3C 16byte iv
        // smth
        // 4'363'102 // __time32 - GetSystemTimeAsFileTime 4'363'628 iat wrapper end (__time32 start)
        // 4'495'273 rand
        // 4'619'720 // Write 1st key // 4'619'132 with hook

        if (self->GetInstructionCount() >= 4'495'273) {
            //self->SetPCTraceFull("trace.txt", nullptr, true, 0, 0, 0, true, true, true, true, true, false, false);
        }
        if (self->GetInstructionCount() > /*4'619'720*/ 4'619'132) { // 132 hook
            //return false;
        }

        //uintptr_t outReg = 0;
        //std::string outName = "";
        //if (self->IsAnyReg((uintptr_t)'$eJ%', outReg, outName)) {
        //	MboxSTD("IsAnyReg", "OpcodeCb");
        //}

        // log change funcs
        if (self->IsSymMapInitialised()) {
            static const tFuncNode* lastsym = nullptr;
            const tFuncNode* sym = self->FindSymbolByRuntime(address);
            if (sym && sym != lastsym) {
                printf("%s\n", sym->funcName.c_str());
                lastsym = sym;

                //if (self->GetInstructionCount() > 4'304'723) {
                //	MboxSTD("apply ch", "OpcodeCb");
                //}
            }
        }

        return true;
    };

    static uintptr_t slpSystemTimeAsFileTime = 0;
    static uintptr_t n1 = 0;

    auto MemCb = [&](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        bool isRead = (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT || type == UC_MEM_READ_AFTER);
        bool isWrite = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT);
        bool isAnyFetch = (type == UC_MEM_FETCH || type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT); // code read
        uintptr_t a = self->CalcWithCASLR(address);

        //printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n", (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);
        if (!self || !uc || size == 0)
            return true;

        // TODO capture virtualalloc ranges
        if (self->IsInAddr(address, self->GetFSTEBStart(), self->GetFSTEBEnd())) {
            printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);
            //MboxSTD("Warn! access TID", "MemCb");
        }
        else if (!self->IsInAddr(address, self->GetModStart(), self->GetModEnd()) &&
            !self->IsInAddr(address, self->GetStackStart(), self->GetStackEnd())) {
            //printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
            //	(void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite); // todo filter out malloc ranges
            //MboxSTD("Warn! access smth outside the module", "MemCb");
        }

        if (slpSystemTimeAsFileTime != 0 && self->IsInAddr(address, slpSystemTimeAsFileTime, slpSystemTimeAsFileTime + 8)) {
            printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n", (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);
            //self->SetLogDisasm(true);
            //self->DisassembleWithZydis(true);
            MboxSTD("slpSystemTimeAsFileTime", "MemCb");

        }

        //$eJ%sY^7DkIbD%e#
        //if (self->IsInAddr(address, 0x001F0D3C, 0x001F0D3C + 16) && isWrite) {
        //	n1++;
        //	if (n1 > 5) {
        //		self->DumpMemory(0x001F0D3C, 16);
        //		//self->SetRWHistory(true);
        //		//self->SetPCTraceFull("trace.txt", nullptr, true, 0, 0, 0, true, true, true, true, true, false, true);
        //		if (n1 > 7) { // 6 before time
        //			//self->SetPCTrace("trace.txt", nullptr, true, 0x12290000, /*9'500'000*/0, 3 * 0); // def
        //			//self->DumpStack(50);
        //			//self->DumpRegisters();
        //			//self->WaitBuff(self->GetStackMinAddrBP(), self->GetStackMaxAddrSP() - self->GetStackMinAddrBP());
        //			//self->DumpRWHistoryFile("_HIS" + std::to_string(n1) + ".txt");
        //			//self->ClearRWHistory();
        //		}
        //		if (n1 > 8) {
        //			//return false;
        //		}

        //		printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n", (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);
        //		self->DumpMemoryVal(value, size);
        //		//self->SetLogDisasm(true);
        //		//self->DisassembleWithZydis(true);
        //		//MboxSTD("0x001F0D3C", "MemCb");
        //	}
        //}


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
            printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

            self->DumpRegisters();
            //self->DumpRWHistory();
            SetConsoleColor(3);
            tFuncNode* sym = self->FindSymbolByRuntime(address); // iat and symmap
            if (sym) printf("%s\n", sym->GetAbsoluteName().c_str());
            printf("[!] Unmapped access at 0x%p, mapping 0x%zx bytes from 0x%p size 0x%zx bytes\n", (void*)address, (size_t)mapSize, (void*)base, size);
            MboxSTD("Warn! isUnmapped", "MemCb");

            if (!self->AddMemoryTo(base, mapSize, UC_PROT_READ | UC_PROT_WRITE))
                //if (!self->AddMemoryTo(address, size, UC_PROT_READ | UC_PROT_WRITE))
            {
                printf("[!] Failed to map region at 0x%p\n", (void*)base);
                SetConsoleColor(1);
                return false;
            }

            printf("[+] Created Region at 0x%p [0x%zx]\n", (void*)base, (size_t)mapSize);
            SetConsoleColor(1);

            // 0x76F60A40 [1] 0xC3 DbgBreakPoint
            // 0x767A003C [4] 0xF0 0x00 0x00 0x00 kernel32 this program
            //if (address == 0x76F60A40)
            //	self->WriteMemory<uint8_t>(address, 0xC3); // todo GetCurrentProcess
            if (address == 0x767A003C)
                self->WriteMemory<uint32_t>(address, 0x00'00'00'F0);

            //if (self->IsNTMemoryReadable(address, size))
            //{ // custom // themida read correct crc // 0x4F238ED8
            //	//self->CompareRegionsSnapshots(regionsBF, regionsAF);
            //	self->CopyMemory(address, address, size); // maping equal in native proc // докопирую данные в которые оно лезет, где то зашит регион в vmctx
            //	self->DumpMemory(address, size); // uc copy result view
            //	//MboxSTD("custom wait", "MemCb");
            //}
            //else
            //	MboxSTD("cant read nt", "MemCb");

            return true;
        }

        if (isProt)
        {
            printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

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

    auto JmpCb = [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        if (self->IsHaltAddr(to))
            return true; // actual false



        //printf("JmpCb 0x%p %d\n", (void*)to, mnemonic);

        if (!self->IsPCNormal(to)) {
            tFuncNode* pNode = self->FindIATNode(to); // nullable

            printf("JmpCb 0x%p %d %s\n", (void*)to, mnemonic, pNode ? pNode->GetAbsoluteName().c_str() : "");
            MboxSTD("module escape", "asm runner");
            return false;
        }

        return true;
    };

    runner.SetCallbacks(OpcodeCb, &runner, MemCb, &runner, JmpCb, &runner);

    //runner.SetMemoryRangeCB(tRange(_TADDR(0x12544000), _TADDR(0x1395D000)), [&](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size,
    //		uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
    //			auto* self = static_cast<AsmRunner*>(user_data);
    //			bool isRead = (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT || type == UC_MEM_READ_AFTER);
    //			bool isWrite = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT);
    //			bool isAnyFetch = (type == UC_MEM_FETCH || type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT); // code read

    //			uintptr_t a = self->CalcWithCASLR(address);

    //			if (self->GetInstructionCount() >= 4'495'273) {
    //				//self->SetPCTraceFull("trace.txt", nullptr, true, 0, 0, 0, true, true, true, true, true, false, false);

    //				printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
    //					(void*)a, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

    //				MboxSTD("SetMemoryRangeCB", "asm runner");
    //			}


    //			return true;
    //	},
    //	&runner);

    {
        runner.SetAnyJmpHook(runner.FindIATNode("RtlEnterCriticalSection", "ntdll.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
                ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                //cb(FindIATNode("RtlEnterCriticalSection", "ntdll.dll"));

                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                const bool bShouldPopArgs_NoCdecl = true;

                uintptr_t pCs = 0;
                uintptr_t retaddr = 0;

                if (bBefore)
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                else if (!self->StackPop(retaddr))
                    return false;

                if (!self->StackGetArg(pCs, 0, bShouldPopArgs_NoCdecl))
                    return false;

                DWORD tid = GetCurrentThreadId();

                int32_t lockCount = self->ReadMemory<int32_t>(pCs + 4);
                uint32_t owner = self->ReadMemory<uint32_t>(pCs + 12);

                if (lockCount == -1)
                {
                    self->WriteMemory<int32_t>(pCs + 4, 0);
                    self->WriteMemory<int32_t>(pCs + 8, 1);
                    self->WriteMemory<uint32_t>(pCs + 12, tid);
                }
                else if (owner == tid)
                {
                    auto rec = self->ReadMemory<int32_t>(pCs + 8);
                    self->WriteMemory<int32_t>(pCs + 8, rec + 1);
                }
                else
                {
                    printf("[RtlEnterCriticalSection] contention detected, forcing ownership\n");

                    self->WriteMemory<int32_t>(pCs + 4, 0);
                    self->WriteMemory<int32_t>(pCs + 8, 1);
                    self->WriteMemory<uint32_t>(pCs + 12, tid);
                }

                printf("[RtlEnterCriticalSection] CriticalSection=0x%p lock=%d owner=0x%X tid=0x%X ret=0x%p\n",
                    (void*)pCs,
                    lockCount,
                    owner,
                    tid,
                    (void*)retaddr);

                self->SetRegister(self->AxReg(), 0);
                self->UpdatePC(retaddr, true);
                //MboxSTD("RtlEnterCriticalSection", "hold");

                return true;
            }, &runner, bBefore, false, runner.FindIATNode("RtlEnterCriticalSection", "ntdll.dll")->GetAbsoluteName());


        runner.SetAnyJmpHook(runner.FindIATNode("RtlLeaveCriticalSection", "ntdll.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
                ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                //cb(FindIATNode("RtlLeaveCriticalSection", "ntdll.dll"));

                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                const bool bShouldPopArgs_NoCdecl = true;

                uintptr_t pCs = 0;
                uintptr_t retaddr = 0;

                if (bBefore)
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                else if (!self->StackPop(retaddr))
                    return false;

                if (!self->StackGetArg(pCs, 0, bShouldPopArgs_NoCdecl))
                    return false;

                int32_t rec = self->ReadMemory<int32_t>(pCs + 8);

                printf("[RtlLeaveCriticalSection] CriticalSection=0x%p RecursionCount=%d ret=0x%p\n",
                    (void*)pCs,
                    rec,
                    (void*)retaddr);

                if (rec > 1)
                {
                    self->WriteMemory<int32_t>(pCs + 8, rec - 1);
                }
                else
                {
                    self->WriteMemory<int32_t>(pCs + 8, 0);
                    self->WriteMemory<uint32_t>(pCs + 12, 0);
                    self->WriteMemory<int32_t>(pCs + 4, -1);
                }

                self->SetRegister(self->AxReg(), 0);
                self->UpdatePC(retaddr, true);
                //MboxSTD("RtlLeaveCriticalSection", "hold");

                return true;
            }, &runner, bBefore, false, runner.FindIATNode("RtlLeaveCriticalSection", "ntdll.dll")->GetAbsoluteName());

        runner.SetAnyJmpHook(runner.FindIATNode("RtlAllocateHeap", "ntdll.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
                ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                //cb(FindIATNode("RtlAllocateHeap", szModule));

                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                const bool bShouldPopArgs_NoCdecl = true;

                uintptr_t hHeap = 0;
                uintptr_t dwFlags = 0;
                uintptr_t dwBytes = 0;
                uintptr_t retaddr = 0;

                if (bBefore)
                {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr))
                {
                    return false;
                }

                if (!self->StackGetArg(hHeap, 0, bShouldPopArgs_NoCdecl))   return false;
                if (!self->StackGetArg(dwFlags, 1, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(dwBytes, 2, bShouldPopArgs_NoCdecl)) return false;

                printf("[RtlAllocateHeap] Heap=0x%p Flags=0x%p Size=0x%p ret=0x%p\n",
                    (void*)hHeap,
                    (void*)dwFlags,
                    (void*)dwBytes,
                    (void*)retaddr);

                uintptr_t result = 0;

                if (dwBytes != 0)
                {
                    result = self->AddMemory(dwBytes, UC_PROT_ALL, true);

                    if ((dwFlags & HEAP_ZERO_MEMORY) && result)
                    {
                        std::vector<uint8_t> zero(dwBytes, 0);
                        self->CopyMemory(result, (uintptr_t)zero.data(), zero.size());
                    }

                    printf("[RtlAllocateHeap] Allocated %zu bytes -> 0x%p\n",
                        (size_t)dwBytes,
                        (void*)result);
                }

                self->SetRegister(self->AxReg(), result);
                self->UpdatePC(retaddr, true);
                //MboxSTD("RtlAllocateHeap", "hold");

                return true;
            }, &runner, bBefore, false, runner.FindIATNode("RtlAllocateHeap", "ntdll.dll")->GetAbsoluteName());

        runner.SetAnyJmpHook(runner.FindIATNode("RtlFreeHeap", "ntdll.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
                ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                //cb(FindIATNode("RtlFreeHeap", szModule));

                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                const bool bShouldPopArgs_NoCdecl = true;

                uintptr_t hHeap = 0;
                uintptr_t dwFlags = 0;
                uintptr_t lpMem = 0;
                uintptr_t retaddr = 0;

                if (bBefore)
                {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr))
                {
                    return false;
                }

                if (!self->StackGetArg(hHeap, 0, bShouldPopArgs_NoCdecl))   return false;
                if (!self->StackGetArg(dwFlags, 1, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(lpMem, 2, bShouldPopArgs_NoCdecl))   return false;

                printf("[RtlFreeHeap] Heap=0x%p Flags=0x%p Mem=0x%p ret=0x%p\n",
                    (void*)hHeap,
                    (void*)dwFlags,
                    (void*)lpMem,
                    (void*)retaddr);

                BOOLEAN result = TRUE;

                if (lpMem)
                {
                    self->FreeMemory(lpMem);
                    printf("[RtlFreeHeap] Freed 0x%p\n", (void*)lpMem);
                }

                self->SetRegister(self->AxReg(), result);
                self->UpdatePC(retaddr, true);
                //MboxSTD("RtlFreeHeap", "hold");

                return true;
            }, &runner, bBefore, false, runner.FindIATNode("RtlFreeHeap", "ntdll.dll")->GetAbsoluteName());
    }


    {
        runner.SetAnyJmpHook(runner.FindIATNode("GetProcessHeap", "kernel32.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
                ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                //cb(FindIATNode("GetProcessHeap", szModule));

                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                uintptr_t retaddr = 0;

                if (bBefore)
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                else if (!self->StackPop(retaddr))
                    return false;

                // Один глобальный heap для процесса.
                static constexpr uintptr_t kFakeProcessHeap = 0x13370000;

                printf("[GetProcessHeap] returning 0x%p ret=0x%p\n",
                    (void*)kFakeProcessHeap,
                    (void*)retaddr);

                self->SetRegister(self->AxReg(), kFakeProcessHeap);
                self->UpdatePC(retaddr, true);
                //MboxSTD("GetProcessHeap", "hold");

                return true;
            }, & runner, bBefore, false, runner.FindIATNode("GetProcessHeap", "kernel32.dll")->GetAbsoluteName());
        // srand(time(NULL))
        runner.SetAnyJmpHook(runner.FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                //hcb(self->FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll"));

                //self->DumpRegisters();
                //self->DumpStack(7);
                //MboxSTD("custom wait", "GetSystemTimeAsFileTime");

                printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                    (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

                const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

                // Получаем аргументы
                uintptr_t lpSystemTimeAsFileTime = 0;
                uintptr_t retaddr = 0;
                if (bBefore) {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr)) {
                    return false;
                }

                if (!self->StackGetArg(lpSystemTimeAsFileTime, 0, bShouldPopArgs_NoCdecl)) return false;

                printf("[GetSystemTimeAsFileTime] lpSystemTimeAsFileTime=0x%p\n", (void*)lpSystemTimeAsFileTime);

                FILETIME ft = { 0 };

#if 0
                GetSystemTimeAsFileTime(&ft);
#else
                static FILETIME s_ft = { 0 };
                static BOOL bInitialized = FALSE;

                if (!bInitialized)
                {
                    GetSystemTimeAsFileTime(&s_ft);
                    bInitialized = TRUE;
                    printf("[GetSystemTimeAsFileTime] Static time initialized: 0x%08X%08X\n",
                        s_ft.dwHighDateTime, s_ft.dwLowDateTime);
                }

                ft = s_ft;
#endif
                //slpSystemTimeAsFileTime = lpSystemTimeAsFileTime;
                //self->SetLogDisasm(true);

                //ft = 0x01DD0590972804C6; // NERzZEBYQkt4ZF5nSzcoUxCs_gLK6Bh50pc3tWiZeX3AtcgFUaPqVyEDkWnASFj2
                ft.dwHighDateTime = 0x01DD0590; // 4Dsd@XBKxd^gK7(S
                ft.dwLowDateTime = 0x972804C6;
                //ft.dwHighDateTime = 0x0; // $eJ%sY^7DkIbD%e#
                //ft.dwLowDateTime = 0x0; // $eJ%sY^7DkIbD%e#
                //ft.dwLowDateTime = 0x1; // &wfu93)s0eIT40*n
                //ft.dwLowDateTime = 0x2; // &wfu93)s0eIT40*n
                //ft.dwLowDateTime = 0x6; // &wfu93)s0eIT40*n
                //MboxSTD("custom wait", "GetSystemTimeAsFileTime");

                //// Базовые значения
                //ft.dwHighDateTime = 0x00000000;
                //ft.dwLowDateTime = 0x00000000;  // Ожидается: "$eJ%sY^7DkIbD%e#"

                //ft.dwHighDateTime = 0x00000001;
                //ft.dwLowDateTime = 0x00000000;  // Изменение старшей части

                //ft.dwHighDateTime = 0x00000000;
                //ft.dwLowDateTime = 0x00000001;  // Изменение младшей части

                //// Степени двойки (для проверки битовых операций)
                //ft.dwHighDateTime = 0x00000000;
                //ft.dwLowDateTime = 0x00000001;  // 2^0
                //ft.dwLowDateTime = 0x00000002;  // 2^1
                //ft.dwLowDateTime = 0x00000004;  // 2^2
                //ft.dwLowDateTime = 0x00000008;  // 2^3
                //ft.dwLowDateTime = 0x00000010;  // 2^4
                //ft.dwLowDateTime = 0x00000020;  // 2^5
                //ft.dwLowDateTime = 0x00000040;  // 2^6
                //ft.dwLowDateTime = 0x00000080;  // 2^7

                //// Комбинации битов
                //ft.dwLowDateTime = 0x00000003;  // 0b11
                //ft.dwLowDateTime = 0x00000005;  // 0b101
                //ft.dwLowDateTime = 0x0000000A;  // 0b1010
                //ft.dwLowDateTime = 0x0000000F;  // 0b1111

                //// Максимальные значения
                //ft.dwHighDateTime = 0xFFFFFFFF;
                //ft.dwLowDateTime = 0xFFFFFFFF;

                //// Случайные значения для проверки
                //ft.dwHighDateTime = 0x12345678;
                //ft.dwLowDateTime = 0x9ABCDEF0;

                //ft.dwHighDateTime = 0xDEADBEEF;
                //ft.dwLowDateTime = 0xCAFEBABE;

                //// Дата/время (реальные FILETIME)
                //ft.dwHighDateTime = 0x01D9B8E0;  // 2024-01-01
                //ft.dwLowDateTime = 0x00000000;

                //ft.dwHighDateTime = 0x01D9B8E0;  // 2024-01-01 12:00:00
                //ft.dwLowDateTime = 0x1B774000;

                printf("[GetSystemTimeAsFileTime] result: 0x%08X%08X\n", ft.dwHighDateTime, ft.dwLowDateTime);

                // Записываем результат обратно в память эмулятора
                if (lpSystemTimeAsFileTime)
                    self->CopyMemory(lpSystemTimeAsFileTime, (uintptr_t)&ft, sizeof(FILETIME));

                self->UpdatePC(retaddr, true);

                return true;
            }, & runner, bBefore, false, runner.FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll")->GetAbsoluteName());

        runner.SetAnyJmpHook(runner.FindIATNode("Sleep", "kernel32.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                //hcb(self->FindIATNode("Sleep", "kernel32.dll"));

                printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                    (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

                const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

                // Получаем аргументы
                uintptr_t dwMilliseconds = 0;
                uintptr_t retaddr = 0;
                if (bBefore) {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr)) {
                    return false;
                }

                if (!self->StackGetArg(dwMilliseconds, 0, bShouldPopArgs_NoCdecl)) return false;

                printf("[Sleep] dwMilliseconds=0x%X\n", dwMilliseconds);

                self->UpdatePC(retaddr, true);

                return true;
            }, & runner, bBefore, false, runner.FindIATNode("Sleep", "kernel32.dll")->GetAbsoluteName());

        runner.SetAnyJmpHook(runner.FindIATNode("GetLastError", "kernel32.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
                ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                //cb(FindIATNode("GetLastError", "kernel32.dll"));

                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                uintptr_t retaddr = 0;

                if (bBefore)
                {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr))
                {
                    return false;
                }
                uintptr_t err = self->GetFSTEBLastError();
                printf("[GetLastError] -> %u (0x%08X)\n", err, err);

                self->SetRegister(self->AxReg(), err);
                self->UpdatePC(retaddr, true);

                return true;
            }, & runner, bBefore, false, runner.FindIATNode("GetLastError", "kernel32.dll")->GetAbsoluteName());

        runner.SetAnyJmpHook(runner.FindIATNode("SetLastError", "kernel32.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
                ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                //cb(FindIATNode("SetLastError", "kernel32.dll"));

                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                const bool bShouldPopArgs_NoCdecl = true;

                uintptr_t dwErrCode = 0;
                uintptr_t retaddr = 0;

                if (bBefore)
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                else if (!self->StackPop(retaddr))
                    return false;

                if (!self->StackGetArg(dwErrCode, 0, bShouldPopArgs_NoCdecl))
                    return false;

                self->SetTebLastError(dwErrCode);

                printf("[SetLastError] Error=%u (0x%08X)\n", self->GetTebLastError(), self->GetTebLastError());

                self->UpdatePC(retaddr, true);

                return true;
            }, & runner, bBefore, false, runner.FindIATNode("SetLastError", "kernel32.dll")->GetAbsoluteName());

        runner.SetAnyJmpHook(runner.FindIATNode("HeapFree", "kernel32.dll")->GetAbsolute(),
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
                ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                //cb(FindIATNode("HeapFree", "kernel32.dll"));

                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                const bool bShouldPopArgs_NoCdecl = true;

                uintptr_t hHeap = 0;
                uintptr_t dwFlags = 0;
                uintptr_t lpMem = 0;
                uintptr_t retaddr = 0;

                if (bBefore)
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                else if (!self->StackPop(retaddr))
                    return false;

                if (!self->StackGetArg(hHeap, 0, bShouldPopArgs_NoCdecl))   return false;
                if (!self->StackGetArg(dwFlags, 1, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(lpMem, 2, bShouldPopArgs_NoCdecl))   return false;

                printf("[HeapFree] Heap=0x%p Flags=0x%p Mem=0x%p ret=0x%p\n",
                    (void*)hHeap,
                    (void*)dwFlags,
                    (void*)lpMem,
                    (void*)retaddr);

                BOOL result = TRUE;

                if (lpMem)
                {
                    self->FreeMemory(lpMem);
                    printf("[HeapFree] Freed 0x%p\n", (void*)lpMem);
                }

                self->SetRegister(self->AxReg(), result);
                self->UpdatePC(retaddr, true);

                return true;
            }, & runner, bBefore, false, runner.FindIATNode("HeapFree", "kernel32.dll")->GetAbsoluteName());
    }

    runner.SetAnyJmpHook(runner.FindIATNode("FlsGetValue", "kernelbase.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            //cb(FindIATNode("FlsGetValue", szModule));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t dwFlsIndex = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(dwFlsIndex, 0, bShouldPopArgs_NoCdecl))
                return false;

            uintptr_t value = self->GetFlsValue(dwFlsIndex);

            printf("[FlsGetValue] Index=%u -> 0x%p\n",
                (DWORD)dwFlsIndex,
                (void*)value);

            self->SetRegister(self->AxReg(), value);
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, false, runner.FindIATNode("FlsGetValue", "kernelbase.dll")->GetAbsoluteName());

    runner.SetAnyJmpHook(runner.FindIATNode("FlsSetValue", "kernelbase.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size,
            ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            //cb(FindIATNode("FlsSetValue", szModule));

            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            const bool bShouldPopArgs_NoCdecl = true;

            uintptr_t dwFlsIndex = 0;
            uintptr_t lpFlsData = 0;
            uintptr_t retaddr = 0;

            if (bBefore)
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            else if (!self->StackPop(retaddr))
                return false;

            if (!self->StackGetArg(dwFlsIndex, 0, bShouldPopArgs_NoCdecl))
                return false;

            if (!self->StackGetArg(lpFlsData, 1, bShouldPopArgs_NoCdecl))
                return false;

            self->SetFlsValue(static_cast<size_t>(dwFlsIndex), lpFlsData);

            printf("[FlsSetValue] Index=%u Value=0x%p\n",
                (DWORD)dwFlsIndex,
                (void*)lpFlsData);

            self->SetRegister(self->AxReg(), TRUE);
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, false, runner.FindIATNode("FlsSetValue", "kernelbase.dll")->GetAbsoluteName());



    runner.SetAnyJmpHook(pPostSend,
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            printf("[hook] pPostSend hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            //MboxSTD("custom wait", "post");
            //self->DumpRegisters();
            //self->DumpStack(7);

            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            uintptr_t pUrl = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(pUrl, 0, bShouldPopArgs_NoCdecl)) return false;

            uintptr_t pTicket = self->GetRegister(self->CxReg());

            self->DumpMemory(pUrl, 250);
            self->DumpMemory(pTicket, 250);

            uintptr_t paPostAnswer = pTicket + 0x00000408;
            //uintptr_t pbDoneRequest = pData + 0x00000754;
            //self->WriteMemory<bool>(pbDoneRequest, true);

            //const char* filename = "answ.bin";
            //FILE* file = self->FileOpen(filename, "rb");
            //size_t fileSize = self->FileSize(file);
            //char* buffer = new char[fileSize];
            //size_t bytesRead = self->FileRead(file, buffer, fileSize);
            //self->CopyMemory(paPostAnswer, (uintptr_t)buffer, fileSize);
            //delete[] buffer;
            //buffer = nullptr;
            //self->FileClose(file);
            self->DumpMemory(paPostAnswer, 150);

            self->SetRegister(self->AxReg(), paPostAnswer);

            MboxSTD("custom wait", "post");

            // Устанавливаем возврат
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, true, "POST SENDER");

    if (0)
        runner.SetAnyJmpHook(pMd5,
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                printf("[hook] pMd5 hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                    (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

                //MboxSTD("custom wait", "pMd5");
                //self->DumpRegisters();
                //self->DumpStack(7);

                const bool bShouldPopArgs_NoCdecl = false; // true=stdcall pop like, false=cdecl peek

                uintptr_t Src_input = 0;
                uintptr_t Size_inputLen = 0;
                uintptr_t pMd5Out = 0;
                uintptr_t retaddr = 0;
                if (bBefore) {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr)) {
                    return false;
                }

                if (!self->StackGetArg(Src_input, 0, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(Size_inputLen, 1, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(pMd5Out, 2, bShouldPopArgs_NoCdecl)) return false;

                self->DumpMemory(Src_input, Size_inputLen + 1);
                if (pMd5Out)
                    self->MemSet(pMd5Out, 0, 16);
                self->MemSet(pMd5Buff, 0, 16);

                //uintptr_t pbDoneRequest = pData + 0x00000754;
                //uintptr_t paPostAnswer = pData + 0x00018E00;
                //self->WriteMemory<bool>(pbDoneRequest, true);


                //self->SetRegister(self->AxReg(), paPostAnswer);

                MboxSTD("custom wait", "pMd5");

                // Устанавливаем возврат
                self->UpdatePC(retaddr, true);

                return true;
            }, &runner, bBefore, true, "pMd5");

    static int nmc = 0;
    runner.SetAnyJmpHook(pMemcpy,
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            //MboxSTD("custom wait", "Free");

            printf("[hook] pMemcpy hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));
            MboxSTD("custom wait", "pMemcpy");

            tFuncNode* pNode = self->FindIATNode(to);
            if (pNode)
                printf("hit %s %s\n", pNode->funcName.c_str(), pNode->moduleName.c_str());

            // BOOL VirtualFree(
            //   LPVOID lpAddress,   // x86: [ESP+4], x64: RCX
            //   SIZE_T dwSize,      // x86: [ESP+8], x64: RDX  
            //   DWORD dwFreeType    // x86: [ESP+12], x64: R8
            // );

            const bool bShouldPopArgs_NoCdecl = false; // true=stdcall pop like, false=cdecl peek

            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            uintptr_t _dst = 0;
            uintptr_t _src = 0;
            uintptr_t _size = 0;
            if (!self->StackGetArg(_dst, 0, bShouldPopArgs_NoCdecl)) return false;
            if (!self->StackGetArg(_src, 1, bShouldPopArgs_NoCdecl)) return false;
            if (!self->StackGetArg(_size, 2, bShouldPopArgs_NoCdecl)) return false;

            self->MemCpy(_dst, _src, _size);
            self->DumpMemory(_src, _size);
            //nmc++;
            //printf("memcpy %d\n", nmc);
            //if(nmc > 12)
            //MboxSTD("custom wait", "pMemcpy");

            self->SetRegister(self->AxReg(), _dst);
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, true, "free");

    if (0)
        runner.SetAnyJmpHook(pAes128E,
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                printf("[hook] pAes128 hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                    (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

                //MboxSTD("custom wait", "pMd5");
                //self->DumpRegisters();
                //self->DumpStack(7);

                const bool bShouldPopArgs_NoCdecl = false; // true=stdcall pop like, false=cdecl peek

                uintptr_t ctx = 0;
                uintptr_t cipher = 0;
                uintptr_t impl = 0;
                uintptr_t key = 0;
                uintptr_t iv = 0;
                uintptr_t retaddr = 0;
                if (bBefore) {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr)) {
                    return false;
                }

                if (!self->StackGetArg(ctx, 0, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(cipher, 1, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(impl, 2, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(key, 3, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(iv, 4, bShouldPopArgs_NoCdecl)) return false;

                self->DumpMemory(key, 250);
                self->DumpMemory(iv, 250);


                //uintptr_t pbDoneRequest = pData + 0x00000754;
                //uintptr_t paPostAnswer = pData + 0x00018E00;
                //self->WriteMemory<bool>(pbDoneRequest, true);


                //self->SetRegister(self->AxReg(), paPostAnswer);

                MboxSTD("custom wait", "pAes128");

                // Устанавливаем возврат
                self->UpdatePC(retaddr, true);

                return true;
            }, &runner, bBefore, true, "pAes128");

    if (0)
        runner.SetAnyJmpHook(pAes128U,
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                printf("[hook] pAes128U hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                    (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

                //MboxSTD("custom wait", "pMd5");
                //self->DumpRegisters();
                //self->DumpStack(7);

                const bool bShouldPopArgs_NoCdecl = false; // true=stdcall pop like, false=cdecl peek

                uintptr_t ctx = 0;
                uintptr_t out = 0;
                uintptr_t outl = 0;
                uintptr_t in = 0;
                uintptr_t inl = 0;

                uintptr_t retaddr = 0;
                if (bBefore) {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr)) {
                    return false;
                }

                if (!self->StackGetArg(ctx, 0, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(out, 1, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(outl, 2, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(in, 3, bShouldPopArgs_NoCdecl)) return false;
                if (!self->StackGetArg(inl, 4, bShouldPopArgs_NoCdecl)) return false;

                printf("inl %d\n", inl);
                self->DumpMemory(in, inl);


                //uintptr_t pbDoneRequest = pData + 0x00000754;
                //uintptr_t paPostAnswer = pData + 0x00018E00;
                //self->WriteMemory<bool>(pbDoneRequest, true);


                //self->SetRegister(self->AxReg(), paPostAnswer);

                MboxSTD("custom wait", "pAes128U");

                // Устанавливаем возврат
                self->UpdatePC(retaddr, true);

                return true;
        }, &runner, bBefore, true, "pAes128U");

    if (0)
        runner.SetAnyJmpHook(pRand,
            [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
            {
                auto* self = static_cast<AsmRunner*>(user_data);
                if (!self)
                    return true;

                printf("[hook] pRand hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                    (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

                //MboxSTD("custom wait", "pRand");
                //self->DumpRegisters();
                //self->DumpStack(7);

                const bool bShouldPopArgs_NoCdecl = false; // true=stdcall pop like, false=cdecl peek



                uintptr_t retaddr = 0;
                if (bBefore) {
                    retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
                }
                else if (!self->StackPop(retaddr)) {
                    return false;
                }



                //uintptr_t pbDoneRequest = pData + 0x00000754;
                //uintptr_t paPostAnswer = pData + 0x00018E00;
                //self->WriteMemory<bool>(pbDoneRequest, true);
                static uintptr_t rnd = 70;
                printf("rnd %d\n", rnd);
                self->SetRegister(self->AxReg(), rnd);
                ++rnd;

                MboxSTD("custom wait", "pRand");

                // Устанавливаем возврат
                self->UpdatePC(retaddr, true);

                return true;
            }, &runner, bBefore, true, "pAes128U");

#ifdef T93
    runner.SetRegister(runner.CxReg(), pEntryArg);
    runner.InitialiseSymMap("93idasym.txt", 0x12290000); // IDB base -> RVA map
    //runner.LoadIATEnv(szModIAT);
    runner.SetDisasmRVA(true, 0x12290000);
#else
    runner.SetEntryPointStackArg(0, pEntryArg);
    runner.InitialiseSymMap("idasym.txt", 0x60F00000); // IDB base -> RVA map
    runner.SetDisasmRVA(true, 0x60F00000);
#endif

    runner.SetLogDisasmICNotice(100'000);
    runner.SetDisasmSepGroup(3);

    //runner.WriteMemory<uint32_t>(pnSteamID_SHL1, 0x47CE6816); // 1204709398
    //runner.WriteMemory<uint32_t>(pnSteamID_SHL1, 3531943054); // 3531943054 1765971527
    //runner.WriteMemory<uint32_t>(pnSteamID_SHL1, 0x0E8B0D6C6); // orig

    try
    {
        if (!bFromState)
            runner.Run(pEntry, 0);
        else
            runner.RunCurrentPC(0);
        //while (!runner.Run(pEntry, 0)) {
        //	runner.HardReset();
        //}
    }
    catch (const std::exception& e) {
        printf("std::exception: %s\n", e.what());
    }
    catch (...) {
        printf("Unknown C++ exception\n");
    }
    runner.DumpMemory(pEntryArg, 0x1A0);

    runner.Shutdown();
    MboxSTD("halt", "hold");
}

void VMTEST(int a1)
{
    //IatTestUC();
    //Test1();
    //TestInsnHookCpuid();

    while (1)
        TESTA();
    return;

    ULONG_PTR lowLimit = 0;
    ULONG_PTR highLimit = 0;

    GetCurrentThreadStackLimits(&lowLimit, &highLimit);

    printf("base (Stack Base): 0x%p\n", (void*)lowLimit);
    printf("max (Stack Limit): 0x%p\n", (void*)highLimit);
    printf("Size:   0x%zx (%zu MB)\n", static_cast<size_t>(highLimit - lowLimit), static_cast<size_t>(highLimit - lowLimit / (1024 * 1024)));

    //auto regions = FindRegions(0x4D000, MEM_PRIVATE, PAGE_READWRITE, MEM_COMMIT);
    //printf("[*] regions=%d\n", regions.size());
    //void* pACPISSDT = regions.size() ? regions[0].baseAddress : null;
    //printf("[*] pACPISSDT=0x%p\n", pACPISSDT);

    //HMODULE hMod = LoadLibraryA("c_export_test_dll.dll");
    //if (hMod) { FreeLibrary(hMod); printf("Module unloaded!\n"); }
    //printf("Module still loaded: %s\n", GetModuleHandleA("c_export_test_dll.dll") ? "YES" : "NO");

    AsmRunner runner(false);
    const bool bCRC = true;
    const bool bBefore = false;
    const bool bBrokeCRC = false;
#define _ADDR(_p) (bCRC ? addrCRC(_p) : addr(_p))

    void* pEntry = _ADDR(0x60F2F0C0);
    void* pEntryArg = _ADDR(0x615CDB58);

    uintptr_t pThemidaStart = (uintptr_t)(_ADDR(0x629D5000));
    uintptr_t pThemidaEnd = (uintptr_t)(_ADDR(0x630DD000)); // size: 0x708000
    uintptr_t p4Ex = (uintptr_t)(_ADDR(0x62A35968));
    uintptr_t pCRC = (uintptr_t)(_ADDR(0x60F0101D));
    uintptr_t pPostSend = (uintptr_t)(_ADDR(0x60F2D910));
    uintptr_t pMalloc = (uintptr_t)(_ADDR(0x610AE29B));
    uintptr_t pFree = (uintptr_t)(_ADDR(0x610AE261));
    uintptr_t pB64 = (uintptr_t)(_ADDR(0x60F303A0));
    uintptr_t pMd5 = (uintptr_t)(_ADDR(0x61020220));
    uintptr_t pDLLS = (uintptr_t)(_ADDR(0x60F2FA89)); // MZ_SERIY_PARSE_IP_SERVERS_sub_60F2FA89
    uintptr_t pToken = (uintptr_t)(_ADDR(0x615CDFE4)); // на момент 0x60F2FA89 MZ_SERIY_PARSE_IP_SERVERS_sub_60F2FA89 готов
    uintptr_t pTokenProt = (uintptr_t)(_ADDR(0x615CDF64)); // на момент 0x60F2FA89 MZ_SERIY_PARSE_IP_SERVERS_sub_60F2FA89 не готов // копирует memcpy

    uintptr_t pNextAllowedTime = (uintptr_t)_ADDR(0x615CDB18);
    uintptr_t pLastRequestTime = (uintptr_t)_ADDR(0x615CDB1C);
    uintptr_t pnSteamID_SHL1 = (uintptr_t)_ADDR(0x615CE164);
    uintptr_t pbSemaSetSubkey = (uintptr_t)_ADDR(0x615CE064);


    std::vector<uintptr_t> jcc = { // TestScanC
        0x62A3F360, // 0x62A3F44E
        0x62A85596, // 0x62A856A9
        0x62A8F81F, // 0x62A8F8D7
        0x62AA2EC5, // 0x62AA2FB8
        0x62ABE6E6, // 0x62ABE7B8
        0x62AEF4B8, // 0x62AEF674
        0x62B6CD32, // 0x62B6CE83
        0x62B6DE40, // 0x62B6DF05
        0x62BCDE12, // 0x62BCDEE2
        0x62BCF3D0, // 0x62BCF4C4
        0x62BD194B, // 0x62BD1A2B
        0x62BDCBDB, // 0x62BDCEA5
        0x62BE0FFE, // 0x62BE10B5
        0x62C4EE38, // 0x62C4EF57
        0x62CE3D22, // 0x62CE3E24
        0x62D1C626, // 0x62D1C691
        0x62D2C485, // 0x62D2C575
        0x62D35399, // 0x62D355D7
        0x62D47C1B, // 0x62D47D1B
        0x62D52D4B, // 0x62D52E25
        0x62D76FD9, // 0x62D77055
        0x62DD02BB, // 0x62DD02A0
        //0x62E52D54, // 0x62E52D54
        0x62E55719, // 0x62E55700
        0x62E580CE, // 0x62E581CC
    }; // handmade adj to codeflow by AsmRunner::TestScanC results
    uintptr_t jccBpTolerance = 100; // окно вверх от паттерна &40 чтобы выйти на безусловный прямой codeflow
    auto JccBpCb = [&](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        //self->AdjustBreakpointCodeRangeAt(address); // adj100 попадаем в тело if выше (bp на частичный flow)
        printf("JccBpCb: 0x%p\n", address);
        //MboxSTD("IF COND FLOW BLOCK", "disasm");

        return true;
    };
    for (const auto& p : jcc) {
        runner.SetBreakpointCode((uintptr_t)_ADDR(p), JccBpCb, &runner);
        //runner.SetUsingBpCodeSizeRange(true);
        //runner.SetBreakpointCode((uintptr_t)_ADDR(p - jccBpTolerance), JccBpCb, &runner, jccBpTolerance);
        //runner.SetBreakpointRangeCode((uintptr_t)_ADDR(p - jccBpTolerance), (uintptr_t)_ADDR(p), JccBpCb, &runner);
    }

    //runner.SetBreakpointCode((uintptr_t)_ADDR(0x610C495A), JccBpCb, &runner, 50);
    //runner.SetBreakpointRangeCode((uintptr_t)_ADDR(0x610C495A - 50), (uintptr_t)_ADDR(0x610C495A), JccBpCb, &runner);
    //runner.SetBreakpointMem(p4Ex, 20, BP_MEM_RW,
    //	[&](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
    //	auto* self = static_cast<AsmRunner*>(user_data);
    //	//printf("mem bp: 0x%p\n", address);
    //	MboxSTD("mem bp", "disasm");

    //	return true;
    //	}, &runner);

    runner.SetBreakpointCode(pDLLS,
        [&](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
            auto* self = static_cast<AsmRunner*>(user_data);
            //printf("bp: 0x%p\n", address);
            self->MemCpy(pTokenProt, pToken, self->StrLen(pToken)); // 0x60F30363
            MboxSTD("MZ_SERIY_PARSE_IP_SERVERS_sub_60F2FA89 sucesss", "disasm");

            return false; // halt exit
        }, &runner);

    AsmRunner::HookNotifyCb hcb = [&](tFuncNode* pNode) {
        //MboxSTD("hook call " + pNode->GetAbsoluteName(), "hook");
    };

    //std::vector<uintptr_t> possibleJcc = AsmRunner::TestScanC(pThemidaStart, pThemidaEnd, (uintptr_t)(_ADDR(0x60F00000)) - 0x60F00000);
    std::vector<uintptr_t> outVMEntries;
    std::vector<uintptr_t> outVMExits;
    //AsmRunner::TestScanD(pThemidaStart, pThemidaEnd, (uintptr_t)(_ADDR(0x60F00000)) - 0x60F00000, outVMEntries, outVMExits);
    MboxSTD("VMENTRY_UT_HK", "hold");

    //crc start 0x60F01000,  size 0x47A000
    uintptr_t nSize = 0x47A000; // 4'694'016
    // unmapped from boot
    // valloc
    uintptr_t nCpyStart = 153495 + 1; // 1st rep movsb
    uintptr_t nCpyEnd = 4'847'512; // last rep movsb
    uintptr_t nCrcSumEnd = 93'017'845; // 83 instr / per 4 byte  // (0x47A000 / 4) * 83  ~97'400'832
    // 93017871 VirtualFree
    // GetSystemTimeAsFileTime
    // Sleep
    // vmexit sendPOST
    uintptr_t nPostAfter = 94'956'241 + 10; // bf post 94861903, af 94861907 //!upd normalid 94956241, 0id 94861903
    uintptr_t nPostEnd = 108'500'000; //108500000
    // GetSystemTimeAsFileTime
    uintptr_t nA1 = 109'000'000;
    uintptr_t nA2 = 142'000'000;
    // b64, md5

    //uintptr_t pStart = 0;
    //uintptr_t pEnd = 0;
    //uintptr_t nSize = 0;
    //runner.GetMappedModuleBounds(STEAM_LIB, pStart, pEnd, nSize);

    //if (nSize == 0 || pStart == 0)
    //{
    //	MboxSTD("VMENTRY_UT_HK", "module not found");
    //	return;
    //}

    //printf("[%s] base=0x%p end=0x%p size=0x%zx\n", STEAM_LIB, (void*)pStart, (void*)pEnd, (size_t)nSize);

    runner.SetICCallback(nCpyEnd, [&](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        MboxSTD("crc cpy end", "Cb");
        return true;
        },
        &runner);

    runner.SetICCallback(nCrcSumEnd, [&](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        MboxSTD("crc sum end", "Cb");
        return true;
        },
        &runner);

    auto OpcodeCb = [&](uc_engine* uc, uintptr_t address, uint32_t size, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        //printf("OpcodeCb 0x%p (%d)\n", (void*)address, mnemonic);
        //self->DumpRegisters(true);
        //self->DumpSegmentRegisters();
        if (self->IsInAddr(address, pThemidaStart, pThemidaEnd)) {
            SetConsoleColor(0); // red
        }
        else {
            SetConsoleColor(1);
        }

        //if(address == (uintptr_t)_ADDR(0x610C495A))
        //	MboxSTD("bp", "disasm");

        //if(address == pMd5)
        //	MboxSTD("md5", "disasm");
        //if (address == pB64)
        //	MboxSTD("base64", "disasm");

        //if (self->GetInstructionCount() > /*5080*/(/*nCrcSumEnd*/ 93130827)
        //if (self->GetInstructionCount() > /*5080*//*nCpyEnd*/ nPostAfter)
        if (self->GetInstructionCount() > /*5080*//*nCpyEnd*/ /*nPostAfter*/ 93'944'371)
        {
            self->SetDisasmAfterCB(false);
            //self->SetLogDisasm(true);

            self->SetLogDisasmICNotice(500'000);

            //self->SetRWHistory(true);
            //self->DumpRWHistory();
            //self->DumpRWHistory(0, false, true, true, true, true, true, true);
            /*self->SetDisasmAfterCB(false);
            self->SendIDAAddr(self->CalcWithCASLR(address));
            self->DumpRegisters();
            self->DumpFlags();
            self->DumpSegmentRegisters();
            self->DumpStack(7);
            MboxSTD("apply this opcode", "disasm");*/
        }
        else {
            self->SetLogDisasm(false);
        }

        //if (self->GetInstructionCount() == (nA1 - 50))
        //	self->SaveRunStateEnvFile("nA1.bin");

        if (self->GetInstructionCount() > 143'353'261) //0-142'917'282 //id-143'353'281
        {
            printf("size=%u mnemonic=%u pc=0x%p\n", (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            self->SetRWHistory(true);
            self->DumpRWHistory();
            //self->DumpRWHistory(0, false, true, true, true, true, true, true);

            self->SetLogDisasm(true);
            self->SetDisasmAfterCB(false);
            self->DumpRegisters();
            //self->DumpFlags();
            //self->DumpSegmentRegisters();
            self->DumpStack(7);
            //MboxSTD("apply this opcode", "disasm");
        }


        // VA 153415
        // C 153476  (153477)
        //if (self->GetInstructionCount() == 153000)
        //	MboxSTD("custom wait before virual alloc", "MemCb");

        // log change funcs
        if (self->IsSymMapInitialised()) {
            static const tFuncNode* lastsym = nullptr;
            const tFuncNode* sym = self->FindSymbolByRuntime(address);
            if (sym && sym != lastsym) {
                printf("%s\n", sym->funcName.c_str());
                lastsym = sym;
            }
        }

        return true;
    };

    auto MemCb = [&](uc_engine* uc, int32_t type, uintptr_t address, uintptr_t size, uintptr_t value, ZydisMnemonic mnemonic, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        bool isRead = (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT || type == UC_MEM_READ_AFTER);
        bool isWrite = (type == UC_MEM_WRITE || type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT);
        bool isAnyFetch = (type == UC_MEM_FETCH || type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT); // code read

        //printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n", (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);
        if (!self || !uc || size == 0)
            return true;

        // TODO capture virtualalloc ranges
        if (self->IsInAddr(address, self->GetFSTEBStart(), self->GetFSTEBEnd())) {
            printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);
            MboxSTD("Warn! access TID", "MemCb");
        }
        else if (!self->IsInAddr(address, self->GetModStart(), self->GetModEnd()) &&
            !self->IsInAddr(address, self->GetStackStart(), self->GetStackEnd())) {
            //printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
            //	(void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite); // todo filter out malloc ranges
            //MboxSTD("Warn! access smth outside the module", "MemCb");
        }


        if (address == p4Ex) // [93228455] 0x62D872AD
        { // custom, tmp
            self->DumpMemory(p4Ex, 20);
            //MboxSTD("p4Ex", "MemCb");
        }

        if (address == pnSteamID_SHL1)
        { // custom, tmp
            self->DumpMemory(pnSteamID_SHL1, 4);
            //MboxSTD("sid", "MemCb");
        }


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
            printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

            self->DumpRegisters();
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

            if (self->IsNTMemoryReadable(address, size))
            { // custom // themida read correct crc // 0x4F238ED8
                //self->CompareRegionsSnapshots(regionsBF, regionsAF);
                self->CopyMemory(address, address, size); // maping equal in native proc // докопирую данные в которые оно лезет, где то зашит регион в vmctx
                self->DumpMemory(address, size); // uc copy result view
                //MboxSTD("custom wait", "MemCb");
            }
            else
                MboxSTD("cant read nt", "MemCb");

            return true;
        }

        if (isProt)
        {
            printf("MemCb address 0x%p type %d size %d value %d pc 0x%p mn %d r %d w %d\n",
                (void*)address, type, size, value, (void*)self->CurrentPc(uc), mnemonic, isRead, isWrite);

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

    auto JmpCb = [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool {
        auto* self = static_cast<AsmRunner*>(user_data);
        if (self->IsHaltAddr(to))
            return true; // actual false



        //printf("JmpCb 0x%p %d\n", (void*)to, mnemonic);

        if (!self->IsPCNormal(to)) {
            tFuncNode* pNode = self->FindIATNode(to); // nullable

            printf("JmpCb 0x%p %d %s\n", (void*)to, mnemonic, pNode ? pNode->GetAbsoluteName().c_str() : "");
            MboxSTD("module escape", "asm runner");
            return false;
        }

        return true;
    };

    runner.Initialise(true, false, false, true);      // disasm + memrw + runner logs
    //runner.CopyModule(pStart, nSize);         // копируем модуль в Unicorn по тому же base
    if (!bCRC) {
        uintptr_t mod = runner.CopyModule(STEAM_LIB);
        runner.SetIAT((uintptr_t)addr(0x6137B000), (uintptr_t)addr(0x6137B508), false);
    }
    else {
        uintptr_t mod = runner.CopyModule(CRC_STEAM_LIB);
        runner.SetIAT((uintptr_t)addrCRC(0x6137B000), (uintptr_t)addrCRC(0x6137B508), false);
    }

    //runner.SetAnyJmpHook(0x12345678, [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
    //	{
    //		auto* self = static_cast<AsmRunner*>(user_data);
    //		if (!self)
    //			return true;

    //		printf("[memcpy hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u", (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic);

    //		uintptr_t retaddr = 0;
    //		if (bBefore) {
    //			retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
    //		}
    //		else if (!self->StackPop(retaddr)) {
    //			return false;
    //		}

    //		uintptr_t dst = 0;
    //		uintptr_t src = 0;
    //		uintptr_t n = 0;

    //		if (self->IsX64())
    //		{
    //			dst = self->GetRegister(UC_X86_REG_RCX);
    //			src = self->GetRegister(UC_X86_REG_RDX);
    //			n = self->GetRegister(UC_X86_REG_R8);
    //		}
    //		else
    //		{
    //			if (!self->StackPop(dst)) return false;
    //			if (!self->StackPop(src)) return false;
    //			if (!self->StackPop(n))   return false;
    //		}

    //		printf("[memcpy] dst=0x%p src=0x%p n=0x%p ret=0x%p", (void*)dst, (void*)src, (void*)n, (void*)retaddr);

    //		if (n != 0)
    //			self->_CopyMemory(dst, src, n);

    //		self->SetRegister(self->AxReg(), dst);
    //		self->SetRegister(self->PcReg(), retaddr);
    //		self->SetUpdatedPC(true);

    //		return true;
    //	},
    //	&runner, bBefore);

    runner.SetIAT(0, 0, false); // collect temp ENV
    //printf("0x%p\n", runner.FindIATNode("VirtualAlloc", "kernel32.dll")->GetAbsolute());
    runner.SetAnyJmpHook(runner.FindIATNode("VirtualAlloc", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        { // LPVOID __stdcall VirtualAllocStub(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) // b+8 b+C b+10 b+14
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            hcb(self->FindIATNode("VirtualAlloc", "kernel32.dll"));

            printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));
            tFuncNode* pNode = self->FindIATNode(to);
            if (pNode)
                printf("hit %s %s\n", pNode->funcName.c_str(), pNode->moduleName.c_str());

            //MboxSTD("custom wait", "MemCb");

            // LPVOID VirtualAlloc(
            //   LPVOID lpAddress,         // x86: [ESP+4], x64: RCX
            //   SIZE_T dwSize,            // x86: [ESP+8], x64: RDX
            //   DWORD flAllocationType,   // x86: [ESP+12], x64: R8
            //   DWORD flProtect           // x86: [ESP+16], x64: R9
            // );

            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            uintptr_t lpAddress = 0;
            uintptr_t dwSize = 0;
            uintptr_t flAllocationType = 0;
            uintptr_t flProtect = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(lpAddress, 0, bShouldPopArgs_NoCdecl))        return false;
            if (!self->StackGetArg(dwSize, 1, bShouldPopArgs_NoCdecl))           return false;
            if (!self->StackGetArg(flAllocationType, 2, bShouldPopArgs_NoCdecl)) return false;
            if (!self->StackGetArg(flProtect, 3, bShouldPopArgs_NoCdecl))        return false;

            printf("[VirtualAlloc] lpAddress=0x%p dwSize=0x%p flAllocationType=0x%p flProtect=0x%p ret=0x%p\n",
                (void*)lpAddress, (void*)dwSize, (void*)flAllocationType, (void*)flProtect, (void*)retaddr);

            uintptr_t allocated = 0;

            if (dwSize == 0) {
                allocated = 0;
            }
            else {
                allocated = self->AddMemory(dwSize, UC_PROT_ALL, true);
                if (!allocated)
                {
                    printf("[VirtualAlloc] AddMemory failed for size 0x%p\n", (void*)dwSize);
                    self->SetRegister(self->AxReg(), 0);
                    self->UpdatePC(retaddr, true);
                    return true;
                }

                printf("[VirtualAlloc] allocated 0x%p bytes at 0x%p\n", (void*)dwSize, (void*)allocated);

                if (lpAddress != 0 && lpAddress != allocated)
                {
                    printf("[VirtualAlloc] WARNING: requested specific address 0x%p but allocated at 0x%p\n",
                        (void*)lpAddress, (void*)allocated);
                }
            }

            self->SetRegister(self->AxReg(), allocated);
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, false, runner.FindIATNode("VirtualAlloc", "kernel32.dll")->GetAbsoluteName());
    runner.SetAnyJmpHook(runner.FindIATNode("VirtualFree", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            hcb(self->FindIATNode("VirtualFree", "kernel32.dll"));

            //MboxSTD("custom wait", "VirtualFree");

            printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            tFuncNode* pNode = self->FindIATNode(to);
            if (pNode)
                printf("hit %s %s\n", pNode->funcName.c_str(), pNode->moduleName.c_str());

            // BOOL VirtualFree(
            //   LPVOID lpAddress,   // x86: [ESP+4], x64: RCX
            //   SIZE_T dwSize,      // x86: [ESP+8], x64: RDX  
            //   DWORD dwFreeType    // x86: [ESP+12], x64: R8
            // );

            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            uintptr_t lpAddress = 0;
            uintptr_t dwSize = 0;
            uintptr_t dwFreeType = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(lpAddress, 0, bShouldPopArgs_NoCdecl))     return false;
            if (!self->StackGetArg(dwSize, 1, bShouldPopArgs_NoCdecl))        return false;
            if (!self->StackGetArg(dwFreeType, 2, bShouldPopArgs_NoCdecl))    return false;

            printf("[VirtualFree] lpAddress=0x%p dwSize=0x%p dwFreeType=0x%p ret=0x%p\n",
                (void*)lpAddress, (void*)dwSize, (void*)dwFreeType, (void*)retaddr);

            BOOL result = TRUE; // или VirtualFreeStub((LPVOID)lpAddress, dwSize, dwFreeType);

            // Если нужно освободить память в эмуляторе:
            if (dwFreeType == MEM_RELEASE || dwFreeType == MEM_DECOMMIT)
            {
                if (lpAddress != 0)
                {
                    self->FreeMemory(lpAddress);
                    printf("[VirtualFree] Freeing memory at 0x%p\n", (void*)lpAddress);
                }
            }

            self->SetRegister(self->AxReg(), result);
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, false, runner.FindIATNode("VirtualFree", "kernel32.dll")->GetAbsoluteName());

    runner.SetAnyJmpHook(runner.FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            hcb(self->FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll"));

            //self->DumpRegisters();
            //self->DumpStack(7);
            //MboxSTD("custom wait", "GetSystemTimeAsFileTime");

            printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            // Получаем аргументы
            uintptr_t lpSystemTimeAsFileTime = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(lpSystemTimeAsFileTime, 0, bShouldPopArgs_NoCdecl)) return false;

            printf("[GetSystemTimeAsFileTime] lpSystemTimeAsFileTime=0x%p\n", (void*)lpSystemTimeAsFileTime);

            FILETIME ft = { 0 };

#if 0
            GetSystemTimeAsFileTime(&ft);
#else
            static FILETIME s_ft = { 0 };
            static BOOL bInitialized = FALSE;

            if (!bInitialized)
            {
                GetSystemTimeAsFileTime(&s_ft);
                bInitialized = TRUE;
                printf("[GetSystemTimeAsFileTime] Static time initialized: 0x%08X%08X\n",
                    s_ft.dwHighDateTime, s_ft.dwLowDateTime);
            }

            ft = s_ft;
#endif

            printf("[GetSystemTimeAsFileTime] result: 0x%08X%08X\n", ft.dwHighDateTime, ft.dwLowDateTime);

            // Записываем результат обратно в память эмулятора
            if (lpSystemTimeAsFileTime)
                self->CopyMemory(lpSystemTimeAsFileTime, (uintptr_t)&ft, sizeof(FILETIME));

            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, false, runner.FindIATNode("GetSystemTimeAsFileTime", "kernel32.dll")->GetAbsoluteName());

    runner.SetAnyJmpHook(runner.FindIATNode("Sleep", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            hcb(self->FindIATNode("Sleep", "kernel32.dll"));

            printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            // Получаем аргументы
            uintptr_t dwMilliseconds = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(dwMilliseconds, 0, bShouldPopArgs_NoCdecl)) return false;

            printf("[Sleep] dwMilliseconds=0x%X\n", dwMilliseconds);

            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, false, runner.FindIATNode("Sleep", "kernel32.dll")->GetAbsoluteName());

    runner.SetAnyJmpHook(runner.FindIATNode("GetCurrentThreadId", "kernel32.dll")->GetAbsolute(),
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            hcb(self->FindIATNode("GetCurrentThreadId", "kernel32.dll"));

            printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            // Получаем аргументы
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

#if 0
            uintptr_t tid = 0;
#else
            uintptr_t tid = static_cast<uintptr_t>(GetCurrentThreadId());
#endif

            self->SetRegister(self->AxReg(), tid);
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, false, runner.FindIATNode("GetCurrentThreadId", "kernel32.dll")->GetAbsoluteName());
    //GetCurrentThreadId

    //WSAStartup WS2_32.dll

    runner.SetAllInsnCB(
        [&](uc_engine* uc, uintptr_t address, uint32_t size, uintptr_t nUcInsn, ZydisMnemonic mnemonic, void* user_data) -> bool {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            MboxSTD("Warn! UC_HOOK_INSN SetAllInsnCB!!!!", AR_SNAME);
            return true;
        },
        &runner);

    // unsupported 4 now
    //runner.SetInsnCB(UC_X86_INS_MOV,
    //	[&](uc_engine* uc, uintptr_t address, uint32_t size, uintptr_t nUcInsn, ZydisMnemonic mnemonic, void* user_data) -> bool
    //	{
    //		auto* self = static_cast<AsmRunner*>(user_data);
    //		if (!self || !uc)
    //			return true;

    //		MboxSTD("Warn! HOOK!!!!", AR_SNAME);

    //		return true;
    //	}, &runner);

    //// unsupported 4 now
    //runner.SetInsnCB(UC_X86_INS_ADD,
    //	[&](uc_engine* uc, uintptr_t address, uint32_t size, uintptr_t nUcInsn, ZydisMnemonic mnemonic, void* user_data) -> bool
    //	{
    //		auto* self = static_cast<AsmRunner*>(user_data);
    //		if (!self || !uc)
    //			return true;

    //		MboxSTD("Warn! HOOK!!!!", AR_SNAME);


    //		// Let the instruction execute normally
    //		return true;
    //	}, &runner);

    runner.SetAnyJmpHook(pPostSend,
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            printf("[hook] pPostSend hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            //MboxSTD("custom wait", "post");
            //self->DumpRegisters();
            //self->DumpStack(7);

            const bool bShouldPopArgs_NoCdecl = true; // true=stdcall pop like, false=cdecl peek

            uintptr_t pData = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(pData, 0, bShouldPopArgs_NoCdecl)) return false;

            uintptr_t pArg1 = self->GetRegister(self->CxReg());
            self->DumpMemory(pArg1, 150);
            uintptr_t pbDoneRequest = pData + 0x00000754;
            uintptr_t paPostAnswer = pData + 0x00018E00;
            self->WriteMemory<bool>(pbDoneRequest, true);

            const char* filename = "answ.bin";
            FILE* file = self->FileOpen(filename, "rb");
            size_t fileSize = self->FileSize(file);
            char* buffer = new char[fileSize];
            size_t bytesRead = self->FileRead(file, buffer, fileSize);
            self->CopyMemory(paPostAnswer, (uintptr_t)buffer, fileSize);
            delete[] buffer;
            buffer = nullptr;
            self->FileClose(file);
            self->DumpMemory(paPostAnswer, 150);

            self->SetRegister(self->AxReg(), paPostAnswer);

            MboxSTD("custom wait", "post");

            // Устанавливаем возврат
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, true, "POST SENDER");

    runner.SetAnyJmpHook(pMalloc,
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        { // LPVOID __stdcall VirtualAllocStub(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) // b+8 b+C b+10 b+14
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            //self->SetLogDisasm(true);
            //self->DumpRegisters();
            //self->DumpStack(7);

            printf("[hook] pMalloc hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));
            tFuncNode* pNode = self->FindIATNode(to);
            if (pNode)
                printf("hit %s %s\n", pNode->funcName.c_str(), pNode->moduleName.c_str());

            //MboxSTD("custom wait", "pMalloc");

            // LPVOID VirtualAlloc(
            //   LPVOID lpAddress,         // x86: [ESP+4], x64: RCX
            //   SIZE_T dwSize,            // x86: [ESP+8], x64: RDX
            //   DWORD flAllocationType,   // x86: [ESP+12], x64: R8
            //   DWORD flProtect           // x86: [ESP+16], x64: R9
            // );

            const bool bShouldPopArgs_NoCdecl = false; // true=stdcall pop like, false=cdecl peek

            uintptr_t dwSize = 0;

            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(dwSize, 0, bShouldPopArgs_NoCdecl)) return false;

            uintptr_t allocated = 0;

            if (dwSize == 0) {
                allocated = 0;
            }
            else {
                allocated = self->AddMemory(dwSize, UC_PROT_ALL, true);
                if (!allocated)
                {
                    printf("[malloc] AddMemory failed for size 0x%p\n", (void*)dwSize);
                    self->SetRegister(self->AxReg(), 0);
                    self->UpdatePC(retaddr, true);
                    return true;
                }

                printf("[malloc] allocated 0x%p bytes at 0x%p\n", (void*)dwSize, (void*)allocated);
            }

            self->SetRegister(self->AxReg(), allocated);
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, true, "malloc");

    runner.SetAnyJmpHook(pFree,
        [&](uc_engine* uc, uintptr_t from, uintptr_t to, uint32_t size, ZydisMnemonic mnemonic, bool bIsCondMn, bool bCond, bool bIsInvMn, void* user_data) -> bool
        {
            auto* self = static_cast<AsmRunner*>(user_data);
            if (!self)
                return true;

            //MboxSTD("custom wait", "Free");

            printf("[hook] hit: from=0x%p to=0x%p size=%u mnemonic=%u pc=0x%p\n",
                (void*)from, (void*)to, (unsigned)size, (unsigned)mnemonic, (void*)self->CurrentPc(uc));

            tFuncNode* pNode = self->FindIATNode(to);
            if (pNode)
                printf("hit %s %s\n", pNode->funcName.c_str(), pNode->moduleName.c_str());

            // BOOL VirtualFree(
            //   LPVOID lpAddress,   // x86: [ESP+4], x64: RCX
            //   SIZE_T dwSize,      // x86: [ESP+8], x64: RDX  
            //   DWORD dwFreeType    // x86: [ESP+12], x64: R8
            // );

            const bool bShouldPopArgs_NoCdecl = false; // true=stdcall pop like, false=cdecl peek

            uintptr_t lpAddress = 0;
            uintptr_t retaddr = 0;
            if (bBefore) {
                retaddr = self->ExtractAnyIpTransferReturn(mnemonic, from, size);
            }
            else if (!self->StackPop(retaddr)) {
                return false;
            }

            if (!self->StackGetArg(lpAddress, 0, bShouldPopArgs_NoCdecl)) return false;

            printf("[Free] lpAddress=0x%p ret=0x%p\n", (void*)lpAddress, (void*)retaddr);

            BOOL result = TRUE; // или VirtualFreeStub((LPVOID)lpAddress, dwSize, dwFreeType);

            if (lpAddress != 0)
            {
                self->FreeMemory(lpAddress);
                printf("[Free] Freeing memory at 0x%p\n", (void*)lpAddress);
            }

            self->SetRegister(self->AxReg(), result);
            self->UpdatePC(retaddr, true);

            return true;
        }, &runner, bBefore, true, "free");

    // Themida: читает из какой то памяти вне модуля crc посчитанную в boot
    // MZ_VM_conditional_jump_handler___virtual_machine_jcc_handler_if_branch_  
    // v6 = (unsigned __int16)(v1 & 0x800) >> 11
    // v1 = (unsigned __int8)(v1 & 0x80) >> 7;

    //runner.Initialise(true, false, false, true);      // disasm + memrw + runner logs
    runner.InitialiseSymMap("idasym.txt", 0x60F00000); // IDB base -> RVA map
    //runner.SetDisasmAfterCB(true);
    runner.SetPerformanceConstantsHost(1.0f);
    //runner.SetRWHistory(true);
    runner.SetDisasmRVA(true, 0x60F00000);
    runner.SetLogDisasmRawBytes(true);
    if (!bBrokeCRC) runner.SetPCTrace("TR3.txt", nullptr, true, 0x60F00000, /*9'500'000*/nCrcSumEnd, 3); // ok
    else runner.SetPCTrace("TR4.txt", nullptr, true, 0x60F00000, /*9'500'000*/nCrcSumEnd, 3); // ne ok
    //runner.SetPCTrace("TR5.txt", nullptr, true, 0x60F00000, /*9'500'000*/nCrcSumEnd, 3); // def
    runner.SetLogDisasmICNotice(500'000 * 20);
    //runner.AddDeadzoneIC(nCpyStart, nCpyEnd, false, false); // skip rep movsd
    //runner.AddDeadzoneIC(nCpyEnd, nCrcSumEnd, false, false); // skip crc eax sum
    runner.AddDeadzoneIC(nCpyStart, nCrcSumEnd, false, false);
    runner.AddDeadzoneIC(nPostAfter, nPostEnd, false);
    runner.AddDeadzoneIC(nA1, nA2, false);
    runner.InitIDAWS();
    //runner.WaitIDAWSConnection();
    //runner.ComparePCTrace("TR1.txt", "TR2.txt", true, "TR_cmp.txt");
    runner.SetCallbacks(OpcodeCb, &runner, MemCb, &runner, JmpCb, &runner);
    //runner.TraceInstruction("C:\\trace.txt", reinterpret_cast<uintptr_t>(pEntry), 300); return; // автостарт

    // UC буфер 0x1000 под аргумент entrypoint
    //uintptr_t pEntryArg = runner.AddMemory(0x1000, UC_PROT_READ | UC_PROT_WRITE);
    //if (!pEntryArg)
    //{
    //	MboxSTD("VMENTRY_UT_HK", "alloc uc buffer failed");
    //	runner.Shutdown();
    //	return;
    //}
    if (bBrokeCRC)
        runner.WriteMemory<uint8_t>(pCRC, 0x0);

    runner.WriteMemory<uint32_t>(pNextAllowedTime, 0x0);
    runner.WriteMemory<uint32_t>(pLastRequestTime, 0x0);
    runner.WriteMemory<bool>(pbSemaSetSubkey, false); // not need
    runner.WriteMemory<uint32_t>(pnSteamID_SHL1, 0x47CE6816); // 1204709398
    runner.WriteMemory<uint32_t>(pnSteamID_SHL1, 3531943054); // 3531943054 1765971527
    runner.MemSet(pTokenProt, 0, 86);

    runner.SetEntryPointStackArg(0, reinterpret_cast<uintptr_t>(pEntryArg));
    //runner.SetRegister(UC_X86_REG_ECX, reinterpret_cast<uintptr_t>(pEntryArg)); // if thiscall-style ctx is needed

    // Пример бряка по адресу
    // runner.SetBreakpoint(reinterpret_cast<uintptr_t>(pEntry), [](AsmRunner*, uint64_t a){ printf("BP hit 0x%llx\n", (unsigned long long)a); }, true);

    printf("[*] entry=0x%p\n", pEntry);
    //runner.DisassembleWithZydis(); // покажет первые инструкции модуля с именами

    //{ // diff test
    //	auto s1 = runner.MakeSnapshotS((uintptr_t)pEntry, 0x1000);
    //	char* buf = (char*)runner.DumpMemoryNTAlloc((uintptr_t)pEntry, 0x1000);
    //	buf[0] = 0xCC;
    //	buf[100] = 0xCC;
    //	runner._CopyMemory((uintptr_t)pEntry, (uintptr_t)buf, 0x1000);
    //	free(buf);
    //	auto s2 = runner.MakeSnapshotS((uintptr_t)pEntry, 0x1000);
    //	runner.CompareSnapshots(s1, s2);
    //	return;
    //}

    runner.ParseModuleSections();
    runner.SetLogDisasmSection(true);
    runner.SetDisasmSepGroup(3);
    //runner.LoadRunStateEnvFile("nA1.bin");
    runner.Run(reinterpret_cast<uintptr_t>(pEntry), 0); // 0 = без лимита по шагам // 800 000 crc copy
    runner.DumpMemory(pToken, 50);
    runner.DumpMemory(pTokenProt, 50);
    runner.Shutdown();


    MboxSTD("halt", "hold");
    SetConsoleColor(1);
}
#endif