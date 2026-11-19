#pragma once

#include <llvm/IR/CallingConv.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/TargetParser/Triple.h>

#include <algorithm>
#include <vector>

namespace cabi
{

enum class Flavor { None, SysV, Win64 };

enum class ArgKind
{
    Direct,
    Coerce,
    Indirect,
    Ignore,
};

enum class Ext { None, ZExt, SExt };

struct ArgInfo
{
    ArgKind kind = ArgKind::Direct;
    llvm::Type* type = nullptr;
    llvm::Type* coerceType = nullptr;
    bool byval = false;
    uint64_t align = 0;
    Ext ext = Ext::None;
};

struct FunctionAbi
{
    ArgInfo ret;
    std::vector<ArgInfo> params;
    llvm::FunctionType* loweredType = nullptr;
    bool changesType = false;
};

struct ParamType
{
    llvm::Type* type;
    bool isUnsigned;
};

inline Flavor FlavorFor(const llvm::Triple& triple, llvm::CallingConv::ID cc)
{
    if (cc == llvm::CallingConv::Win64)       return Flavor::Win64;
    if (cc == llvm::CallingConv::X86_64_SysV) return Flavor::SysV;
    if (triple.getArch() != llvm::Triple::x86_64)
        return Flavor::None;
    return triple.isOSWindows() ? Flavor::Win64 : Flavor::SysV;
}

namespace detail
{

enum Class { NoClass, Integer, SSE, Memory };

inline Class Merge(Class a, Class b)
{
    if (a == b)                       return a;
    if (a == NoClass)                 return b;
    if (b == NoClass)                 return a;
    if (a == Memory || b == Memory)   return Memory;
    if (a == Integer || b == Integer) return Integer;
    return SSE;
}

struct Eightbytes
{
    Class cls[2] = { NoClass, NoClass };
    bool hasDouble[2] = { false, false };
    bool upperHalf[2] = { false, false };
};

inline bool Classify(llvm::Type* t, uint64_t offset, Eightbytes& eb, const llvm::DataLayout& dl)
{
    uint64_t size = dl.getTypeAllocSize(t);
    if (size == 0)
        return true;

    if (auto* st = llvm::dyn_cast<llvm::StructType>(t))
    {
        const llvm::StructLayout* layout = dl.getStructLayout(st);
        for (unsigned i = 0; i < st->getNumElements(); i++)
        {
            llvm::Type* elem = st->getElementType(i);
            if (dl.getTypeAllocSize(elem) == 0)
                continue;
            uint64_t off = offset + layout->getElementOffset(i);
            if (off % dl.getABITypeAlign(elem).value() != 0)
                return false;
            if (!Classify(elem, off, eb, dl))
                return false;
        }
        return true;
    }

    if (auto* at = llvm::dyn_cast<llvm::ArrayType>(t))
    {
        if (at->getElementType()->isVectorTy())
            return true;
        uint64_t elemSize = dl.getTypeAllocSize(at->getElementType());
        for (uint64_t i = 0; i < at->getNumElements(); i++)
            if (!Classify(at->getElementType(), offset + i * elemSize, eb, dl))
                return false;
        return true;
    }

    Class c;
    if (t->isIntegerTy() || t->isPointerTy())
        c = Integer;
    else if (t->isFloatTy() || t->isDoubleTy() || t->isHalfTy() || t->isBFloatTy())
        c = SSE;
    else
        return false;

    for (uint64_t b = offset; b < offset + size; b += 8)
    {
        unsigned idx = (unsigned)(b / 8);
        if (idx > 1)
            return false;
        eb.cls[idx] = Merge(eb.cls[idx], c);
    }

    unsigned idx = (unsigned)(offset / 8);
    if (t->isDoubleTy())
        eb.hasDouble[idx] = true;
    if (offset % 8 + size > 4)
        eb.upperHalf[idx] = true;
    return true;
}

inline llvm::Type* EightbyteType(const Eightbytes& eb, unsigned idx, uint64_t bytes, llvm::LLVMContext& ctx)
{
    if (eb.cls[idx] == Integer)
        return llvm::IntegerType::get(ctx, (unsigned)(bytes * 8));

    if (eb.hasDouble[idx])
        return llvm::Type::getDoubleTy(ctx);
    if (eb.upperHalf[idx])
        return llvm::FixedVectorType::get(llvm::Type::getFloatTy(ctx), 2);
    return llvm::Type::getFloatTy(ctx);
}

inline bool IsAggregate(llvm::Type* t)
{
    return t->isStructTy() || t->isArrayTy();
}

inline Ext ExtFor(llvm::Type* t, bool isUnsigned)
{
    if (!t->isIntegerTy() || t->getIntegerBitWidth() >= 32)
        return Ext::None;
    return (isUnsigned || t->isIntegerTy(1)) ? Ext::ZExt : Ext::SExt;
}

struct RegisterBudget
{
    int ints = 6;
    int sse = 8;
};

inline ArgInfo ClassifySysV(llvm::Type* t, bool isUnsigned, bool isReturn, RegisterBudget& regs,
                            const llvm::DataLayout& dl, llvm::LLVMContext& ctx)
{
    ArgInfo info;
    info.type = t;

    if (t->isVoidTy())
        return info;

    if (!IsAggregate(t))
    {
        info.ext = ExtFor(t, isUnsigned);
        if (!isReturn)
        {
            if (t->isFloatingPointTy()) { if (regs.sse > 0) regs.sse--; }
            else if (regs.ints > 0) regs.ints--;
        }
        return info;
    }

    uint64_t size = dl.getTypeAllocSize(t);
    info.align = dl.getABITypeAlign(t).value();

    if (size == 0)
    {
        info.kind = ArgKind::Ignore;
        return info;
    }

    Eightbytes eb;
    bool inRegs = size <= 16 && Classify(t, 0, eb, dl) &&
                  eb.cls[0] != Memory && eb.cls[1] != Memory;

    if (inRegs)
    {
        int needInt = 0, needSse = 0;
        unsigned count = size > 8 ? 2 : 1;
        for (unsigned i = 0; i < count; i++)
        {
            if (eb.cls[i] == NoClass) eb.cls[i] = SSE;
            (eb.cls[i] == Integer ? needInt : needSse)++;
        }

        if (isReturn || (needInt <= regs.ints && needSse <= regs.sse))
        {
            if (!isReturn) { regs.ints -= needInt; regs.sse -= needSse; }

            std::vector<llvm::Type*> parts;
            for (unsigned i = 0; i < count; i++)
                parts.push_back(EightbyteType(eb, i, std::min<uint64_t>(8, size - i * 8), ctx));

            info.kind = ArgKind::Coerce;
            info.coerceType = parts.size() == 1 ? parts[0] : llvm::StructType::get(ctx, parts);
            return info;
        }
    }

    info.kind = ArgKind::Indirect;
    info.byval = !isReturn;
    if (isReturn && regs.ints > 0)
        regs.ints--;
    return info;
}

inline ArgInfo ClassifyWin64(llvm::Type* t, bool isUnsigned, bool isReturn,
                             const llvm::DataLayout& dl, llvm::LLVMContext& ctx)
{
    ArgInfo info;
    info.type = t;

    if (t->isVoidTy())
        return info;

    if (!IsAggregate(t))
    {
        info.ext = ExtFor(t, isUnsigned);
        return info;
    }

    uint64_t size = dl.getTypeAllocSize(t);
    info.align = dl.getABITypeAlign(t).value();

    if (size == 1 || size == 2 || size == 4 || size == 8)
    {
        info.kind = ArgKind::Coerce;
        info.coerceType = llvm::IntegerType::get(ctx, (unsigned)(size * 8));
        return info;
    }

    info.kind = ArgKind::Indirect;
    return info;
}

} // namespace detail

inline FunctionAbi Lower(Flavor flavor, const llvm::DataLayout& dl, llvm::LLVMContext& ctx,
                         ParamType ret, const std::vector<ParamType>& params, bool isVarArg)
{
    using namespace detail;

    FunctionAbi abi;
    RegisterBudget regs;

    auto classify = [&](ParamType p, bool isReturn) -> ArgInfo
    {
        switch (flavor)
        {
            case Flavor::SysV:  return ClassifySysV(p.type, p.isUnsigned, isReturn, regs, dl, ctx);
            case Flavor::Win64: return ClassifyWin64(p.type, p.isUnsigned, isReturn, dl, ctx);
            default:
            {
                ArgInfo info;
                info.type = p.type;
                info.ext = IsAggregate(p.type) || p.type->isVoidTy() ? Ext::None : ExtFor(p.type, p.isUnsigned);
                return info;
            }
        }
    };

    abi.ret = classify(ret, true);

    std::vector<llvm::Type*> loweredParams;
    if (abi.ret.kind == ArgKind::Indirect)
        loweredParams.push_back(llvm::PointerType::getUnqual(ctx));

    for (const auto& p : params)
    {
        ArgInfo info = classify(p, false);
        switch (info.kind)
        {
            case ArgKind::Direct:
                loweredParams.push_back(p.type);
                break;
            case ArgKind::Coerce:
                if (auto* st = llvm::dyn_cast<llvm::StructType>(info.coerceType))
                    for (llvm::Type* elem : st->elements())
                        loweredParams.push_back(elem);
                else
                    loweredParams.push_back(info.coerceType);
                break;
            case ArgKind::Indirect:
                loweredParams.push_back(llvm::PointerType::getUnqual(ctx));
                break;
            case ArgKind::Ignore:
                break;
        }
        if (info.kind != ArgKind::Direct)
            abi.changesType = true;
        abi.params.push_back(info);
    }

    llvm::Type* loweredRet = ret.type;
    if (abi.ret.kind == ArgKind::Coerce)
        loweredRet = abi.ret.coerceType;
    else if (abi.ret.kind == ArgKind::Indirect || abi.ret.kind == ArgKind::Ignore)
        loweredRet = llvm::Type::getVoidTy(ctx);

    if (abi.ret.kind != ArgKind::Direct)
        abi.changesType = true;

    abi.loweredType = llvm::FunctionType::get(loweredRet, loweredParams, isVarArg);
    return abi;
}

} // namespace cabi
