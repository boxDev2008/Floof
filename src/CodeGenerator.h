#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/TargetParser/Host.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/IR/ConstantFold.h>
#include <unordered_set>

using namespace llvm;

class CodeGenerator
{
    struct FunctionInfo;
    struct TypeInfo
    {
        Type* llvmType;
        Type* pointeeType;
        bool isUnsigned;
        bool isConst;
        std::vector<bool> pointerConst;
        
        std::shared_ptr<FunctionInfo> functionInfo;

        TypeInfo() : llvmType(nullptr), isUnsigned(false), isConst(false), pointeeType(nullptr) {}
        TypeInfo(Type* t, bool u, bool c = false, Type* pt = nullptr, std::shared_ptr<FunctionInfo> fi = nullptr,
                std::vector<bool> ptrConst = {}) 
        : llvmType(t), isUnsigned(u), isConst(c), pointeeType(pt), functionInfo(fi), pointerConst(ptrConst) {}

        bool operator==(const TypeInfo& other) const {
            return llvmType == other.llvmType &&
                isUnsigned == other.isUnsigned &&
                isConst == other.isConst &&
                pointeeType == other.pointeeType &&
                pointerConst == other.pointerConst;
        }
        
        bool operator!=(const TypeInfo& other) const {
            return !(*this == other);
        }
    };

    struct TypedValue
    {
        Value* value;
        TypeInfo type;

        TypedValue() = default;
        TypedValue(Value* v, const TypeInfo& t) : value(v), type(t) {}
    };

    struct Variable
    {
        TypeInfo type;
        Value* storage;
        bool isConst;

        Variable() = default;
        Variable(const TypeInfo& t, Value* s, bool c) : type(t), storage(s), isConst(c) {}
    };

    struct StructInfo
    {
        StructType* type;
        std::unordered_map<std::string, unsigned> fieldIndices;
        std::unordered_map<std::string, TypeInfo> fieldTypes;
    };

    struct EnumInfo
    {
        std::string name;
        std::unordered_map<std::string, int> values;
    };

    struct FunctionInfo
    {
        Function* function;
        std::vector<TypeInfo> paramTypes;
        TypeInfo returnType;
        bool isVarArg;
        
        FunctionInfo() : function(nullptr), isVarArg(false) {}
        FunctionInfo(Function* fn, const std::vector<TypeInfo>& params, const TypeInfo& ret, bool varArg = false)
            : function(fn), paramTypes(params), returnType(ret), isVarArg(varArg) {}
    };

    struct LoopContext
    {
        BasicBlock* continueTarget;
        BasicBlock* breakTarget;

        LoopContext() : continueTarget(nullptr), breakTarget(nullptr) {}
        LoopContext(BasicBlock* cont, BasicBlock* brk) 
            : continueTarget(cont), breakTarget(brk) {}
    };

public:
    CodeGenerator(LLVMContext& ctx, const ModuleAST& ast, const std::string& moduleName, 
                  std::map<std::string, std::unique_ptr<ModuleAST>>& moduleTable) 
        : m_context(ctx), m_builder(ctx), m_loopContext()
    {
        m_module = std::make_unique<Module>(moduleName, ctx);

        ImportUsedModules(ast, moduleTable);
        RegisterEnums(ast);
        RegisterStructs(ast);
        DeclareUserFunctions(ast);
        DeclareGlobalVariables(ast);
        RegisterBuiltinFunctions();
        DefineUserFunctionBodies(ast);
    }

    std::unique_ptr<Module> GetModule() { return std::move(m_module); }

private:
    struct Scope
    {
        int32_t parent;
        uint32_t id;
    };

    void ImportUsedModules(const ModuleAST& ast, std::map<std::string, std::unique_ptr<ModuleAST>>& moduleTable)
    {
        for (const auto& use : ast.usings)
            ImportModuleRecursively(use->name, moduleTable);
    }

    std::unordered_set<std::string> m_importedModules;
    void ImportModuleRecursively(const std::string& moduleName, std::map<std::string, std::unique_ptr<ModuleAST>>& moduleTable)
    {
        if (m_importedModules.count(moduleName) > 0)
            return;
        
        auto it = moduleTable.find(moduleName);
        if (it == moduleTable.end())
            Error("Module not found: " + moduleName);
        
        m_importedModules.insert(moduleName);
        
        const ModuleAST& module = *it->second;
        
        for (const auto& use : module.usings)
        {
            if (use->is_pub)
                ImportModuleRecursively(use->name, moduleTable);
        }
        
        ImportModuleEnums(module);
        ImportModuleStructs(module);
        ImportModuleGlobals(module);
        ImportModuleFunctions(module);
    }

    void ImportModuleGlobals(const ModuleAST& module)
    {
        for (const auto& decl : module.globals)
        {
            if (!decl->is_pub) continue;
            
            TypeInfo type = ResolveType(decl->type.get());
            auto* globalVar = new GlobalVariable(
                *m_module, type.llvmType, decl->type->is_const,
                GlobalValue::ExternalLinkage, nullptr, decl->name
            );
            m_globals[decl->name] = {type, globalVar, decl->type->is_const};
        }
    }

    void ImportModuleFunctions(const ModuleAST& module)
    {
        for (const auto& proc : module.procs)
        {
            if (!proc->is_pub) continue;
            DeclareFunction(proc.get(), GlobalValue::ExternalLinkage);
        }
    }

    void DeclareUserFunctions(const ModuleAST& ast)
    {
        for (const auto& proc : ast.procs)
        {
            auto linkage = (proc->is_pub || proc->is_extern) 
                ? Function::ExternalLinkage 
                : Function::InternalLinkage;
            
            DeclareFunction(proc.get(), linkage);
        }
    }

    void DefineUserFunctionBodies(const ModuleAST& ast)
    {
        for (const auto& proc : ast.procs)
        {
            if (!proc->is_extern)
            {
                auto it = m_functions.find(proc->name);
                if (it == m_functions.end())
                    Error("Function not declared: " + proc->name, proc->line);
                
                DefineFunctionBody(proc.get(), it->second);
            }
        }
    }

    void RegisterEnums(const ModuleAST& ast)
    {
        for (const auto& decl : ast.enums)
            RegisterEnum(decl.get());
    }

    void ImportModuleEnums(const ModuleAST& ast)
    {
        for (const auto& decl : ast.enums)
            if (decl->is_pub)
                RegisterEnum(decl.get());
    }
    
    void RegisterStructs(const ModuleAST& ast)
    {
        for (const auto& decl : ast.structs)
            RegisterStruct(decl.get());
    }

    void ImportModuleStructs(const ModuleAST& ast)
    {
        for (const auto& decl : ast.structs)
            if (decl->is_pub)
                RegisterStruct(decl.get());
    }

    void RegisterEnum(const EnumDecl* decl)
    {
        EnumInfo info;
        info.name = decl->name;

        int next_value = 0;
        for (const auto& val : decl->values)
        {
            int resolved;
            if (val.expr)
            {
                TypedValue result = EvaluateConstantExpr(val.expr.get());
                
                auto* constInt = llvm::dyn_cast<llvm::ConstantInt>(result.value);
                if (!constInt)
                    Error("Enum value '" + val.name + "' must be a constant integer expression", val.expr->line);
                
                resolved = (int)constInt->getSExtValue();
                next_value = resolved + 1;
            }
            else
                resolved = next_value++;

            info.values[val.name] = resolved;
        }

        m_enums[decl->name] = info;
    }

    void RegisterStruct(const StructDecl* decl)
    {
        auto* structType = StructType::create(m_context, decl->name);
        StructInfo info;
        info.type = structType;
        
        std::vector<Type*> memberTypes;
        for (unsigned i = 0; i < decl->fields.size(); i++)
        {
            const auto& field = decl->fields[i];
            TypeInfo fieldType = ResolveType(field->type.get());
            
            memberTypes.push_back(fieldType.llvmType);
            info.fieldIndices[field->name] = i;
            info.fieldTypes[field->name] = fieldType;
        }
        
        structType->setBody(memberTypes, decl->is_packed);
        m_structs[decl->name] = info;
    }
    
    void DeclareGlobalVariables(const ModuleAST& ast)
    {
        for (const auto& decl : ast.globals)
        {
            TypeInfo type;
            Constant* initializer = nullptr;
            
            if (decl->type)
            {
                type = ResolveType(decl->type.get());
                if (decl->init)
                {
                    TypedValue initValue = EvaluateConstantExpr(decl->init.get(), &type);
                    initializer = cast<Constant>(initValue.value);
                }
                else
                    initializer = Constant::getNullValue(type.llvmType);
            }
            else if (decl->init)
            {
                TypedValue initValue = EvaluateConstantExpr(decl->init.get());
                type = initValue.type;
                initializer = cast<Constant>(initValue.value);
            }
            else
                Error("Global variable '" + decl->name + "' must have either a type or an initializer", decl->line);
            
            auto linkage = decl->is_pub ? GlobalValue::ExternalLinkage : GlobalValue::InternalLinkage;
            auto* globalVar = new GlobalVariable(
                *m_module, type.llvmType, decl->type ? decl->type->is_const : false, 
                linkage, initializer, decl->name
            );
            m_globals[decl->name] = {type, globalVar, decl->type ? decl->type->is_const : false};
        }
    }

    TypedValue EvaluateConstantExpr(ExprNode* node, const TypeInfo* expectedType = nullptr)
    {
        if (auto* id = dynamic_cast<Identifier*>(node))
        {
            auto funcIt = m_functions.find(id->name);
            if (funcIt != m_functions.end())
            {
                Function* func = funcIt->second.function;

                if (expectedType && expectedType->functionInfo)
                {
                    TypeInfo type = *expectedType;
                    type.functionInfo->function = func;
                    return TypedValue(func, type);
                }
                return TypedValue(
                    func,
                    TypeInfo(
                        func->getType(),
                        false,
                        false,
                        func->getFunctionType(),
                        std::make_shared<FunctionInfo>(funcIt->second)
                    )
                );
            }

            auto globalIt = m_globals.find(id->name);
            if (globalIt != m_globals.end())
            {
                GlobalVariable* globalVar = cast<GlobalVariable>(globalIt->second.storage);
                if (globalVar->hasInitializer())
                    return TypedValue(globalVar->getInitializer(), globalIt->second.type);
                else
                    return TypedValue(globalVar, globalIt->second.type);
            }
            
            Error("Cannot use variable in constant expression: " + id->name, id->line);
        }
    
        if (auto* num = dynamic_cast<NumberLiteral*>(node))
        {
            TypedValue result = EvaluateNumberLiteral(num);
            if (expectedType && result.type != *expectedType)
            {
                Constant* constValue = llvm::cast<Constant>(result.value);
                return TypedValue(ConstantCast(constValue, result.type, *expectedType, node->line), *expectedType);
            }
            return result;
        }
        
        if (auto* str = dynamic_cast<::StringLiteral*>(node))
        {
            auto* strGlobal = m_builder.CreateGlobalString(str->value, ".str", 0, m_module.get());
            std::vector<Constant*> indices = {
                m_builder.getInt64(0),
                m_builder.getInt64(0)
            };
            auto* strPtr = ConstantExpr::getInBoundsGetElementPtr(
                strGlobal->getValueType(),
                strGlobal,
                indices
            );
            return TypedValue(strPtr, TypeInfo(llvm::PointerType::getUnqual(m_builder.getContext()), false, m_builder.getInt8Ty()));
        }

        if (auto* ch = dynamic_cast<CharLiteral*>(node))
        {
            if (ch->value.empty())
                Error("Empty character literal", ch->line);
            
            uint8_t charValue = static_cast<uint8_t>(ch->value[0]);
            auto* val = m_builder.getInt8(charValue);
            return TypedValue(val, TypeInfo(m_builder.getInt8Ty(), false));
        }
        
        if (auto* cast = dynamic_cast<CastExpr*>(node))
        {
            TypedValue operand = EvaluateConstantExpr(cast->operand.get());
            TypeInfo targetType = ResolveType(cast->target_type.get());
            
            Constant* constOperand = llvm::cast<Constant>(operand.value);
            Constant* result = ConstantCast(constOperand, operand.type, targetType, cast->line);
            
            return TypedValue(result, targetType);
        }

        if (auto* unary = dynamic_cast<UnaryExpr*>(node))
        {
            if (unary->op == '-')
            {
                TypedValue operand = EvaluateConstantExpr(unary->operand.get());
                Constant* constOperand = llvm::cast<Constant>(operand.value);
                
                Constant* result = operand.type.llvmType->isFloatingPointTy()
                    ? llvm::ConstantFoldUnaryInstruction(llvm::Instruction::FNeg, constOperand)
                    : llvm::ConstantFoldBinaryInstruction(llvm::Instruction::Sub,
                          llvm::Constant::getNullValue(constOperand->getType()), constOperand);
                
                TypedValue negated(result, operand.type);
                
                if (expectedType && negated.type != *expectedType)
                {
                    result = ConstantCast(result, operand.type, *expectedType, unary->line);
                    return TypedValue(result, *expectedType);
                }
                
                return negated;
            }
            Error("Unsupported unary operator in constant expression", unary->line);
        }
        
        if (auto* arrInit = dynamic_cast<ArrayInit*>(node))
        {
            TypeInfo elemType;
            size_t arraySize;
            
            if (expectedType && expectedType->llvmType->isArrayTy())
            {
                auto* arrayType = cast<ArrayType>(expectedType->llvmType);
                elemType = TypeInfo(arrayType->getElementType(), expectedType->isUnsigned);
                arraySize = arrayType->getNumElements();
            }
            else
            {
                if (arrInit->elements.empty())
                    Error("Cannot infer array type from empty initializer", arrInit->line);
                
                elemType = EvaluateConstantExpr(arrInit->elements[0].get()).type;
                
                for (size_t i = 1; i < arrInit->elements.size(); i++)
                    elemType = PromoteToCommonType(elemType, EvaluateConstantExpr(arrInit->elements[i].get()).type);
                
                arraySize = arrInit->elements.size();
            }
            
            auto* arrayType = ArrayType::get(elemType.llvmType, arraySize);
            std::vector<Constant*> elements;
            for (size_t i = 0; i < arraySize; i++)
            {
                if (i < arrInit->elements.size())
                {
                    auto constVal = EvaluateConstantExpr(arrInit->elements[i].get(), &elemType);
                    elements.push_back(llvm::cast<Constant>(constVal.value));
                }
                else
                {
                    elements.push_back(Constant::getNullValue(elemType.llvmType));
                }
            }
            
            return TypedValue(ConstantArray::get(arrayType, elements), 
                            TypeInfo(arrayType, elemType.isUnsigned));
        }
        
        if (auto* structInit = dynamic_cast<StructInit*>(node))
        {
            auto it = m_structs.find(structInit->type_name);
            if (it == m_structs.end())
                Error("Unknown struct: " + structInit->type_name, structInit->line);
            
            const StructInfo& info = it->second;
            std::vector<Constant*> fieldValues;
            
            for (unsigned i = 0; i < info.fieldIndices.size(); i++)
            {
                const TypeInfo* fieldType = FindFieldTypeAtIndex(info, i);
                if (i < structInit->fields.size())
                {
                    auto constVal = EvaluateConstantExpr(structInit->fields[i].get(), fieldType);
                    fieldValues.push_back(llvm::cast<Constant>(constVal.value));
                }
                else
                {
                    fieldValues.push_back(Constant::getNullValue(fieldType->llvmType));
                }
            }
            
            return TypedValue(ConstantStruct::get(info.type, fieldValues), 
                            TypeInfo(info.type, false));
        }

        if (auto* enumAccess = dynamic_cast<EnumAccess*>(node))
        {
            auto it = m_enums.find(enumAccess->enum_name);
            if (it == m_enums.end())
                Error("Unknown enum: " + enumAccess->enum_name, enumAccess->line);
            
            auto valueIt = it->second.values.find(enumAccess->value_name);
            if (valueIt == it->second.values.end())
                Error("Unknown enum value: " + enumAccess->value_name, enumAccess->line);
            
            auto* val = m_builder.getInt32(valueIt->second);
            return TypedValue(val, TypeInfo(m_builder.getInt32Ty(), false));
        }

        if (auto* sizeofExpr = dynamic_cast<SizeofExpr*>(node))
        {
            TypeInfo type = ResolveType(sizeofExpr->type.get());
            uint64_t size = m_module->getDataLayout().getTypeAllocSize(type.llvmType);
            return TypedValue(m_builder.getInt64(size), TypeInfo(m_builder.getInt64Ty(), true));
        }

        if (auto* binary = dynamic_cast<BinaryExpr*>(node))
        {
            TypedValue lhs = EvaluateConstantExpr(binary->left.get());
            TypedValue rhs = EvaluateConstantExpr(binary->right.get());
            
            auto* lhsConst = llvm::cast<Constant>(lhs.value);
            auto* rhsConst = llvm::cast<Constant>(rhs.value);
            
            TypeInfo commonType = PromoteToCommonType(lhs.type, rhs.type);
            lhsConst = ConstantCast(lhsConst, lhs.type, commonType, binary->line);
            rhsConst = ConstantCast(rhsConst, rhs.type, commonType, binary->line);
            
            Constant* result = nullptr;
            switch (binary->op)
            {
                case '+': result = llvm::ConstantFoldBinaryInstruction(llvm::Instruction::Add,  lhsConst, rhsConst); break;
                case '-': result = llvm::ConstantFoldBinaryInstruction(llvm::Instruction::Sub,  lhsConst, rhsConst); break;
                case '*': result = llvm::ConstantFoldBinaryInstruction(llvm::Instruction::Mul,  lhsConst, rhsConst); break;
                case '|': result = llvm::ConstantFoldBinaryInstruction(llvm::Instruction::Or,   lhsConst, rhsConst); break;
                case '&': result = llvm::ConstantFoldBinaryInstruction(llvm::Instruction::And,  lhsConst, rhsConst); break;
                case '^': result = llvm::ConstantFoldBinaryInstruction(llvm::Instruction::Xor,  lhsConst, rhsConst); break;
                case TokenType_LeftShift:  result = llvm::ConstantFoldBinaryInstruction(llvm::Instruction::Shl,  lhsConst, rhsConst); break;
                case TokenType_RightShift: result = llvm::ConstantFoldBinaryInstruction(llvm::Instruction::LShr, lhsConst, rhsConst); break;
                default: Error("Unsupported binary operator in constant expression", binary->line);
            }
            return TypedValue(result, commonType);
        }
        
        Error("Invalid constant expression for global variable", node->line);
    }

    Constant* ConstantCast(Constant* value, const TypeInfo& fromType, const TypeInfo& toType, uint32_t line = 0)
    {
        if (fromType == toType)
            return value;
        
        Type* fromLLVMType = fromType.llvmType;
        Type* toLLVMType = toType.llvmType;

        if ((toType.functionInfo && !fromType.functionInfo))
            Error("Cannot assign non-function pointer to function pointer", line);
        
        if (fromLLVMType->isPointerTy() && toLLVMType->isPointerTy())
        {
            if (fromType.pointeeType == toType.pointeeType)
                return value;
            return llvm::ConstantFoldCastInstruction(llvm::Instruction::BitCast, value, toLLVMType);
        }
        
        if (fromLLVMType->isIntegerTy() && toLLVMType->isIntegerTy())
        {
            unsigned fromBits = fromLLVMType->getIntegerBitWidth();
            unsigned toBits = toLLVMType->getIntegerBitWidth();
            
            if (fromBits < toBits)
            {
                return (fromBits == 1 || fromType.isUnsigned)
                    ? llvm::ConstantFoldCastInstruction(llvm::Instruction::ZExt, value, toLLVMType)
                    : llvm::ConstantFoldCastInstruction(llvm::Instruction::SExt, value, toLLVMType);
            }
            else if (fromBits > toBits)
            {
                return llvm::ConstantFoldCastInstruction(llvm::Instruction::Trunc, value, toLLVMType);
            }
            return value;
        }
        
        if (fromLLVMType->isFloatingPointTy() && toLLVMType->isFloatingPointTy())
        {
            unsigned fromBits = fromLLVMType->getPrimitiveSizeInBits();
            unsigned toBits = toLLVMType->getPrimitiveSizeInBits();
            
            if (fromBits < toBits)
                return llvm::ConstantFoldCastInstruction(llvm::Instruction::FPExt, value, toLLVMType);
            else if (fromBits > toBits)
                return llvm::ConstantFoldCastInstruction(llvm::Instruction::FPTrunc, value, toLLVMType);
            return value;
        }
        
        if (fromLLVMType->isIntegerTy() && toLLVMType->isFloatingPointTy())
        {
            return (fromLLVMType->isIntegerTy(1) || fromType.isUnsigned)
                ? llvm::ConstantFoldCastInstruction(llvm::Instruction::UIToFP, value, toLLVMType)
                : llvm::ConstantFoldCastInstruction(llvm::Instruction::SIToFP, value, toLLVMType);
        }
        
        if (fromLLVMType->isFloatingPointTy() && toLLVMType->isIntegerTy())
        {
            return toType.isUnsigned
                ? llvm::ConstantFoldCastInstruction(llvm::Instruction::FPToUI, value, toLLVMType)
                : llvm::ConstantFoldCastInstruction(llvm::Instruction::FPToSI, value, toLLVMType);
        }

        if (fromLLVMType->isIntegerTy() && toLLVMType->isPointerTy())
            return llvm::ConstantFoldCastInstruction(llvm::Instruction::IntToPtr, value, toLLVMType);

        if (fromLLVMType->isPointerTy() && toLLVMType->isIntegerTy())
            return llvm::ConstantFoldCastInstruction(llvm::Instruction::PtrToInt, value, toLLVMType);
        
        Error("Cannot cast between incompatible types in constant expression", line);
    }
    
    void RegisterBuiltinFunctions(void)
    {
        auto* printfFunc = Function::Create(
            FunctionType::get(
                m_builder.getInt32Ty(),
                {llvm::PointerType::getUnqual(m_builder.getContext())},
                true
            ),
            Function::ExternalLinkage, "printf", m_module.get()
        );
        m_functions["printf"] = FunctionInfo(
            printfFunc,
            {TypeInfo(llvm::PointerType::getUnqual(m_builder.getContext()), false)},
            TypeInfo(m_builder.getInt32Ty(), false),
            true
        );

        auto* vaStartFunc = Function::Create(
            FunctionType::get(
                m_builder.getVoidTy(),
                {m_builder.getPtrTy()},
                false
            ),
            Function::ExternalLinkage, "llvm.va_start", m_module.get()
        );
        m_functions["llvm.va_start"] = FunctionInfo(
            vaStartFunc,
            {TypeInfo(m_builder.getPtrTy(), false)},
            TypeInfo(m_builder.getVoidTy(), false),
            false
        );

        auto* vaEndFunc = Function::Create(
            FunctionType::get(
                m_builder.getVoidTy(),
                {m_builder.getPtrTy()},
                false
            ),
            Function::ExternalLinkage, "llvm.va_end", m_module.get()
        );
        m_functions["llvm.va_end"] = FunctionInfo(
            vaEndFunc,
            {TypeInfo(m_builder.getPtrTy(), false)},
            TypeInfo(m_builder.getVoidTy(), false),
            false
        );
    }

    FunctionInfo DeclareFunction(const ProcDecl* proc, GlobalValue::LinkageTypes linkage)
    {
        std::vector<Type*> paramLLVMTypes;
        std::vector<TypeInfo> paramTypes;
        
        for (const auto& param : proc->params)
        {
            TypeInfo paramType = ResolveType(param.type.get());
            paramLLVMTypes.push_back(paramType.llvmType);
            paramTypes.push_back(paramType);
        }
        
        TypeInfo returnType = proc->return_type 
            ? ResolveType(proc->return_type.get())
            : TypeInfo(Type::getVoidTy(m_context), false);
        
        auto* funcType = FunctionType::get(returnType.llvmType, paramLLVMTypes, proc->is_vararg);
        auto* func = Function::Create(funcType, linkage, proc->name, m_module.get());
        
        unsigned idx = 0;
        for (auto& arg : func->args())
            arg.setName(proc->params[idx++].name);
        
        FunctionInfo info(func, paramTypes, returnType, proc->is_vararg);
        m_functions[proc->name] = info;
        return info;
    }

    void DefineFunctionBody(const ProcDecl* proc, const FunctionInfo& funcInfo)
    {
        m_scopes.clear();
        m_locals.clear();

        m_scopes.push_back(Scope{ -1, 0 });
        m_currentScope = 0;
        m_scopeCount = 0;
        auto* entry = BasicBlock::Create(m_context, "entry", funcInfo.function);
        m_builder.SetInsertPoint(entry);
        
        unsigned idx = 0;
        for (auto& arg : funcInfo.function->args())
        {
            const Parameter &param = proc->params[idx];
            TypeInfo paramType = funcInfo.paramTypes[idx++];
            std::string name = arg.getName().str() + ".0";
            auto* alloca = m_builder.CreateAlloca(paramType.llvmType, nullptr, name);
            m_builder.CreateStore(&arg, alloca);
            m_locals[name] = Variable(paramType, alloca, param.type->is_const);
        }
        
        GenerateHostingAllocs(proc->body.get());

        m_currentScope = 0;
        m_scopeCount = 0;
        GenerateBlock(proc->body.get(), funcInfo.returnType);
        
        if (!m_builder.GetInsertBlock()->getTerminator())
        {
            if (funcInfo.returnType.llvmType->isVoidTy())
                m_builder.CreateRetVoid();
            else
                Error("Non-void function '" + proc->name + "' must return a value", proc->line);
        }
    }

    bool IsVariableAccessibleInCurrentScope(const std::string& name)
    {
        int32_t scopeIdx = m_currentScope;
        while (scopeIdx >= 0)
        {
            Scope& scope = m_scopes[scopeIdx];
            if (m_locals.find(name + '.' + std::to_string(scope.id)) != m_locals.end())
                return true;
            scopeIdx = scope.parent;
        }
        return false;
    }

    void GenerateVarDeclHosingAlloc(VarDecl *decl)
    {
        if (IsVariableAccessibleInCurrentScope(decl->name))
            Error("Variable already declared in this scope: " + decl->name, decl->line);

        TypeInfo type;
        
        if (decl->type)
        {
            type = ResolveType(decl->type.get());
        }
        else if (decl->init)
        {
            TypedValue initValue = EvaluateRValue(decl->init.get());
            type = initValue.type;
        }
        else
            Error("Variable '" + decl->name + "' must have either a type or an initializer", decl->line);
        
        std::string scopedName = decl->name + '.' + std::to_string(m_currentScope);
        auto* alloca = m_builder.CreateAlloca(type.llvmType, nullptr, scopedName);
        m_locals[scopedName] = Variable(type, alloca, decl->type ? decl->type->is_const : false);
    }

    void GenerateHostingAllocs(BlockStmt* block)
    {
        uint32_t scopeId = m_currentScope;
        for (const auto& stmt : block->statements)
        {
            if (auto* decl = dynamic_cast<VarDecl*>(stmt.get()))
                GenerateVarDeclHosingAlloc(decl);
            else if (auto* s = dynamic_cast<IfStmt*>(stmt.get()))
            {
                m_scopes.push_back(Scope{ (int32_t)scopeId, ++m_scopeCount });
                GenerateHostingAllocs(s->then_branch.get());
                m_currentScope = scopeId;
                if (s->else_branch)
                {
                    m_scopes.push_back(Scope{ (int32_t)scopeId, ++m_scopeCount });
                    GenerateHostingAllocs(s->else_branch.get());
                    m_currentScope = scopeId;
                }
            }
            else if (auto* s = dynamic_cast<WhileStmt*>(stmt.get()))
            {
                m_scopes.push_back(Scope{ (int32_t)scopeId, ++m_scopeCount });
                GenerateHostingAllocs(s->then_branch.get());
                m_currentScope = scopeId;
            }
            else if (auto* s = dynamic_cast<ForStmt*>(stmt.get()))
            {
                uint32_t forScopeId = ++m_scopeCount;
                m_scopes.push_back(Scope{ (int32_t)scopeId, forScopeId });
                m_currentScope = forScopeId;
                if (s->init)
                    GenerateVarDeclHosingAlloc(s->init.get());
                GenerateHostingAllocs(s->body.get());
                m_currentScope = scopeId;
            }
            else if (auto* s = dynamic_cast<MatchStmt*>(stmt.get()))
            {
                for (auto &c : s->cases)
                {
                    m_scopes.push_back(Scope{ (int32_t)scopeId, ++m_scopeCount });
                    GenerateHostingAllocs(c->body.get());
                }
                m_currentScope = scopeId;
            }
        }
    }
    
    void GenerateBlock(BlockStmt* block, const TypeInfo& returnType)
    {
        uint32_t scopeId = m_currentScope;
        for (const auto& stmt : block->statements)
        {
            if (auto* s = dynamic_cast<VarDecl*>(stmt.get()))
                GenerateVarDecl(s);
            else if (auto* s = dynamic_cast<ExprStmt*>(stmt.get()))
                GenerateExprStmt(s);
            else if (auto* s = dynamic_cast<ReturnStmt*>(stmt.get()))
                GenerateReturn(s, returnType);
            else if (auto* s = dynamic_cast<IfStmt*>(stmt.get()))
            {
                m_currentScope = ++m_scopeCount;
                GenerateIf(s, returnType);
                m_currentScope = scopeId;
            }
            else if (auto* s = dynamic_cast<WhileStmt*>(stmt.get()))
            {
                m_currentScope = ++m_scopeCount;
                GenerateWhile(s, returnType);
                m_currentScope = scopeId;
            }
            else if (auto* s = dynamic_cast<ForStmt*>(stmt.get()))
            {
                m_currentScope = ++m_scopeCount;
                GenerateFor(s, returnType);
                m_currentScope = scopeId;
            }
            else if (auto* s = dynamic_cast<BreakStmt*>(stmt.get()))
                GenerateBreak(s);
            else if (auto* s = dynamic_cast<ContinueStmt*>(stmt.get()))
                GenerateContinue(s);
            else if (auto* s = dynamic_cast<MatchStmt*>(stmt.get()))
            {
                GenerateMatch(s, returnType);
                m_currentScope = scopeId;
            }
        }
    }

    void GenerateVarDecl(VarDecl* decl)
    {
        std::string scopedName = decl->name + '.' + std::to_string(m_currentScope);
        Variable& variable = m_locals[scopedName];
        
        if (!decl->init)
            return;
        
        if (auto* arrInit = dynamic_cast<ArrayInit*>(decl->init.get()))
            if (variable.type.llvmType->isArrayTy())
            {
                InitializeArrayInPlace(variable.storage, variable.type, arrInit);
                return;
            }
        
        if (auto* structInit = dynamic_cast<StructInit*>(decl->init.get()))
            if (variable.type.llvmType->isStructTy())
            {
                InitializeStructInPlace(variable.storage, variable.type, structInit);
                return;
            }
        
        TypedValue initValue = EvaluateRValue(decl->init.get(), &variable.type);
        if (initValue.type != variable.type)
            initValue = CastValue(initValue, variable.type, decl->line);
        m_builder.CreateStore(initValue.value, variable.storage);
    }

    void InitializeArrayInPlace(Value* arrayPtr, const TypeInfo& arrayTypeInfo, ArrayInit* init)
    {
        auto* arrayType = cast<ArrayType>(arrayTypeInfo.llvmType);
        size_t arraySize = arrayType->getNumElements();
        Type* elemLLVMType = arrayType->getElementType();
        
        TypeInfo elementType(elemLLVMType, arrayTypeInfo.isUnsigned);
        
        if (elemLLVMType->isArrayTy())
        {
            elementType.pointeeType = arrayTypeInfo.pointeeType;
            elementType.functionInfo = arrayTypeInfo.functionInfo;
        }
        else if (arrayTypeInfo.functionInfo)
        {
            elementType.pointeeType = arrayTypeInfo.pointeeType;
            elementType.functionInfo = arrayTypeInfo.functionInfo;
        }
        
        if (init->elements.size() < arraySize) {
            uint64_t arrayBytes = m_module->getDataLayout().getTypeAllocSize(arrayType);
            m_builder.CreateMemSet(
                arrayPtr,
                m_builder.getInt8(0),
                arrayBytes,
                MaybeAlign()
            );
            
            for (size_t i = 0; i < init->elements.size(); i++)
            {
                TypedValue elemValue = EvaluateRValue(init->elements[i].get(), &elementType);
                if (elemValue.type != elementType)
                    elemValue = CastValue(elemValue, elementType, init->elements[i]->line);
                
                auto* elemPtr = m_builder.CreateInBoundsGEP(
                    arrayType, arrayPtr,
                    {m_builder.getInt64(0), m_builder.getInt64(i)}
                );
                m_builder.CreateStore(elemValue.value, elemPtr);
            }
        } else {
            for (size_t i = 0; i < arraySize; i++)
            {
                Value* elemValue = (i < init->elements.size())
                    ? CastIfNeeded(EvaluateRValue(init->elements[i].get(), &elementType), elementType, init->elements[i]->line).value
                    : CreateZeroValue(elementType.llvmType);
                
                auto* elemPtr = m_builder.CreateInBoundsGEP(
                    arrayType, arrayPtr,
                    {m_builder.getInt64(0), m_builder.getInt64(i)}
                );
                m_builder.CreateStore(elemValue, elemPtr);
            }
        }
    }

    void InitializeStructInPlace(Value* structPtr, const TypeInfo& structTypeInfo, StructInit* init)
    {
        auto it = m_structs.find(init->type_name);
        if (it == m_structs.end())
            Error("Unknown struct: " + init->type_name, init->line);
        
        const StructInfo& info = it->second;
        
        if (init->fields.size() > info.fieldIndices.size())
            Error("Too many fields in struct initializer", init->line);
        
        if (init->fields.size() < info.fieldIndices.size()) {
            uint64_t structBytes = m_module->getDataLayout().getTypeAllocSize(info.type);
            m_builder.CreateMemSet(
                structPtr,
                m_builder.getInt8(0),
                structBytes,
                MaybeAlign()
            );
        }
        
        for (unsigned i = 0; i < init->fields.size(); i++)
        {
            const TypeInfo* fieldType = FindFieldTypeAtIndex(info, i);
            if (!fieldType)
                Error("Field type not found at index " + std::to_string(i), init->line);
            
            TypedValue fieldValue = EvaluateRValue(init->fields[i].get(), fieldType);
            if (fieldValue.type != *fieldType)
                fieldValue = CastValue(fieldValue, *fieldType, init->fields[i]->line);
            
            auto* fieldPtr = m_builder.CreateStructGEP(info.type, structPtr, i);
            m_builder.CreateStore(fieldValue.value, fieldPtr);
        }
    }

    void GenerateExprStmt(ExprStmt* stmt)
    {
        EvaluateRValue(stmt->expr.get());
    }

    void GenerateReturn(ReturnStmt* stmt, const TypeInfo& returnType)
    {
        if (stmt->value)
        {
            TypedValue retValue = EvaluateRValue(stmt->value.get());
            if (retValue.type != returnType)
                retValue = CastValue(retValue, returnType, stmt->line);
            m_builder.CreateRet(retValue.value);
        }
        else
        {
            m_builder.CreateRetVoid();
        }
    }

    void GenerateIf(IfStmt* stmt, const TypeInfo& returnType)
    {
        TypedValue condition = EvaluateRValue(stmt->condition.get());
        condition = EnsureBooleanType(condition, stmt->condition->line);
        
        auto* function = m_builder.GetInsertBlock()->getParent();
        auto* thenBB = BasicBlock::Create(m_context, "if.then", function);
        auto* elseBB = stmt->else_branch ? BasicBlock::Create(m_context, "if.else", function) : nullptr;
        auto* mergeBB = BasicBlock::Create(m_context, "if.end", function);
        
        m_builder.CreateCondBr(condition.value, thenBB, elseBB ? elseBB : mergeBB);
        
        m_builder.SetInsertPoint(thenBB);
        GenerateBlock(stmt->then_branch.get(), returnType);
        if (!m_builder.GetInsertBlock()->getTerminator())
            m_builder.CreateBr(mergeBB);
        
        if (elseBB)
        {
            m_builder.SetInsertPoint(elseBB);
            m_currentScope++;
            GenerateBlock(stmt->else_branch.get(), returnType);
            if (!m_builder.GetInsertBlock()->getTerminator())
                m_builder.CreateBr(mergeBB);
        }
        
        m_builder.SetInsertPoint(mergeBB);
    }

    void GenerateWhile(WhileStmt* stmt, const TypeInfo& returnType)
    {
        auto* function = m_builder.GetInsertBlock()->getParent();
        auto* condBB = BasicBlock::Create(m_context, "while.cond", function);
        auto* bodyBB = BasicBlock::Create(m_context, "while.body", function);
        auto* endBB = BasicBlock::Create(m_context, "while.end", function);
        
        LoopContext loopCtx = PushLoop(condBB, endBB);
        
        m_builder.CreateBr(condBB);
        
        m_builder.SetInsertPoint(condBB);
        TypedValue condition = EvaluateRValue(stmt->condition.get());
        condition = EnsureBooleanType(condition, stmt->condition->line);
        m_builder.CreateCondBr(condition.value, bodyBB, endBB);
        
        m_builder.SetInsertPoint(bodyBB);
        GenerateBlock(stmt->then_branch.get(), returnType);
        if (!m_builder.GetInsertBlock()->getTerminator())
            m_builder.CreateBr(condBB);
        
        PopLoop(loopCtx);
        m_builder.SetInsertPoint(endBB);
    }

    void GenerateFor(ForStmt* stmt, const TypeInfo& returnType)
    {
        auto* function = m_builder.GetInsertBlock()->getParent();
        
        if (stmt->init)
        {
            Variable variable = m_locals[stmt->init->name + '.' + std::to_string(m_currentScope)];
            if (stmt->init->init)
            {
                TypedValue initValue = EvaluateRValue(stmt->init->init.get(), &variable.type);
                if (initValue.type != variable.type)
                    initValue = CastValue(initValue, variable.type, stmt->init->line);
                m_builder.CreateStore(initValue.value, variable.storage);
            }
        }
        
        auto* condBB = BasicBlock::Create(m_context, "for.cond", function);
        auto* bodyBB = BasicBlock::Create(m_context, "for.body", function);
        auto* incBB = BasicBlock::Create(m_context, "for.inc", function);
        auto* endBB = BasicBlock::Create(m_context, "for.end", function);
        
        LoopContext loopCtx = PushLoop(incBB, endBB);
        
        m_builder.CreateBr(condBB);
        
        m_builder.SetInsertPoint(condBB);
        TypedValue condition = EvaluateRValue(stmt->condition.get());
        condition = EnsureBooleanType(condition, stmt->condition->line);
        m_builder.CreateCondBr(condition.value, bodyBB, endBB);
        
        m_builder.SetInsertPoint(bodyBB);
        GenerateBlock(stmt->body.get(), returnType);
        if (!m_builder.GetInsertBlock()->getTerminator())
            m_builder.CreateBr(incBB);
        
        m_builder.SetInsertPoint(incBB);
        EvaluateRValue(stmt->increment.get());
        m_builder.CreateBr(condBB);
        
        PopLoop(loopCtx);
        m_builder.SetInsertPoint(endBB);
    }

    void GenerateBreak(BreakStmt* stmt)
    {
        if (!m_loopContext.breakTarget)
            Error("'break' outside of loop", stmt->line);
        
        m_builder.CreateBr(m_loopContext.breakTarget);
        CreateUnreachableBlock();
    }

    void GenerateContinue(ContinueStmt* stmt)
    {
        if (!m_loopContext.continueTarget)
            Error("'continue' outside of loop", stmt->line);
        
        m_builder.CreateBr(m_loopContext.continueTarget);
        CreateUnreachableBlock();
    }

    void GenerateMatch(MatchStmt* stmt, const TypeInfo& returnType)
    {
        TypedValue matchValue = EvaluateRValue(stmt->value.get());
        
        auto* function = m_builder.GetInsertBlock()->getParent();
        auto* endBB = BasicBlock::Create(m_context, "match.end", function);
        
        if (stmt->cases.empty())
        {
            m_builder.CreateBr(endBB);
            m_builder.SetInsertPoint(endBB);
            return;
        }
        
        BasicBlock* elseBB = nullptr;
        
        for (const auto& case_stmt : stmt->cases)
        {
            if (case_stmt->is_else)
            {
                elseBB = BasicBlock::Create(m_context, "match.else", function);
                break;
            }
        }
        
        if (stmt->cases[0]->is_else)
            m_builder.CreateBr(elseBB);
        
        BasicBlock* nextCaseBB = nullptr;
        
        for (size_t i = 0; i < stmt->cases.size(); i++)
        {
            const auto& case_stmt = stmt->cases[i];
            
            m_currentScope = ++m_scopeCount;
            
            if (case_stmt->is_else)
            {
                m_builder.SetInsertPoint(elseBB);
                GenerateBlock(case_stmt->body.get(), returnType);
                if (!m_builder.GetInsertBlock()->getTerminator())
                    m_builder.CreateBr(endBB);
                continue;
            }
            
            if (i > 0 && nextCaseBB && nextCaseBB != elseBB && nextCaseBB != endBB)
                m_builder.SetInsertPoint(nextCaseBB);
            
            auto* caseBB = BasicBlock::Create(m_context, "match.case", function);
            nextCaseBB = (i + 1 < stmt->cases.size() && !stmt->cases[i+1]->is_else)
                ? BasicBlock::Create(m_context, "match.next", function)
                : (elseBB ? elseBB : endBB);
            
            TypedValue caseValue = EvaluateRValue(case_stmt->value.get());
            if (caseValue.type != matchValue.type)
                caseValue = CastValue(caseValue, matchValue.type, case_stmt->value->line);
            
            auto* cond = m_builder.CreateICmpEQ(matchValue.value, caseValue.value);
            m_builder.CreateCondBr(cond, caseBB, nextCaseBB);
            
            m_builder.SetInsertPoint(caseBB);
            GenerateBlock(case_stmt->body.get(), returnType);
            if (!m_builder.GetInsertBlock()->getTerminator())
                m_builder.CreateBr(endBB);
        }
        
        m_builder.SetInsertPoint(endBB);
    }
    
    TypedValue EvaluateLValue(ExprNode* node)
    {
        if (auto* id = dynamic_cast<Identifier*>(node))
        {
            Variable var = LookupVariable(id->name, id->line);
            TypeInfo type = var.type;
            type.isConst = var.isConst;
            return TypedValue(var.storage, type);
        }
        
        if (auto* unary = dynamic_cast<UnaryExpr*>(node))
        {
            if (unary->op == '*')
            {
                TypedValue ptr = EvaluateRValue(unary->operand.get());
                if (!ptr.type.llvmType->isPointerTy() || !ptr.type.pointeeType)
                    Error("Cannot dereference non-pointer", unary->line);

                bool pointeeIsConst = false;
                std::vector<bool> newPointerConst;
                
                if (ptr.type.pointerConst.size() > 1)
                {
                    pointeeIsConst = ptr.type.pointerConst[0];
                    newPointerConst = std::vector<bool>(
                        ptr.type.pointerConst.begin() + 1, 
                        ptr.type.pointerConst.end()
                    );
                }
                else if (ptr.type.pointerConst.size() == 1)
                    pointeeIsConst = ptr.type.isConst;
                
                TypeInfo derefType(
                    ptr.type.pointeeType, 
                    ptr.type.isUnsigned, 
                    pointeeIsConst,
                    nullptr,
                    nullptr,
                    newPointerConst
                );
                
                return TypedValue(ptr.value, derefType);
            }
        }
        
        if (auto* arr = dynamic_cast<ArrayAccess*>(node))
            return EvaluateArrayAccess(arr);
        
        if (auto* member = dynamic_cast<MemberAccess*>(node))
            return EvaluateMemberAccess(member);

        if (auto* member = dynamic_cast<PointerMemberAccess*>(node))
            return EvaluatePointerMemberAccess(member);

        if (auto* cast = dynamic_cast<CastExpr*>(node))
        {
            TypedValue operand = EvaluateLValue(cast->operand.get());
            TypeInfo targetType = ResolveType(cast->target_type.get());
            return TypedValue(m_builder.CreateBitCast(operand.value, m_builder.getPtrTy()), targetType);
        }
        
        Error("Expression is not an lvalue", node->line);
    }

    TypedValue EvaluateRValue(ExprNode* node, const TypeInfo* expectedType = nullptr)
    {
        if (auto* id = dynamic_cast<Identifier*>(node))
        {
            auto funcIt = m_functions.find(id->name);
            if (funcIt != m_functions.end())
            {
                Function* func = funcIt->second.function;
                if (expectedType && expectedType->functionInfo)
                {
                    TypeInfo type = *expectedType;
                    type.functionInfo->function = func;
                    return TypedValue(func, type);
                }
                return TypedValue(
                    func,
                    TypeInfo(
                        func->getType(),
                        false,
                        false,
                        func->getFunctionType(),
                        std::make_shared<FunctionInfo>(funcIt->second)
                    )
                );
            }
            
            Variable var = LookupVariable(id->name, id->line);
            return TypedValue(m_builder.CreateLoad(var.type.llvmType, var.storage), var.type);
        }
        
        if (auto* num = dynamic_cast<NumberLiteral*>(node))
            return EvaluateNumberLiteral(num);
        
        if (auto* str = dynamic_cast<::StringLiteral*>(node))
            return EvaluateStringLiteral(str);
        
        if (auto* ch = dynamic_cast<CharLiteral*>(node))
        {
            if (ch->value.empty())
                Error("Empty character literal", ch->line);
            
            uint8_t charValue = static_cast<uint8_t>(ch->value[0]);
            auto* val = m_builder.getInt8(charValue);
            return TypedValue(val, TypeInfo(m_builder.getInt8Ty(), false));
        }

        if (auto* arr = dynamic_cast<ArrayAccess*>(node))
        {
            TypedValue ptr = EvaluateLValue(arr);
            return TypedValue(m_builder.CreateLoad(ptr.type.llvmType, ptr.value), ptr.type);
        }
        
        if (auto* member = dynamic_cast<MemberAccess*>(node))
        {
            TypedValue ptr = EvaluateLValue(member);
            return TypedValue(m_builder.CreateLoad(ptr.type.llvmType, ptr.value), ptr.type);
        }

        if (auto* member = dynamic_cast<PointerMemberAccess*>(node))
        {
            TypedValue ptr = EvaluateLValue(member);
            return TypedValue(m_builder.CreateLoad(ptr.type.llvmType, ptr.value), ptr.type);
        }

        if (auto* enumAccess = dynamic_cast<EnumAccess*>(node))
        {
            auto it = m_enums.find(enumAccess->enum_name);
            if (it == m_enums.end())
                Error("Unknown enum: " + enumAccess->enum_name, enumAccess->line);
            
            auto valueIt = it->second.values.find(enumAccess->value_name);
            if (valueIt == it->second.values.end())
                Error("Unknown enum value: " + enumAccess->value_name, enumAccess->line);
            
            auto* val = m_builder.getInt32(valueIt->second);
            return TypedValue(val, TypeInfo(m_builder.getInt32Ty(), false));
        }

        if (auto* sizeofExpr = dynamic_cast<SizeofExpr*>(node))
        {
            TypeInfo type = ResolveType(sizeofExpr->type.get());
            uint64_t size = m_module->getDataLayout().getTypeAllocSize(type.llvmType);
            auto* val = m_builder.getInt64(size);
            return TypedValue(val, TypeInfo(m_builder.getInt64Ty(), true));
        }
        
        if (auto* cast = dynamic_cast<CastExpr*>(node))
            return EvaluateCast(cast);
        
        if (auto* call = dynamic_cast<CallExpr*>(node))
            return EvaluateFunctionCall(call);
        
        if (auto* arrInit = dynamic_cast<ArrayInit*>(node))
            return EvaluateArrayInit(arrInit, expectedType);
        
        if (auto* structInit = dynamic_cast<StructInit*>(node))
            return EvaluateStructInit(structInit);
        
        if (auto* unary = dynamic_cast<UnaryExpr*>(node))
            return EvaluateUnaryExpr(unary);
        
        if (auto* binary = dynamic_cast<BinaryExpr*>(node))
            return EvaluateBinaryExpr(binary);
        
        if (auto* vaArg = dynamic_cast<VaArgExpr*>(node))
        {
            TypedValue vaList = EvaluateLValue(vaArg->va_list.get());
            TypeInfo targetType = ResolveType(vaArg->type.get());
            
            Value* vaListPtr = vaList.value;
            
            if (vaList.type.llvmType->isArrayTy())
            {
                vaListPtr = m_builder.CreateInBoundsGEP(
                    vaList.type.llvmType,
                    vaList.value,
                    {m_builder.getInt64(0), m_builder.getInt64(0)}
                );
            }
            
            auto* result = m_builder.CreateVAArg(vaListPtr, targetType.llvmType);
            return TypedValue(result, targetType);
        }

        Error("Invalid rvalue expression", node->line);
    }

    TypedValue EvaluateNumberLiteral(NumberLiteral* lit)
    {
        const std::string &value = lit->value;

        bool isHex = value.size() >= 2 && value[0] == '0' && 
                    (value[1] == 'x' || value[1] == 'X');

        bool isFloatingPoint = !isHex && (
            value.find('.') != std::string::npos ||
            value.find('e') != std::string::npos ||
            value.find('E') != std::string::npos
        );

        if (!isFloatingPoint)
        {
            bool isUnsigned = false;
            bool isLong = false;
            
            size_t pos = value.size();
            while (pos > 0 && !std::isdigit(value[pos - 1]))
            {
                char c = std::tolower(value[pos - 1]);
                if (c == 'u') isUnsigned = true;
                else if (c == 'l') isLong = true;
                pos--;
            }
            
            std::string numericPart = value.substr(0, pos);
            int64_t intValue = std::stoll(numericPart, nullptr, 0);
            
            if (isLong || intValue > INT32_MAX || intValue < INT32_MIN)
            {
                auto* val = m_builder.getInt64(intValue);
                return TypedValue(val, TypeInfo(m_builder.getInt64Ty(), isUnsigned));
            }
            else
            {
                auto* val = m_builder.getInt32((int32_t)intValue);
                return TypedValue(val, TypeInfo(m_builder.getInt32Ty(), isUnsigned));
            }
        }
        else
        {
            bool isFloat = false;
            
            size_t pos = value.size();
            if (pos > 0 && std::tolower(value[pos - 1]) == 'f')
            {
                isFloat = true;
                pos--;
            }
            
            std::string numericPart = value.substr(0, pos);
            double doubleValue = std::stod(numericPart);
            
            if (isFloat)
            {
                auto* val = ConstantFP::get(m_builder.getFloatTy(), (float)doubleValue);
                return TypedValue(val, TypeInfo(m_builder.getFloatTy(), false));
            }
            else
            {
                auto* val = ConstantFP::get(m_builder.getDoubleTy(), doubleValue);
                return TypedValue(val, TypeInfo(m_builder.getDoubleTy(), false));
            }
        }
    }

    TypedValue EvaluateStringLiteral(::StringLiteral* lit)
    {
        auto* str = m_builder.CreateGlobalString(lit->value, ".str");
        return TypedValue(str, TypeInfo(llvm::PointerType::getUnqual(m_builder.getContext()), false, m_builder.getInt8Ty()));
    }

    TypedValue EvaluateCast(CastExpr *cast)
    {
        TypedValue operand = EvaluateRValue(cast->operand.get());
        TypeInfo targetType = ResolveType(cast->target_type.get());
        return CastValue(operand, targetType, cast->line);
    }

    TypedValue EvaluateFunctionCall(CallExpr *call)
    {
        if (auto* ident = dynamic_cast<Identifier*>(call->callee.get()))
        {
            if (ident->name == "va_start")
            {
                if (call->args.size() != 2)
                    Error("va_start requires exactly 2 arguments: va_list and last named parameter", call->line);
                
                TypedValue vaListArg = EvaluateLValue(call->args[0].get());
                
                auto funcIt = m_functions.find("llvm.va_start");
                if (funcIt == m_functions.end())
                    Error("llvm.va_start intrinsic not found", call->line);
                
                Value* vaListPtr = m_builder.CreateBitCast(vaListArg.value, m_builder.getPtrTy());
                
                m_builder.CreateCall(funcIt->second.function, {vaListPtr});
                return TypedValue(nullptr, TypeInfo(m_builder.getVoidTy(), false));
            }

            if (ident->name == "va_end")
            {
                if (call->args.size() != 1)
                    Error("va_end requires exactly 1 argument: va_list", call->line);

                TypedValue vaListArg = EvaluateLValue(call->args[0].get());

                auto funcIt = m_functions.find("llvm.va_end");
                if (funcIt == m_functions.end())
                    Error("llvm.va_end intrinsic not found", call->line);

                Value* vaListPtr = m_builder.CreateBitCast(vaListArg.value, m_builder.getPtrTy());

                m_builder.CreateCall(funcIt->second.function, {vaListPtr});
                return TypedValue(nullptr, TypeInfo(m_builder.getVoidTy(), false));
            }

            auto funcIt = m_functions.find(ident->name);
            if (funcIt != m_functions.end())
            {
                const FunctionInfo& func = funcIt->second;
                
                if (func.isVarArg)
                {
                    if (call->args.size() < func.paramTypes.size())
                        Error("Too few arguments for " + ident->name, call->line);
                }
                else
                {
                    if (call->args.size() != func.paramTypes.size())
                        Error("Argument count mismatch for " + ident->name, call->line);
                }
                
                std::vector<Value*> args;
                for (size_t i = 0; i < call->args.size(); i++)
                {
                    TypedValue arg = EvaluateRValue(call->args[i].get());
                    
                    if (i < func.paramTypes.size())
                    {
                        if (arg.type != func.paramTypes[i])
                            arg = CastValue(arg, func.paramTypes[i], call->args[i]->line);
                    }
                    
                    args.push_back(arg.value);
                }
                
                auto* result = m_builder.CreateCall(func.function, args);
                return TypedValue(result, func.returnType);
            }
            
            Variable var = LookupVariable(ident->name, ident->line);
            
            if (!var.type.functionInfo)
                Error("Variable '" + ident->name + "' is not callable", call->line);
            
            const FunctionInfo& funcInfo = *var.type.functionInfo;
            
            if (funcInfo.isVarArg)
            {
                if (call->args.size() < funcInfo.paramTypes.size())
                    Error("Too few arguments", call->line);
            }
            else
            {
                if (call->args.size() != funcInfo.paramTypes.size())
                    Error("Argument count mismatch", call->line);
            }
            
            Value* funcPtr = m_builder.CreateLoad(var.type.llvmType, var.storage);
            FunctionType* funcType = cast<FunctionType>(var.type.pointeeType);
            
            std::vector<Value*> args;
            for (size_t i = 0; i < call->args.size(); i++)
            {
                TypedValue arg = EvaluateRValue(call->args[i].get());
                
                if (i < funcInfo.paramTypes.size())
                {
                    if (arg.type != funcInfo.paramTypes[i])
                        arg = CastValue(arg, funcInfo.paramTypes[i], call->args[i]->line);
                }
                
                args.push_back(arg.value);
            }
            
            auto* result = m_builder.CreateCall(funcType, funcPtr, args);
            return TypedValue(result, funcInfo.returnType);
        }
        
        TypedValue calleeValue = EvaluateRValue(call->callee.get());
        
        if (!calleeValue.type.functionInfo)
            Error("Expression is not callable", call->line);
        
        const FunctionInfo& funcInfo = *calleeValue.type.functionInfo;
        
        if (funcInfo.isVarArg)
        {
            if (call->args.size() < funcInfo.paramTypes.size())
                Error("Too few arguments for function call", call->line);
        }
        else
        {
            if (call->args.size() != funcInfo.paramTypes.size())
                Error("Argument count mismatch for function call", call->line);
        }
        
        FunctionType* funcType = cast<FunctionType>(calleeValue.type.pointeeType);
        
        std::vector<Value*> args;
        for (size_t i = 0; i < call->args.size(); i++)
        {
            TypedValue arg = EvaluateRValue(call->args[i].get());
            
            if (i < funcInfo.paramTypes.size())
            {
                if (arg.type != funcInfo.paramTypes[i])
                    arg = CastValue(arg, funcInfo.paramTypes[i], call->args[i]->line);
            }
            
            args.push_back(arg.value);
        }
        
        auto* result = m_builder.CreateCall(funcType, calleeValue.value, args);
        return TypedValue(result, funcInfo.returnType);
    }

    TypedValue EvaluateArrayAccess(ArrayAccess* access)
    {
        TypedValue index = EvaluateRValue(access->index.get());
        
        if (!index.type.llvmType->isIntegerTy(64))
            index = CastValue(index, TypeInfo(m_builder.getInt64Ty(), false), access->index->line);
        
        TypedValue base = EvaluateLValue(access->array.get());
        Type* baseType = base.type.llvmType;
        
        if (baseType->isArrayTy())
        {
            Type* elementType = baseType->getArrayElementType();
            Value* gep = m_builder.CreateInBoundsGEP(
                baseType, base.value,
                {m_builder.getInt64(0), index.value}
            );
            
            TypeInfo elemTypeInfo(elementType, base.type.isUnsigned, base.type.isConst);
            
            if (elementType->isArrayTy() && base.type.functionInfo)
            {
                elemTypeInfo.pointeeType = base.type.pointeeType;
                elemTypeInfo.functionInfo = base.type.functionInfo;
            }
            else if (elementType->isPointerTy() && base.type.functionInfo)
            {
                elemTypeInfo.pointeeType = base.type.pointeeType;
                elemTypeInfo.functionInfo = base.type.functionInfo;
            }
            
            return TypedValue(gep, elemTypeInfo);
        }
        
        if (baseType->isPointerTy())
        {
            if (!base.type.pointeeType)
                Error("Cannot index pointer without pointee type", access->line);
            
            Value* ptr = m_builder.CreateLoad(baseType, base.value);
            Value* gep = m_builder.CreateInBoundsGEP(
                base.type.pointeeType, ptr, index.value
            );
            
            TypeInfo elemTypeInfo(base.type.pointeeType, base.type.isUnsigned, base.type.isConst);
            
            if (base.type.pointeeType->isArrayTy() && base.type.functionInfo)
            {
                elemTypeInfo.pointeeType = base.type.pointeeType;
                elemTypeInfo.functionInfo = base.type.functionInfo;
            }
            else if (base.type.pointeeType->isPointerTy() && base.type.functionInfo)
            {
                elemTypeInfo.pointeeType = base.type.functionInfo->function->getFunctionType();
                elemTypeInfo.functionInfo = base.type.functionInfo;
            }
            
            return TypedValue(gep, elemTypeInfo);
        }
        
        Error("Cannot index non-array/non-pointer type", access->line);
    }

    TypedValue EvaluateMemberAccess(MemberAccess* access)
    {
        TypedValue structPtr = EvaluateLValue(access->object.get());
        
        Type* structType = structPtr.type.llvmType;
        if (!structType->isStructTy())
            Error("Member access on non-struct type", access->line);
        
        const StructInfo* structInfo = FindStructInfo(structType);
        if (!structInfo)
            Error("Unknown struct type", access->line);
        
        auto it = structInfo->fieldIndices.find(access->member);
        if (it == structInfo->fieldIndices.end())
            Error("Unknown member: " + access->member, access->line);
        
        unsigned fieldIndex = it->second;
        TypeInfo fieldType = structInfo->fieldTypes.at(access->member);
        fieldType.isConst = structPtr.type.isConst || fieldType.isConst;

        auto* fieldPtr = m_builder.CreateStructGEP(structType, structPtr.value, fieldIndex);
        return TypedValue(fieldPtr, fieldType);
    }

    TypedValue EvaluatePointerMemberAccess(PointerMemberAccess* access)
    {
        TypedValue ptr = EvaluateRValue(access->object.get());
        
        if (!ptr.type.llvmType->isPointerTy() || !ptr.type.pointeeType)
            Error("Cannot use -> on non-pointer type", access->line);
        
        Type* pointeeType = ptr.type.pointeeType;
        if (!pointeeType->isStructTy())
            Error("Cannot access member on non-struct pointer", access->line);
        
        const StructInfo* structInfo = FindStructInfo(pointeeType);
        if (!structInfo)
            Error("Unknown struct type", access->line);
        
        auto it = structInfo->fieldIndices.find(access->member);
        if (it == structInfo->fieldIndices.end())
            Error("Unknown member: " + access->member, access->line);
        
        unsigned fieldIndex = it->second;
    
        TypeInfo fieldType = structInfo->fieldTypes.at(access->member);
        fieldType.isConst = ptr.type.isConst || fieldType.isConst;

        auto* fieldPtr = m_builder.CreateStructGEP(pointeeType, ptr.value, fieldIndex);
        return TypedValue(fieldPtr, fieldType);
    }

    TypedValue EvaluateArrayInit(ArrayInit* init, const TypeInfo* expectedType)
    {
        size_t arraySize;
        TypeInfo elementType;
        
        if (expectedType && expectedType->llvmType->isArrayTy())
        {
            auto* arrayType = cast<ArrayType>(expectedType->llvmType);
            arraySize = arrayType->getNumElements();
            
            Type* elemLLVMType = arrayType->getElementType();
            elementType = TypeInfo(elemLLVMType, expectedType->isUnsigned);
            
            if (expectedType->functionInfo)
            {
                elementType.pointeeType = expectedType->pointeeType;
                elementType.functionInfo = expectedType->functionInfo;
            }
        }
        else
        {
            if (init->elements.empty())
                Error("Cannot infer array type from empty initializer", init->line);
            
            arraySize = init->elements.size();
            
            elementType = EvaluateRValue(init->elements[0].get()).type;
            
            if (auto* firstIdent = dynamic_cast<Identifier*>(init->elements[0].get()))
            {
                auto funcIt = m_functions.find(firstIdent->name);
                if (funcIt != m_functions.end())
                {
                    Function* func = funcIt->second.function;
                    elementType = TypeInfo(
                        func->getType(),
                        false,
                        false,
                        func->getFunctionType(),
                        std::make_shared<FunctionInfo>(funcIt->second)
                    );
                }
            }
            
            for (size_t i = 1; i < init->elements.size(); i++)
            {
                TypeInfo elemType = EvaluateRValue(init->elements[i].get()).type;
                
                if (auto* ident = dynamic_cast<Identifier*>(init->elements[i].get()))
                {
                    auto funcIt = m_functions.find(ident->name);
                    if (funcIt != m_functions.end())
                    {
                        Function* func = funcIt->second.function;
                        elemType = TypeInfo(
                            func->getType(),
                            false,
                            false,
                            func->getFunctionType(),
                            std::make_shared<FunctionInfo>(funcIt->second)
                        );
                    }
                }
                
                elementType = PromoteToCommonType(elementType, elemType);
            }
        }
        
        auto* arrayType = ArrayType::get(elementType.llvmType, arraySize);
        auto* alloca = m_builder.CreateAlloca(arrayType, nullptr, "array_tmp");
        
        TypeInfo arrayTypeInfo(arrayType, elementType.isUnsigned);
        arrayTypeInfo.pointeeType = elementType.pointeeType;
        arrayTypeInfo.functionInfo = elementType.functionInfo;
        
        InitializeArrayInPlace(alloca, arrayTypeInfo, init);
        
        auto* arrayValue = m_builder.CreateLoad(arrayType, alloca);
        return TypedValue(arrayValue, arrayTypeInfo);
    }

    TypedValue EvaluateStructInit(StructInit* init)
    {
        auto it = m_structs.find(init->type_name);
        if (it == m_structs.end())
            Error("Unknown struct: " + init->type_name, init->line);
        
        const StructInfo& info = it->second;
        auto* alloca = m_builder.CreateAlloca(info.type, nullptr, "struct_tmp");
        
        InitializeStructInPlace(alloca, TypeInfo(info.type, false), init);
        
        auto* structValue = m_builder.CreateLoad(info.type, alloca);
        return TypedValue(structValue, TypeInfo(info.type, false));
    }

    TypedValue EvaluateUnaryExpr(UnaryExpr* unary)
    {
        if (unary->op == '&')
        {
            TypedValue lval = EvaluateLValue(unary->operand.get());
            
            std::vector<bool> ptrConst;
            ptrConst.push_back(false);
            
            TypeInfo ptrType(
                m_builder.getPtrTy(),
                false,
                false,
                lval.type.llvmType,
                nullptr,
                ptrConst
            );

            return TypedValue(lval.value, ptrType);
        }
        
        if (unary->op == '*')
        {
            TypedValue ptr = EvaluateRValue(unary->operand.get());
            if (!ptr.type.llvmType->isPointerTy() || !ptr.type.pointeeType)
                Error("Cannot dereference non-pointer", unary->line);

            bool pointeeIsConst = false;
            if (!ptr.type.pointerConst.empty())
                pointeeIsConst = ptr.type.isConst;
            
            auto* loaded = m_builder.CreateLoad(ptr.type.pointeeType, ptr.value);
            return TypedValue(loaded, TypeInfo(ptr.type.pointeeType, ptr.type.isUnsigned, pointeeIsConst));
        }
        
        if (unary->op == '-')
        {
            TypedValue operand = EvaluateRValue(unary->operand.get());
            Value* result = operand.type.llvmType->isFloatingPointTy()
                ? m_builder.CreateFNeg(operand.value)
                : m_builder.CreateNeg(operand.value);
            return TypedValue(result, operand.type);
        }

        if (unary->op == '!')
        {
            TypedValue operand = EvaluateRValue(unary->operand.get());
            Value* cond = operand.type.llvmType->isFloatingPointTy()
                ? m_builder.CreateFCmpUNE(operand.value, ConstantFP::get(operand.type.llvmType, 0.0))
                : m_builder.CreateICmpNE(operand.value, ConstantInt::get(operand.type.llvmType, 0));
            Value* result = m_builder.CreateNot(cond);
            return TypedValue(result, TypeInfo(m_builder.getInt1Ty(), false));
        }
        
        Error("Unknown unary operator", unary->line);
    }

    TypedValue EvaluateBinaryExpr(BinaryExpr* binary)
    {
        if (binary->op == '=')
        {
            TypedValue lhs = EvaluateLValue(binary->left.get());

            if (lhs.type.isConst)
            {
                if (auto* id = dynamic_cast<Identifier*>(binary->left.get()))
                    Error("Cannot assign to constant variable '" + id->name + "'", binary->line);
                else if (auto* unary = dynamic_cast<UnaryExpr*>(binary->left.get()))
                {
                    if (unary->op == '*')
                        Error("Cannot assign to const-qualified pointee", binary->line);
                }
                else if (auto* member = dynamic_cast<MemberAccess*>(binary->left.get()))
                    Error("Cannot assign to constant member '" + member->member + "'", binary->line);
                else if (dynamic_cast<ArrayAccess*>(binary->left.get()))
                    Error("Cannot assign to constant array element", binary->line);
                else
                    Error("Cannot assign to constant expression", binary->line);
            }

            if (lhs.type.llvmType->isArrayTy() || lhs.type.llvmType->isStructTy())
            {
                bool isInitializer = dynamic_cast<StructInit*>(binary->right.get()) != nullptr ||
                                    dynamic_cast<ArrayInit*>(binary->right.get()) != nullptr;
                
                TypedValue rhs = isInitializer 
                    ? EvaluateRValue(binary->right.get())
                    : EvaluateLValue(binary->right.get());
                
                if (rhs.type != lhs.type)
                    Error("Type mismatch in aggregate assignment", binary->line);
                
                if (isInitializer) {
                    auto* tempAlloca = m_builder.CreateAlloca(rhs.type.llvmType, nullptr, "temp_aggregate");
                    m_builder.CreateStore(rhs.value, tempAlloca);
                    rhs.value = tempAlloca;
                }
                
                uint64_t size = m_module->getDataLayout().getTypeAllocSize(lhs.type.llvmType);
                m_builder.CreateMemCpy(
                    lhs.value,
                    MaybeAlign(),
                    rhs.value,
                    MaybeAlign(),
                    size
                );
                
                return rhs;
            }

            TypedValue rhs = EvaluateRValue(binary->right.get());
            
            if (rhs.type != lhs.type)
                rhs = CastValue(rhs, lhs.type, binary->line);
            m_builder.CreateStore(rhs.value, lhs.value);
            return rhs;
        }

        if (binary->op == TokenType_PlusEqual || binary->op == TokenType_MinusEqual ||
            binary->op == TokenType_StarEqual || binary->op == TokenType_SlashEqual ||
            binary->op == TokenType_PercentEqual)
        {
            TypedValue lhs = EvaluateLValue(binary->left.get());
            
            if (lhs.type.isConst)
            {
                if (auto* id = dynamic_cast<Identifier*>(binary->left.get()))
                    Error("Cannot assign to constant variable '" + id->name + "'", binary->line);
                else if (auto* member = dynamic_cast<MemberAccess*>(binary->left.get()))
                    Error("Cannot assign to constant member '" + member->member + "'", binary->line);
                else if (dynamic_cast<ArrayAccess*>(binary->left.get()))
                    Error("Cannot assign to constant array element", binary->line);
                else if (dynamic_cast<UnaryExpr*>(binary->left.get()))
                    Error("Cannot assign to constant through pointer dereference", binary->line);
                else
                    Error("Cannot assign to constant expression", binary->line);
            }
            
            TypedValue currentValue(m_builder.CreateLoad(lhs.type.llvmType, lhs.value), lhs.type);
            TypedValue rhs = EvaluateRValue(binary->right.get());
            
            char opChar;
            switch (binary->op)
            {
                case TokenType_PlusEqual:    opChar = '+'; break;
                case TokenType_MinusEqual:   opChar = '-'; break;
                case TokenType_StarEqual:    opChar = '*'; break;
                case TokenType_SlashEqual:   opChar = '/'; break;
                case TokenType_PercentEqual: opChar = '%'; break;
                default: Error("Unknown compound assignment operator", binary->line);
            }
            
            if ((binary->op == TokenType_PlusEqual || binary->op == TokenType_MinusEqual) &&
                currentValue.type.llvmType->isPointerTy())
            {
                if (auto result = TryPointerArithmetic(opChar, currentValue, rhs))
                {
                    m_builder.CreateStore(result->value, lhs.value);
                    return *result;
                }
            }
            
            TypeInfo commonType = PromoteToCommonType(currentValue.type, rhs.type);
            currentValue = CastIfNeeded(currentValue, commonType, binary->line);
            rhs = CastIfNeeded(rhs, commonType, binary->line);
            
            const bool isFloat = commonType.llvmType->isFloatingPointTy();
            const bool isUnsigned = commonType.isUnsigned;
            
            Value* result = nullptr;
            switch (opChar)
            {
                case '+': result = isFloat ? m_builder.CreateFAdd(currentValue.value, rhs.value) : m_builder.CreateAdd(currentValue.value, rhs.value); break;
                case '-': result = isFloat ? m_builder.CreateFSub(currentValue.value, rhs.value) : m_builder.CreateSub(currentValue.value, rhs.value); break;
                case '*': result = isFloat ? m_builder.CreateFMul(currentValue.value, rhs.value) : m_builder.CreateMul(currentValue.value, rhs.value); break;
                case '/': result = CreateDivision(currentValue.value, rhs.value, isFloat, isUnsigned); break;
                case '%': result = CreateRemainder(currentValue.value, rhs.value, isFloat, isUnsigned); break;
                default: Error("Unknown binary operator in compound assignment", binary->line);
            }
            
            TypedValue resultValue(result, commonType);
            
            if (resultValue.type != lhs.type)
                resultValue = CastValue(resultValue, lhs.type, binary->line);
            
            m_builder.CreateStore(resultValue.value, lhs.value);
            return resultValue;
        }

        TypedValue lhs = EvaluateRValue(binary->left.get());
        TypedValue rhs = EvaluateRValue(binary->right.get());

        if (binary->op == '+' || binary->op == '-')
        {
            if (auto result = TryPointerArithmetic(binary->op, lhs, rhs))
                return *result;
        }

        TypeInfo commonType = PromoteToCommonType(lhs.type, rhs.type);
        lhs = CastIfNeeded(lhs, commonType, binary->line);
        rhs = CastIfNeeded(rhs, commonType, binary->line);
        
        const bool isFloat = commonType.llvmType->isFloatingPointTy();
        const bool isUnsigned = commonType.isUnsigned;
        
        Value* result = nullptr;
        TypeInfo resultType = commonType;
        
        switch (binary->op)
        {
            case '+': result = isFloat ? m_builder.CreateFAdd(lhs.value, rhs.value) : m_builder.CreateAdd(lhs.value, rhs.value); break;
            case '-': result = isFloat ? m_builder.CreateFSub(lhs.value, rhs.value) : m_builder.CreateSub(lhs.value, rhs.value); break;
            case '*': result = isFloat ? m_builder.CreateFMul(lhs.value, rhs.value) : m_builder.CreateMul(lhs.value, rhs.value); break;
            case '/': result = CreateDivision(lhs.value, rhs.value, isFloat, isUnsigned); break;
            case '%': result = CreateRemainder(lhs.value, rhs.value, isFloat, isUnsigned); break;
            case '&': 
                if (isFloat) Error("Bitwise AND not supported on floating-point types", binary->line);
                result = m_builder.CreateAnd(lhs.value, rhs.value); 
                break;
            case '|': 
                if (isFloat) Error("Bitwise OR not supported on floating-point types", binary->line);
                result = m_builder.CreateOr(lhs.value, rhs.value); 
                break;
            case '^': 
                if (isFloat) Error("Bitwise XOR not supported on floating-point types", binary->line);
                result = m_builder.CreateXor(lhs.value, rhs.value); 
                break;
            case TokenType_LeftShift:
                if (isFloat) Error("Left shift not supported on floating-point types", binary->line);
                result = m_builder.CreateShl(lhs.value, rhs.value); 
                break;
            case TokenType_RightShift:
                if (isFloat) Error("Right shift not supported on floating-point types", binary->line);
                result = isUnsigned ? m_builder.CreateLShr(lhs.value, rhs.value) : m_builder.CreateAShr(lhs.value, rhs.value);
                break;
            case TokenType_EqualEqual: result = CreateEquality(lhs.value, rhs.value, isFloat, true); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case TokenType_NotEqual: result = CreateEquality(lhs.value, rhs.value, isFloat, false); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case '<': result = CreateComparison(lhs.value, rhs.value, isFloat, isUnsigned, CmpInst::ICMP_SLT, CmpInst::ICMP_ULT, CmpInst::FCMP_OLT); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case TokenType_LessEqual: result = CreateComparison(lhs.value, rhs.value, isFloat, isUnsigned, CmpInst::ICMP_SLE, CmpInst::ICMP_ULE, CmpInst::FCMP_OLE); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case '>': result = CreateComparison(lhs.value, rhs.value, isFloat, isUnsigned, CmpInst::ICMP_SGT, CmpInst::ICMP_UGT, CmpInst::FCMP_OGT); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case TokenType_GreaterEqual: result = CreateComparison(lhs.value, rhs.value, isFloat, isUnsigned, CmpInst::ICMP_SGE, CmpInst::ICMP_UGE, CmpInst::FCMP_OGE); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            default: Error("Unknown binary operator", binary->line);
        }
        
        return TypedValue(result, resultType);
    }

    std::optional<TypedValue> TryPointerArithmetic(char op, TypedValue& lhs, TypedValue& rhs)
    {
        if (lhs.type.llvmType->isPointerTy() && rhs.type.llvmType->isIntegerTy())
        {
            rhs = CastIfNeeded(rhs, TypeInfo(m_builder.getInt64Ty(), false));
            Value* offset = (op == '+') ? rhs.value : m_builder.CreateNeg(rhs.value);
            Value* result = m_builder.CreateGEP(lhs.type.pointeeType, lhs.value, offset);
            return TypedValue(result, lhs.type);
        }
        
        if (lhs.type.llvmType->isIntegerTy() && rhs.type.llvmType->isPointerTy() && op == '+')
        {
            lhs = CastIfNeeded(lhs, TypeInfo(m_builder.getInt64Ty(), false));
            Value* result = m_builder.CreateGEP(rhs.type.pointeeType, rhs.value, lhs.value);
            return TypedValue(result, rhs.type);
        }
        
        if (lhs.type.llvmType->isPointerTy() && rhs.type.llvmType->isPointerTy() && op == '-')
        {
            Value* lhsInt = m_builder.CreatePtrToInt(lhs.value, m_builder.getInt64Ty());
            Value* rhsInt = m_builder.CreatePtrToInt(rhs.value, m_builder.getInt64Ty());
            Value* diff = m_builder.CreateSub(lhsInt, rhsInt);
            return TypedValue(diff, TypeInfo(m_builder.getInt64Ty(), false));
        }
        
        return std::nullopt;
    }
    
    TypeInfo ResolveType(TypeNode* node)
    {
        if (node->is_function_type)
        {
            TypeInfo returnType = node->return_type ?
                ResolveType(node->return_type.get()) :
                TypeInfo(Type::getVoidTy(m_context), false);
            
            FunctionInfo funcInfo;
            funcInfo.isVarArg = false;
            funcInfo.function = nullptr;

            std::vector<Type*> paramLLVMTypes;
            for (const auto& paramType : node->param_types)
            {
                TypeInfo paramInfo = ResolveType(paramType.get());
                funcInfo.paramTypes.push_back(paramInfo);
                paramLLVMTypes.push_back(paramInfo.llvmType);
            }

            funcInfo.returnType = returnType;
            
            auto* funcType = FunctionType::get(returnType.llvmType, paramLLVMTypes, false);
            auto* funcPtrType = m_builder.getPtrTy();

            if (!node->array_dimensions.empty())
            {
                Type* arrayType = funcPtrType;
                for (size_t dim : node->array_dimensions)
                    arrayType = ArrayType::get(arrayType, dim);
                return TypeInfo(arrayType, false, node->is_const, funcType, std::make_shared<FunctionInfo>(funcInfo));
            }

            return TypeInfo(funcPtrType, false, node->is_const, funcType, std::make_shared<FunctionInfo>(funcInfo));
        }
        
        if (!node->array_dimensions.empty())
        {
            TypeInfo baseType = ResolveSimpleType(node);
            Type* type = baseType.llvmType;
            for (size_t dim : node->array_dimensions)
                type = ArrayType::get(type, dim);
            return TypeInfo(type, baseType.isUnsigned, false, nullptr, nullptr, baseType.pointerConst);
        }
        
        return ResolveSimpleType(node);
    }

    TypeInfo ResolveSimpleType(TypeNode* node)
    {
        Type* baseType = nullptr;
        bool isUnsigned = false;
        
        baseType = GetBuiltinType(node->name, isUnsigned);
        
        if (!baseType)
        {
            auto structIt = m_structs.find(node->name);
            if (structIt != m_structs.end())
                baseType = structIt->second.type;
        }
        
        if (!baseType)
        {
            auto enumIt = m_enums.find(node->name);
            if (enumIt != m_enums.end())
            {
                baseType = m_builder.getInt32Ty();
                isUnsigned = false;
            }
        }

        if (!baseType)
            Error("Unknown type: " + node->name, node->line);
        
        if (node->pointer_depth > 0)
        {
            Type* pointeeType = baseType->isVoidTy() ? m_builder.getInt8Ty() : baseType;
            
            std::vector<bool> ptrConst = node->pointer_const;
            bool topLevelConst = !ptrConst.empty() ? ptrConst.back() : false;
            
            return TypeInfo(m_builder.getPtrTy(), false, topLevelConst, pointeeType, nullptr, ptrConst);
        }
        
        return TypeInfo(baseType, isUnsigned, node->is_const, nullptr, nullptr, {});
    }

    Type* GetBuiltinType(const std::string& name, bool& outIsUnsigned)
    {
        static const std::unordered_map<std::string, std::function<Type*(IRBuilder<>&)>> typeMap = {
            {"u0", [](auto& b) { return b.getVoidTy(); }},
            {"bool", [](auto& b) { return b.getInt1Ty(); }},
            {"char", [](auto& b) { return b.getInt8Ty(); }},
            {"i8", [](auto& b) { return b.getInt8Ty(); }},
            {"i16", [](auto& b) { return b.getInt16Ty(); }},
            {"i32", [](auto& b) { return b.getInt32Ty(); }},
            {"i64", [](auto& b) { return b.getInt64Ty(); }},
            {"u8", [](auto& b) { return b.getInt8Ty(); }},
            {"u16", [](auto& b) { return b.getInt16Ty(); }},
            {"u32", [](auto& b) { return b.getInt32Ty(); }},
            {"u64", [](auto& b) { return b.getInt64Ty(); }},
            {"usize", [](auto& b) { return b.getInt64Ty(); }},
            {"f32", [](auto& b) { return b.getFloatTy(); }},
            {"f64", [](auto& b) { return b.getDoubleTy(); }},
            {"va_list", [](auto& b) { 
                return ArrayType::get(b.getInt8Ty(), 32);
            }}
        };
        
        auto it = typeMap.find(name);
        if (it != typeMap.end())
        {
            outIsUnsigned = (name[0] == 'u' && name != "u0");
            return it->second(m_builder);
        }
        
        outIsUnsigned = false;
        return nullptr;
    }
    
    TypedValue CastValue(TypedValue value, TypeInfo targetType, uint32_t line = 0)
    {
        if (value.type == targetType)
            return value;
        
        Type* fromType = value.type.llvmType;
        Type* toType = targetType.llvmType;

        if ((targetType.functionInfo && !value.type.functionInfo))
            Error("Cannot assign non-function pointer to function pointer", line);
        
        if (fromType->isPointerTy() && toType->isPointerTy())
        {
            if (value.type.pointeeType == targetType.pointeeType)
                return TypedValue(value.value, targetType);
            return TypedValue(m_builder.CreateBitCast(value.value, toType), targetType);
        }
        
        if (fromType->isIntegerTy() && toType->isIntegerTy())
        {
            unsigned fromBits = fromType->getIntegerBitWidth();
            unsigned toBits = toType->getIntegerBitWidth();
            
            if (fromBits < toBits)
            {
                Value* result = (fromBits == 1 || value.type.isUnsigned)
                    ? m_builder.CreateZExt(value.value, toType)
                    : m_builder.CreateSExt(value.value, toType);
                return TypedValue(result, targetType);
            }
            else if (fromBits > toBits)
            {
                return TypedValue(m_builder.CreateTrunc(value.value, toType), targetType);
            }
            return TypedValue(value.value, targetType);
        }
        
        if (fromType->isFloatingPointTy() && toType->isFloatingPointTy())
        {
            unsigned fromBits = fromType->getPrimitiveSizeInBits();
            unsigned toBits = toType->getPrimitiveSizeInBits();
            
            Value* result = (fromBits < toBits)
                ? m_builder.CreateFPExt(value.value, toType)
                : (fromBits > toBits)
                    ? m_builder.CreateFPTrunc(value.value, toType)
                    : value.value;
            return TypedValue(result, targetType);
        }
        
        if (fromType->isIntegerTy() && toType->isFloatingPointTy())
        {
            Value* result = (fromType->isIntegerTy(1) || value.type.isUnsigned)
                ? m_builder.CreateUIToFP(value.value, toType)
                : m_builder.CreateSIToFP(value.value, toType);
            return TypedValue(result, targetType);
        }
        
        if (fromType->isFloatingPointTy() && toType->isIntegerTy())
        {
            Value* result = targetType.isUnsigned
                ? m_builder.CreateFPToUI(value.value, toType)
                : m_builder.CreateFPToSI(value.value, toType);
            return TypedValue(result, targetType);
        }

        if (fromType->isIntegerTy() && toType->isPointerTy())
            return TypedValue(m_builder.CreateIntToPtr(value.value, toType), targetType);

        if (fromType->isPointerTy() && toType->isIntegerTy())
            return TypedValue(m_builder.CreatePtrToInt(value.value, toType), targetType);
        
        Error("Cannot cast between incompatible types", line);
    }
    
    TypeInfo PromoteToCommonType(const TypeInfo& left, const TypeInfo& right)
    {
        Type* leftType = left.llvmType;
        Type* rightType = right.llvmType;
        
        if (leftType->isFloatingPointTy() || rightType->isFloatingPointTy())
        {
            if (leftType->isFloatingPointTy() && rightType->isFloatingPointTy())
            {
                return (leftType->getPrimitiveSizeInBits() >= rightType->getPrimitiveSizeInBits())
                    ? left : right;
            }
            return leftType->isFloatingPointTy() ? left : right;
        }
        
        if (leftType->isIntegerTy() && rightType->isIntegerTy())
        {
            unsigned leftBits = leftType->getIntegerBitWidth();
            unsigned rightBits = rightType->getIntegerBitWidth();
            
            if (leftBits == rightBits)
                return (left.isUnsigned != right.isUnsigned && left.isUnsigned) ? left : right;
            
            return (leftBits > rightBits) ? left : right;
        }

        if (leftType->isPointerTy() && rightType->isIntegerTy())
            return left;
        if (leftType->isIntegerTy() && rightType->isPointerTy())
            return right;
        
        return left;
    }

    TypedValue CastIfNeeded(TypedValue value, const TypeInfo& targetType, uint32_t line = 0)
    {
        return (value.type != targetType) ? CastValue(value, targetType, line) : value;
    }

    TypedValue EnsureBooleanType(TypedValue value, uint32_t line = 0)
    {
        if (value.type.llvmType->isIntegerTy(1))
            return value;
        return CastValue(value, TypeInfo(m_builder.getInt1Ty(), false), line);
    }
    
    Variable LookupVariable(const std::string& name, uint32_t line = 0)
    {
        int32_t scopeIdx = m_currentScope;
        while (scopeIdx >= 0)
        {
            Scope& scope = m_scopes[scopeIdx];
            std::string scopedName = name + '.' + std::to_string(scope.id);
            if (m_locals.find(scopedName) != m_locals.end())
                return m_locals[scopedName];
            scopeIdx = scope.parent;
        }
        
        auto it = m_globals.find(name);
        if (it != m_globals.end())
            return it->second;
        
        Error("Unknown variable: " + name, line);
    }

    const StructInfo* FindStructInfo(Type* structType) const
    {
        for (const auto& [name, info] : m_structs)
        {
            if (info.type == structType)
                return &info;
        }
        return nullptr;
    }

    const TypeInfo* FindFieldTypeAtIndex(const StructInfo& info, unsigned index) const
    {
        for (const auto& [name, idx] : info.fieldIndices)
        {
            if (idx == index)
                return &info.fieldTypes.at(name);
        }
        return nullptr;
    }

    LoopContext PushLoop(BasicBlock* continueTarget, BasicBlock* breakTarget)
    {
        LoopContext prev = m_loopContext;
        m_loopContext = {continueTarget, breakTarget};
        return prev;
    }

    void PopLoop(const LoopContext& prev)
    {
        m_loopContext = prev;
    }

    void CreateUnreachableBlock()
    {
        auto* function = m_builder.GetInsertBlock()->getParent();
        auto* unreachableBB = BasicBlock::Create(m_context, "unreachable", function);
        m_builder.SetInsertPoint(unreachableBB);
    }

    Value* CreateZeroValue(Type* type)
    {
        if (type->isIntegerTy())
            return ConstantInt::get(type, 0);
        if (type->isFloatingPointTy())
            return ConstantFP::get(type, 0.0);
        if (type->isPointerTy())
            return ConstantPointerNull::get(cast<PointerType>(type));
        return ConstantAggregateZero::get(type);
    }

    Value* CreateDivision(Value* lhs, Value* rhs, bool isFloat, bool isUnsigned)
    {
        if (isFloat)
            return m_builder.CreateFDiv(lhs, rhs);
        return isUnsigned ? m_builder.CreateUDiv(lhs, rhs) : m_builder.CreateSDiv(lhs, rhs);
    }

    Value* CreateRemainder(Value* lhs, Value* rhs, bool isFloat, bool isUnsigned)
    {
        if (isFloat)
            return m_builder.CreateFRem(lhs, rhs);
        return isUnsigned ? m_builder.CreateURem(lhs, rhs) : m_builder.CreateSRem(lhs, rhs);
    }

    Value* CreateEquality(Value* lhs, Value* rhs, bool isFloat, bool equals)
    {
        if (isFloat)
            return equals ? m_builder.CreateFCmpOEQ(lhs, rhs) : m_builder.CreateFCmpONE(lhs, rhs);
        return equals ? m_builder.CreateICmpEQ(lhs, rhs) : m_builder.CreateICmpNE(lhs, rhs);
    }

    Value* CreateComparison(Value* lhs, Value* rhs, bool isFloat, bool isUnsigned,
                           CmpInst::Predicate signedPred, CmpInst::Predicate unsignedPred,
                           CmpInst::Predicate floatPred)
    {
        if (isFloat)
            return m_builder.CreateFCmp(floatPred, lhs, rhs);
        return isUnsigned 
            ? m_builder.CreateICmp(unsignedPred, lhs, rhs)
            : m_builder.CreateICmp(signedPred, lhs, rhs);
    }

    // line = 0 means "no specific source location known"
    [[noreturn]] void Error(const std::string& msg, uint32_t line = 0)
    {
        std::string location = " in module '" + m_module->getName().str() + "'";
        if (line > 0)
            location = " at line " + std::to_string(line) + location;
        throw std::runtime_error(msg + location);
    }
    
    std::vector<Scope> m_scopes;
    std::unordered_map<std::string, FunctionInfo> m_functions;
    std::unordered_map<std::string, StructInfo> m_structs;
    std::unordered_map<std::string, EnumInfo> m_enums;
    std::unordered_map<std::string, Variable> m_locals;
    std::unordered_map<std::string, Variable> m_globals;
    
    LLVMContext& m_context;
    IRBuilder<> m_builder;
    std::unique_ptr<Module> m_module;

    uint32_t m_currentScope = 0;
    uint32_t m_scopeCount = 0;

    LoopContext m_loopContext;
};