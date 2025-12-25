#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Host.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/MC/TargetRegistry.h>

using namespace llvm;

class CodeGenerator
{    
    struct TypeInfo
    {
        Type* llvmType;
        bool isUnsigned;
        Type* pointeeType;  // For pointer types

        TypeInfo() : llvmType(nullptr), isUnsigned(false), pointeeType(nullptr) {}
        TypeInfo(Type* t, bool u, Type* pt = nullptr) 
            : llvmType(t), isUnsigned(u), pointeeType(pt) {}
        
        bool operator==(const TypeInfo& other) const {
            return llvmType == other.llvmType && 
                   isUnsigned == other.isUnsigned && 
                   pointeeType == other.pointeeType;
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
        TypedValue initValue;
        Value* storage;  // alloca or global

        Variable() = default;
        Variable(const TypeInfo& t, Value* s) : type(t), storage(s) {}
        Variable(const TypeInfo& t, Value* s, const TypedValue &init) : type(t), storage(s), initValue(init) {}
    };

    struct StructInfo
    {
        StructType* type;
        std::unordered_map<std::string, unsigned> fieldIndices;
        std::unordered_map<std::string, TypeInfo> fieldTypes;
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
        BasicBlock* continueTarget;  // Where 'continue' jumps to
        BasicBlock* breakTarget;     // Where 'break' jumps to

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
        RegisterStructs(ast);
        DeclareGlobalVariables(ast);
        RegisterBuiltinFunctions();
        DefineUserFunctions(ast);
        
        //m_module->print(llvm::outs(), nullptr);
    }

    std::unique_ptr<Module> GetModule() { return std::move(m_module); }

private:    
    void ImportUsedModules(const ModuleAST& ast, std::map<std::string, std::unique_ptr<ModuleAST>>& moduleTable)
    {
        for (const auto& use : ast.usings)
        {
            auto it = moduleTable.find(use->name);
            if (it == moduleTable.end())
                throw std::runtime_error("Module not found: " + use->name);
            
            ImportModuleStructs(*it->second);
            ImportModuleGlobals(*it->second);
            ImportModuleFunctions(*it->second);
        }
    }

    void ImportModuleStructs(const ModuleAST& module)
    {
        for (const auto& decl : module.structs)
            RegisterStruct(decl.get());
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
            m_globals[decl->name] = {type, globalVar};
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
    
    void RegisterStructs(const ModuleAST& ast)
    {
        for (const auto& decl : ast.structs)
            RegisterStruct(decl.get());
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
        
        structType->setBody(memberTypes);
        m_structs[decl->name] = info;
    }
    
    void DeclareGlobalVariables(const ModuleAST& ast)
    {
        for (const auto& decl : ast.globals)
        {
            TypeInfo type = ResolveType(decl->type.get());
            Constant* initializer = decl->init 
                ? CreateConstant(decl->init.get(), type)
                : Constant::getNullValue(type.llvmType);
            
            auto linkage = decl->is_pub ? GlobalValue::ExternalLinkage : GlobalValue::InternalLinkage;
            auto* globalVar = new GlobalVariable(
                *m_module, type.llvmType, decl->type->is_const, linkage, initializer, decl->name
            );
            m_globals[decl->name] = {type, globalVar};
        }
    }
    
    void RegisterBuiltinFunctions()
    {
        // printf(i8*, ...) -> i32
        auto* printfFunc = Function::Create(
                FunctionType::get(
                m_builder.getInt32Ty(),
                {m_builder.getInt8PtrTy()},
                true  // varargs
            ),
            Function::ExternalLinkage, "printf", m_module.get()
        );
        m_functions["printf"] = FunctionInfo(
            printfFunc,
            {TypeInfo(m_builder.getInt8PtrTy(), false)},
            TypeInfo(m_builder.getInt32Ty(), false),
            true  // isVarArg
        );

        auto* mallocFunc = Function::Create(
                FunctionType::get(
                m_builder.getPtrTy(),
                {m_builder.getInt64Ty()},
                false
            ),
            Function::ExternalLinkage, "malloc", m_module.get()
        );
        m_functions["malloc"] = FunctionInfo(
            mallocFunc,
            {TypeInfo(m_builder.getInt64Ty(), false)},
            TypeInfo(m_builder.getPtrTy(), false)
        );

        auto* freeFunc = Function::Create(
                FunctionType::get(
                m_builder.getVoidTy(),
                {m_builder.getPtrTy()},
                false
            ),
            Function::ExternalLinkage, "free", m_module.get()
        );
        m_functions["free"] = FunctionInfo(
            freeFunc,
            {TypeInfo(m_builder.getPtrTy(), false)},
            TypeInfo(m_builder.getVoidTy(), false)
        );
    }

    void DefineUserFunctions(const ModuleAST& ast)
    {
        for (const auto& proc : ast.procs)
        {
            auto linkage = (proc->is_pub || proc->is_extern) 
                ? Function::ExternalLinkage 
                : Function::InternalLinkage;
            
            FunctionInfo funcInfo = DeclareFunction(proc.get(), linkage);
            
            if (!proc->is_extern)
                DefineFunctionBody(proc.get(), funcInfo);
        }
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
        
        auto* funcType = FunctionType::get(returnType.llvmType, paramLLVMTypes, false);
        auto* func = Function::Create(funcType, linkage, proc->name, m_module.get());
        
        // Set parameter names
        unsigned idx = 0;
        for (auto& arg : func->args())
            arg.setName(proc->params[idx++].name);
        
        FunctionInfo info(func, paramTypes, returnType);
        m_functions[proc->name] = info;
        return info;
    }

    void DefineFunctionBody(const ProcDecl* proc, const FunctionInfo& funcInfo)
    {
        m_locals.clear();
        
        auto* entry = BasicBlock::Create(m_context, "entry", funcInfo.function);
        m_builder.SetInsertPoint(entry);
        
        // Allocate and initialize parameters
        unsigned idx = 0;
        for (auto& arg : funcInfo.function->args())
        {
            TypeInfo paramType = funcInfo.paramTypes[idx++];
            auto* alloca = m_builder.CreateAlloca(paramType.llvmType, nullptr, arg.getName());
            m_builder.CreateStore(&arg, alloca);
            m_locals[std::string(arg.getName())] = Variable(paramType, alloca);
        }
        
        GenerateHostingAllocs(proc->body.get());
        GenerateBlock(proc->body.get(), funcInfo.returnType);
        
        // Add implicit return if needed
        if (!m_builder.GetInsertBlock()->getTerminator())
        {
            if (funcInfo.returnType.llvmType->isVoidTy())
                m_builder.CreateRetVoid();
            else
                throw std::runtime_error("Non-void function '" + proc->name + "' must return a value");
        }
    }

    void GenerateVarDeclHosingAlloc(VarDecl *decl)
    {
        if (m_locals.find(decl->name) != m_locals.end())
            return;

        TypeInfo type;
        TypedValue initValue;
        
        if (decl->type)
        {
            type = ResolveType(decl->type.get());
            if (decl->init)
            {
                initValue = EvaluateRValue(decl->init.get(), &type);
                if (initValue.type != type)
                    initValue = CastValue(initValue, type);
            }
        }
        else if (decl->init)
        {
            initValue = EvaluateRValue(decl->init.get());
            type = initValue.type;
        }
        else
            throw std::runtime_error("Variable '" + decl->name + "' must have either a type or an initializer");
        
        auto* alloca = m_builder.CreateAlloca(type.llvmType, nullptr, decl->name);
        m_locals[decl->name] = Variable(type, alloca, initValue);
    }

    void GenerateHostingAllocs(BlockStmt* block)
    {
        for (const auto& stmt : block->statements)
        {
            if (auto* decl = dynamic_cast<VarDecl*>(stmt.get()))
                GenerateVarDeclHosingAlloc(decl);
            else if (auto* s = dynamic_cast<IfStmt*>(stmt.get()))
            {
                GenerateHostingAllocs(s->then_branch.get());
                if (s->else_branch)
                    GenerateHostingAllocs(s->else_branch.get());
            }
            else if (auto* s = dynamic_cast<WhileStmt*>(stmt.get()))
                GenerateHostingAllocs(s->then_branch.get());
            else if (auto* s = dynamic_cast<ForStmt*>(stmt.get()))
            {
                if (s->init)
                    GenerateVarDeclHosingAlloc(s->init.get());
                GenerateHostingAllocs(s->body.get());
            }
        }
    }
    
    void GenerateBlock(BlockStmt* block, const TypeInfo& returnType)
    {
        for (const auto& stmt : block->statements)
        {
            if (auto* s = dynamic_cast<VarDecl*>(stmt.get()))
                GenerateVarDecl(s);
            else if (auto* s = dynamic_cast<ExprStmt*>(stmt.get()))
                GenerateExprStmt(s);
            else if (auto* s = dynamic_cast<ReturnStmt*>(stmt.get()))
                GenerateReturn(s, returnType);
            else if (auto* s = dynamic_cast<IfStmt*>(stmt.get()))
                GenerateIf(s, returnType);
            else if (auto* s = dynamic_cast<WhileStmt*>(stmt.get()))
                GenerateWhile(s, returnType);
            else if (auto* s = dynamic_cast<ForStmt*>(stmt.get()))
                GenerateFor(s, returnType);
            else if (auto* s = dynamic_cast<BreakStmt*>(stmt.get()))
                GenerateBreak();
            else if (auto* s = dynamic_cast<ContinueStmt*>(stmt.get()))
                GenerateContinue();
        }
    }

    void GenerateVarDecl(VarDecl* decl)
    {
        if (decl->init)
        {
            const Variable &variable = m_locals[decl->name];
            m_builder.CreateStore(variable.initValue.value, variable.storage);
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
                retValue = CastValue(retValue, returnType);
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
        condition = EnsureBooleanType(condition);
        
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
        condition = EnsureBooleanType(condition);
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
        
        // Initialize loop variable
        if (stmt->init)
        {
            Variable variable = m_locals[stmt->init->name];
            if (stmt->init->init)
            {
                TypedValue initValue = EvaluateRValue(stmt->init->init.get(), &variable.type);
                if (initValue.type != variable.type)
                    initValue = CastValue(initValue, variable.type);
                m_builder.CreateStore(initValue.value, variable.storage);
            }
        }
        
        auto* condBB = BasicBlock::Create(m_context, "for.cond", function);
        auto* bodyBB = BasicBlock::Create(m_context, "for.body", function);
        auto* incBB = BasicBlock::Create(m_context, "for.inc", function);
        auto* endBB = BasicBlock::Create(m_context, "for.end", function);
        
        // Continue jumps to increment, not condition
        LoopContext loopCtx = PushLoop(incBB, endBB);
        
        m_builder.CreateBr(condBB);
        
        m_builder.SetInsertPoint(condBB);
        TypedValue condition = EvaluateRValue(stmt->condition.get());
        condition = EnsureBooleanType(condition);
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

    void GenerateBreak()
    {
        if (!m_loopContext.breakTarget)
            throw std::runtime_error("'break' outside of loop");
        
        m_builder.CreateBr(m_loopContext.breakTarget);
        CreateUnreachableBlock();
    }

    void GenerateContinue()
    {
        if (!m_loopContext.continueTarget)
            throw std::runtime_error("'continue' outside of loop");
        
        m_builder.CreateBr(m_loopContext.continueTarget);
        CreateUnreachableBlock();
    }
    
    TypedValue EvaluateLValue(ExprNode* node)
    {
        if (auto* id = dynamic_cast<Identifier*>(node))
            return TypedValue(LookupVariable(id->name).storage, LookupVariable(id->name).type);
        
        if (auto* unary = dynamic_cast<UnaryExpr*>(node))
        {
            if (unary->op == '*')
            {
                TypedValue ptr = EvaluateRValue(unary->operand.get());
                if (!ptr.type.llvmType->isPointerTy() || !ptr.type.pointeeType)
                    throw std::runtime_error("Cannot dereference non-pointer");
                return TypedValue(ptr.value, TypeInfo(ptr.type.pointeeType, ptr.type.isUnsigned));
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
        
        throw std::runtime_error("Expression is not an lvalue");
    }

    TypedValue EvaluateRValue(ExprNode* node, const TypeInfo* expectedType = nullptr)
    {
        if (auto* id = dynamic_cast<Identifier*>(node))
        {
            Variable var = LookupVariable(id->name);
            return TypedValue(m_builder.CreateLoad(var.type.llvmType, var.storage), var.type);
        }
        
        if (auto* num = dynamic_cast<NumberLiteral*>(node))
            return EvaluateNumberLiteral(num);
        
        if (auto* str = dynamic_cast<::StringLiteral*>(node))
            return EvaluateStringLiteral(str);
        
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
        
        throw std::runtime_error("Invalid rvalue expression");
    }

    TypedValue EvaluateNumberLiteral(NumberLiteral* lit)
    {
        if (lit->value.find('.') == std::string::npos)
        {
            auto* val = m_builder.getInt32(std::stoi(lit->value));
            return TypedValue(val, TypeInfo(m_builder.getInt32Ty(), false));
        }
        else
        {
            auto* val = ConstantFP::get(m_builder.getDoubleTy(), std::stod(lit->value));
            return TypedValue(val, TypeInfo(m_builder.getDoubleTy(), false));
        }
    }

    TypedValue EvaluateStringLiteral(::StringLiteral* lit)
    {
        auto* str = m_builder.CreateGlobalStringPtr(lit->value, ".str");
        return TypedValue(str, TypeInfo(m_builder.getInt8PtrTy(), false, m_builder.getInt8Ty()));
    }

    TypedValue EvaluateCast(CastExpr* cast)
    {
        TypedValue operand = EvaluateRValue(cast->operand.get());
        TypeInfo targetType = ResolveType(cast->target_type.get());
        return CastValue(operand, targetType);
    }

    TypedValue EvaluateFunctionCall(CallExpr* call)
    {
        auto it = m_functions.find(call->function);
        if (it == m_functions.end())
            throw std::runtime_error("Unknown function: " + call->function);
        
        const FunctionInfo& func = it->second;
        
        // For vararg functions, check minimum argument count
        // For normal functions, check exact argument count
        if (func.isVarArg)
        {
            if (call->args.size() < func.paramTypes.size())
                throw std::runtime_error("Too few arguments for " + call->function);
        }
        else
        {
            if (call->args.size() != func.paramTypes.size())
                throw std::runtime_error("Argument count mismatch for " + call->function);
        }
        
        std::vector<Value*> args;
        for (size_t i = 0; i < call->args.size(); i++)
        {
            TypedValue arg = EvaluateRValue(call->args[i].get());
            
            // Only cast if we're within the fixed parameters range
            if (i < func.paramTypes.size())
            {
                if (arg.type != func.paramTypes[i])
                    arg = CastValue(arg, func.paramTypes[i]);
            }
            // For vararg arguments, they're passed as-is
            
            args.push_back(arg.value);
        }
        
        auto* result = m_builder.CreateCall(func.function, args);
        return TypedValue(result, func.returnType);
    }

    TypedValue EvaluateArrayAccess(ArrayAccess* access)
    {
        TypedValue base = EvaluateRValue(access->array.get());  // Changed from EvaluateLValue
        TypedValue index = EvaluateRValue(access->index.get());
        
        if (!index.type.llvmType->isIntegerTy(64))
            index = CastValue(index, TypeInfo(m_builder.getInt64Ty(), false));
        
        Type* baseType = base.type.llvmType;
        
        // Handle pointer indexing: ptr[i] -> *(ptr + i)
        if (baseType->isPointerTy())
        {
            if (!base.type.pointeeType)
                throw std::runtime_error("Cannot index pointer without pointee type");
            
            Value* gep = m_builder.CreateInBoundsGEP(
                base.type.pointeeType, base.value, index.value
            );
            return TypedValue(gep, TypeInfo(base.type.pointeeType, base.type.isUnsigned));
        }
        
        // Handle array indexing (requires lvalue)
        if (baseType->isArrayTy())
        {
            base = EvaluateLValue(access->array.get());  // Get the array's address
            Type* elementType = baseType->getArrayElementType();
            Value* gep = m_builder.CreateInBoundsGEP(
                baseType, base.value,
                {m_builder.getInt64(0), index.value}
            );
            return TypedValue(gep, TypeInfo(elementType, base.type.isUnsigned));
        }
        
        throw std::runtime_error("Cannot index non-array/non-pointer type");
    }

    TypedValue EvaluateMemberAccess(MemberAccess* access)
    {
        TypedValue structPtr = EvaluateLValue(access->object.get());
        
        Type* structType = structPtr.type.llvmType;
        if (!structType->isStructTy())
            throw std::runtime_error("Member access on non-struct type");
        
        const StructInfo* structInfo = FindStructInfo(structType);
        if (!structInfo)
            throw std::runtime_error("Unknown struct type");
        
        auto it = structInfo->fieldIndices.find(access->member);
        if (it == structInfo->fieldIndices.end())
            throw std::runtime_error("Unknown member: " + access->member);
        
        unsigned fieldIndex = it->second;
        const TypeInfo& fieldType = structInfo->fieldTypes.at(access->member);
        
        auto* fieldPtr = m_builder.CreateStructGEP(structType, structPtr.value, fieldIndex);
        return TypedValue(fieldPtr, fieldType);
    }

    TypedValue EvaluatePointerMemberAccess(PointerMemberAccess* access)
    {
        TypedValue ptr = EvaluateRValue(access->object.get());
        
        if (!ptr.type.llvmType->isPointerTy() || !ptr.type.pointeeType)
            throw std::runtime_error("Cannot use -> on non-pointer type");
        
        Type* pointeeType = ptr.type.pointeeType;
        if (!pointeeType->isStructTy())
            throw std::runtime_error("Cannot access member on non-struct pointer");
        
        const StructInfo* structInfo = FindStructInfo(pointeeType);
        if (!structInfo)
            throw std::runtime_error("Unknown struct type");
        
        auto it = structInfo->fieldIndices.find(access->member);
        if (it == structInfo->fieldIndices.end())
            throw std::runtime_error("Unknown member: " + access->member);
        
        unsigned fieldIndex = it->second;
        const TypeInfo& fieldType = structInfo->fieldTypes.at(access->member);
        
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
            elementType = TypeInfo(arrayType->getElementType(), expectedType->isUnsigned);
        }
        else
        {
            if (init->elements.empty())
                throw std::runtime_error("Cannot infer array type from empty initializer");
            
            arraySize = init->elements.size();
            elementType = EvaluateRValue(init->elements[0].get()).type;
            
            for (size_t i = 1; i < init->elements.size(); i++)
                elementType = PromoteToCommonType(elementType, EvaluateRValue(init->elements[i].get()).type);
        }
        
        auto* arrayType = ArrayType::get(elementType.llvmType, arraySize);
        auto* alloca = m_builder.CreateAlloca(arrayType, nullptr, "array_tmp");
        
        for (size_t i = 0; i < arraySize; i++)
        {
            Value* elemValue = (i < init->elements.size())
                ? CastIfNeeded(EvaluateRValue(init->elements[i].get()), elementType).value
                : CreateZeroValue(elementType.llvmType);
            
            auto* elemPtr = m_builder.CreateInBoundsGEP(
                arrayType, alloca,
                {m_builder.getInt64(0), m_builder.getInt64(i)}
            );
            m_builder.CreateStore(elemValue, elemPtr);
        }
        
        auto* arrayValue = m_builder.CreateLoad(arrayType, alloca);
        return TypedValue(arrayValue, TypeInfo(arrayType, elementType.isUnsigned));
    }

    TypedValue EvaluateStructInit(StructInit* init)
    {
        auto it = m_structs.find(init->type_name);
        if (it == m_structs.end())
            throw std::runtime_error("Unknown struct: " + init->type_name);
        
        const StructInfo& info = it->second;
        
        if (init->fields.size() > info.fieldIndices.size())
            throw std::runtime_error("Too many fields in struct initializer");
        
        auto* alloca = m_builder.CreateAlloca(info.type, nullptr, "struct_tmp");
        
        for (unsigned i = 0; i < info.fieldIndices.size(); i++)
        {
            const TypeInfo* fieldType = FindFieldTypeAtIndex(info, i);
            if (!fieldType)
                throw std::runtime_error("Field type not found at index " + std::to_string(i));
            
            Value* fieldValue = (i < init->fields.size())
                ? CastIfNeeded(EvaluateRValue(init->fields[i].get(), fieldType), *fieldType).value  // Pass fieldType here
                : CreateZeroValue(fieldType->llvmType);
            
            auto* fieldPtr = m_builder.CreateStructGEP(info.type, alloca, i);
            m_builder.CreateStore(fieldValue, fieldPtr);
        }
        
        auto* structValue = m_builder.CreateLoad(info.type, alloca);
        return TypedValue(structValue, TypeInfo(info.type, false));
    }

    TypedValue EvaluateUnaryExpr(UnaryExpr* unary)
    {
        if (unary->op == '&')
        {
            TypedValue lval = EvaluateLValue(unary->operand.get());
            return TypedValue(lval.value, TypeInfo(m_builder.getPtrTy(), false, lval.type.llvmType));
        }
        
        if (unary->op == '*')
        {
            TypedValue ptr = EvaluateRValue(unary->operand.get());
            if (!ptr.type.llvmType->isPointerTy() || !ptr.type.pointeeType)
                throw std::runtime_error("Cannot dereference non-pointer");
            auto* loaded = m_builder.CreateLoad(ptr.type.pointeeType, ptr.value);
            return TypedValue(loaded, TypeInfo(ptr.type.pointeeType, ptr.type.isUnsigned));
        }
        
        if (unary->op == '-')
        {
            TypedValue operand = EvaluateRValue(unary->operand.get());
            Value* result = operand.type.llvmType->isFloatingPointTy()
                ? m_builder.CreateFNeg(operand.value)
                : m_builder.CreateNeg(operand.value);
            return TypedValue(result, operand.type);
        }
        
        throw std::runtime_error("Unknown unary operator");
    }

    TypedValue EvaluateBinaryExpr(BinaryExpr* binary)
    {
        // Handle assignment
        if (binary->op == '=')
        {
            TypedValue lhs = EvaluateLValue(binary->left.get());
            TypedValue rhs = EvaluateRValue(binary->right.get());
            
            if (rhs.type != lhs.type)
                rhs = CastValue(rhs, lhs.type);
            m_builder.CreateStore(rhs.value, lhs.value);
            return rhs;  // Assignment expressions return the assigned value
        }

        // Handle pointer arithmetic
        if (binary->op == '+' || binary->op == '-')
        {
            TypedValue lhs = EvaluateRValue(binary->left.get());
            TypedValue rhs = EvaluateRValue(binary->right.get());
            
            if (auto result = TryPointerArithmetic(binary->op, lhs, rhs))
                return *result;
        }
        
        TypedValue lhs = EvaluateRValue(binary->left.get());
        TypedValue rhs = EvaluateRValue(binary->right.get());
        
        TypeInfo commonType = PromoteToCommonType(lhs.type, rhs.type);
        lhs = CastIfNeeded(lhs, commonType);
        rhs = CastIfNeeded(rhs, commonType);
        
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
            case 'E': result = CreateEquality(lhs.value, rhs.value, isFloat, true); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case 'N': result = CreateEquality(lhs.value, rhs.value, isFloat, false); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case '<': result = CreateComparison(lhs.value, rhs.value, isFloat, isUnsigned, CmpInst::ICMP_SLT, CmpInst::ICMP_ULT, CmpInst::FCMP_OLT); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case 'L': result = CreateComparison(lhs.value, rhs.value, isFloat, isUnsigned, CmpInst::ICMP_SLE, CmpInst::ICMP_ULE, CmpInst::FCMP_OLE); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case '>': result = CreateComparison(lhs.value, rhs.value, isFloat, isUnsigned, CmpInst::ICMP_SGT, CmpInst::ICMP_UGT, CmpInst::FCMP_OGT); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            case 'G': result = CreateComparison(lhs.value, rhs.value, isFloat, isUnsigned, CmpInst::ICMP_SGE, CmpInst::ICMP_UGE, CmpInst::FCMP_OGE); resultType = TypeInfo(m_builder.getInt1Ty(), false); break;
            default: throw std::runtime_error("Unknown binary operator");
        }
        
        return TypedValue(result, resultType);
    }

    std::optional<TypedValue> TryPointerArithmetic(char op, TypedValue& lhs, TypedValue& rhs)
    {
        // Pointer + Integer
        if (lhs.type.llvmType->isPointerTy() && rhs.type.llvmType->isIntegerTy())
        {
            rhs = CastIfNeeded(rhs, TypeInfo(m_builder.getInt64Ty(), false));
            Value* offset = (op == '+') ? rhs.value : m_builder.CreateNeg(rhs.value);
            Value* result = m_builder.CreateGEP(lhs.type.pointeeType, lhs.value, offset);
            return TypedValue(result, lhs.type);
        }
        
        // Integer + Pointer
        if (lhs.type.llvmType->isIntegerTy() && rhs.type.llvmType->isPointerTy() && op == '+')
        {
            lhs = CastIfNeeded(lhs, TypeInfo(m_builder.getInt64Ty(), false));
            Value* result = m_builder.CreateGEP(rhs.type.pointeeType, rhs.value, lhs.value);
            return TypedValue(result, rhs.type);
        }
        
        // Pointer - Pointer
        if (lhs.type.llvmType->isPointerTy() && rhs.type.llvmType->isPointerTy() && op == '-')
        {
            Value* lhsInt = m_builder.CreatePtrToInt(lhs.value, m_builder.getInt64Ty());
            Value* rhsInt = m_builder.CreatePtrToInt(rhs.value, m_builder.getInt64Ty());
            Value* diff = m_builder.CreateSub(lhsInt, rhsInt);
            return TypedValue(diff, TypeInfo(m_builder.getInt64Ty(), false));
        }
        
        return std::nullopt;
    }
    
    Constant* CreateConstant(ExprNode* node, const TypeInfo& expectedType)
    {
        if (auto* num = dynamic_cast<NumberLiteral*>(node))
        {
            if (num->value.find('.') == std::string::npos)
            {
                int64_t val = std::stoll(num->value);
                if (expectedType.llvmType->isIntegerTy())
                    return ConstantInt::get(expectedType.llvmType, val);
                else if (expectedType.llvmType->isFloatingPointTy())
                    return ConstantFP::get(expectedType.llvmType, (double)val);
            }
            else
            {
                return ConstantFP::get(expectedType.llvmType, std::stod(num->value));
            }
        }
        
        if (auto* str = dynamic_cast<::StringLiteral*>(node))
        {
            auto* strGlobal = m_builder.CreateGlobalString(str->value, ".str", 0, m_module.get());
            std::vector<Constant*> indices = {
                m_builder.getInt64(0),
                m_builder.getInt64(0)
            };
            return ConstantExpr::getInBoundsGetElementPtr(
                strGlobal->getValueType(),
                strGlobal,
                indices
            );
        }
        
        if (auto* arrInit = dynamic_cast<ArrayInit*>(node))
        {
            auto* arrayType = cast<ArrayType>(expectedType.llvmType);
            TypeInfo elemType(arrayType->getElementType(), expectedType.isUnsigned);
            
            std::vector<Constant*> elements;
            for (size_t i = 0; i < arrayType->getNumElements(); i++)
            {
                elements.push_back(i < arrInit->elements.size()
                    ? CreateConstant(arrInit->elements[i].get(), elemType)
                    : Constant::getNullValue(elemType.llvmType));
            }
            return ConstantArray::get(arrayType, elements);
        }
        
        if (auto* structInit = dynamic_cast<StructInit*>(node))
        {
            auto it = m_structs.find(structInit->type_name);
            if (it == m_structs.end())
                throw std::runtime_error("Unknown struct: " + structInit->type_name);
            
            const StructInfo& info = it->second;
            std::vector<Constant*> fieldValues;
            
            for (unsigned i = 0; i < info.fieldIndices.size(); i++)
            {
                const TypeInfo* fieldType = FindFieldTypeAtIndex(info, i);
                fieldValues.push_back(i < structInit->fields.size()
                    ? CreateConstant(structInit->fields[i].get(), *fieldType)
                    : Constant::getNullValue(fieldType->llvmType));
            }
            
            return ConstantStruct::get(info.type, fieldValues);
        }
        
        throw std::runtime_error("Invalid constant expression");
    }
    
    TypeInfo ResolveType(TypeNode* node)
    {
        if (!node->array_dimensions.empty())
        {
            TypeInfo baseType = ResolveBaseType(node);
            Type* type = baseType.llvmType;
            for (size_t dim : node->array_dimensions)
                type = ArrayType::get(type, dim);
            return TypeInfo(type, baseType.isUnsigned);
        }
        return ResolveBaseType(node);
    }

    TypeInfo ResolveBaseType(TypeNode* node)
    {
        if (node->pointer_depth)
        {
            TypeNode temp = *node;
            temp.pointer_depth = 0;
            TypeInfo pointeeType = ResolveBaseType(&temp);
            return TypeInfo(m_builder.getPtrTy(), false, pointeeType.llvmType);
        }
        
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
            {"f64", [](auto& b) { return b.getDoubleTy(); }}
        };
        
        auto it = typeMap.find(node->name);
        if (it != typeMap.end())
        {
            bool isUnsigned = node->name[0] == 'u' && node->name != "u0";
            return TypeInfo(it->second(m_builder), isUnsigned);
        }
        
        auto structIt = m_structs.find(node->name);
        if (structIt != m_structs.end())
            return TypeInfo(structIt->second.type, false);
        
        throw std::runtime_error("Unknown type: " + node->name);
    }
    
    TypedValue CastValue(TypedValue value, TypeInfo targetType)
    {
        if (value.type == targetType)
            return value;
        
        Type* fromType = value.type.llvmType;
        Type* toType = targetType.llvmType;
        
        // Pointer to Pointer
        if (fromType->isPointerTy() && toType->isPointerTy())
        {
            if (value.type.pointeeType == targetType.pointeeType)
                return TypedValue(value.value, targetType);
            return TypedValue(m_builder.CreateBitCast(value.value, toType), targetType);
        }
        
        // Integer to Integer
        if (fromType->isIntegerTy() && toType->isIntegerTy())
        {
            unsigned fromBits = fromType->getIntegerBitWidth();
            unsigned toBits = toType->getIntegerBitWidth();
            
            if (fromBits < toBits)
            {
                // i1 (bool) always zero-extends
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
        
        // Float to Float
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
        
        // Integer to Float
        if (fromType->isIntegerTy() && toType->isFloatingPointTy())
        {
            Value* result = (fromType->isIntegerTy(1) || value.type.isUnsigned)
                ? m_builder.CreateUIToFP(value.value, toType)
                : m_builder.CreateSIToFP(value.value, toType);
            return TypedValue(result, targetType);
        }
        
        // Float to Integer
        if (fromType->isFloatingPointTy() && toType->isIntegerTy())
        {
            Value* result = targetType.isUnsigned
                ? m_builder.CreateFPToUI(value.value, toType)
                : m_builder.CreateFPToSI(value.value, toType);
            return TypedValue(result, targetType);
        }
        
        throw std::runtime_error("Cannot cast between incompatible types");
    }
    
    TypeInfo PromoteToCommonType(const TypeInfo& left, const TypeInfo& right)
    {
        Type* leftType = left.llvmType;
        Type* rightType = right.llvmType;
        
        // Float promotion
        if (leftType->isFloatingPointTy() || rightType->isFloatingPointTy())
        {
            if (leftType->isFloatingPointTy() && rightType->isFloatingPointTy())
            {
                return (leftType->getPrimitiveSizeInBits() >= rightType->getPrimitiveSizeInBits())
                    ? left : right;
            }
            return leftType->isFloatingPointTy() ? left : right;
        }
        
        // Integer promotion
        if (leftType->isIntegerTy() && rightType->isIntegerTy())
        {
            unsigned leftBits = leftType->getIntegerBitWidth();
            unsigned rightBits = rightType->getIntegerBitWidth();
            
            if (leftBits == rightBits)
                return (left.isUnsigned != right.isUnsigned && left.isUnsigned) ? left : right;
            
            return (leftBits > rightBits) ? left : right;
        }
        
        return left;
    }

    TypedValue CastIfNeeded(TypedValue value, const TypeInfo& targetType)
    {
        return (value.type != targetType) ? CastValue(value, targetType) : value;
    }

    TypedValue EnsureBooleanType(TypedValue value)
    {
        if (value.type.llvmType->isIntegerTy(1))
            return value;
        return CastValue(value, TypeInfo(m_builder.getInt1Ty(), false));
    }
    
    Variable LookupVariable(const std::string& name)
    {
        auto it = m_locals.find(name);
        if (it != m_locals.end())
            return it->second;
        
        it = m_globals.find(name);
        if (it != m_globals.end())
            return it->second;
        
        throw std::runtime_error("Unknown variable: " + name);
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
    
    LLVMContext& m_context;
    IRBuilder<> m_builder;
    std::unique_ptr<Module> m_module;
    
    std::unordered_map<std::string, FunctionInfo> m_functions;
    std::unordered_map<std::string, StructInfo> m_structs;
    std::unordered_map<std::string, Variable> m_locals;
    std::unordered_map<std::string, Variable> m_globals;
    
    LoopContext m_loopContext;
};