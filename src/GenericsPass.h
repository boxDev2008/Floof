#pragma once

#include "Parser.h"

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <stdexcept>

class GenericsPass
{
public:
    struct TemplateStore
    {
        struct StructEntry { std::string ownerModule; std::unique_ptr<StructDecl> decl; };
        struct ProcEntry   { std::string ownerModule; std::unique_ptr<ProcDecl>   decl; };

        std::vector<StructEntry> structs;
        std::vector<ProcEntry> procs;
    };

    static void Run(ModuleAST &module, const std::string &moduleName,
                     std::map<std::string, std::unique_ptr<ModuleAST>> &moduleTable,
                     TemplateStore &templateStore)
    {
        GenericsPass pass(module, moduleName, moduleTable, templateStore);
        pass.Execute();
    }

private:
    ModuleAST &m_module;
    const std::string &m_moduleName;
    std::map<std::string, std::unique_ptr<ModuleAST>> &m_moduleTable;
    TemplateStore &m_templateStore;

    std::unordered_map<std::string, StructDecl *> m_structTemplates;
    std::unordered_map<std::string, ProcDecl *> m_procTemplates;

    std::unordered_set<std::string> m_instantiated;
    std::unordered_set<std::string> m_publicStructs;

    struct PendingInstantiation
    {
        std::string templateName;
        std::vector<std::unique_ptr<TypeNode>> args;
        bool isStruct;
    };
    std::deque<PendingInstantiation> m_worklist;

    GenericsPass(ModuleAST &module, const std::string &moduleName,
                 std::map<std::string, std::unique_ptr<ModuleAST>> &moduleTable,
                 TemplateStore &templateStore)
        : m_module(module), m_moduleName(moduleName), m_moduleTable(moduleTable),
          m_templateStore(templateStore) {}

    void Execute()
    {
        ExtractTemplates();
        ImportUsedTemplates();

        for (auto &global : m_module.globals)
            if (global->type)
                m_originalLocalTypesStorage[global->name] = global->type->Clone();

        for (auto &proc : m_module.procs)
            ScanAndRewriteProc(proc.get());

        LocalTypes noLocals;
        for (auto &global : m_module.globals)
        {
            std::unique_ptr<TypeNode> expected = global->type ? global->type->Clone() : nullptr;

            if (global->type)
                RewriteType(global->type.get(), noLocals, global->is_pub);
            if (global->init)
                RewriteExpr(global->init.get(), noLocals, expected.get());
        }

        while (!m_worklist.empty())
        {
            PendingInstantiation job = std::move(m_worklist.front());
            m_worklist.pop_front();

            std::string mangled = MangleName(job.templateName, job.args);
            if (m_instantiated.count(mangled))
                continue;
            m_instantiated.insert(mangled);

            if (job.isStruct)
                InstantiateStruct(job.templateName, mangled, job.args);
            else
                InstantiateProc(job.templateName, mangled, job.args);
        }
    }

    void ExtractTemplates()
    {
        {
            auto &structs = m_module.structs;
            for (auto it = structs.begin(); it != structs.end();)
            {
                if ((*it)->IsGeneric())
                {
                    m_structTemplates[(*it)->name] = it->get();
                    m_templateStore.structs.push_back({m_moduleName, std::move(*it)});
                    it = structs.erase(it);
                }
                else ++it;
            }
        }
        {
            auto &procs = m_module.procs;
            for (auto it = procs.begin(); it != procs.end();)
            {
                if ((*it)->IsGeneric())
                {
                    m_procTemplates[(*it)->name] = it->get();
                    m_templateStore.procs.push_back({m_moduleName, std::move(*it)});
                    it = procs.erase(it);
                }
                else ++it;
            }
        }
    }

    std::unordered_set<std::string> m_importedModules;
    void ImportUsedTemplates()
    {
        for (const auto &use : m_module.usings)
            ImportTemplatesFromModuleRecursively(use->name);
    }

    void ImportTemplatesFromModuleRecursively(const std::string &moduleName)
    {
        if (m_importedModules.count(moduleName) > 0)
            return;

        auto it = m_moduleTable.find(moduleName);
        if (it == m_moduleTable.end())
            throw std::runtime_error("Module not found: " + moduleName +
                " (used from module " + m_moduleName + ")");

        m_importedModules.insert(moduleName);

        const ModuleAST &module = *it->second;

        for (const auto &use : module.usings)
            if (use->is_pub)
                ImportTemplatesFromModuleRecursively(use->name);

        for (const auto &s : module.structs)
            if (s->IsGeneric() && s->is_pub && !m_structTemplates.count(s->name))
                m_structTemplates[s->name] = s.get();

        for (const auto &p : module.procs)
            if (p->IsGeneric() && p->is_pub && !m_procTemplates.count(p->name))
                m_procTemplates[p->name] = p.get();

        for (const auto &entry : m_templateStore.structs)
            if (entry.ownerModule == moduleName && entry.decl->is_pub &&
                !m_structTemplates.count(entry.decl->name))
                m_structTemplates[entry.decl->name] = entry.decl.get();

        for (const auto &entry : m_templateStore.procs)
            if (entry.ownerModule == moduleName && entry.decl->is_pub &&
                !m_procTemplates.count(entry.decl->name))
                m_procTemplates[entry.decl->name] = entry.decl.get();
    }

    using LocalTypes = std::unordered_map<std::string, TypeNode *>;

    using OriginalLocalTypes = std::unordered_map<std::string, std::unique_ptr<TypeNode>>;
    OriginalLocalTypes m_originalLocalTypesStorage;

    void ScanAndRewriteProc(ProcDecl *proc)
    {
        if (!proc->body)
            return;

        LocalTypes locals;
        for (auto &param : proc->params)
            if (param.type)
                locals[param.name] = param.type.get();

        RewriteBlock(proc->body.get(), locals);
    }

    void RewriteBlock(BlockStmt *block, LocalTypes locals )
    {
        for (auto &stmt : block->statements)
            RewriteStmt(stmt.get(), locals);
    }

    void RewriteStmt(StmtNode *stmt, LocalTypes &locals)
    {
        if (auto *vd = dynamic_cast<VarDecl *>(stmt))
        {

            std::unique_ptr<TypeNode> expected = vd->type ? vd->type->Clone() : nullptr;

            if (vd->type)
            {
                m_originalLocalTypesStorage[vd->name] = vd->type->Clone();
                RewriteType(vd->type.get(), locals);
            }
            if (vd->init)
                RewriteExpr(vd->init.get(), locals, expected.get());
            if (vd->type)
                locals[vd->name] = vd->type.get();

            return;
        }
        if (auto *es = dynamic_cast<ExprStmt *>(stmt))
        {
            RewriteExpr(es->expr.get(), locals);
            return;
        }
        if (auto *ret = dynamic_cast<ReturnStmt *>(stmt))
        {
            if (ret->value) RewriteExpr(ret->value.get(), locals);
            return;
        }
        if (auto *blk = dynamic_cast<BlockStmt *>(stmt))
        {
            RewriteBlock(blk, locals);
            return;
        }
        if (auto *ifs = dynamic_cast<IfStmt *>(stmt))
        {
            RewriteExpr(ifs->condition.get(), locals);
            if (ifs->then_branch) RewriteBlock(ifs->then_branch.get(), locals);
            if (ifs->else_branch) RewriteBlock(ifs->else_branch.get(), locals);
            return;
        }
        if (auto *ws = dynamic_cast<WhileStmt *>(stmt))
        {
            RewriteExpr(ws->condition.get(), locals);
            if (ws->then_branch) RewriteBlock(ws->then_branch.get(), locals);
            return;
        }
        if (auto *dws = dynamic_cast<DoWhileStmt *>(stmt))
        {
            if (dws->then_branch) RewriteBlock(dws->then_branch.get(), locals);
            RewriteExpr(dws->condition.get(), locals);
            return;
        }
        if (auto *fs = dynamic_cast<ForStmt *>(stmt))
        {
            LocalTypes forLocals = locals;
            if (fs->init_decl)
            {
                RewriteStmt(fs->init_decl.get(), forLocals);
            }
            if (fs->init_expr) RewriteExpr(fs->init_expr.get(), forLocals);
            if (fs->condition) RewriteExpr(fs->condition.get(), forLocals);
            if (fs->increment) RewriteExpr(fs->increment.get(), forLocals);
            if (fs->body) RewriteBlock(fs->body.get(), forLocals);
            return;
        }
        if (auto *ms = dynamic_cast<MatchStmt *>(stmt))
        {
            RewriteExpr(ms->value.get(), locals);
            for (auto &c : ms->cases)
            {
                if (c->value) RewriteExpr(c->value.get(), locals);
                if (c->body) RewriteBlock(c->body.get(), locals);
            }
            return;
        }

    }

    void RewriteExpr(ExprNode *node, LocalTypes &locals, const TypeNode *expectedType = nullptr)
    {
        if (!node) return;

        if (auto *bin = dynamic_cast<BinaryExpr *>(node))
        {
            RewriteExpr(bin->left.get(), locals);
            RewriteExpr(bin->right.get(), locals);
            return;
        }
        if (auto *un = dynamic_cast<UnaryExpr *>(node))
        {
            RewriteExpr(un->operand.get(), locals);
            return;
        }
        if (auto *call = dynamic_cast<CallExpr *>(node))
        {

            for (auto &arg : call->args)
                RewriteExpr(arg.get(), locals);
            for (auto &g : call->generic_args)
                RewriteType(g.get(), locals);

            RewriteCall(call, locals, expectedType);
            return;
        }
        if (auto *arr = dynamic_cast<ArrayAccess *>(node))
        {
            RewriteExpr(arr->array.get(), locals);
            RewriteExpr(arr->index.get(), locals);
            return;
        }
        if (auto *mem = dynamic_cast<MemberAccess *>(node))
        {
            RewriteExpr(mem->object.get(), locals);
            return;
        }
        if (auto *pmem = dynamic_cast<PointerMemberAccess *>(node))
        {
            RewriteExpr(pmem->object.get(), locals);
            return;
        }
        if (auto *si = dynamic_cast<StructInit *>(node))
        {
            for (auto &g : si->generic_args)
                RewriteType(g.get(), locals);
            for (auto &f : si->fields)
                if (f.value) RewriteExpr(f.value.get(), locals);

            RewriteStructInit(si);
            return;
        }
        if (auto *ai = dynamic_cast<ArrayInit *>(node))
        {
            for (auto &e : ai->elements)
                RewriteExpr(e.get(), locals);
            return;
        }
        if (auto *sz = dynamic_cast<SizeofExpr *>(node))
        {
            RewriteType(sz->type.get(), locals);
            return;
        }
        if (auto *cst = dynamic_cast<CastExpr *>(node))
        {
            RewriteType(cst->target_type.get(), locals);
            RewriteExpr(cst->operand.get(), locals);
            return;
        }
        if (auto *va = dynamic_cast<VaArgExpr *>(node))
        {
            RewriteExpr(va->va_list.get(), locals);
            RewriteType(va->type.get(), locals);
            return;
        }
        if (auto *tern = dynamic_cast<TernaryExpr *>(node))
        {
            RewriteExpr(tern->condition.get(), locals);
            RewriteExpr(tern->then_expr.get(), locals);
            RewriteExpr(tern->else_expr.get(), locals);
            return;
        }

    }

    void RewriteType(TypeNode *type, LocalTypes &locals, bool forcePublic = false)
    {
        if (!type) return;

        if (type->is_function_type)
        {
            if (type->return_type) RewriteType(type->return_type.get(), locals, forcePublic);
            for (auto &p : type->param_types) RewriteType(p.get(), locals, forcePublic);
            return;
        }

        for (auto &g : type->generic_args)
            RewriteType(g.get(), locals, forcePublic);

        if (!type->generic_args.empty())
        {
            auto structTemplateIt = m_structTemplates.find(type->name);
            if (structTemplateIt == m_structTemplates.end())
            {
                throw std::runtime_error("Unknown generic struct '" + type->name +
                    "' on line " + std::to_string(type->line) + " in module " + m_moduleName);
            }

            const StructDecl *structTmpl = structTemplateIt->second;
            if (type->generic_args.size() != structTmpl->generic_params.size())
                throw std::runtime_error("Generic struct '" + type->name + "' expected " +
                    std::to_string(structTmpl->generic_params.size()) + " type argument(s), got " +
                    std::to_string(type->generic_args.size()) +
                    " on line " + std::to_string(type->line) + " in module " + m_moduleName);

            std::string mangled = MangleName(type->name, type->generic_args);
            if (forcePublic)
                m_publicStructs.insert(mangled);
            EnqueueStruct(type->name, CloneTypeList(type->generic_args));

            type->name = mangled;
            type->generic_args.clear();
        }
    }

    void RewriteStructInit(StructInit *si)
    {
        if (si->generic_args.empty())
            return;

        auto it = m_structTemplates.find(si->type_name);
        if (it == m_structTemplates.end())
            throw std::runtime_error("Unknown generic struct '" + si->type_name +
                "' on line " + std::to_string(si->line) + " in module " + m_moduleName);

        const StructDecl *structTmpl = it->second;
        if (si->generic_args.size() != structTmpl->generic_params.size())
            throw std::runtime_error("Generic struct '" + si->type_name + "' expected " +
                std::to_string(structTmpl->generic_params.size()) + " type argument(s), got " +
                std::to_string(si->generic_args.size()) +
                " on line " + std::to_string(si->line) + " in module " + m_moduleName);

        std::string mangled = MangleName(si->type_name, si->generic_args);
        EnqueueStruct(si->type_name, CloneTypeList(si->generic_args));

        si->type_name = mangled;
        si->generic_args.clear();
    }

    void RewriteCall(CallExpr *call, LocalTypes &locals, const TypeNode *expectedType = nullptr)
    {
        auto *ident = dynamic_cast<Identifier *>(call->callee.get());
        if (!ident)
            return;

        auto templateIt = m_procTemplates.find(ident->name);
        if (templateIt == m_procTemplates.end())
            return;

        ProcDecl *tmpl = templateIt->second;
        std::vector<std::unique_ptr<TypeNode>> concreteArgs;

        if (!call->generic_args.empty())
        {

            if (call->generic_args.size() != tmpl->generic_params.size())
                throw std::runtime_error("Generic call to '" + ident->name + "' expected " +
                    std::to_string(tmpl->generic_params.size()) + " type argument(s), got " +
                    std::to_string(call->generic_args.size()) +
                    " on line " + std::to_string(call->line) + " in module " + m_moduleName);

            for (auto &g : call->generic_args)
                concreteArgs.push_back(g->Clone());
        }
        else
        {

            std::unordered_map<std::string, const TypeNode *> inferred;
            for (size_t i = 0; i < tmpl->params.size() && i < call->args.size(); i++)
            {
                TypeNode *argType = InferExprType(call->args[i].get(), locals);
                if (!argType) continue;
                UnifyParam(tmpl->params[i].type.get(), argType, tmpl->generic_params, inferred);
            }

            if (expectedType && tmpl->return_type)
                UnifyParam(tmpl->return_type.get(), expectedType, tmpl->generic_params, inferred);

            for (const auto &paramName : tmpl->generic_params)
            {
                auto found = inferred.find(paramName);
                if (found == inferred.end())
                    throw std::runtime_error("Could not infer generic argument '" + paramName +
                        "' for call to '" + ident->name + "' on line " +
                        std::to_string(call->line) + " in module " + m_moduleName +
                        " -- pass it explicitly, e.g. " + ident->name + "<...>(...)");
                concreteArgs.push_back(found->second->Clone());
            }
        }

        std::string mangled = MangleName(ident->name, concreteArgs);
        EnqueueProc(ident->name, std::move(concreteArgs));

        ident->name = mangled;
        call->generic_args.clear();
    }

    void UnifyParam(const TypeNode *paramType, const TypeNode *concreteType,
                     const std::vector<std::string> &genericParams,
                     std::unordered_map<std::string, const TypeNode *> &outBindings)
    {
        if (!paramType || !concreteType) return;

        bool paramIsGenericParam = !paramType->is_function_type &&
            std::find(genericParams.begin(), genericParams.end(), paramType->name) != genericParams.end();

        if (paramIsGenericParam)
        {

            if (outBindings.find(paramType->name) == outBindings.end())
                outBindings[paramType->name] = concreteType;
            return;
        }

        if (!paramType->generic_args.empty() && paramType->name == concreteType->name)
        {
            size_t n = std::min(paramType->generic_args.size(), concreteType->generic_args.size());
            for (size_t i = 0; i < n; i++)
                UnifyParam(paramType->generic_args[i].get(), concreteType->generic_args[i].get(),
                           genericParams, outBindings);
        }
    }

    std::vector<std::unique_ptr<TypeNode>> m_scratchTypes;

    TypeNode *MakeScratchType(const std::string &name)
    {
        auto t = std::make_unique<TypeNode>();
        t->name = name;
        TypeNode *raw = t.get();
        m_scratchTypes.push_back(std::move(t));
        return raw;
    }

    TypeNode *InferExprType(ExprNode *expr, LocalTypes &locals)
    {
        if (auto *ident = dynamic_cast<Identifier *>(expr))
        {
            auto origIt = m_originalLocalTypesStorage.find(ident->name);
            if (origIt != m_originalLocalTypesStorage.end())
                return origIt->second.get();

            auto it = locals.find(ident->name);
            return it != locals.end() ? it->second : nullptr;
        }
        if (auto *num = dynamic_cast<NumberLiteral *>(expr))
        {
            switch (num->type)
            {
                case NumberType::I32: return MakeScratchType("i32");
                case NumberType::I64: return MakeScratchType("i64");
                case NumberType::U32: return MakeScratchType("u32");
                case NumberType::U64: return MakeScratchType("u64");
                case NumberType::F32: return MakeScratchType("f32");
                case NumberType::F64: return MakeScratchType("f64");
            }
            return nullptr;
        }
        if (dynamic_cast<StringLiteral *>(expr)) return MakeScratchType("i8");
        if (dynamic_cast<CharLiteral *>(expr)) return MakeScratchType("i8");
        if (dynamic_cast<BoolLiteral *>(expr)) return MakeScratchType("bool");
        if (auto *un = dynamic_cast<UnaryExpr *>(expr))
        {

            return InferExprType(un->operand.get(), locals);
        }

        return nullptr;
    }

    static std::string MangleTypeArg(const TypeNode *t)
    {
        std::string s = t->name;
        if (!t->generic_args.empty())
        {
            for (const auto &g : t->generic_args)
                s += "." + MangleTypeArg(g.get());
        }
        return s;
    }

    static std::string MangleName(const std::string &baseName,
                                   const std::vector<std::unique_ptr<TypeNode>> &args)
    {
        std::string s = baseName;
        for (const auto &a : args)
            s += "." + MangleTypeArg(a.get());
        return s;
    }

    static std::vector<std::unique_ptr<TypeNode>> CloneTypeList(
        const std::vector<std::unique_ptr<TypeNode>> &src)
    {
        std::vector<std::unique_ptr<TypeNode>> out;
        for (const auto &t : src) out.push_back(t->Clone());
        return out;
    }

    void EnqueueStruct(const std::string &templateName, std::vector<std::unique_ptr<TypeNode>> args)
    {
        std::string mangled = MangleName(templateName, args);
        if (m_instantiated.count(mangled)) return;
        m_worklist.push_back({templateName, std::move(args), true});
    }

    void EnqueueProc(const std::string &templateName, std::vector<std::unique_ptr<TypeNode>> args)
    {
        std::string mangled = MangleName(templateName, args);
        if (m_instantiated.count(mangled)) return;
        m_worklist.push_back({templateName, std::move(args), false});
    }

    static std::unordered_map<std::string, const TypeNode *> BuildSubstitution(
        const std::vector<std::string> &params,
        const std::vector<std::unique_ptr<TypeNode>> &args)
    {
        std::unordered_map<std::string, const TypeNode *> subst;
        for (size_t i = 0; i < params.size() && i < args.size(); i++)
            subst[params[i]] = args[i].get();
        return subst;
    }

    static void SubstituteType(std::unique_ptr<TypeNode> &type,
                                const std::unordered_map<std::string, const TypeNode *> &subst)
    {
        if (!type) return;

        if (type->is_function_type)
        {
            SubstituteType(type->return_type, subst);
            for (auto &p : type->param_types) SubstituteType(p, subst);
            return;
        }

        for (auto &g : type->generic_args)
            SubstituteType(g, subst);

        auto it = subst.find(type->name);
        if (it != subst.end())
        {
            const TypeNode *concrete = it->second;

            auto replacement = concrete->Clone();

            for (bool pc : type->pointer_const) replacement->pointer_const.push_back(pc);
            replacement->pointer_depth += type->pointer_depth;
            for (int dim : type->array_dimensions) replacement->array_dimensions.push_back(dim);
            if (type->is_const) replacement->is_const = true;
            replacement->line = type->line;

            type = std::move(replacement);
            return;
        }

        if (!type->generic_args.empty())
        {
            bool anyIsFullyConcrete = true;
            for (auto &g : type->generic_args)
                if (ContainsGenericParam(g.get(), subst))
                    anyIsFullyConcrete = false;
            if (anyIsFullyConcrete)
            {

            }
        }
    }

    static bool ContainsGenericParam(const TypeNode *type,
                                      const std::unordered_map<std::string, const TypeNode *> &subst)
    {
        if (!type) return false;
        if (subst.count(type->name)) return true;
        for (auto &g : type->generic_args)
            if (ContainsGenericParam(g.get(), subst)) return true;
        if (type->return_type && ContainsGenericParam(type->return_type.get(), subst)) return true;
        for (auto &p : type->param_types)
            if (ContainsGenericParam(p.get(), subst)) return true;
        return false;
    }

    static std::unique_ptr<ExprNode> CloneExpr(const ExprNode *node);
    static std::unique_ptr<StmtNode> CloneStmt(const StmtNode *node);
    static std::unique_ptr<BlockStmt> CloneBlock(const BlockStmt *block)
    {
        auto out = std::make_unique<BlockStmt>();
        out->line = block->line;
        for (auto &s : block->statements)
            out->statements.push_back(CloneStmt(s.get()));
        return out;
    }

    void InstantiateStruct(const std::string &templateName, const std::string &mangled,
                            const std::vector<std::unique_ptr<TypeNode>> &args)
    {
        StructDecl *tmpl = m_structTemplates.at(templateName);
        auto subst = BuildSubstitution(tmpl->generic_params, args);

        bool isPublic = m_publicStructs.count(mangled) > 0;

        auto decl = std::make_unique<StructDecl>();
        decl->name = mangled;
        decl->line = tmpl->line;
        decl->is_packed = tmpl->is_packed;
        decl->is_pub = isPublic;

        for (auto &field : tmpl->fields)
        {
            auto f = std::make_unique<StructField>();
            f->name = field->name;
            f->type = field->type->Clone();
            SubstituteType(f->type, subst);
            if (field->default_value)
                f->default_value = CloneExpr(field->default_value.get());
            decl->fields.push_back(std::move(f));
        }

        StructDecl *inserted = decl.get();
        m_module.structs.push_back(std::move(decl));

        LocalTypes noLocals;
        for (auto &field : inserted->fields)
            RewriteType(field->type.get(), noLocals, isPublic);
    }

    void InstantiateProc(const std::string &templateName, const std::string &mangled,
                          const std::vector<std::unique_ptr<TypeNode>> &args)
    {
        ProcDecl *tmpl = m_procTemplates.at(templateName);
        auto subst = BuildSubstitution(tmpl->generic_params, args);

        auto proc = std::make_unique<ProcDecl>();
        proc->name = mangled;
        proc->line = tmpl->line;
        proc->is_pub = false;
        proc->is_extern = tmpl->is_extern;
        proc->is_vararg = tmpl->is_vararg;

        for (auto &param : tmpl->params)
        {
            Parameter p;
            p.name = param.name;
            p.type = param.type->Clone();
            SubstituteType(p.type, subst);
            if (param.default_value)
                p.default_value = CloneExpr(param.default_value.get());
            proc->params.push_back(std::move(p));
        }

        if (tmpl->return_type)
        {
            proc->return_type = tmpl->return_type->Clone();
            SubstituteType(proc->return_type, subst);
        }

        if (tmpl->body)
        {
            proc->body = CloneBlock(tmpl->body.get());
            SubstituteTypesInBlock(proc->body.get(), subst);
        }

        ProcDecl *inserted = proc.get();
        m_module.procs.push_back(std::move(proc));

        LocalTypes locals;
        for (auto &param : inserted->params)
            if (param.type) locals[param.name] = param.type.get();
        if (inserted->return_type)
            RewriteType(inserted->return_type.get(), locals);
        for (auto &param : inserted->params)
            if (param.type) RewriteType(param.type.get(), locals);
        if (inserted->body)
            RewriteBlock(inserted->body.get(), locals);
    }

    static void SubstituteTypesInBlock(BlockStmt *block, const std::unordered_map<std::string, const TypeNode *> &subst)
    {
        for (auto &stmt : block->statements)
            SubstituteTypesInStmt(stmt.get(), subst);
    }

    static void SubstituteTypesInStmt(StmtNode *stmt, const std::unordered_map<std::string, const TypeNode *> &subst)
    {
        if (auto *vd = dynamic_cast<VarDecl *>(stmt))
        {
            if (vd->type) SubstituteType(vd->type, subst);
            if (vd->init) SubstituteTypesInExpr(vd->init.get(), subst);
            return;
        }
        if (auto *es = dynamic_cast<ExprStmt *>(stmt)) { SubstituteTypesInExpr(es->expr.get(), subst); return; }
        if (auto *ret = dynamic_cast<ReturnStmt *>(stmt)) { if (ret->value) SubstituteTypesInExpr(ret->value.get(), subst); return; }
        if (auto *blk = dynamic_cast<BlockStmt *>(stmt)) { SubstituteTypesInBlock(blk, subst); return; }
        if (auto *ifs = dynamic_cast<IfStmt *>(stmt))
        {
            SubstituteTypesInExpr(ifs->condition.get(), subst);
            if (ifs->then_branch) SubstituteTypesInBlock(ifs->then_branch.get(), subst);
            if (ifs->else_branch) SubstituteTypesInBlock(ifs->else_branch.get(), subst);
            return;
        }
        if (auto *ws = dynamic_cast<WhileStmt *>(stmt))
        {
            SubstituteTypesInExpr(ws->condition.get(), subst);
            if (ws->then_branch) SubstituteTypesInBlock(ws->then_branch.get(), subst);
            return;
        }
        if (auto *dws = dynamic_cast<DoWhileStmt *>(stmt))
        {
            if (dws->then_branch) SubstituteTypesInBlock(dws->then_branch.get(), subst);
            SubstituteTypesInExpr(dws->condition.get(), subst);
            return;
        }
        if (auto *fs = dynamic_cast<ForStmt *>(stmt))
        {
            if (fs->init_decl) SubstituteTypesInStmt(fs->init_decl.get(), subst);
            if (fs->init_expr) SubstituteTypesInExpr(fs->init_expr.get(), subst);
            if (fs->condition) SubstituteTypesInExpr(fs->condition.get(), subst);
            if (fs->increment) SubstituteTypesInExpr(fs->increment.get(), subst);
            if (fs->body) SubstituteTypesInBlock(fs->body.get(), subst);
            return;
        }
        if (auto *ms = dynamic_cast<MatchStmt *>(stmt))
        {
            SubstituteTypesInExpr(ms->value.get(), subst);
            for (auto &c : ms->cases)
            {
                if (c->value) SubstituteTypesInExpr(c->value.get(), subst);
                if (c->body) SubstituteTypesInBlock(c->body.get(), subst);
            }
            return;
        }
    }

    static void SubstituteTypesInExpr(ExprNode *node, const std::unordered_map<std::string, const TypeNode *> &subst)
    {
        if (!node) return;
        if (auto *bin = dynamic_cast<BinaryExpr *>(node)) { SubstituteTypesInExpr(bin->left.get(), subst); SubstituteTypesInExpr(bin->right.get(), subst); return; }
        if (auto *un = dynamic_cast<UnaryExpr *>(node)) { SubstituteTypesInExpr(un->operand.get(), subst); return; }
        if (auto *call = dynamic_cast<CallExpr *>(node))
        {
            for (auto &a : call->args) SubstituteTypesInExpr(a.get(), subst);
            for (auto &g : call->generic_args) SubstituteType(g, subst);
            return;
        }
        if (auto *arr = dynamic_cast<ArrayAccess *>(node)) { SubstituteTypesInExpr(arr->array.get(), subst); SubstituteTypesInExpr(arr->index.get(), subst); return; }
        if (auto *mem = dynamic_cast<MemberAccess *>(node)) { SubstituteTypesInExpr(mem->object.get(), subst); return; }
        if (auto *pmem = dynamic_cast<PointerMemberAccess *>(node)) { SubstituteTypesInExpr(pmem->object.get(), subst); return; }
        if (auto *si = dynamic_cast<StructInit *>(node))
        {
            for (auto &g : si->generic_args) SubstituteType(g, subst);
            for (auto &f : si->fields) if (f.value) SubstituteTypesInExpr(f.value.get(), subst);
            return;
        }
        if (auto *ai = dynamic_cast<ArrayInit *>(node)) { for (auto &e : ai->elements) SubstituteTypesInExpr(e.get(), subst); return; }
        if (auto *sz = dynamic_cast<SizeofExpr *>(node)) { SubstituteType(sz->type, subst); return; }
        if (auto *cst = dynamic_cast<CastExpr *>(node)) { SubstituteType(cst->target_type, subst); SubstituteTypesInExpr(cst->operand.get(), subst); return; }
        if (auto *va = dynamic_cast<VaArgExpr *>(node)) { SubstituteTypesInExpr(va->va_list.get(), subst); SubstituteType(va->type, subst); return; }
        if (auto *tern = dynamic_cast<TernaryExpr *>(node)) { SubstituteTypesInExpr(tern->condition.get(), subst); SubstituteTypesInExpr(tern->then_expr.get(), subst); SubstituteTypesInExpr(tern->else_expr.get(), subst); return; }
    }
};

inline std::unique_ptr<ExprNode> GenericsPass::CloneExpr(const ExprNode *node)
{
    if (!node) return nullptr;

    if (auto *n = dynamic_cast<const BinaryExpr *>(node))
    {
        auto c = std::make_unique<BinaryExpr>();
        c->line = n->line; c->op = n->op;
        c->left = CloneExpr(n->left.get());
        c->right = CloneExpr(n->right.get());
        return c;
    }
    if (auto *n = dynamic_cast<const UnaryExpr *>(node))
    {
        auto c = std::make_unique<UnaryExpr>();
        c->line = n->line; c->op = n->op; c->is_prefix = n->is_prefix;
        c->operand = CloneExpr(n->operand.get());
        return c;
    }
    if (auto *n = dynamic_cast<const NumberLiteral *>(node))
    {
        auto c = std::make_unique<NumberLiteral>();
        c->line = n->line; c->value = n->value; c->numeric_part = n->numeric_part; c->type = n->type;
        return c;
    }
    if (auto *n = dynamic_cast<const StringLiteral *>(node))
    {
        auto c = std::make_unique<StringLiteral>();
        c->line = n->line; c->value = n->value;
        return c;
    }
    if (auto *n = dynamic_cast<const CharLiteral *>(node))
    {
        auto c = std::make_unique<CharLiteral>();
        c->line = n->line; c->value = n->value;
        return c;
    }
    if (auto *n = dynamic_cast<const BoolLiteral *>(node))
    {
        auto c = std::make_unique<BoolLiteral>();
        c->line = n->line; c->value = n->value;
        return c;
    }
    if (auto *n = dynamic_cast<const Identifier *>(node))
    {
        auto c = std::make_unique<Identifier>();
        c->line = n->line; c->name = n->name;
        return c;
    }
    if (auto *n = dynamic_cast<const CallExpr *>(node))
    {
        auto c = std::make_unique<CallExpr>();
        c->line = n->line;
        c->callee = CloneExpr(n->callee.get());
        for (auto &a : n->args) c->args.push_back(CloneExpr(a.get()));
        for (auto &g : n->generic_args) c->generic_args.push_back(g->Clone());
        return c;
    }
    if (auto *n = dynamic_cast<const ArrayAccess *>(node))
    {
        auto c = std::make_unique<ArrayAccess>();
        c->line = n->line;
        c->array = CloneExpr(n->array.get());
        c->index = CloneExpr(n->index.get());
        return c;
    }
    if (auto *n = dynamic_cast<const MemberAccess *>(node))
    {
        auto c = std::make_unique<MemberAccess>();
        c->line = n->line; c->member = n->member;
        c->object = CloneExpr(n->object.get());
        return c;
    }
    if (auto *n = dynamic_cast<const PointerMemberAccess *>(node))
    {
        auto c = std::make_unique<PointerMemberAccess>();
        c->line = n->line; c->member = n->member;
        c->object = CloneExpr(n->object.get());
        return c;
    }
    if (auto *n = dynamic_cast<const StructInit *>(node))
    {
        auto c = std::make_unique<StructInit>();
        c->line = n->line; c->type_name = n->type_name;
        for (auto &g : n->generic_args) c->generic_args.push_back(g->Clone());
        for (auto &f : n->fields)
        {
            FieldInit fi;
            fi.name = f.name;
            fi.value = CloneExpr(f.value.get());
            c->fields.push_back(std::move(fi));
        }
        return c;
    }
    if (auto *n = dynamic_cast<const ArrayInit *>(node))
    {
        auto c = std::make_unique<ArrayInit>();
        c->line = n->line;
        for (auto &e : n->elements) c->elements.push_back(CloneExpr(e.get()));
        return c;
    }
    if (auto *n = dynamic_cast<const SizeofExpr *>(node))
    {
        auto c = std::make_unique<SizeofExpr>();
        c->line = n->line;
        c->type = n->type->Clone();
        return c;
    }
    if (auto *n = dynamic_cast<const CastExpr *>(node))
    {
        auto c = std::make_unique<CastExpr>();
        c->line = n->line;
        c->target_type = n->target_type->Clone();
        c->operand = CloneExpr(n->operand.get());
        return c;
    }
    if (auto *n = dynamic_cast<const VaArgExpr *>(node))
    {
        auto c = std::make_unique<VaArgExpr>();
        c->line = n->line;
        c->va_list = CloneExpr(n->va_list.get());
        c->type = n->type->Clone();
        return c;
    }
    if (auto *n = dynamic_cast<const TernaryExpr *>(node))
    {
        auto c = std::make_unique<TernaryExpr>();
        c->line = n->line;
        c->condition = CloneExpr(n->condition.get());
        c->then_expr = CloneExpr(n->then_expr.get());
        c->else_expr = CloneExpr(n->else_expr.get());
        return c;
    }
    if (auto *n = dynamic_cast<const EnumAccess *>(node))
    {
        auto c = std::make_unique<EnumAccess>();
        c->line = n->line; c->enum_name = n->enum_name; c->value_name = n->value_name;
        return c;
    }

    throw std::runtime_error("GenericsPass: unhandled expression node type during clone");
}

inline std::unique_ptr<StmtNode> GenericsPass::CloneStmt(const StmtNode *node)
{
    if (!node) return nullptr;

    if (auto *n = dynamic_cast<const VarDecl *>(node))
    {
        auto c = std::make_unique<VarDecl>();
        c->line = n->line; c->name = n->name;
        if (n->type) c->type = n->type->Clone();
        if (n->init) c->init = CloneExpr(n->init.get());
        return c;
    }
    if (auto *n = dynamic_cast<const ExprStmt *>(node))
    {
        auto c = std::make_unique<ExprStmt>();
        c->line = n->line;
        c->expr = CloneExpr(n->expr.get());
        return c;
    }
    if (auto *n = dynamic_cast<const ReturnStmt *>(node))
    {
        auto c = std::make_unique<ReturnStmt>();
        c->line = n->line;
        if (n->value) c->value = CloneExpr(n->value.get());
        return c;
    }
    if (dynamic_cast<const BreakStmt *>(node)) { auto c = std::make_unique<BreakStmt>(); c->line = node->line; return c; }
    if (dynamic_cast<const ContinueStmt *>(node)) { auto c = std::make_unique<ContinueStmt>(); c->line = node->line; return c; }
    if (auto *n = dynamic_cast<const BlockStmt *>(node))
    {
        return GenericsPass::CloneBlock(n);
    }
    if (auto *n = dynamic_cast<const IfStmt *>(node))
    {
        auto c = std::make_unique<IfStmt>();
        c->line = n->line;
        c->condition = CloneExpr(n->condition.get());
        if (n->then_branch) c->then_branch = GenericsPass::CloneBlock(n->then_branch.get());
        if (n->else_branch) c->else_branch = GenericsPass::CloneBlock(n->else_branch.get());
        return c;
    }
    if (auto *n = dynamic_cast<const WhileStmt *>(node))
    {
        auto c = std::make_unique<WhileStmt>();
        c->line = n->line;
        c->condition = CloneExpr(n->condition.get());
        if (n->then_branch) c->then_branch = GenericsPass::CloneBlock(n->then_branch.get());
        return c;
    }
    if (auto *n = dynamic_cast<const DoWhileStmt *>(node))
    {
        auto c = std::make_unique<DoWhileStmt>();
        c->line = n->line;
        c->condition = CloneExpr(n->condition.get());
        if (n->then_branch) c->then_branch = GenericsPass::CloneBlock(n->then_branch.get());
        return c;
    }
    if (auto *n = dynamic_cast<const ForStmt *>(node))
    {
        auto c = std::make_unique<ForStmt>();
        c->line = n->line;
        if (n->init_decl)
        {
            auto vd = CloneStmt(n->init_decl.get());
            c->init_decl.reset(static_cast<VarDecl *>(vd.release()));
        }
        if (n->init_expr) c->init_expr = CloneExpr(n->init_expr.get());
        if (n->condition) c->condition = CloneExpr(n->condition.get());
        if (n->increment) c->increment = CloneExpr(n->increment.get());
        if (n->body) c->body = GenericsPass::CloneBlock(n->body.get());
        return c;
    }
    if (auto *n = dynamic_cast<const MatchStmt *>(node))
    {
        auto c = std::make_unique<MatchStmt>();
        c->line = n->line;
        c->value = CloneExpr(n->value.get());
        for (auto &cs : n->cases)
        {
            auto nc = std::make_unique<MatchCase>();
            nc->is_else = cs->is_else;
            if (cs->value) nc->value = CloneExpr(cs->value.get());
            if (cs->body) nc->body = GenericsPass::CloneBlock(cs->body.get());
            c->cases.push_back(std::move(nc));
        }
        return c;
    }

    throw std::runtime_error("GenericsPass: unhandled statement node type during clone");
}