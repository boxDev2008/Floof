#pragma once

#include <vector>
#include <set>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <algorithm>
#include <map>
#include <unordered_map>

#include "Lexer.h"

struct ASTNode {
    virtual ~ASTNode() = default;
    uint32_t line = 0;
};

struct NamespaceScope {
    std::string path;
    std::vector<std::string> usings;
    const NamespaceScope* parent = nullptr;
};

inline std::string QualifyName(const NamespaceScope* ns, const std::string& name)
{
    return (!ns || ns->path.empty()) ? name : ns->path + "." + name;
}

struct AttributeNode {
    std::string name;
    std::vector<Token> args;
    uint32_t line = 0;
};

typedef std::vector<AttributeNode> AttributeList;

inline const AttributeNode* FindAttribute(const AttributeList& list, const std::string& name)
{
    for (const auto& attr : list)
        if (attr.name == name)
            return &attr;
    return nullptr;
}

inline bool HasAttribute(const AttributeList& list, const std::string& name)
{
    return FindAttribute(list, name) != nullptr;
}

struct TypeNode : ASTNode {
    std::string name;
    std::vector<int> array_dimensions;
    
    std::unique_ptr<TypeNode> return_type;
    std::vector<std::unique_ptr<TypeNode>> param_types;
    std::vector<std::unique_ptr<TypeNode>> generic_args;
    std::vector<bool> pointer_const;
    int pointer_depth = 0;
    bool is_const = false;
    bool is_function_type = false;
};

struct ExprNode : ASTNode {
    virtual ~ExprNode() = default;
};

struct BinaryExpr : ExprNode {
    std::unique_ptr<ExprNode> left, right;
    uint16_t op;
};

struct UnaryExpr : ExprNode {
    std::unique_ptr<ExprNode> operand;
    char op;
    bool is_prefix;
};

enum class NumberType {
    I32,
    I64,
    U32,
    U64,
    F32,
    F64
};

struct NumberLiteral : ExprNode {
    std::string value;
    std::string numeric_part;
    NumberType type;
};

struct StringLiteral : ExprNode {
    std::string value;
};

struct CharLiteral : ExprNode {
    std::string value;
};

struct BoolLiteral : ExprNode {
    bool value;
};

struct Identifier : ExprNode {
    std::string name;
    std::vector<std::unique_ptr<TypeNode>> generic_args;
};

struct CallExpr : ExprNode {
    std::unique_ptr<ExprNode> callee;
    std::vector<std::unique_ptr<ExprNode>> args;
};

struct ArrayAccess : ExprNode {
    std::unique_ptr<ExprNode> array;
    std::unique_ptr<ExprNode> index;
};

struct MemberAccess : ExprNode {
    std::unique_ptr<ExprNode> object;
    std::string member;
    std::vector<std::unique_ptr<TypeNode>> generic_args;
};

struct FieldInit {
    std::string name;
    std::unique_ptr<ExprNode> value;
};

struct StructInit : ExprNode {
    std::string type_name;
    std::vector<std::unique_ptr<TypeNode>> type_args;
    std::vector<FieldInit> fields;
};

struct ArrayInit : ExprNode {
    std::vector<std::unique_ptr<ExprNode>> elements;
};

struct SizeofExpr : ExprNode {
    std::unique_ptr<TypeNode> type;
};

struct NewExpr : ExprNode {
    std::unique_ptr<TypeNode> type;
    std::unique_ptr<ExprNode> count;
};

struct StmtNode : ASTNode {
    virtual ~StmtNode() = default;
};

struct VarDecl : StmtNode {
    std::string name;
    std::unique_ptr<TypeNode> type;
    std::unique_ptr<ExprNode> init;
};

struct GlobalVarDecl : StmtNode {
    std::string name;
    std::unique_ptr<TypeNode> type;
    std::unique_ptr<ExprNode> init;
    AttributeList attributes;
    const NamespaceScope* ns = nullptr;
    bool is_pub = false;
};

struct ExprStmt : StmtNode {
    std::unique_ptr<ExprNode> expr;
};

struct CastExpr : ExprNode {
    std::unique_ptr<TypeNode> target_type;
    std::unique_ptr<ExprNode> operand;
};

struct ReturnStmt : StmtNode {
    std::unique_ptr<ExprNode> value;
};

struct TypeofExpr : ExprNode {
    std::unique_ptr<ExprNode> operand;
    std::unique_ptr<TypeNode> type;
};

struct SpreadExpr : ExprNode {
    std::unique_ptr<ExprNode> operand;
};

struct TernaryExpr : ExprNode {
    std::unique_ptr<ExprNode> condition;
    std::unique_ptr<ExprNode> then_expr;
    std::unique_ptr<ExprNode> else_expr;
};

struct FreeStmt : StmtNode {
    std::unique_ptr<ExprNode> value;
};

struct BreakStmt : StmtNode { };

struct ContinueStmt : StmtNode { };

struct BlockStmt : StmtNode {
    std::vector<std::unique_ptr<StmtNode>> statements;
};

struct IfStmt : StmtNode {
    std::unique_ptr<ExprNode> condition;
    std::unique_ptr<BlockStmt> then_branch, else_branch;
};

struct WhileStmt : StmtNode {
    std::unique_ptr<ExprNode> condition;
    std::unique_ptr<BlockStmt> then_branch;
};

struct DoWhileStmt : StmtNode {
    std::unique_ptr<ExprNode> condition;
    std::unique_ptr<BlockStmt> then_branch;
};

struct ForStmt : StmtNode {
    std::unique_ptr<VarDecl> init_decl;
    std::unique_ptr<ExprNode> init_expr;
    std::unique_ptr<ExprNode> condition;
    std::unique_ptr<ExprNode> increment;
    std::unique_ptr<BlockStmt> body;
};

typedef std::vector<std::unique_ptr<TypeNode>> GenericConstraint;

struct StructField {
    std::string name;
    std::unique_ptr<TypeNode> type;
    std::unique_ptr<ExprNode> default_value;
    AttributeList attributes;
};

struct StructDecl : ASTNode {
    std::string name;
    std::vector<std::string> generic_params;
    std::vector<GenericConstraint> generic_constraints;
    std::vector<std::unique_ptr<StructField>> fields;
    AttributeList attributes;
    const NamespaceScope* ns = nullptr;
    bool is_packed = false;
    bool is_pub = false;
};

struct EnumValue
{
    std::string name;
    std::unique_ptr<ExprNode> expr;
};

struct EnumDecl : ASTNode
{
    std::string name;
    std::vector<EnumValue> values;
    std::unique_ptr<TypeNode> base_type;
    AttributeList attributes;
    const NamespaceScope* ns = nullptr;
    bool is_pub = false;
};

struct MatchCase
{
    std::unique_ptr<ExprNode> value;
    std::unique_ptr<BlockStmt> body;
    bool is_else = false;
};

struct MatchStmt : StmtNode {
    std::unique_ptr<ExprNode> value;
    std::vector<std::unique_ptr<MatchCase>> cases;
};

struct Parameter {
    std::string name;
    std::unique_ptr<TypeNode> type;
    std::unique_ptr<ExprNode> default_value;
    bool is_variadic = false;
};

struct ProcDecl : ASTNode {
    std::string name;
    std::vector<std::string> generic_params;
    std::vector<GenericConstraint> generic_constraints;
    std::vector<Parameter> params;
    std::unique_ptr<TypeNode> return_type;
    std::unique_ptr<BlockStmt> body;
    AttributeList attributes;
    const NamespaceScope* ns = nullptr;
    bool is_pub = false;
    bool is_extern = false;
    bool is_c_abi = false;
    bool is_vararg = false;

    bool HasVariadicParam() const { return !params.empty() && params.back().is_variadic; }
};

struct UsingDecl : ASTNode {
    std::string name;
    bool is_pub = false;
};

struct RequireDecl : ASTNode {
    std::string library;
    AttributeList attributes;
};

struct AliasDecl : ASTNode {
    std::string name;
    std::unique_ptr<TypeNode> target;
    const NamespaceScope* ns = nullptr;
    bool is_pub = false;
};

struct AttrDef : ASTNode {
    std::string name;
    std::vector<std::string> params;
    AttributeList attributes;
    bool is_pub = false;
};

struct ModuleAST : ASTNode {
    std::vector<std::unique_ptr<NamespaceScope>> scopes;
    std::vector<std::unique_ptr<UsingDecl>> usings;
    std::vector<std::unique_ptr<StructDecl>> structs;
    std::vector<std::unique_ptr<EnumDecl>> enums;
    std::vector<std::unique_ptr<AliasDecl>> aliases;
    std::vector<std::unique_ptr<GlobalVarDecl>> globals;
    std::vector<std::unique_ptr<ProcDecl>> procs;
    std::vector<std::unique_ptr<RequireDecl>> requires_;
    std::vector<std::unique_ptr<AttrDef>> attrdefs;
};

class AttributeResolver
{
public:
    enum DeclKind { Decl_Proc, Decl_Struct, Decl_Enum, Decl_Global, Decl_Require, Decl_Field };

    static bool IsBuiltin(const std::string& name)
    {
        return name == "align" || name == "callconv" || name == "feat" ||
               name == "noreturn" || name == "inline";
    }

    static bool IsKnownCallConv(const std::string& name)
    {
        static const std::set<std::string> names = {
            "c", "cdecl", "stdcall", "fastcall", "vectorcall", "thiscall", "win64", "sysv"
        };
        return names.count(name) > 0;
    }

    static uint64_t AlignValue(const AttributeNode& attr)
    {
        return std::stoull(attr.args[0].value, nullptr, 0);
    }

    AttributeResolver(std::map<std::string, std::unique_ptr<ModuleAST>>& modules, const std::string& builtinModule)
        : m_modules(modules), m_builtinModule(builtinModule) {}

    void ResolveAll(void)
    {
        for (auto& [name, module] : m_modules)
            for (const auto& def : module->attrdefs)
            {
                if (IsBuiltin(def->name))
                    Fail("Cannot redefine builtin attribute '@" + def->name + "'", def->line, name);
                m_defModule[def.get()] = name;
            }

        for (auto& [name, module] : m_modules)
            m_scopes[name] = CollectVisible(name);

        for (auto& [name, module] : m_modules)
        {
            for (auto& d : module->procs)     Resolve(d->attributes, Decl_Proc, name);
            for (auto& d : module->structs)
            {
                Resolve(d->attributes, Decl_Struct, name);
                for (auto& f : d->fields)
                    Resolve(f->attributes, Decl_Field, name);
            }
            for (auto& d : module->enums)     Resolve(d->attributes, Decl_Enum, name);
            for (auto& d : module->globals)   Resolve(d->attributes, Decl_Global, name);
            for (auto& d : module->requires_) Resolve(d->attributes, Decl_Require, name);

            for (auto& def : module->attrdefs)
                if (def->params.empty())
                {
                    AttributeList out;
                    std::vector<const AttrDef*> stack;
                    AttributeNode use{def->name, {}, def->line};
                    Expand(use, m_scopes[name], stack, name, out);
                }
        }
    }

private:
    using DefMap = std::unordered_map<std::string, const AttrDef*>;

    std::map<std::string, std::unique_ptr<ModuleAST>>& m_modules;
    std::string m_builtinModule;
    std::unordered_map<const AttrDef*, std::string> m_defModule;
    std::unordered_map<std::string, DefMap> m_scopes;

    [[noreturn]] static void Fail(const std::string& msg, uint32_t line, const std::string& module)
    {
        throw std::runtime_error(msg + " on line " + std::to_string(line) + " in module " + module);
    }

    static void AddDef(DefMap& map, const AttrDef* def, uint32_t line, const std::string& module)
    {
        auto [it, inserted] = map.emplace(def->name, def);
        if (!inserted && it->second != def)
            Fail("Attribute '@" + def->name + "' is defined in more than one visible module", line, module);
    }

    DefMap CollectVisible(const std::string& moduleName)
    {
        DefMap map;
        const ModuleAST& self = *m_modules.at(moduleName);
        for (const auto& def : self.attrdefs)
            AddDef(map, def.get(), def->line, moduleName);

        std::set<std::string> visited{moduleName};
        std::vector<std::string> pending;
        if (moduleName != m_builtinModule && m_modules.count(m_builtinModule))
            pending.push_back(m_builtinModule);
        for (const auto& use : self.usings)
            pending.push_back(use->name);

        while (!pending.empty())
        {
            std::string name = pending.back();
            pending.pop_back();
            if (!visited.insert(name).second)
                continue;

            auto it = m_modules.find(name);
            if (it == m_modules.end())
                continue;

            for (const auto& def : it->second->attrdefs)
                if (def->is_pub)
                    AddDef(map, def.get(), def->line, moduleName);
            for (const auto& use : it->second->usings)
                if (use->is_pub)
                    pending.push_back(use->name);
        }
        return map;
    }

    static void ValidateBuiltin(const AttributeNode& attr, const std::string& module)
    {
        auto expectArgs = [&](size_t n) {
            if (attr.args.size() != n)
                Fail("Attribute '@" + attr.name + "' expects " + std::to_string(n) + " argument(s)", attr.line, module);
        };

        if (attr.name == "noreturn" || attr.name == "inline")
            expectArgs(0);
        else if (attr.name == "align")
        {
            expectArgs(1);
            uint64_t value = 0;
            if (attr.args[0].type == TokenType_Number)
            {
                try { value = AlignValue(attr); } catch (...) { value = 0; }
            }
            if (value == 0 || (value & (value - 1)) != 0)
                Fail("'@align' expects a power-of-two integer, got '" + attr.args[0].value + "'", attr.line, module);
        }
        else if (attr.name == "callconv")
        {
            expectArgs(1);
            const Token& arg = attr.args[0];
            if ((arg.type != TokenType_String && arg.type != TokenType_Identifier) || !IsKnownCallConv(arg.value))
                Fail("Unknown calling convention '" + arg.value + "' (expected one of: c, cdecl, stdcall, "
                     "fastcall, vectorcall, thiscall, win64, sysv)", attr.line, module);
        }
        else if (attr.name == "feat")
        {
            if (attr.args.empty())
                Fail("'@feat' expects at least one feature name", attr.line, module);
            for (const auto& arg : attr.args)
                if (arg.type != TokenType_Identifier && arg.type != TokenType_String)
                    Fail("'@feat' arguments must be feature names, got '" + arg.value + "'", attr.line, module);
        }
    }

    void Expand(const AttributeNode& attr, const DefMap& scope, std::vector<const AttrDef*>& stack,
                const std::string& module, AttributeList& out)
    {
        if (IsBuiltin(attr.name))
        {
            ValidateBuiltin(attr, module);
            out.push_back(attr);
            return;
        }

        auto it = scope.find(attr.name);
        if (it == scope.end())
            Fail("Unknown attribute '@" + attr.name + "'", attr.line, module);

        const AttrDef* def = it->second;
        if (std::find(stack.begin(), stack.end(), def) != stack.end())
            Fail("Attribute '@" + attr.name + "' is defined in terms of itself", attr.line, module);
        if (attr.args.size() != def->params.size())
            Fail("Attribute '@" + attr.name + "' expects " + std::to_string(def->params.size()) +
                 " argument(s), got " + std::to_string(attr.args.size()), attr.line, module);

        stack.push_back(def);
        const DefMap& defScope = m_scopes.at(m_defModule.at(def));
        for (const auto& inner : def->attributes)
        {
            AttributeNode copy = inner;
            copy.line = attr.line;
            for (auto& arg : copy.args)
            {
                if (arg.type != TokenType_Identifier) continue;
                auto p = std::find(def->params.begin(), def->params.end(), arg.value);
                if (p != def->params.end())
                    arg = attr.args[p - def->params.begin()];
            }
            Expand(copy, defScope, stack, module, out);
        }
        stack.pop_back();
    }

    void Resolve(AttributeList& attributes, DeclKind kind, const std::string& module)
    {
        if (attributes.empty())
            return;

        AttributeList out;
        for (const auto& attr : attributes)
        {
            std::vector<const AttrDef*> stack;
            Expand(attr, m_scopes.at(module), stack, module, out);
        }

        static const char* kindNames[] = { "functions", "structs", "enums", "global variables", "require declarations", "struct fields" };
        for (size_t i = 0; i < out.size(); i++)
        {
            const AttributeNode& attr = out[i];
            bool allowed = (attr.name == "feat" && kind != Decl_Field) ||
                (attr.name == "align" && (kind == Decl_Proc || kind == Decl_Struct || kind == Decl_Global || kind == Decl_Field)) ||
                (kind == Decl_Proc && (attr.name == "callconv" || attr.name == "noreturn" || attr.name == "inline"));
            if (!allowed)
                Fail("Attribute '@" + attr.name + "' cannot be applied to " + kindNames[kind], attr.line, module);

            if (attr.name != "feat")
                for (size_t j = 0; j < i; j++)
                    if (out[j].name == attr.name)
                        Fail("Duplicate attribute '@" + attr.name + "'", attr.line, module);
        }

        attributes = std::move(out);
    }
};

class AttributeFilter
{
public:
    AttributeFilter(const std::set<std::string>& flags)
        : m_flags(flags) {}

    void FilterModule(ModuleAST& module) const
    {
        FilterItems(module.structs);
        FilterItems(module.enums);
        FilterItems(module.procs);
        FilterItems(module.requires_);
        FilterItems(module.globals);
    }

private:
    const std::set<std::string> &m_flags;

    bool ShouldKeepItem(const AttributeList& attributes) const
    {
        for (const auto& attr : attributes)
        {
            if (attr.name != "feat") continue;
            for (const auto& flag : attr.args)
                if (m_flags.find(flag.value) == m_flags.end())
                    return false;
        }

        return true;
    }

    template <typename T>
    void FilterItems(std::vector<std::unique_ptr<T>>& items) const
    {
        items.erase(
            std::remove_if(items.begin(), items.end(),
                [&](const std::unique_ptr<T>& item)
                {
                    return !ShouldKeepItem(item->attributes);
                }),
            items.end());
    }
};

class NamespaceResolver
{
public:
    NamespaceResolver(std::map<std::string, std::unique_ptr<ModuleAST>>& modules)
        : m_modules(modules) {}

    void ResolveAll(void)
    {
        for (auto& [name, module] : m_modules)
            for (const auto& scope : module->scopes)
                for (std::string path = scope->path; !path.empty(); )
                {
                    m_namespaces.insert(path);
                    size_t dot = path.rfind('.');
                    path = dot == std::string::npos ? "" : path.substr(0, dot);
                }

        for (auto& [name, module] : m_modules)
        {
            m_moduleName = &name;

            for (const auto& use : module->usings)
                if (!m_modules.count(use->name) && !m_namespaces.count(use->name))
                    Fail("Unknown module or namespace '" + use->name + "'", use->line);

            for (auto& decl : module->globals)
            {
                m_scope = decl->ns;
                RewriteExpr(decl->init);
            }
            for (auto& decl : module->structs)
            {
                m_scope = decl->ns;
                for (auto& field : decl->fields)
                    RewriteExpr(field->default_value);
            }
            for (auto& decl : module->enums)
            {
                m_scope = decl->ns;
                for (auto& value : decl->values)
                    RewriteExpr(value.expr);
            }
            for (auto& proc : module->procs)
            {
                m_scope = proc->ns;
                for (auto& param : proc->params)
                    RewriteExpr(param.default_value);
                if (!proc->body)
                    continue;

                m_locals.emplace_back();
                for (const auto& param : proc->params)
                    m_locals.back().insert(param.name);
                RewriteBlock(proc->body.get());
                m_locals.pop_back();
            }
        }
    }

private:
    std::map<std::string, std::unique_ptr<ModuleAST>>& m_modules;
    std::set<std::string> m_namespaces;
    std::vector<std::set<std::string>> m_locals;
    const NamespaceScope* m_scope = nullptr;
    const std::string* m_moduleName = nullptr;

    [[noreturn]] void Fail(const std::string& msg, uint32_t line) const
    {
        throw std::runtime_error(msg + " on line " + std::to_string(line) + " in module " + *m_moduleName);
    }

    bool IsLocal(const std::string& name) const
    {
        for (const auto& scope : m_locals)
            if (scope.count(name))
                return true;
        return false;
    }

    bool IsNamespace(const std::string& path) const
    {
        std::string outer = m_scope ? m_scope->path : "";
        while (true)
        {
            if (m_namespaces.count(outer.empty() ? path : outer + "." + path))
                return true;
            if (outer.empty())
                return false;
            size_t dot = outer.rfind('.');
            outer = dot == std::string::npos ? "" : outer.substr(0, dot);
        }
    }

    void CollapseQualifiedName(std::unique_ptr<ExprNode>& expr)
    {
        std::vector<MemberAccess*> chain;
        ExprNode* node = expr.get();
        while (auto* member = dynamic_cast<MemberAccess*>(node))
        {
            chain.push_back(member);
            node = member->object.get();
        }
        std::reverse(chain.begin(), chain.end());

        auto* root = dynamic_cast<Identifier*>(node);
        if (chain.empty() || !root || !root->generic_args.empty() || IsLocal(root->name) || !IsNamespace(root->name))
            return;

        std::string path = root->name;
        size_t used = 0;
        while (used < chain.size() && chain[used]->generic_args.empty() && IsNamespace(path + "." + chain[used]->member))
            path += "." + chain[used++]->member;

        if (used == chain.size())
            Fail("Namespace '" + path + "' cannot be used as a value", chain.back()->line);

        MemberAccess* target = chain[used];
        auto qualified = std::make_unique<Identifier>();
        qualified->line = target->line;
        qualified->name = path + "." + target->member;
        qualified->generic_args = std::move(target->generic_args);

        if (used + 1 < chain.size())
            chain[used + 1]->object = std::move(qualified);
        else
            expr = std::move(qualified);
    }

    void RewriteExpr(std::unique_ptr<ExprNode>& expr)
    {
        if (!expr)
            return;

        if (dynamic_cast<MemberAccess*>(expr.get()))
            CollapseQualifiedName(expr);

        ExprNode* node = expr.get();
        if (auto* e = dynamic_cast<MemberAccess*>(node))
        {
            if (!e->generic_args.empty())
                Fail("Type arguments can only be given to a function, but '" + e->member + "' is a member", e->line);
            RewriteExpr(e->object);
        }
        else if (auto* e = dynamic_cast<BinaryExpr*>(node))  { RewriteExpr(e->left); RewriteExpr(e->right); }
        else if (auto* e = dynamic_cast<UnaryExpr*>(node))   RewriteExpr(e->operand);
        else if (auto* e = dynamic_cast<CallExpr*>(node))
        {
            RewriteExpr(e->callee);
            for (auto& arg : e->args)
                RewriteExpr(arg);
        }
        else if (auto* e = dynamic_cast<ArrayAccess*>(node)) { RewriteExpr(e->array); RewriteExpr(e->index); }
        else if (auto* e = dynamic_cast<StructInit*>(node))
        {
            for (auto& field : e->fields)
                RewriteExpr(field.value);
        }
        else if (auto* e = dynamic_cast<ArrayInit*>(node))
        {
            for (auto& element : e->elements)
                RewriteExpr(element);
        }
        else if (auto* e = dynamic_cast<NewExpr*>(node))     RewriteExpr(e->count);
        else if (auto* e = dynamic_cast<CastExpr*>(node))    RewriteExpr(e->operand);
        else if (auto* e = dynamic_cast<TypeofExpr*>(node))  RewriteExpr(e->operand);
        else if (auto* e = dynamic_cast<SpreadExpr*>(node))  RewriteExpr(e->operand);
        else if (auto* e = dynamic_cast<TernaryExpr*>(node))
        {
            RewriteExpr(e->condition);
            RewriteExpr(e->then_expr);
            RewriteExpr(e->else_expr);
        }
    }

    void RewriteBlock(BlockStmt* block)
    {
        if (!block)
            return;
        m_locals.emplace_back();
        for (auto& stmt : block->statements)
            RewriteStmt(stmt.get());
        m_locals.pop_back();
    }

    void RewriteVarDecl(VarDecl* decl)
    {
        RewriteExpr(decl->init);
        m_locals.back().insert(decl->name);
    }

    void RewriteStmt(StmtNode* stmt)
    {
        if (auto* s = dynamic_cast<VarDecl*>(stmt))          RewriteVarDecl(s);
        else if (auto* s = dynamic_cast<ExprStmt*>(stmt))    RewriteExpr(s->expr);
        else if (auto* s = dynamic_cast<ReturnStmt*>(stmt))  RewriteExpr(s->value);
        else if (auto* s = dynamic_cast<FreeStmt*>(stmt))    RewriteExpr(s->value);
        else if (auto* s = dynamic_cast<BlockStmt*>(stmt))   RewriteBlock(s);
        else if (auto* s = dynamic_cast<IfStmt*>(stmt))
        {
            RewriteExpr(s->condition);
            RewriteBlock(s->then_branch.get());
            RewriteBlock(s->else_branch.get());
        }
        else if (auto* s = dynamic_cast<WhileStmt*>(stmt))   { RewriteExpr(s->condition); RewriteBlock(s->then_branch.get()); }
        else if (auto* s = dynamic_cast<DoWhileStmt*>(stmt)) { RewriteBlock(s->then_branch.get()); RewriteExpr(s->condition); }
        else if (auto* s = dynamic_cast<ForStmt*>(stmt))
        {
            m_locals.emplace_back();
            if (s->init_decl)
                RewriteVarDecl(s->init_decl.get());
            RewriteExpr(s->init_expr);
            RewriteExpr(s->condition);
            RewriteExpr(s->increment);
            RewriteBlock(s->body.get());
            m_locals.pop_back();
        }
        else if (auto* s = dynamic_cast<MatchStmt*>(stmt))
        {
            RewriteExpr(s->value);
            for (auto& c : s->cases)
            {
                RewriteExpr(c->value);
                RewriteBlock(c->body.get());
            }
        }
    }
};

class Parser {
public:
    Parser(Lexer& lex, const std::string &moduleName) : m_lexer(lex), m_moduleName(moduleName)
    {
        Advance();
    }

    AttributeList ParseAttributeList(bool commaSeparated = false)
    {
        AttributeList attributes;

        while (Check('@'))
        {
            AttributeNode attr;
            attr.line = CurrentLine();
            Advance();
            Expect(TokenType_Identifier, "Expected attribute name after '@'");
            attr.name = m_last.value;

            if (Match('('))
            {
                if (!Check(')'))
                {
                    do {
                        if (!Match(TokenType_Identifier) && !Match(TokenType_Number) && !Match(TokenType_String))
                            throw std::runtime_error("Expected identifier, number or string as argument of '@"
                                + attr.name + "' on line " + std::to_string(CurrentLine()) + " in module " + m_moduleName);
                        attr.args.push_back(m_last);
                    } while (Match(','));
                }
                Expect(')', "Expected ')' after attribute arguments");
            }

            attributes.push_back(std::move(attr));

            if (commaSeparated && !Match(','))
                break;
            if (!commaSeparated && Check(',') && PeekIs('@'))
                Advance();
        }

        return attributes;
    }

    std::unique_ptr<AttrDef> ParseAttrDef(void)
    {
        auto def = std::make_unique<AttrDef>();
        def->line = CurrentLine();
        Expect('@', "Expected '@' after 'attrdef'");
        Expect(TokenType_Identifier, "Expected attribute name after '@'");
        def->name = m_last.value;

        if (Match('('))
        {
            if (!Check(')'))
            {
                do {
                    Expect(TokenType_Identifier, "Expected parameter name in attrdef");
                    if (std::find(def->params.begin(), def->params.end(), m_last.value) != def->params.end())
                        throw std::runtime_error("Duplicate attrdef parameter '" + m_last.value + "' on line "
                            + std::to_string(CurrentLine()) + " in module " + m_moduleName);
                    def->params.push_back(m_last.value);
                } while (Match(','));
            }
            Expect(')', "Expected ')' after attrdef parameters");
        }

        Expect('=', "Expected '=' after attrdef name");
        def->attributes = ParseAttributeList(true);
        if (def->attributes.empty())
            throw std::runtime_error("attrdef '@" + def->name + "' must contain at least one attribute on line "
                + std::to_string(def->line) + " in module " + m_moduleName);
        Expect(';', "Expected ';' after attrdef");
        return def;
    }

    std::unique_ptr<ModuleAST> ParseModule(void)
    {
        std::unique_ptr<ModuleAST> module = std::make_unique<ModuleAST>();
        module->scopes.push_back(std::make_unique<NamespaceScope>());
        m_ns = module->scopes.back().get();

        while (m_current.type != TokenType_EOF)
            ParseTopLevel(*module);

        return module;
    }

    void ParseNamespace(ModuleAST& module)
    {
        uint32_t line = CurrentLine();
        Advance();
        Expect(TokenType_Identifier, "Expected namespace name after 'namespace'");
        std::string path = m_last.value;
        while (Match('.'))
        {
            Expect(TokenType_Identifier, "Expected identifier after '.' in namespace name");
            path += '.' + m_last.value;
        }

        auto scope = std::make_unique<NamespaceScope>();
        scope->parent = m_ns;
        scope->path = m_ns->path.empty() ? path : m_ns->path + "." + path;
        NamespaceScope* inner = scope.get();
        module.scopes.push_back(std::move(scope));

        auto fail = [&](const std::string& msg) {
            throw std::runtime_error(msg + " on line " + std::to_string(line) + " in module " + m_moduleName);
        };

        if (Match(';'))
        {
            bool hasDecls = !module.structs.empty() || !module.enums.empty() || !module.aliases.empty() ||
                !module.globals.empty() || !module.procs.empty() || !module.attrdefs.empty();
            if (m_ns->parent || m_hasBlockNamespace || m_hasFileNamespace)
                fail("A file-scoped namespace must be the only namespace declaration in the file");
            if (hasDecls)
                fail("A file-scoped namespace must come before any declarations");
            m_hasFileNamespace = true;
            m_ns = inner;
            return;
        }

        if (m_hasFileNamespace)
            fail("Namespace blocks cannot be used in a file with a file-scoped namespace");
        m_hasBlockNamespace = true;

        Expect('{', "Expected '{' or ';' after namespace name");
        NamespaceScope* outer = m_ns;
        m_ns = inner;
        while (!Check('}'))
        {
            if (m_current.type == TokenType_EOF)
                fail("Unterminated namespace '" + inner->path + "'");
            ParseTopLevel(module);
        }
        Expect('}', "Expected '}' after namespace body");
        m_ns = outer;
    }

    void ParseTopLevel(ModuleAST& moduleRef)
    {
        ModuleAST* module = &moduleRef;
        if (Check(TokenType_Identifier) && m_current.value == "namespace" && PeekIs(TokenType_Identifier))
        {
            ParseNamespace(moduleRef);
            return;
        }

        if (Check('@'))
            throw std::runtime_error("Attributes go after the declaration, e.g. 'foo() @inline { }' or "
                "'struct Foo @align(16) { }', on line " + std::to_string(CurrentLine()) + " in module " + m_moduleName);

        if (Check(TokenType_Identifier))
        {
            uint32_t declLine = CurrentLine();
            const bool is_pub = Match("pub");
            const bool is_extern = Match("extern");
            bool is_c_abi = false;
            if (is_extern && Match(TokenType_String))
            {
                if (m_last.value != "C")
                    throw std::runtime_error("Unknown extern ABI \"" + m_last.value + "\" (only \"C\" is supported) on line "
                        + std::to_string(declLine) + " in module " + m_moduleName);
                is_c_abi = true;
            }
            const bool is_packed = Match("packed");

            if (Check(TokenType_Identifier) && (PeekIs('(') || PeekIs('<')))
            {
                std::unique_ptr<ProcDecl> proc = ParseProcDecl(is_extern);
                proc->is_c_abi = is_c_abi;
                proc->is_pub = is_pub;
                proc->line = declLine;
                proc->ns = m_ns;
                module->procs.push_back(std::move(proc));
            }
            else if (Match("struct"))
            {
                std::unique_ptr<StructDecl> decl = ParseStructDecl();
                decl->is_pub = is_pub;
                decl->is_packed = is_packed;
                decl->line = declLine;
                decl->ns = m_ns;
                module->structs.push_back(std::move(decl));
            }
            else if (Match("enum"))
            {
                std::unique_ptr<EnumDecl> decl = ParseEnumDecl();
                decl->is_pub = is_pub;
                decl->line = declLine;
                decl->ns = m_ns;
                module->enums.push_back(std::move(decl));
            }
            else if (Match("attrdef"))
            {
                auto def = ParseAttrDef();
                def->is_pub = is_pub;
                module->attrdefs.push_back(std::move(def));
            }
            else if (Match("using"))
            {
                auto using_decl = std::make_unique<UsingDecl>();
                using_decl->line = declLine;
                Expect(TokenType_Identifier, "Expected module name after 'using'");
                using_decl->name = m_last.value;
                using_decl->is_pub = is_pub;
                while (Match('.'))
                {
                    Expect(TokenType_Identifier, "Expected identifier after '.'");
                    using_decl->name += '.' + m_last.value;
                }
                Expect(';', "Expected ';' after using declaration");
                m_ns->usings.push_back(using_decl->name);
                module->usings.push_back(std::move(using_decl));
            }
            else if (Match("require"))
            {
                auto require_decl = std::make_unique<RequireDecl>();
                require_decl->line = declLine;
                Expect(TokenType_String, "Expected library name string after 'require'");
                require_decl->library = m_last.value;
                require_decl->attributes = ParseAttributeList();
                Expect(';', "Expected ';' after require declaration");
                module->requires_.push_back(std::move(require_decl));
            }
            else if (Check(TokenType_Identifier) && m_current.value == "typename" && !PeekIs(':') && Match("typename"))
            {
                std::unique_ptr<AliasDecl> alias = std::make_unique<AliasDecl>();
                alias->line = declLine;
                alias->is_pub = is_pub;
                alias->ns = m_ns;
                Expect(TokenType_Identifier, "Expected alias name after '='");
                alias->name = m_last.value;
                Expect('=', "Expected '=' after type in alias declaration");
                alias->target = ParseType();
                Expect(';', "Expected ';' after type alias declaration");
                module->aliases.push_back(std::move(alias));
            }
            else
            {
                std::string name = m_current.value;
                uint32_t varLine = CurrentLine();
                Advance();
                
                AttributeList varAttributes = ParseAttributeList();

                if (Check(':'))
                {
                    auto var = std::make_unique<GlobalVarDecl>();
                    var->name = name;
                    var->line = varLine;
                    
                    Expect(':', "Expected ':'");
                    
                    var->is_pub = is_pub;
                    var->ns = m_ns;
                    var->attributes = std::move(varAttributes);

                    if (Check(TokenType_Identifier) || Check('('))
                        var->type = ParseType();
                    
                    if (Match('='))
                    {
                        var->init = ParseExpr();
                    }
                    
                    Expect(';', "Expected ';'");
                    module->globals.push_back(std::move(var));
                }
                else
                {
                    throw std::runtime_error("Unexpected token at top level: " + name + " on line " + std::to_string(CurrentLine()) + " in module " + m_moduleName);
                }
            }
        }
        else
        {
            std::string msg = "Unexpected token at module level: ";
            if (m_current.type == TokenType_Identifier)
                msg += m_current.value;
            else if (m_current.type < 256)
                msg += std::string(1, (char)m_current.type);
            else
                msg += "token type " + std::to_string(m_current.type);
            throw std::runtime_error(msg + " on line " + std::to_string(CurrentLine()) + " in module " + m_moduleName);
        }
    }

    std::unique_ptr<TypeNode> ParseType(bool allowArrayDims = true)
    {
        std::unique_ptr<TypeNode> type = std::make_unique<TypeNode>();
        type->line = CurrentLine();
        
        if (Match("const"))
            type->is_const = true;
        
        if (Match('('))
        {
            type->is_function_type = true;

            if (!Check(')'))
            {
                do {
                    // Parameter names are optional: (x: i32) and (i32) are equivalent
                    if (Check(TokenType_Identifier) && PeekIs(':'))
                    {
                        Advance();
                        Advance();
                    }
                    type->param_types.push_back(ParseType());
                } while (Match(','));
            }

            Expect(')', "Expected ')'");
            
            while (Match('['))
            {
                if (Match(']'))
                    type->array_dimensions.push_back(-1);
                else
                {
                    Expect(TokenType_Number, "Expected array size");
                    type->array_dimensions.push_back(std::stoi(m_last.value));
                    Expect(']', "Expected ']'");
                }
            }

            if (Match(TokenType_Arrow))
                type->return_type = ParseType();
            
            return type;
        }
        
        Expect(TokenType_Identifier, "Expected type name");
        type->name = m_last.value;

        while (Check('.') && PeekIs(TokenType_Identifier))
        {
            Advance();
            Expect(TokenType_Identifier, "Expected type name after '.'");
            type->name += '.' + m_last.value;
        }

        if (Match('<'))
        {
            do {
                type->generic_args.push_back(ParseType());
            } while (Match(','));
            ExpectCloseAngle("Expected '>' after type arguments");
        }
        
        while (Match('*'))
        {
            type->pointer_depth++;
            if (Match("const"))
                type->pointer_const.push_back(true);
            else
                type->pointer_const.push_back(false);
        }
        
        while (allowArrayDims && Match('['))
        {
            if (Match(']'))
                type->array_dimensions.push_back(-1);
            else
            {
                Expect(TokenType_Number, "Expected array size");
                type->array_dimensions.push_back(std::stoi(m_last.value));
                Expect(']', "Expected ']'");
            }
        }
        
        return type;
    }

    std::unique_ptr<ExprNode> ParseExpr(void)
    {
        return ParseAssignment();
    }

    std::unique_ptr<ExprNode> ParseAssignment(void)
    {
        auto expr = ParseTernary();
        
        uint32_t opLine = CurrentLine();

        if (Match('='))
        {
            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = '=';
            binary->right = ParseAssignment();
            return binary;
        }

        if (Match(TokenType_PlusEqual) || Match(TokenType_MinusEqual) || 
            Match(TokenType_StarEqual) || Match(TokenType_SlashEqual) || 
            Match(TokenType_PercentEqual))
        {
            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = m_last.type;
            binary->right = ParseAssignment();
            return binary;
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseTernary(void)
    {
        auto expr = ParseLogicalOr();

        if (Match('?'))
        {
            uint32_t opLine = CurrentLine();
            auto ternary = std::make_unique<TernaryExpr>();
            ternary->line = opLine;
            ternary->condition = std::move(expr);
            ternary->then_expr = ParseExpr();
            Expect(':', "Expected ':' in ternary expression");
            ternary->else_expr = ParseTernary();
            return ternary;
        }

        return expr;
    }

    std::unique_ptr<ExprNode> ParseLogicalOr(void)
    {
        auto expr = ParseLogicalAnd();

        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match(TokenType_OrOr)) break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = TokenType_OrOr;
            binary->right = ParseLogicalAnd();
            expr = std::move(binary);
        }

        return expr;
    }

    std::unique_ptr<ExprNode> ParseLogicalAnd(void)
    {
        auto expr = ParseBitwiseOr();

        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match(TokenType_AndAnd)) break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = TokenType_AndAnd;
            binary->right = ParseBitwiseOr();
            expr = std::move(binary);
        }

        return expr;
    }

    std::unique_ptr<ExprNode> ParseBitwiseOr(void)
    {
        auto expr = ParseBitwiseXor();
        
        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match('|')) break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = '|';
            binary->right = ParseBitwiseXor();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseBitwiseXor(void)
    {
        auto expr = ParseBitwiseAnd();
        
        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match('^')) break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = '^';
            binary->right = ParseBitwiseAnd();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseBitwiseAnd(void)
    {
        auto expr = ParseComparison();
        
        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match('&')) break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = '&';
            binary->right = ParseComparison();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseComparison(void)
    {
        auto expr = ParseShift();
        
        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match(TokenType_EqualEqual) && !Match(TokenType_NotEqual) &&
                !Match('<') && !Match(TokenType_LessEqual) &&
                !Match('>') && !Match(TokenType_GreaterEqual))
                break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            
            if (m_last.type == TokenType_EqualEqual)
                binary->op = TokenType_EqualEqual;
            else if (m_last.type == TokenType_NotEqual)
                binary->op = TokenType_NotEqual;
            else if (m_last.type == TokenType_LessEqual)
                binary->op = TokenType_LessEqual;
            else if (m_last.type == TokenType_GreaterEqual)
                binary->op = TokenType_GreaterEqual;
            else
                binary->op = m_last.value[0];
            
            binary->right = ParseShift();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseShift(void)
    {
        auto expr = ParseAdditive();
        
        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match(TokenType_LeftShift) && !Match(TokenType_RightShift)) break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = (m_last.type == TokenType_LeftShift) ? TokenType_LeftShift : TokenType_RightShift;
            binary->right = ParseAdditive();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseAdditive(void)
    {
        auto expr = ParseMultiplicative();
        
        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match('+') && !Match('-')) break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = m_last.value[0];
            binary->right = ParseMultiplicative();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseMultiplicative(void)
    {
        auto expr = ParseUnary();
        
        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (!Match('*') && !Match('/') && !Match('%')) break;

            auto binary = std::make_unique<BinaryExpr>();
            binary->line = opLine;
            binary->left = std::move(expr);
            binary->op = m_last.value[0];
            binary->right = ParseUnary();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseUnary(void)
    {
        uint32_t opLine = CurrentLine();
        if (Match('-') || Match('!') || Match('&') || Match('*') || Match('~'))
        {
            auto unary = std::make_unique<UnaryExpr>();
            unary->line = opLine;
            unary->op = m_last.value[0];
            unary->is_prefix = true;
            unary->operand = ParseUnary();
            return unary;
        }
        
        return ParsePostfix();
    }

    std::unique_ptr<ExprNode> ParsePostfix(void)
    {
        return ParsePostfixOps(ParsePrimary());
    }

    std::unique_ptr<ExprNode> ParsePostfixOps(std::unique_ptr<ExprNode> expr)
    {
        while (true)
        {
            uint32_t opLine = CurrentLine();
            if (Match('['))
            {
                auto access = std::make_unique<ArrayAccess>();
                access->line = opLine;
                access->array = std::move(expr);
                access->index = ParseExpr();
                Expect(']', "Expected ']'");
                expr = std::move(access);
            }
            else if (Match('.'))
            {
                auto member = std::make_unique<MemberAccess>();
                member->line = opLine;
                member->object = std::move(expr);
                Expect(TokenType_Identifier, "Expected member name");
                member->member = m_last.value;
                TryParseGenericArgs(member->generic_args);

                std::string path;
                if (!m_parsingStatement && Check('{') && DottedPath(member->object.get(), path))
                {
                    auto init = std::make_unique<StructInit>();
                    init->line = opLine;
                    init->type_name = path + "." + member->member;
                    init->type_args = std::move(member->generic_args);
                    Advance();
                    ParseStructInitFields(*init);
                    expr = std::move(init);
                    continue;
                }

                expr = std::move(member);
            }
            else if (Match('('))
            {
                auto call = std::make_unique<CallExpr>();
                call->line = opLine;
                call->callee = std::move(expr);
                
                ParseCallArgs(call->args);
                expr = std::move(call);
            }
            else break;
        }
        
        return expr;
    }

    static bool DottedPath(const ExprNode* expr, std::string& out)
    {
        if (auto* id = dynamic_cast<const Identifier*>(expr))
        {
            if (!id->generic_args.empty())
                return false;
            out = id->name;
            return true;
        }
        if (auto* member = dynamic_cast<const MemberAccess*>(expr))
        {
            if (!member->generic_args.empty() || !DottedPath(member->object.get(), out))
                return false;
            out += "." + member->member;
            return true;
        }
        return false;
    }

    void ParseStructInitFields(StructInit& init)
    {
        if (!Check('}'))
        {
            do {
                if (Check('}')) break;
                FieldInit fi;
                if (Check(TokenType_Identifier) && PeekIs(':'))
                {
                    fi.name = m_current.value;
                    Advance();
                    Advance();
                }
                fi.value = ParseExpr();
                init.fields.push_back(std::move(fi));
            } while (Match(','));
        }

        Expect('}', "Expected '}'");
    }

    NumberType ClassifyNumberLiteral(const std::string& value, std::string& outNumericPart)
    {
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
            while (pos > 0 && !std::isdigit((unsigned char)value[pos - 1]))
            {
                char c = std::tolower((unsigned char)value[pos - 1]);
                if (c == 'u') isUnsigned = true;
                else if (c == 'l') isLong = true;
                pos--;
            }

            outNumericPart = value.substr(0, pos);
            int64_t intValue = std::stoll(outNumericPart, nullptr, 0);

            bool needsLong = isLong || intValue > INT32_MAX || intValue < INT32_MIN;

            if (needsLong)
                return isUnsigned ? NumberType::U64 : NumberType::I64;
            else
                return isUnsigned ? NumberType::U32 : NumberType::I32;
        }
        else
        {
            bool isFloat = false;

            size_t pos = value.size();
            if (pos > 0 && std::tolower((unsigned char)value[pos - 1]) == 'f')
            {
                isFloat = true;
                pos--;
            }

            outNumericPart = value.substr(0, pos);
            return isFloat ? NumberType::F32 : NumberType::F64;
        }
    }

    std::unique_ptr<ExprNode> ParsePrimary(void)
    {
        uint32_t primaryLine = CurrentLine();

        if (Match(TokenType_Number))
        {
            auto num = std::make_unique<NumberLiteral>();
            num->line = primaryLine;
            num->value = m_last.value;
            num->type = ClassifyNumberLiteral(m_last.value, num->numeric_part);
            return num;
        }
        
        if (Match(TokenType_String))
        {
            auto str = std::make_unique<::StringLiteral>();
            str->line = primaryLine;
            str->value = m_last.value;
            return str;
        }

        if (Match(TokenType_Char))
        {
            auto chr = std::make_unique<CharLiteral>();
            chr->line = primaryLine;
            chr->value = m_last.value;
            return chr;
        }
        
        if (Match('('))
        {
            auto expr = ParseExpr();
            Expect(')', "Expected ')'");
            return expr;
        }
        
        if (Match('['))
        {
            auto arr = std::make_unique<ArrayInit>();
            arr->line = primaryLine;
            
            if (!Check(']'))
            {
                do {
                    arr->elements.push_back(ParseExpr());
                } while (Match(','));
            }
            
            Expect(']', "Expected ']'");
            return arr;
        }
        
        if (Match(TokenType_Identifier))
        {
            std::string name = m_last.value;

            if (name == "true" || name == "false")
            {
                auto boolLit = std::make_unique<BoolLiteral>();
                boolLit->line = primaryLine;
                boolLit->value = (name == "true");
                return boolLit;
            }

            if (name == "sizeof" && Match('('))
            {
                auto sizeofExpr = std::make_unique<SizeofExpr>();
                sizeofExpr->line = primaryLine;
                sizeofExpr->type = ParseType();
                Expect(')', "Expected ')' after sizeof type");
                return sizeofExpr;
            }
            
            if (name == "cast" && Match('('))
            {
                auto cast = std::make_unique<CastExpr>();
                cast->line = primaryLine;
                cast->target_type = ParseType();
                Expect(')', "Expected ')' after cast type");
                cast->operand = ParseUnary();
                return cast;
            }

            if (name == "new" && Check(TokenType_Identifier))
            {
                auto newExpr = std::make_unique<NewExpr>();
                newExpr->line = primaryLine;
                newExpr->type = ParseType(false);
                if (Match('['))
                {
                    newExpr->count = ParseExpr();
                    Expect(']', "Expected ']' after 'new' array size");
                }
                return newExpr;
            }

            if (name == "typeof" && Match('('))
            {
                auto typeofExpr = ParseTypeofOperand();
                typeofExpr->line = primaryLine;
                Expect(')', "Expected ')' after typeof operand");
                return typeofExpr;
            }

            std::vector<std::unique_ptr<TypeNode>> genericArgs;
            TryParseGenericArgs(genericArgs);

            if (!m_parsingStatement && Match('{'))
            {
                auto init = std::make_unique<StructInit>();
                init->line = primaryLine;
                init->type_name = name;
                init->type_args = std::move(genericArgs);
                ParseStructInitFields(*init);
                return init;
            }
            
            auto ident = std::make_unique<Identifier>();
            ident->line = primaryLine;
            ident->name = name;
            ident->generic_args = std::move(genericArgs);
            return ident;
        }
        
        throw std::runtime_error("Expected expression on line " + std::to_string(primaryLine) + " in module " + m_moduleName);
    }

    std::unique_ptr<VarDecl> ParseVarDecl(void)
    {
        auto var = std::make_unique<VarDecl>();
        
        Expect(TokenType_Identifier, "Expected variable name");
        var->name = m_last.value;
        var->line = m_lexer.GetCurrentLine();
        
        Expect(':', "Expected ':' after variable name");
        
        if (Check(TokenType_Identifier) || Check('('))
            var->type = ParseType();
        
        if (Match('='))
        {
            var->init = ParseExpr();
        }
        
        Expect(';', "Expected ';' after variable declaration");
        
        return var;
    }

    std::unique_ptr<StmtNode> ParseStmt(void)
    {
        uint32_t stmtLine = CurrentLine();

        if (Match("return"))
        {
            auto ret = std::make_unique<ReturnStmt>();
            ret->line = stmtLine;
            if (!Match(';'))
            {
                ret->value = ParseExpr();
                Expect(';', "Expected ';'");
            }
            return ret;
        }

        if (Match("break"))
        {
            auto breakStmt = std::make_unique<BreakStmt>();
            breakStmt->line = stmtLine;
            Expect(';', "Expected ';' after 'break'");
            return breakStmt;
        }

        if (Match("continue"))
        {
            auto continueStmt = std::make_unique<ContinueStmt>();
            continueStmt->line = stmtLine;
            Expect(';', "Expected ';' after 'continue'");
            return continueStmt;
        }

        if (Match("if"))
        {
            auto statement = std::make_unique<IfStmt>();
            statement->line = stmtLine;
            m_parsingStatement = true;
            statement->condition = ParseExpr();
            m_parsingStatement = false;
            statement->then_branch = ParseBlock();
            if (Match("else"))
                statement->else_branch = ParseBlock();
            return statement;
        }
        
        if (Match("while"))
        {
            auto statement = std::make_unique<WhileStmt>();
            statement->line = stmtLine;
            m_parsingStatement = true;
            statement->condition = ParseExpr();
            m_parsingStatement = false;
            statement->then_branch = ParseBlock();
            return statement;
        }
        
        if (Match("do"))
        {
            auto statement = std::make_unique<DoWhileStmt>();
            statement->line = stmtLine;
            statement->then_branch = ParseBlock();
            if (!Match("while"))
                throw std::runtime_error(std::string("Expected 'while' after 'do' block on line ") + std::to_string(m_lexer.GetCurrentLine()) + " in module " + m_moduleName);
            m_parsingStatement = true;
            statement->condition = ParseExpr();
            m_parsingStatement = false;
            Expect(';', "Expected ';' after do-while condition");
            return statement;
        }
        
        if (Match("for"))
        {
            auto stmt = ParseForStmt();
            stmt->line = stmtLine;
            return stmt;
        }

        if (Check(TokenType_Identifier) && m_current.value == "free" && !PeekIs(':') && !PeekIs('=') && Match("free"))
        {
            auto freeStmt = std::make_unique<FreeStmt>();
            freeStmt->line = stmtLine;
            freeStmt->value = ParseExpr();
            Expect(';', "Expected ';' after 'free'");
            return freeStmt;
        }

        if (Match("match"))
        {
            auto stmt = ParseMatchStmt();
            stmt->line = stmtLine;
            return stmt;
        }
        
        if (Check('{'))
        {
            return ParseBlock();
        }
        
        if (Check(TokenType_Identifier))
        {
            std::string ident_name = m_current.value;
            uint32_t identLine = CurrentLine();
            Advance();
            
            if (Check(':'))
            {
                auto var = std::make_unique<VarDecl>();
                var->name = ident_name;
                var->line = identLine;
                
                Expect(':', "Expected ':'");
                
                if (Check(TokenType_Identifier) || Check('('))
                    var->type = ParseType();
                
                if (Match('='))
                {
                    var->init = ParseExpr();
                }
                
                Expect(';', "Expected ';'");
                
                return var;
            }
            else
            {
                auto ident = std::make_unique<Identifier>();
                ident->name = ident_name;
                ident->line = identLine;
                TryParseGenericArgs(ident->generic_args);
                
                std::unique_ptr<ExprNode> expr = ParsePostfixOps(std::move(ident));
                
                uint32_t assignLine = CurrentLine();
                if (Match('=') || Match(TokenType_PlusEqual) || Match(TokenType_MinusEqual) ||
                    Match(TokenType_StarEqual) || Match(TokenType_SlashEqual) || Match(TokenType_PercentEqual))
                {
                    auto binary = std::make_unique<BinaryExpr>();
                    binary->line = assignLine;
                    binary->left = std::move(expr);
                    binary->op = m_last.type;
                    binary->right = ParseAssignment();
                    expr = std::move(binary);
                }
                
                auto stmt = std::make_unique<ExprStmt>();
                stmt->line = stmtLine;
                stmt->expr = std::move(expr);
                Expect(';', "Expected ';'");
                return stmt;
            }
        }
        
        auto stmt = std::make_unique<ExprStmt>();
        stmt->line = stmtLine;
        stmt->expr = ParseExpr();
        Expect(';', "Expected ';' after expression");
        return stmt;
    }

    std::unique_ptr<BlockStmt> ParseBlock(void)
    {
        uint32_t blockLine = CurrentLine();
        Expect('{', "Expected '{'");
        
        auto block = std::make_unique<BlockStmt>();
        block->line = blockLine;
        
        while (!Check('}') && !Check(TokenType_EOF))
        {
            block->statements.push_back(ParseStmt());
        }
        
        Expect('}', "Expected '}'");
        return block;
    }

    std::unique_ptr<EnumDecl> ParseEnumDecl(void)
    {
        auto enum_decl = std::make_unique<EnumDecl>();
        
        Expect(TokenType_Identifier, "Expected enum name");
        enum_decl->name = m_last.value;
        enum_decl->line = m_lexer.GetCurrentLine();

        if (Match(':'))
            enum_decl->base_type = ParseType();

        enum_decl->attributes = ParseAttributeList();
        Expect('{', "Expected '{'");
        
        while (!Check('}'))
        {
            Expect(TokenType_Identifier, "Expected enum value name");
            EnumValue val;
            val.name = m_last.value;
            
            if (Match('='))
                val.expr = ParseExpr();
            
            enum_decl->values.push_back(std::move(val));
            
            if (!Check('}'))
                Match(',');
        }
        
        Expect('}', "Expected '}'");
        return enum_decl;
    }

    std::unique_ptr<ForStmt> ParseForStmt(void)
    {
        auto statement = std::make_unique<ForStmt>();

        if (!Check(';'))
        {
            if (Check(TokenType_Identifier) && PeekIs(':'))
            {
                statement->init_decl = ParseVarDecl();
            }
            else
            {
                m_parsingStatement = true;
                statement->init_expr = ParseExpr();
                m_parsingStatement = false;
                Expect(';', "Expected ';' after for-init expression");
            }
        }
        else Advance();

        if (!Check(';'))
        {
            m_parsingStatement = true;
            statement->condition = ParseExpr();
            m_parsingStatement = false;
        }
        Expect(';', "Expected ';' after for-condition");

        if (!Check('{'))
        {
            m_parsingStatement = true;
            statement->increment = ParseExpr();
            m_parsingStatement = false;
        }

        statement->body = ParseBlock();
        return statement;
    }

    std::unique_ptr<MatchStmt> ParseMatchStmt(void)
    {
        auto match = std::make_unique<MatchStmt>();
        match->line = CurrentLine();
        
        m_parsingStatement = true;
        match->value = ParseExpr();
        m_parsingStatement = false;
        
        Expect('{', "Expected '{'");

        while (!Check('}'))
        {
            auto case_stmt = std::make_unique<MatchCase>();
            
            if (Match("else"))
                case_stmt->is_else = true;
            else
            {
                m_parsingStatement = true;
                case_stmt->value = ParseExpr();
                m_parsingStatement = false;
            }
            
            case_stmt->body = ParseBlock();
            match->cases.push_back(std::move(case_stmt));
            
            if (!Check('}'))
                Match(',');
        }
        
        Expect('}', "Expected '}'");
        return match;
    }

    std::unique_ptr<StructDecl> ParseStructDecl(void)
    {
        std::unique_ptr<StructDecl> struct_decl = std::make_unique<StructDecl>();

        Expect(TokenType_Identifier, "Expected struct name");
        struct_decl->name = m_last.value;
        struct_decl->line = m_lexer.GetCurrentLine();
        struct_decl->generic_params = ParseGenericParams(struct_decl->generic_constraints);
        struct_decl->attributes = ParseAttributeList();
            
        Expect('{', "Expected '{'");

        while (!Check('}'))
        {
            Expect(TokenType_Identifier, "Expected field name");

            std::unique_ptr<StructField> field = std::make_unique<StructField>();
            field->name = m_last.value;

            Expect(':', "Expected ':'");
            field->type = ParseType();
            field->attributes = ParseAttributeList();

            if (Match('='))
                field->default_value = ParseExpr();

            struct_decl->fields.push_back(std::move(field));

            if (Match(','))
            {
                if (Check('}'))
                    break;
                continue;
            }

            break;
        }

        Expect('}', "Expected '}'");

        return struct_decl;
    }

    std::unique_ptr<ProcDecl> ParseProcDecl(bool is_extern)
    {
        Expect(TokenType_Identifier, "Expected proc name");
        std::unique_ptr<ProcDecl> proc = std::make_unique<ProcDecl>();
        proc->name = m_last.value;
        proc->line = m_lexer.GetCurrentLine();
        proc->is_extern = is_extern;
        proc->generic_params = ParseGenericParams(proc->generic_constraints);

        if (is_extern && !proc->generic_params.empty())
            throw std::runtime_error("Extern proc '" + proc->name + "' cannot be generic on line "
                + std::to_string(m_lexer.GetCurrentLine()) + " in module " + m_moduleName);

        // if (Match('('))
        Expect('(', "Expected '(' after proc name");
        bool hasDefault = false;
        while (!Match(')'))
        {
            if ((Match('.') && Match('.') && Match('.')))
            {
                if (!is_extern)
                    throw std::runtime_error("C-style '...' is only allowed on extern procs; use a typed"
                        " variadic parameter like 'args: ..any' instead on line "
                        + std::to_string(m_lexer.GetCurrentLine()) + " in module " + m_moduleName);
                proc->is_vararg = true;
                Expect(')', "Expected ')' after '...'");
                break;
            }

            if (Match(TokenType_Identifier))
            {
                Parameter param;
                param.name = m_last.value;
                Expect(':', "Expected ':'");
                param.is_variadic = Check('.') && PeekIs('.');
                if (param.is_variadic)
                {
                    Advance();
                    Advance();
                }
                param.type = ParseType();

                if (param.is_variadic)
                {
                    if (!Check(')'))
                        throw std::runtime_error("Variadic parameter '" + param.name + "' must be the last"
                            " parameter on line " + std::to_string(m_lexer.GetCurrentLine()) + " in module " + m_moduleName);
                }
                else if (Match('='))
                {
                    param.default_value = ParseExpr();
                    hasDefault = true;
                }
                else if (hasDefault)
                {
                    throw std::runtime_error(
                        "Required parameter '" + param.name + "' cannot follow a parameter"
                        " with a default value on line " + std::to_string(m_lexer.GetCurrentLine())
                        + " in module " + m_moduleName);
                }

                proc->params.push_back(std::move(param));

                if (!Check(')'))
                    Expect(',', "Expected ',' or ')' after parameter");
            }
        }

        if (Match(TokenType_Arrow))
            proc->return_type = ParseType();

        proc->attributes = ParseAttributeList();

        if (is_extern)
            Expect(';', "Expected ';' after extern proc declaration");
        else proc->body = ParseBlock();

        return proc;
    }

private:

    uint32_t CurrentLine() const { return m_lexer.GetCurrentLine(); }

    std::vector<std::string> ParseGenericParams(std::vector<GenericConstraint>& outConstraints)
    {
        std::vector<std::string> params;
        if (!Match('<'))
            return params;

        do {
            Expect(TokenType_Identifier, "Expected type parameter name");
            if (std::find(params.begin(), params.end(), m_last.value) != params.end())
                throw std::runtime_error("Duplicate type parameter '" + m_last.value + "' on line "
                    + std::to_string(m_lexer.GetCurrentLine()) + " in module " + m_moduleName);
            params.push_back(m_last.value);

            GenericConstraint constraint;
            if (Match(':'))
            {
                do {
                    constraint.push_back(ParseType());
                } while (Match('|'));
            }
            outConstraints.push_back(std::move(constraint));
        } while (Match(','));

        ExpectCloseAngle("Expected '>' after type parameters");
        return params;
    }

    void ExpectCloseAngle(const std::string& msg)
    {
        if (Match('>'))
            return;

        if (Check(TokenType_RightShift) || Check(TokenType_GreaterEqual))
        {
            const int line = m_current.line;
            m_last = {(TokenType)'>', ">", line};
            m_current = (m_current.type == TokenType_RightShift)
                ? Token{(TokenType)'>', ">", line}
                : Token{(TokenType)'=', "=", line};
            return;
        }

        Expect('>', msg);
    }

    bool TryParseGenericArgs(std::vector<std::unique_ptr<TypeNode>>& out)
    {
        if (!Check('<') || !PeekIs(TokenType_Identifier))
            return false;

        State state = SaveState();

        try
        {
            Advance();
            std::vector<std::unique_ptr<TypeNode>> args;
            do {
                args.push_back(ParseType());
            } while (Match(','));
            ExpectCloseAngle("Expected '>' after type arguments");

            if (Check('(') || Check(')') || Check(',') || Check(';') || (Check('{') && !m_parsingStatement))
            {
                out = std::move(args);
                return true;
            }
        }
        catch (const std::runtime_error&) {}

        RestoreState(state);
        return false;
    }

    std::unique_ptr<TypeofExpr> ParseTypeofOperand(void)
    {
        auto typeofExpr = std::make_unique<TypeofExpr>();
        State start = SaveState();

        try
        {
            auto type = ParseType();
            if (Check(')'))
                typeofExpr->type = std::move(type);
        }
        catch (const std::runtime_error&) {}

        const TypeNode* type = typeofExpr->type.get();
        if (type && (type->pointer_depth > 0 || type->is_const || type->is_function_type || !type->generic_args.empty()))
            return typeofExpr;

        if (!type)
        {
            RestoreState(start);
            typeofExpr->operand = ParseExpr();
            return typeofExpr;
        }

        State afterType = SaveState();
        RestoreState(start);
        try
        {
            auto operand = ParseExpr();
            if (Check(')'))
            {
                typeofExpr->operand = std::move(operand);
                return typeofExpr;
            }
        }
        catch (const std::runtime_error&) {}

        RestoreState(afterType);
        return typeofExpr;
    }

    void ParseCallArgs(std::vector<std::unique_ptr<ExprNode>>& args)
    {
        if (!Check(')'))
        {
            do {
                if (Check('.') && PeekIs('.'))
                {
                    auto spread = std::make_unique<SpreadExpr>();
                    spread->line = CurrentLine();
                    Advance();
                    Advance();
                    spread->operand = ParseExpr();
                    args.push_back(std::move(spread));
                }
                else
                    args.push_back(ParseExpr());
            } while (Match(','));
        }

        Expect(')', "Expected ')'");
    }

    struct State
    {
        Lexer::State lexer;
        Token current, last, next;
        bool hasNext;
    };

    State SaveState(void) const { return {m_lexer.SaveState(), m_current, m_last, m_next, m_hasNext}; }

    void RestoreState(const State& state)
    {
        m_lexer.RestoreState(state.lexer);
        m_current = state.current;
        m_last = state.last;
        m_next = state.next;
        m_hasNext = state.hasNext;
    }

    void Advance(void)
    {
        if (m_hasNext)
        {
            m_current = m_next;
            m_hasNext = false;
        }
        else m_current = m_lexer.Next();
    }

    const Token &PeekNext(void)
    {
        if (!m_hasNext)
        {
            m_next = m_lexer.Next();
            m_hasNext = true;
        }
        return m_next;
    }

    bool PeekIs(int type)
    {
        return PeekNext().type == type;
    }

    bool Check(int type)
    {
        return m_current.type == type && m_current.type != TokenType_EOF;
    }

    bool Match(int type)
    {
        if (Check(type))
        {
            m_last = m_current;
            Advance();
            return true;
        }
        return false;
    }

    bool Match(const char *name)
    {
        if (Check(TokenType_Identifier) && m_current.value == name)
        {
            m_last = m_current;
            Advance();
            return true;
        }
        return false;
    }

    void Expect(int type, const std::string& msg)
    {
        if (!Match(type))
            throw std::runtime_error(msg + " on line " + std::to_string(m_lexer.GetCurrentLine()) + " in module " + m_moduleName);
    }

    const std::string &m_moduleName;
    Lexer &m_lexer;
    Token m_current;
    Token m_last;
    Token m_next;
    bool m_hasNext = false;
    bool m_parsingStatement = false;
    NamespaceScope* m_ns = nullptr;
    bool m_hasFileNamespace = false;
    bool m_hasBlockNamespace = false;
};