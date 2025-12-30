#pragma once

#include <vector>
#include <memory>
#include <stdexcept>

#include "Lexer.h"

struct ASTNode {
    virtual ~ASTNode() = default;
};

struct TypeNode : ASTNode {
    std::string name;
    std::vector<int> array_dimensions;
    
    std::unique_ptr<TypeNode> return_type;
    std::vector<std::unique_ptr<TypeNode>> param_types;
    int pointer_depth = 0;
    bool is_const = false;
    bool is_function_type = false;
};

struct ExprNode : ASTNode {
    virtual ~ExprNode() = default;
};

struct BinaryExpr : ExprNode {
    std::unique_ptr<ExprNode> left, right;
    char op;
};

struct UnaryExpr : ExprNode {
    std::unique_ptr<ExprNode> operand;
    char op;
    bool is_prefix;
};

struct NumberLiteral : ExprNode {
    std::string value;
};

struct StringLiteral : ExprNode {
    std::string value;
};

struct CharLiteral : ExprNode {
    std::string value;
};

struct Identifier : ExprNode {
    std::string name;
};

struct CallExpr : ExprNode {
    std::string function;
    std::vector<std::unique_ptr<ExprNode>> args;
};

struct ArrayAccess : ExprNode {
    std::unique_ptr<ExprNode> array;
    std::unique_ptr<ExprNode> index;
};

struct MemberAccess : ExprNode {
    std::unique_ptr<ExprNode> object;
    std::string member;
};

struct PointerMemberAccess : ExprNode {
    std::unique_ptr<ExprNode> object;
    std::string member;
};

struct StructInit : ExprNode {
    std::string type_name;
    std::vector<std::unique_ptr<ExprNode>> fields;
};

struct ArrayInit : ExprNode {
    std::vector<std::unique_ptr<ExprNode>> elements;
};

struct SizeofExpr : ExprNode {
    std::unique_ptr<TypeNode> type;
};

struct EnumConstruct : ExprNode {
    std::string enum_name;
    std::string variant_name;
    std::unique_ptr<ExprNode> payload;
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

struct VaArgExpr : ExprNode {
    std::unique_ptr<ExprNode> va_list;
    std::unique_ptr<TypeNode> type;
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

struct ForStmt : StmtNode {
    std::unique_ptr<VarDecl> init;
    std::unique_ptr<ExprNode> condition;
    std::unique_ptr<ExprNode> increment;
    std::unique_ptr<BlockStmt> body;
};

struct MatchArm {
    std::string enum_name;
    std::string variant_name;
    std::string binding_name;
    std::unique_ptr<BlockStmt> body;
    int literal_value = 0;
    bool is_literal = false;
};

struct MatchStmt : StmtNode {
    std::unique_ptr<ExprNode> expr;
    std::vector<std::unique_ptr<MatchArm>> arms;
};

struct StructField {
    std::string name;
    std::unique_ptr<TypeNode> type;
};

struct StructDecl : ASTNode {
    std::string name;
    bool is_packed;
    std::vector<std::unique_ptr<StructField>> fields;
};

struct EnumVariant {
    std::string name;
    std::unique_ptr<TypeNode> payload_type;
    int explicit_value = -1;
};

struct EnumDecl : ASTNode {
    std::string name;
    std::vector<std::unique_ptr<EnumVariant>> variants;
};

struct Parameter {
    std::string name;
    std::unique_ptr<TypeNode> type;
};

struct ProcDecl : ASTNode {
    std::string name;
    std::vector<Parameter> params;
    std::unique_ptr<TypeNode> return_type;
    std::unique_ptr<BlockStmt> body;
    bool is_pub = false;
    bool is_extern = false;
    bool is_vararg = false;
};

struct UsingDecl : ASTNode {
    std::string name;
};

struct ModuleAST : ASTNode {
    std::vector<std::unique_ptr<UsingDecl>> usings;
    std::vector<std::unique_ptr<StructDecl>> structs;
    std::vector<std::unique_ptr<EnumDecl>> enums;
    std::vector<std::unique_ptr<GlobalVarDecl>> globals;
    std::vector<std::unique_ptr<ProcDecl>> procs;
};

class Parser {
public:
    Parser(Lexer& lex) : m_lexer(lex)
    {
        Advance();
    }

    std::unique_ptr<ModuleAST> ParseModule(void)
    {
        std::unique_ptr<ModuleAST> module = std::make_unique<ModuleAST>();
        
        while (m_current.type != TokenType_EOF)
        {
            if (Match("using"))
            {
                auto using_decl = std::make_unique<UsingDecl>();
                Expect(TokenType_Identifier, "Expected module name after 'using'");
                using_decl->name = m_last.value;
                while (Match('.'))
                {
                    Expect(TokenType_Identifier, "Expected identifier after '.'");
                    using_decl->name += '.' + m_last.value;
                }
                Expect(';', "Expected ';' after using declaration");
                module->usings.push_back(std::move(using_decl));
            }
            else if (Match("struct"))
            {
                module->structs.push_back(ParseStructDecl());
            }
            else if (Match("enum"))
            {
                module->enums.push_back(ParseEnumDecl());
            }
            else if (Check(TokenType_Identifier))
            {
                const bool is_pub = Match("pub");
                const bool is_extern = Match("extern");

                if (Match("proc"))
                {
                    std::unique_ptr<ProcDecl> proc = ParseProcDecl();
                    proc->is_extern = is_extern;
                    proc->is_pub = is_pub;
                    module->procs.push_back(std::move(proc));
                }
                else
                {
                    std::string name = m_current.value;
                    Advance();
                    
                    if (Check(':'))
                    {
                        auto var = std::make_unique<GlobalVarDecl>();
                        var->name = name;
                        
                        Expect(':', "Expected ':'");
                        
                        var->is_pub = is_pub;

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
                        throw std::runtime_error("Unexpected token at top level: " + name);
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
                throw std::runtime_error(msg);
            }
        }
        
        return module;
    }

    std::unique_ptr<EnumDecl> ParseEnumDecl(void)
    {
        auto enum_decl = std::make_unique<EnumDecl>();
        
        Expect(TokenType_Identifier, "Expected enum name");
        enum_decl->name = m_last.value;
        
        Expect('{', "Expected '{' after enum name");
        
        while (!Match('}'))
        {
            auto variant = std::make_unique<EnumVariant>();
            
            Expect(TokenType_Identifier, "Expected variant name");
            variant->name = m_last.value;
            
            if (Match('='))
            {
                Expect(TokenType_Number, "Expected number after '='");
                variant->explicit_value = std::stoi(m_last.value);
            }
            
            if (Match('('))
            {
                variant->payload_type = ParseType();
                Expect(')', "Expected ')' after payload type");
            }
            
            enum_decl->variants.push_back(std::move(variant));
            
            if (!Check('}'))
                Expect(',', "Expected ',' or '}' after variant");
        }
        
        return enum_decl;
    }

    std::unique_ptr<TypeNode> ParseType(void)
    {
        std::unique_ptr<TypeNode> type = std::make_unique<TypeNode>();
        
        if (Match("const"))
            type->is_const = true;
        
        if (Check('('))
        {
            type->is_function_type = true;
            
            Expect('(', "Expected '('");
            
            if (!Check(')'))
            {
                do {
                    if (Check(TokenType_Identifier))
                    {
                        Advance();
                        if (Match(':'))
                        {
                            type->param_types.push_back(ParseType());
                        }
                        else
                        {
                            throw std::runtime_error("Expected ':' after parameter name in function type");
                        }
                    }
                    else
                    {
                        type->param_types.push_back(ParseType());
                    }
                } while (Match(','));
            }
            
            Expect(')', "Expected ')'");

            if (Match(TokenType_Arrow))
                type->return_type = ParseType();
            
            return type;
        }
        
        if (Check(TokenType_Identifier))
        {
            type->name = m_current.value;
            Advance();
        }
        else
        {
            Expect(TokenType_Identifier, "Expected type name");
            type->name = m_last.value;
        }
        
        while (Match('*'))
            type->pointer_depth++;
        
        while (Match('['))
        {
            Expect(TokenType_Number, "Expected array size");
            type->array_dimensions.push_back(std::stoi(m_last.value));
            Expect(']', "Expected ']'");
        }
        
        return type;
    }

    std::unique_ptr<ExprNode> ParseExpr(void)
    {
        return ParseAssignment();
    }

    std::unique_ptr<ExprNode> ParseAssignment(void)
    {
        auto expr = ParseBitwiseOr();
        
        if (Match('='))
        {
            auto binary = std::make_unique<BinaryExpr>();
            binary->left = std::move(expr);
            binary->op = '=';
            binary->right = ParseAssignment();
            return binary;
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseBitwiseOr(void)
    {
        auto expr = ParseBitwiseXor();
        
        while (Match('|'))
        {
            auto binary = std::make_unique<BinaryExpr>();
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
        
        while (Match('^'))
        {
            auto binary = std::make_unique<BinaryExpr>();
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
        
        while (Match('&'))
        {
            auto binary = std::make_unique<BinaryExpr>();
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
        
        while (Match(TokenType_EqualEqual) || Match(TokenType_NotEqual) || 
            Match('<') || Match(TokenType_LessEqual) || 
            Match('>') || Match(TokenType_GreaterEqual))
        {
            auto binary = std::make_unique<BinaryExpr>();
            binary->left = std::move(expr);
            
            if (m_last.type == TokenType_EqualEqual)
                binary->op = 'E';
            else if (m_last.type == TokenType_NotEqual)
                binary->op = 'N';
            else if (m_last.type == TokenType_LessEqual)
                binary->op = 'L';
            else if (m_last.type == TokenType_GreaterEqual)
                binary->op = 'G';
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
        
        while (Match(TokenType_LeftShift) || Match(TokenType_RightShift))
        {
            auto binary = std::make_unique<BinaryExpr>();
            binary->left = std::move(expr);
            
            if (m_last.type == TokenType_LeftShift)
                binary->op = 'l';
            else
                binary->op = 'r';
            
            binary->right = ParseAdditive();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseAdditive(void)
    {
        auto expr = ParseMultiplicative();
        
        while (Match('+') || Match('-'))
        {
            auto binary = std::make_unique<BinaryExpr>();
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
        
        while (Match('*') || Match('/') || Match('%'))
        {
            auto binary = std::make_unique<BinaryExpr>();
            binary->left = std::move(expr);
            binary->op = m_last.value[0];
            binary->right = ParseUnary();
            expr = std::move(binary);
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParseUnary(void)
    {
        if (Match('-') || Match('!') || Match('&') || Match('*') || Match('~'))
        {
            auto unary = std::make_unique<UnaryExpr>();
            unary->op = m_last.value[0];
            unary->is_prefix = true;
            unary->operand = ParseUnary();
            return unary;
        }
        
        return ParsePostfix();
    }

    std::unique_ptr<ExprNode> ParsePostfix(void)
    {
        auto expr = ParsePrimary();
        
        while (true)
        {
            if (Match('['))
            {
                auto access = std::make_unique<ArrayAccess>();
                access->array = std::move(expr);
                access->index = ParseExpr();
                Expect(']', "Expected ']'");
                expr = std::move(access);
            }
            else if (Match('.'))
            {
                if (auto* id = dynamic_cast<Identifier*>(expr.get()))
                {
                    Expect(TokenType_Identifier, "Expected member or variant name");
                    std::string member_or_variant = m_last.value;
                    
                    if (Match('('))
                    {
                        auto enumConstruct = std::make_unique<EnumConstruct>();
                        enumConstruct->enum_name = id->name;
                        enumConstruct->variant_name = member_or_variant;
                        
                        if (!Check(')'))
                            enumConstruct->payload = ParseExpr();
                        
                        Expect(')', "Expected ')'");
                        expr = std::move(enumConstruct);
                    }
                    else
                    {
                        auto enumConstruct = std::make_unique<EnumConstruct>();
                        enumConstruct->enum_name = id->name;
                        enumConstruct->variant_name = member_or_variant;
                        enumConstruct->payload = nullptr;
                        expr = std::move(enumConstruct);
                    }
                }
                else
                {
                    auto member = std::make_unique<MemberAccess>();
                    member->object = std::move(expr);
                    Expect(TokenType_Identifier, "Expected member name");
                    member->member = m_last.value;
                    expr = std::move(member);
                }
            }
            else if (Match(TokenType_Arrow))
            {
                auto member = std::make_unique<PointerMemberAccess>();
                member->object = std::move(expr);
                Expect(TokenType_Identifier, "Expected member name");
                member->member = m_last.value;
                expr = std::move(member);
            }
            else if (Match('('))
            {
                if (auto* id = dynamic_cast<Identifier*>(expr.get()))
                {
                    auto call = std::make_unique<CallExpr>();
                    call->function = id->name;
                    
                    if (!Check(')'))
                    {
                        do {
                            call->args.push_back(ParseExpr());
                        } while (Match(','));
                    }
                    
                    Expect(')', "Expected ')'");
                    expr = std::move(call);
                }
            }
            else break;
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParsePrimary(void)
    {
        if (Match(TokenType_Number))
        {
            auto num = std::make_unique<NumberLiteral>();
            num->value = m_last.value;
            return num;
        }
        
        if (Match(TokenType_String))
        {
            auto str = std::make_unique<::StringLiteral>();
            str->value = m_last.value;
            return str;
        }

        if (Match(TokenType_Char))
        {
            auto chr = std::make_unique<CharLiteral>();
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

            if (name == "sizeof" && Match('('))
            {
                auto sizeofExpr = std::make_unique<SizeofExpr>();
                sizeofExpr->type = ParseType();
                Expect(')', "Expected ')' after sizeof type");
                return sizeofExpr;
            }
            
            if (name == "cast" && Match('('))
            {
                auto cast = std::make_unique<CastExpr>();
                cast->target_type = ParseType();
                Expect(')', "Expected ')' after cast type");
                cast->operand = ParseUnary();
                return cast;
            }

            if (name == "va_arg" && Match('('))
            {
                auto vaArg = std::make_unique<VaArgExpr>();
                vaArg->va_list = ParseExpr();
                Expect(',', "Expected ',' after va_list");
                vaArg->type = ParseType();
                Expect(')', "Expected ')' after va_arg type");
                return vaArg;
            }

            if (!m_parsingStatement && Match('{'))
            {
                auto init = std::make_unique<StructInit>();
                init->type_name = name;
                
                if (!Check('}'))
                {
                    do {
                        init->fields.push_back(ParseExpr());
                    } while (Match(','));
                }
                
                Expect('}', "Expected '}'");
                return init;
            }
            
            auto ident = std::make_unique<Identifier>();
            ident->name = name;
            return ident;
        }
        
        throw std::runtime_error("Expected expression");
    }

    std::unique_ptr<VarDecl> ParseVarDecl(void)
    {
        auto var = std::make_unique<VarDecl>();
        
        Expect(TokenType_Identifier, "Expected variable name");
        var->name = m_last.value;
        
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
        if (Match("return"))
        {
            auto ret = std::make_unique<ReturnStmt>();
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
            Expect(';', "Expected ';' after 'break'");
            return breakStmt;
        }

        if (Match("continue"))
        {
            auto continueStmt = std::make_unique<ContinueStmt>();
            Expect(';', "Expected ';' after 'continue'");
            return continueStmt;
        }

        if (Match("if"))
        {
            auto statement = std::make_unique<IfStmt>();
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
            m_parsingStatement = true;
            statement->condition = ParseExpr();
            m_parsingStatement = false;
            statement->then_branch = ParseBlock();
            return statement;
        }
        
        if (Match("for"))
        {
            auto statement = std::make_unique<ForStmt>();
            statement->init = ParseVarDecl();
            m_parsingStatement = true;
            statement->condition = ParseExpr();
            Expect(';', "Expected ';'");
            statement->increment = ParseExpr();
            m_parsingStatement = false;
            statement->body = ParseBlock();
            return statement;
        }

        if (Match("match"))
            return ParseMatchStmt();
        
        if (Check('{'))
        {
            return ParseBlock();
        }
        
        if (Check(TokenType_Identifier))
        {
            std::string ident_name = m_current.value;
            Advance();
            
            if (Check(':'))
            {
                auto var = std::make_unique<VarDecl>();
                var->name = ident_name;
                
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
                
                std::unique_ptr<ExprNode> expr = std::move(ident);
                
                while (true)
                {
                    if (Match('['))
                    {
                        auto access = std::make_unique<ArrayAccess>();
                        access->array = std::move(expr);
                        access->index = ParseExpr();
                        Expect(']', "Expected ']'");
                        expr = std::move(access);
                    }
                    else if (Match('.'))
                    {
                        auto member = std::make_unique<MemberAccess>();
                        member->object = std::move(expr);
                        Expect(TokenType_Identifier, "Expected member name");
                        member->member = m_last.value;
                        expr = std::move(member);
                    }
                    else if (Match(TokenType_Arrow))
                    {
                        auto member = std::make_unique<PointerMemberAccess>();
                        member->object = std::move(expr);
                        Expect(TokenType_Identifier, "Expected member name");
                        member->member = m_last.value;
                        expr = std::move(member);
                    }
                    else if (Match('('))
                    {
                        if (auto* id = dynamic_cast<Identifier*>(expr.get()))
                        {
                            auto call = std::make_unique<CallExpr>();
                            call->function = id->name;
                            
                            if (!Check(')'))
                            {
                                do {
                                    call->args.push_back(ParseExpr());
                                } while (Match(','));
                            }
                            
                            Expect(')', "Expected ')'");
                            expr = std::move(call);
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                
                if (Match('='))
                {
                    auto binary = std::make_unique<BinaryExpr>();
                    binary->left = std::move(expr);
                    binary->op = '=';
                    binary->right = ParseAssignment();
                    expr = std::move(binary);
                }
                
                auto stmt = std::make_unique<ExprStmt>();
                stmt->expr = std::move(expr);
                Expect(';', "Expected ';'");
                return stmt;
            }
        }
        
        auto stmt = std::make_unique<ExprStmt>();
        stmt->expr = ParseExpr();
        Expect(';', "Expected ';' after expression");
        return stmt;
    }

    std::unique_ptr<MatchStmt> ParseMatchStmt(void)
    {
        auto match = std::make_unique<MatchStmt>();
        
        m_parsingStatement = true;
        match->expr = ParseExpr();
        m_parsingStatement = false;

        Expect('{', "Expected '{' after match expression");
        
        while (!Check('}'))
        {
            auto arm = std::make_unique<MatchArm>();
            
            if (Check(TokenType_Number))
            {
                Expect(TokenType_Number, "Expected number");
                arm->literal_value = std::stoi(m_last.value);
                arm->is_literal = true;
            }
            else if (Check(TokenType_Char))
            {
                Expect(TokenType_Char, "Expected char");
                if (m_last.value.empty())
                    throw std::runtime_error("Empty character literal in match pattern");
                arm->literal_value = static_cast<uint8_t>(m_last.value[0]);
                arm->is_literal = true;
            }
            else
            {
                Expect(TokenType_Identifier, "Expected enum name in match pattern");
                arm->enum_name = m_last.value;
                
                Expect('.', "Expected '.' after enum name");
                
                Expect(TokenType_Identifier, "Expected variant name");
                arm->variant_name = m_last.value;
                
                if (Match('('))
                {
                    Expect(TokenType_Identifier, "Expected binding name");
                    arm->binding_name = m_last.value;
                    Expect(')', "Expected ')' after binding");
                }
                
                arm->is_literal = false;
            }
            
            arm->body = ParseBlock();
            
            match->arms.push_back(std::move(arm));
            
            Match(',');
        }
        
        Expect('}', "Expected '}' after match arms");
        
        return match;
    }

    std::unique_ptr<BlockStmt> ParseBlock(void)
    {
        Expect('{', "Expected '{'");
        
        auto block = std::make_unique<BlockStmt>();
        
        while (!Check('}') && !Check(TokenType_EOF))
        {
            block->statements.push_back(ParseStmt());
        }
        
        Expect('}', "Expected '}'");
        return block;
    }

    std::unique_ptr<StructDecl> ParseStructDecl(void)
    {
        std::unique_ptr<StructDecl> struct_decl = std::make_unique<StructDecl>();

        if (Match('('))
        {
            Expect(TokenType_Identifier, "Expected attribute name");
            if (m_last.value == "packed")
                struct_decl->is_packed = true;
            else
                throw std::runtime_error("Invalid attribute name " + m_last.value + " on line " + std::to_string(m_lexer.GetCurrentLine()));
            Expect(')', "Expected ')'");
        }

        Expect(TokenType_Identifier, "Expected struct name");
        struct_decl->name = m_last.value;
        
        if (Match('{'))
        {
            while (!Match('}'))
            {
                if (Match(TokenType_Identifier))
                {
                    std::unique_ptr<StructField> field = std::make_unique<StructField>();
                    field->name = m_last.value;
                    Expect(':', "Expected ':'");
                    field->type = ParseType();
                    Expect(';', "Expected ';'");
                    struct_decl->fields.push_back(std::move(field));
                }
            }
        }
        
        return struct_decl;
    }

    std::unique_ptr<ProcDecl> ParseProcDecl(void)
    {
        Expect(TokenType_Identifier, "Expected proc name");
        std::unique_ptr<ProcDecl> proc = std::make_unique<ProcDecl>();
        proc->name = m_last.value;

        if (Match('('))
        {
            while (!Match(')'))
            {
                if ((Match('.') && Match('.') && Match('.')))
                {
                    proc->is_vararg = true;
                    Expect(')', "Expected ')' after '...'");
                    break;
                }

                if (Match(TokenType_Identifier))
                {
                    Parameter param;
                    param.name = m_last.value;
                    Expect(':', "Expected ':'");
                    param.type = ParseType();
                    
                    proc->params.push_back(std::move(param));
                    
                    if (!Check(')'))
                        Expect(',', "Expected ',' or ')' after parameter");
                }
            }
        }

        if (Match(TokenType_Arrow))
            proc->return_type = ParseType();

        proc->body = ParseBlock();

        return proc;
    }

private:

    void Advance(void)
    {
        m_current = m_lexer.Next();
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
            throw std::runtime_error(msg + " on line " + std::to_string(m_lexer.GetCurrentLine()));
    }

    Lexer& m_lexer;
    Token m_current;
    Token m_last;
    bool m_parsingStatement = false;
};