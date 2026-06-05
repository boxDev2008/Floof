#pragma once

#include <vector>
#include <memory>
#include <stdexcept>

#include "Lexer.h"

struct ASTNode {
    virtual ~ASTNode() = default;
    uint32_t line = 0;
};

struct TypeNode : ASTNode {
    std::string name;
    std::vector<int> array_dimensions;
    
    std::unique_ptr<TypeNode> return_type;
    std::vector<std::unique_ptr<TypeNode>> param_types;
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
};

struct PointerMemberAccess : ExprNode {
    std::unique_ptr<ExprNode> object;
    std::string member;
};

struct FieldInit {
    std::string name;
    std::unique_ptr<ExprNode> value;
};

struct StructInit : ExprNode {
    std::string type_name;
    std::vector<FieldInit> fields;
};

struct ArrayInit : ExprNode {
    std::vector<std::unique_ptr<ExprNode>> elements;
};

struct SizeofExpr : ExprNode {
    std::unique_ptr<TypeNode> type;
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
    std::unique_ptr<VarDecl> init_decl;
    std::unique_ptr<ExprNode> init_expr;
    std::unique_ptr<ExprNode> condition;
    std::unique_ptr<ExprNode> increment;
    std::unique_ptr<BlockStmt> body;
};

struct StructField {
    std::string name;
    std::unique_ptr<TypeNode> type;
    std::unique_ptr<ExprNode> default_value;
};

struct StructDecl : ASTNode {
    std::string name;
    std::vector<std::unique_ptr<StructField>> fields;
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

struct EnumAccess : ExprNode {
    std::string enum_name;
    std::string value_name;
};

struct Parameter {
    std::string name;
    std::unique_ptr<TypeNode> type;
    std::unique_ptr<ExprNode> default_value;
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
    bool is_pub = false;
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
    Parser(Lexer& lex, const std::string &moduleName) : m_lexer(lex), m_moduleName(moduleName)
    {
        Advance();
    }

    std::unique_ptr<ModuleAST> ParseModule(void)
    {
        std::unique_ptr<ModuleAST> module = std::make_unique<ModuleAST>();
        
        while (m_current.type != TokenType_EOF)
        {
            if (Check(TokenType_Identifier))
            {
                uint32_t declLine = CurrentLine();
                const bool is_pub = Match("pub");
                const bool is_extern = Match("extern");

                if (Match("proc"))
                {
                    std::unique_ptr<ProcDecl> proc = ParseProcDecl(is_extern);
                    proc->is_pub = is_pub;
                    proc->line = declLine;
                    module->procs.push_back(std::move(proc));
                }
                else if (Match("struct"))
                {
                    std::unique_ptr<StructDecl> decl = ParseStructDecl();
                    decl->is_pub = is_pub;
                    decl->line = declLine;
                    module->structs.push_back(std::move(decl));
                }
                else if (Match("enum"))
                {
                    std::unique_ptr<EnumDecl> decl = ParseEnumDecl();
                    decl->is_pub = is_pub;
                    decl->line = declLine;
                    module->enums.push_back(std::move(decl));
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
                    module->usings.push_back(std::move(using_decl));
                }
                else
                {
                    std::string name = m_current.value;
                    uint32_t varLine = CurrentLine();
                    Advance();
                    
                    if (Check(':'))
                    {
                        auto var = std::make_unique<GlobalVarDecl>();
                        var->name = name;
                        var->line = varLine;
                        
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

    std::unique_ptr<TypeNode> ParseType(void)
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
                    if (Check(TokenType_Identifier))
                    {
                        Advance();
                        if (Match(':'))
                        {
                            type->param_types.push_back(ParseType());
                        }
                        else
                        {
                            throw std::runtime_error("Expected ':' after parameter name in function type on line " + std::to_string(m_lexer.GetCurrentLine()) + " in module " + m_moduleName);
                        }
                    }
                    else
                    {
                        type->param_types.push_back(ParseType());
                    }
                } while (Match(','));
            }

            Expect(')', "Expected ')'");
            
            while (Match('['))
            {
                Expect(TokenType_Number, "Expected array size");
                type->array_dimensions.push_back(std::stoi(m_last.value));
                Expect(']', "Expected ']'");
            }

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
        {
            type->pointer_depth++;
            if (Match("const"))
                type->pointer_const.push_back(true);
            else
                type->pointer_const.push_back(false);
        }
        
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
        auto expr = ParsePrimary();
        
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
                expr = std::move(member);
            }
            else if (Match(TokenType_Arrow))
            {
                auto member = std::make_unique<PointerMemberAccess>();
                member->line = opLine;
                member->object = std::move(expr);
                Expect(TokenType_Identifier, "Expected member name");
                member->member = m_last.value;
                expr = std::move(member);
            }
            else if (Match('('))
            {
                auto call = std::make_unique<CallExpr>();
                call->line = opLine;
                call->callee = std::move(expr);
                
                if (!Check(')'))
                {
                    do {
                        call->args.push_back(ParseExpr());
                    } while (Match(','));
                }
                
                Expect(')', "Expected ')'");
                expr = std::move(call);
            }
            else break;
        }
        
        return expr;
    }

    std::unique_ptr<ExprNode> ParsePrimary(void)
    {
        uint32_t primaryLine = CurrentLine();

        if (Match(TokenType_Number))
        {
            auto num = std::make_unique<NumberLiteral>();
            num->line = primaryLine;
            num->value = m_last.value;
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

            if (name == "va_arg" && Match('('))
            {
                auto vaArg = std::make_unique<VaArgExpr>();
                vaArg->line = primaryLine;
                vaArg->va_list = ParseExpr();
                Expect(',', "Expected ',' after va_list");
                vaArg->type = ParseType();
                Expect(')', "Expected ')' after va_arg type");
                return vaArg;
            }

            if (Match(':'))
            {
                Expect(TokenType_Identifier, "Expected enum value name after ':'");
                std::string valueName = m_last.value;
                auto enumAccess = std::make_unique<EnumAccess>();
                enumAccess->line = primaryLine;
                enumAccess->enum_name = name;
                enumAccess->value_name = valueName;
                return enumAccess;
            }

            if (!m_parsingStatement && Match('{'))
            {
                auto init = std::make_unique<StructInit>();
                init->line = primaryLine;
                init->type_name = name;
                
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
                        init->fields.push_back(std::move(fi));
                    } while (Match(','));
                }
                
                Expect('}', "Expected '}'");
                return init;
            }
            
            auto ident = std::make_unique<Identifier>();
            ident->line = primaryLine;
            ident->name = name;
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
        
        if (Match("for"))
        {
            auto stmt = ParseForStmt();
            stmt->line = stmtLine;
            return stmt;
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
                
                std::unique_ptr<ExprNode> expr = std::move(ident);
                
                while (true)
                {
                    uint32_t postfixLine = CurrentLine();
                    if (Match('['))
                    {
                        auto access = std::make_unique<ArrayAccess>();
                        access->line = postfixLine;
                        access->array = std::move(expr);
                        access->index = ParseExpr();
                        Expect(']', "Expected ']'");
                        expr = std::move(access);
                    }
                    else if (Match('.'))
                    {
                        auto member = std::make_unique<MemberAccess>();
                        member->line = postfixLine;
                        member->object = std::move(expr);
                        Expect(TokenType_Identifier, "Expected member name");
                        member->member = m_last.value;
                        expr = std::move(member);
                    }
                    else if (Match(TokenType_Arrow))
                    {
                        auto member = std::make_unique<PointerMemberAccess>();
                        member->line = postfixLine;
                        member->object = std::move(expr);
                        Expect(TokenType_Identifier, "Expected member name");
                        member->member = m_last.value;
                        expr = std::move(member);
                    }
                    else if (Match('('))
                    {
                        auto call = std::make_unique<CallExpr>();
                        call->line = postfixLine;
                        call->callee = std::move(expr);
                        
                        if (!Check(')'))
                        {
                            do {
                                call->args.push_back(ParseExpr());
                            } while (Match(','));
                        }
                        
                        Expect(')', "Expected ')'");
                        expr = std::move(call);
                    }
                    else
                    {
                        break;
                    }
                }
                
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
            {
                case_stmt->is_else = true;
            }
            else
            {
                case_stmt->value = ParseExpr();
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

        if (Match('('))
        {
            Expect(TokenType_Identifier, "Expected attribute name");
            if (m_last.value == "packed")
                struct_decl->is_packed = true;
            else
                throw std::runtime_error(
                    "Invalid attribute name " + m_last.value +
                    " on line " + std::to_string(m_lexer.GetCurrentLine()) +
                    " in module " + m_moduleName);

            Expect(')', "Expected ')'");
        }

        Expect(TokenType_Identifier, "Expected struct name");
        struct_decl->name = m_last.value;
        struct_decl->line = m_lexer.GetCurrentLine();
            
        Expect('{', "Expected '{'");

        while (!Check('}'))
        {
            Expect(TokenType_Identifier, "Expected field name");

            std::unique_ptr<StructField> field = std::make_unique<StructField>();
            field->name = m_last.value;

            Expect(':', "Expected ':'");
            field->type = ParseType();

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

        if (Match('('))
        {
            bool hasDefault = false;
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

                    if (Match('='))
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
        }

        if (Match(TokenType_Arrow))
            proc->return_type = ParseType();

        if (is_extern)
            Expect(';', "Expected ';' after extern proc declaration");
        else proc->body = ParseBlock();

        return proc;
    }

private:

    uint32_t CurrentLine() const { return m_lexer.GetCurrentLine(); }

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
};