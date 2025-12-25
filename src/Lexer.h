#pragma once

#include <string>
#include <cctype>

enum TokenType
{
    TokenType_Identifier = 256,
    TokenType_Number,
    TokenType_String,
    TokenType_Arrow,
    TokenType_EqualEqual,    // ==
    TokenType_NotEqual,      // !=
    TokenType_LessEqual,     // <=
    TokenType_GreaterEqual,  // >=
    TokenType_EOF
};

struct Token
{
    TokenType type;
    std::string value;
};

class Lexer
{
private:
    std::string code;
    size_t pos;
    char current;

    void advance()
    {
        pos++;
        current = (pos < code.length()) ? code[pos] : '\0';
    }

    char peek(int offset = 1)
    {
        size_t peek_pos = pos + offset;
        return (peek_pos < code.length()) ? code[peek_pos] : '\0';
    }

    void skipWhitespace()
    {
        while (current && std::isspace(current))
            advance();
    }

    void skipLineComment()
    {
        // Skip //
        advance();
        advance();
        while (current && current != '\n')
            advance();
    }

    void skipBlockComment()
    {
        // Skip /*
        advance();
        advance();
        while (current)
        {
            if (current == '*' && peek() == '/')
            {
                advance(); // skip *
                advance(); // skip /
                break;
            }
            advance();
        }
    }

    Token readIdentifier()
    {
        std::string value;
        while (current && (std::isalnum(current) || current == '_'))
        {
            value += current;
            advance();
        }
        return {TokenType_Identifier, value};
    }

    Token readNumber()
    {
        std::string value;
        while (current && (std::isdigit(current) || current == '.'))
        {
            value += current;
            advance();
        }
        return {TokenType_Number, value};
    }

    Token readString()
    {
        char quote = current;
        std::string value;
        advance(); // skip opening quote

        while (current && current != quote)
        {
            if (current == '\\' && peek())
            {
                advance();
                switch (current)
                {
                case 'n': value += '\n'; break;
                case 't': value += '\t'; break;
                case 'r': value += '\r'; break;
                case '\\': value += '\\'; break;
                case '"': value += '"'; break;
                case '\'': value += '\''; break;
                default: value += current; break;
                }
            }
            else
            {
                value += current;
            }
            advance();
        }

        if (current == quote)
            advance(); // skip closing quote

        return {TokenType_String, value};
    }

public:
    Lexer(const std::string &code) : code(code), pos(0)
    {
        current = code.empty() ? '\0' : code[0];
    }

    Token Next(void)
    {
        while (current)
        {
            // Skip whitespace
            if (std::isspace(current))
            {
                skipWhitespace();
                continue;
            }

            // Skip comments
            if (current == '/' && peek() == '/')
            {
                skipLineComment();
                continue;
            }
            if (current == '/' && peek() == '*')
            {
                skipBlockComment();
                continue;
            }

            // Identifiers and keywords
            if (std::isalpha(current) || current == '_')
                return readIdentifier();

            // Numbers
            if (std::isdigit(current))
                return readNumber();

            // Strings
            if (current == '"' || current == '\'')
                return readString();

            // Arrow operator
            if (current == '-' && peek() == '>')
            {
                advance();
                advance();
                return {TokenType_Arrow, "->"};
            }

            if (current == '!' && peek() == '=')
            {
                advance();
                advance();
                return {TokenType_NotEqual, "!="};
            }

            if (current == '=' && peek() == '=')
            {
                advance();
                advance();
                return {TokenType_EqualEqual, "=="};
            }

            if (current == '<' && peek() == '=')
            {
                advance();
                advance();
                return {TokenType_LessEqual, "<="};
            }

            if (current == '>' && peek() == '=')
            {
                advance();
                advance();
                return {TokenType_GreaterEqual, ">="};
            }

            // Single character tokens
            char ch = current;
            advance();
            return {(TokenType)ch, std::string(1, ch)};
        }

        return {TokenType_EOF, ""};
    }
};