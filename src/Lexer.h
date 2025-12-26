#pragma once

#include <string>
#include <cctype>
#include <unordered_map>

enum TokenType
{
    TokenType_Identifier = 256,
    TokenType_Number,
    TokenType_String,
    TokenType_Char,
    TokenType_Arrow,
    TokenType_EqualEqual,    // ==
    TokenType_NotEqual,      // !=
    TokenType_LessEqual,     // <=
    TokenType_GreaterEqual,  // >=
    TokenType_LeftShift,     // <<
    TokenType_RightShift,    // >>
    TokenType_EOF
};

struct Token
{
    TokenType type;
    std::string value;
    int line;
};

#include <iostream>

class Lexer
{
private:
    std::string code;
    size_t pos;
    char current;
    int line;

    static const std::unordered_map<std::string, TokenType> two_char_ops;

    void advance()
    {
        if (current == '\n')
            line++;
        
        pos++;
        current = (pos < code.length()) ? code[pos] : '\0';
    }

    char peek(int offset = 1) const
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
        int token_line = line;
        std::string value;
        value.reserve(32); // Reserve space to reduce allocations
        
        while (current && (std::isalnum(current) || current == '_'))
        {
            value += current;
            advance();
        }
        
        return {TokenType_Identifier, value, token_line};
    }

    Token readNumber()
    {
        int token_line = line;
        std::string value;
        value.reserve(16);
        
        if (current == '0' && (peek() == 'x' || peek() == 'X'))
        {
            // Hexadecimal
            value += current;
            advance();
            value += current;
            advance();
            
            while (current && std::isxdigit(current))
            {
                value += current;
                advance();
            }
        }
        else if (current == '0' && std::isdigit(peek()))
        {
            // Octal
            value += current;
            advance();
            
            while (current && (current >= '0' && current <= '7'))
            {
                value += current;
                advance();
            }
        }
        else
        {
            // Decimal or floating point
            while (current && std::isdigit(current))
            {
                value += current;
                advance();
            }
            
            // Check for decimal point
            if (current == '.')
            {
                value += current;
                advance();
                
                while (current && std::isdigit(current))
                {
                    value += current;
                    advance();
                }
            }
            
            // Check for exponent (e.g., 1e10, 3.14e-5)
            if (current && (current == 'e' || current == 'E'))
            {
                value += current;
                advance();
                
                if (current && (current == '+' || current == '-'))
                {
                    value += current;
                    advance();
                }
                
                while (current && std::isdigit(current))
                {
                    value += current;
                    advance();
                }
            }
        }
        
        // Read suffixes
        while (current && (std::tolower(current) == 'u' || 
                        std::tolower(current) == 'l' || 
                        std::tolower(current) == 'f'))
        {
            value += current;
            advance();
        }
        
        return {TokenType_Number, value, token_line};
    }

    Token readString()
    {
        int token_line = line;
        char quote = current;
        std::string value;
        value.reserve(64); // Reserve space
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

        return {TokenType_String, value, token_line};
    }

    Token readChar()
    {
        int token_line = line;
        std::string value;
        advance(); // skip opening '

        if (current == '\\' && peek())
        {
            advance();
            switch (current)
            {
            case 'n': value = "\n"; break;
            case 't': value = "\t"; break;
            case 'r': value = "\r"; break;
            case '\\': value = "\\"; break;
            case '0': value = "\0"; break;
            case '\'': value = "'"; break;
            case '"': value = "\""; break;
            default: value = std::string(1, current); break;
            }
            advance();
        }
        else if (current && current != '\'')
        {
            value = std::string(1, current);
            advance();
        }

        if (current == '\'')
            advance(); // skip closing '

        return {TokenType_Char, value, token_line};
    }

public:
    Lexer(const std::string &code) : code(code), pos(0), line(1)
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

            // Save current line for token
            int token_line = line;

            // Identifiers and keywords
            if (std::isalpha(current) || current == '_')
                return readIdentifier();

            // Numbers
            if (std::isdigit(current))
                return readNumber();

            // Strings (double quotes)
            if (current == '"')
                return readString();

            // Character literals (single quotes)
            if (current == '\'')
                return readChar();

            // Check for two-character operators using map
            std::string two_char;
            two_char += current;
            two_char += peek();
            
            auto it = two_char_ops.find(two_char);
            if (it != two_char_ops.end())
            {
                advance();
                advance();
                return {it->second, two_char, token_line};
            }

            // Single character tokens
            char ch = current;
            advance();
            return {(TokenType)ch, std::string(1, ch), token_line};
        }

        return {TokenType_EOF, "", line};
    }

    int GetCurrentLine(void) const { return line; }
};

// Initialize static maps
const std::unordered_map<std::string, TokenType> Lexer::two_char_ops = {
    {"->", TokenType_Arrow},
    {"==", TokenType_EqualEqual},
    {"!=", TokenType_NotEqual},
    {"<=", TokenType_LessEqual},
    {">=", TokenType_GreaterEqual},
    {"<<", TokenType_LeftShift},
    {">>", TokenType_RightShift}
};