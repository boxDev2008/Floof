#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <sstream>
#include <cctype>
#include <algorithm>

struct MacroDef
{
    std::vector<std::string> params;
    std::string body;
    bool is_function = false;
    bool is_pub = false;
};

class Preprocessor
{
public:

    std::unordered_map<std::string, MacroDef> macros;
    std::unordered_map<std::string, MacroDef> exports;

    void importExports(const std::unordered_map<std::string, MacroDef>& incoming)
    {
        for (const auto& [name, def] : incoming)
            macros[name] = def;
    }

    std::string process(const std::string& source, const std::string& moduleName = "")
    {
        m_module = moduleName;
        m_lineNo = 1;

        std::vector<std::string> lines = splitLines(source);
        std::string result;
        result.reserve(source.size());

        std::vector<bool> condStack;

        std::vector<bool> matched;

        bool emitting = true;

        for (size_t i = 0; i < lines.size(); ++i, ++m_lineNo)
        {
            std::string line = lines[i];

            std::string trimmed = ltrim(line);

            if (!trimmed.empty() && trimmed[0] == '#')
            {
                line = stripLineComment(line);
                trimmed = ltrim(line);
            }

            if (!trimmed.empty() && trimmed[0] == '#')
            {
                size_t pos = 1;

                bool is_pub = false;
                if (trimmed.substr(1, 3) == "pub" &&
                    (trimmed.size() < 4 || std::isspace((unsigned char)trimmed[4]) || trimmed[4] == '\0'))
                {

                    size_t after = trimmed.find_first_not_of(" \t", 4);
                    if (after != std::string::npos)
                    {
                        is_pub = true;
                        pos = after;
                    }
                }

                std::string rest = trimmed.substr(pos);

                if (rest.substr(0, 2) == "if")
                {
                    std::string expr = rtrim(rest.substr(2));

                    if (!expr.empty() && std::isspace((unsigned char)expr[0]))
                        expr = ltrim(expr);

                    bool cond = evaluateCond(expr);
                    condStack.push_back(cond);
                    matched.push_back(cond);
                    emitting = computeEmitting(condStack);

                    result += '\n';
                    continue;
                }

                if (rest == "end")
                {
                    if (condStack.empty())
                        error("#end without matching #if");
                    condStack.pop_back();
                    matched.pop_back();
                    emitting = computeEmitting(condStack);
                    result += '\n';
                    continue;
                }

                if (emitting)
                {
                    std::string name;
                    size_t j = 0;
                    while (j < rest.size() && (std::isalnum((unsigned char)rest[j]) || rest[j] == '_'))
                        name += rest[j++];

                    if (name.empty())
                        error("Expected macro name after '#'");

                    MacroDef def;
                    def.is_pub = is_pub;

                    if (j < rest.size() && rest[j] == '(')
                    {
                        def.is_function = true;
                        ++j;
                        while (j < rest.size() && rest[j] != ')')
                        {

                            while (j < rest.size() && std::isspace((unsigned char)rest[j])) ++j;
                            std::string param;
                            while (j < rest.size() && rest[j] != ',' && rest[j] != ')' &&
                                   !std::isspace((unsigned char)rest[j]))
                                param += rest[j++];
                            if (!param.empty())
                                def.params.push_back(param);
                            while (j < rest.size() && std::isspace((unsigned char)rest[j])) ++j;
                            if (j < rest.size() && rest[j] == ',') ++j;
                        }
                        if (j < rest.size()) ++j;
                    }

                    while (j < rest.size() && std::isspace((unsigned char)rest[j])) ++j;
                    std::string afterSig = rest.substr(j);

                    bool braceBody = false;

                    if (!afterSig.empty() && afterSig[0] == '{')
                    {
                        braceBody = true;
                    }
                    else if (trim(afterSig).empty())
                    {
                        size_t next = i + 1;
                        if (next < lines.size() && ltrim(lines[next]) == "{")
                        {
                            braceBody = true;
                            ++i; ++m_lineNo;
                            afterSig = "{";
                        }
                    }

                    if (braceBody)
                    {
                        std::string bodyAccum;
                        int braceDepth = 1;
                        size_t k = afterSig.find('{') + 1;

                        for (; k < afterSig.size() && braceDepth > 0; ++k)
                        {
                            if      (afterSig[k] == '{') { ++braceDepth; bodyAccum += afterSig[k]; }
                            else if (afterSig[k] == '}') { --braceDepth; if (braceDepth > 0) bodyAccum += afterSig[k]; }
                            else                          { bodyAccum += afterSig[k]; }
                        }

                        while (braceDepth > 0 && i + 1 < lines.size())
                        {
                            ++i; ++m_lineNo;
                            const std::string& bodyLine = lines[i];
                            for (size_t c = 0; c < bodyLine.size() && braceDepth > 0; ++c)
                            {
                                if      (bodyLine[c] == '{') { ++braceDepth; bodyAccum += bodyLine[c]; }
                                else if (bodyLine[c] == '}') { --braceDepth; if (braceDepth > 0) bodyAccum += bodyLine[c]; }
                                else                          { bodyAccum += bodyLine[c]; }
                            }
                            if (braceDepth > 0) bodyAccum += '\n';
                        }

                        if (braceDepth != 0)
                            error("Unterminated '{' in macro body for '" + name + "'");

                        def.body = trim(bodyAccum);
                    }
                    else
                    {
                        def.body = afterSig;
                    }

                    macros[name] = def;
                    if (is_pub)
                        exports[name] = def;
                }

                result += '\n';
                continue;
            }

            if (!emitting)
            {
                result += '\n';
                continue;
            }

            result += expandLine(line);
            result += '\n';
        }

        if (!condStack.empty())
            error("Unterminated #if block (missing #end)");

        return result;
    }

private:
    std::string m_module;
    int m_lineNo = 1;

    bool evaluateCond(const std::string& expr) const
    {
        std::string s = trim(expr);

        if (!s.empty() && s[0] == '!')
        {
            std::string name = trim(s.substr(1));
            return macros.find(name) == macros.end();
        }

        auto eqPos  = s.find("==");
        auto neqPos = s.find("!=");

        if (eqPos != std::string::npos)
        {
            std::string name = trim(s.substr(0, eqPos));
            std::string rhs  = trim(s.substr(eqPos + 2));
            auto it = macros.find(name);
            if (it == macros.end()) return false;
            return trim(it->second.body) == rhs;
        }

        if (neqPos != std::string::npos)
        {
            std::string name = trim(s.substr(0, neqPos));
            std::string rhs  = trim(s.substr(neqPos + 2));
            auto it = macros.find(name);
            if (it == macros.end()) return true;
            return trim(it->second.body) != rhs;
        }

        return macros.find(s) != macros.end();
    }

    static bool computeEmitting(const std::vector<bool>& stack)
    {
        for (bool b : stack)
            if (!b) return false;
        return true;
    }

    std::string expandLine(const std::string& line) const
    {
        return expandText(line);
    }

    std::string expandText(const std::string& text, int depth = 0) const
    {
        if (depth > 64) return text;

        std::string result;
        result.reserve(text.size() + 32);
        size_t i = 0;

        while (i < text.size())
        {
            if (text[i] == '"' || text[i] == '\'')
            {
                char q = text[i];
                result += text[i++];
                while (i < text.size() && text[i] != q)
                {
                    if (text[i] == '\\' && i + 1 < text.size())
                    {
                        result += text[i++];
                        result += text[i++];
                    }
                    else
                    {
                        result += text[i++];
                    }
                }
                if (i < text.size()) result += text[i++];
                continue;
            }

            if (i + 1 < text.size() && text[i] == '/' && text[i+1] == '/')
            {
                result += text.substr(i);
                break;
            }

            if (std::isalpha((unsigned char)text[i]) || text[i] == '_')
            {
                std::string ident;
                while (i < text.size() && (std::isalnum((unsigned char)text[i]) || text[i] == '_'))
                    ident += text[i++];

                auto it = macros.find(ident);
                if (it == macros.end())
                {

                    result += ident;
                    continue;
                }

                const MacroDef& def = it->second;

                if (def.is_function)
                {
                    size_t j = i;
                    while (j < text.size() && std::isspace((unsigned char)text[j])) ++j;

                    if (j < text.size() && text[j] == '(')
                    {
                        ++j;
                        std::vector<std::string> args;
                        std::string arg;
                        int depth2 = 0;

                        while (j < text.size())
                        {
                            char c = text[j];
                            if (c == '(' ) { ++depth2; arg += c; ++j; }
                            else if (c == ')')
                            {
                                if (depth2 == 0) { args.push_back(trim(arg)); ++j; break; }
                                --depth2; arg += c; ++j;
                            }
                            else if (c == ',' && depth2 == 0) { args.push_back(trim(arg)); arg.clear(); ++j; }
                            else { arg += c; ++j; }
                        }

                        if (args.size() != def.params.size())
                        {

                            result += ident;

                            continue;
                        }

                        std::string expanded = substituteMacro(def, args);

                        result += expandText(expanded, depth + 1);
                        i = j;
                    }
                    else
                    {
                        result += ident;
                    }
                }
                else
                {
                    result += expandText(def.body, depth + 1);
                }
            }
            else
            {
                result += text[i++];
            }
        }

        return result;
    }

    std::string substituteMacro(const MacroDef& def, const std::vector<std::string>& args) const
    {
        std::string result = def.body;

        for (size_t p = 0; p < def.params.size(); ++p)
        {
            const std::string& param = def.params[p];
            const std::string& arg   = args[p];
            std::string out;
            size_t i = 0;

            while (i < result.size())
            {
                if ((std::isalpha((unsigned char)result[i]) || result[i] == '_'))
                {
                    std::string word;
                    while (i < result.size() && (std::isalnum((unsigned char)result[i]) || result[i] == '_'))
                        word += result[i++];

                    if (word == param)
                        out += arg;
                    else
                        out += word;
                }
                else
                {
                    out += result[i++];
                }
            }

            result = out;
        }

        return result;
    }

    static std::vector<std::string> splitLines(const std::string& s)
    {
        std::vector<std::string> lines;
        std::string line;
        for (char c : s)
        {
            if (c == '\n') { lines.push_back(line); line.clear(); }
            else if (c != '\r') line += c;
        }
        if (!line.empty()) lines.push_back(line);
        return lines;
    }

    static std::string stripLineComment(const std::string& s)
    {
        bool in_str = false;
        char str_ch = 0;
        for (size_t i = 0; i < s.size(); ++i)
        {
            char c = s[i];
            if (in_str)
            {
                if (c == '\\') { ++i; continue; }
                if (c == str_ch) in_str = false;
            }
            else if (c == '"' || c == '\'') { in_str = true; str_ch = c; }
            else if (c == '/' && i + 1 < s.size() && s[i+1] == '/')
                return rtrim(s.substr(0, i));
        }
        return s;
    }

    static std::string ltrim(const std::string& s)
    {
        size_t start = s.find_first_not_of(" \t\r\n");
        return (start == std::string::npos) ? "" : s.substr(start);
    }

    static std::string rtrim(const std::string& s)
    {
        size_t end = s.find_last_not_of(" \t\r\n");
        return (end == std::string::npos) ? "" : s.substr(0, end + 1);
    }

    static std::string trim(const std::string& s)
    {
        return ltrim(rtrim(s));
    }

    [[noreturn]] void error(const std::string& msg) const
    {
        std::string loc;
        if (!m_module.empty()) loc = " in module " + m_module;
        loc += " on line " + std::to_string(m_lineNo);
        throw std::runtime_error("Preprocessor error: " + msg + loc);
    }
};