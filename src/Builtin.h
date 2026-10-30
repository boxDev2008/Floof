#pragma once

constexpr const char* BUILTIN_MODULE_NAME = "__builtin";

constexpr const char* BUILTIN_MODULE_SOURCE = R"floof(
extern printf(fmt: const char*, ...) -> i32;
extern putchar(c: i32) -> i32;
extern snprintf(buf: char*, size: usize, fmt: const char*, ...) -> i32;
extern strtod(str: const char*, end: char**) -> f64;

write_float(value: f64, is_f32: bool)
{
    buf: char[32];
    precision: i32 = 1;
    while precision <= 17
    {
        snprintf(buf, 32, "%.*g", precision, value);
        parsed := strtod(buf, cast(char**) 0);
        if is_f32
        {
            if cast(f32) parsed == cast(f32) value { break; }
        }
        else
        {
            if parsed == value { break; }
        }
        precision += 1;
    }
    printf("%s", buf);
}

write_text(text: const char*, len: usize)
{
    if len > 0
    {
        printf("%.*s", cast(i32) len, text);
    }
}

write_value(arg: any)
{
    match typeof(arg)
    {
        bool
        {
            if cast(bool) arg { printf("true"); }
            else { printf("false"); }
        }
        char { putchar(cast(char) arg); }
        i16 { printf("%d", cast(i16) arg); }
        i32 { printf("%d", cast(i32) arg); }
        i64 { printf("%lld", cast(i64) arg); }
        u8 { printf("%u", cast(u8) arg); }
        u16 { printf("%u", cast(u16) arg); }
        u32 { printf("%u", cast(u32) arg); }
        u64 { printf("%llu", cast(u64) arg); }
        f32 { write_float(cast(f32) arg, true); }
        f64 { write_float(cast(f64) arg, false); }
        typeof(char*) { printf("%s", cast(char*) arg); }
        else
        {
            if typeof(arg) >> 63 == 1 { printf("%p", cast(u0*) arg); }
            else { printf("{?}"); }
        }
    }
}

pub print(fmt: const char*, args: ..any)
{
    i: usize = 0;
    run: usize = 0;
    next: usize = 0;
    while fmt[i] != '\0'
    {
        c := fmt[i];
        if (c == '{' & fmt[i + 1] == '{') | (c == '}' & fmt[i + 1] == '}')
        {
            write_text(fmt + run, i - run + 1);
            i += 2;
            run = i;
            continue;
        }
        if c == '{' & fmt[i + 1] == '}'
        {
            write_text(fmt + run, i - run);
            if next < args.len { write_value(args[next]); }
            else { printf("{}"); }
            next += 1;
            i += 2;
            run = i;
            continue;
        }
        i += 1;
    }
    write_text(fmt + run, i - run);
}

pub println(fmt: const char*, args: ..any)
{
    print(fmt, ..args);
    putchar('\n');
}
)floof";
