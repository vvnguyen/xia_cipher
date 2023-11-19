#pragma once
#include <string>
#include "generate_random.h"

bool is_proper_for_password(unsigned char c) {
    return ((c >= 'A') && (c <= 'Z')) ||
        ((c >= 'a') && (c <= 'z')) ||
        ((c >= '0') && (c <= '9')) ||
        (c == '!') ||
        (c == '@') ||
        (c == '#') ||
        (c == '$') ||
        (c == '%') ||
        (c == '^') ||
        (c == '&') ||
        (c == '*') ||
        (c == '(') ||
        (c == ')') ||
        (c == '{') ||
        (c == '}') ||
        (c == '[') ||
        (c == ']') ||
        (c == ';') ||
        (c == ':') ||
        (c == '<') ||
        (c == '>') ||
        (c == '?') ||
        (c == ',') ||
        (c == '.');
}

std::string generate_password(int length) {
    std::string password = "";
    unsigned char c;
    for (int i = 0;i < length;++i) {
        c = generate_random_char();
        password += c;
    }
    CryptoPP::byte out[64];
    CryptoPP::OS_GenerateRandomBlock(false, out, 64);
    for (int i = 0;i < length;++i) {
        password[i] ^= out[i];
    }
    for (int i = 0;i < length;++i) {
        while (!is_proper_for_password(password[i])) {
            c = generate_random_char();
            password[i] ^= c;
        }
    }
    return password;
}