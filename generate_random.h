#pragma once
#include <chrono>
#include <thread>
#include "chacha.h"
#include "osrng.h"

inline
int generate_random_bit() {
    int random_bit = 0;
    auto current_time = std::chrono::high_resolution_clock::now();
    auto time_since_epoch = (current_time.time_since_epoch()).count();
    time_since_epoch /= 100;
    random_bit |= (time_since_epoch & 1);
    return random_bit;
}

int generate_random_char() {
    int random_char = 0;
    for (int bit = 0; bit < 7; ++bit) {
        random_char |= generate_random_bit();
        random_char <<= 1;
    }
    random_char |= generate_random_bit();//last bit
    return random_char;
}