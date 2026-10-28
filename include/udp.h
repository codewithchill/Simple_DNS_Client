#pragma once

#include <stddef.h>
#include <stdint.h>

#define _1KB_ 1024
uint8_t* getData(const uint8_t* message, const size_t length, int *buf_len);

