#pragma once
#include <stdint.h>
int get_sig_from_server(uint8_t* dgst, size_t  dgstlen, uint8_t* sig, size_t* siglen);
int get_ssh_sig(uint8_t* data, size_t datalen, uint8_t** sigssh, size_t* sigsshlen);