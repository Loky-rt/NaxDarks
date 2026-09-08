#pragma once
#include "nax_linux.h"

uint8_t nax_dispatch(NaxAgent *a, NaxTask *t,
                     uint8_t **out, uint32_t *out_len);
