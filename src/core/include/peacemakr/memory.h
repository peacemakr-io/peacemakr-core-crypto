//
// Copyright 2021 Peacemakr, Inc.
// Full license at peacemakr_core_crypto/LICENSE.txt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PEACEMAKR_CORE_CRYPTO_MEMORY_H
#define PEACEMAKR_CORE_CRYPTO_MEMORY_H

#include <stddef.h>

typedef void *(*peacemakr_malloc_cb)(size_t);
typedef void *(*peacemakr_calloc_cb)(size_t, size_t);
typedef void *(*peacemakr_realloc_cb)(void *, size_t);
typedef void (*peacemakr_free_cb)(void *);

extern peacemakr_malloc_cb peacemakr_global_malloc;
extern peacemakr_calloc_cb peacemakr_global_calloc;
extern peacemakr_realloc_cb peacemakr_global_realloc;
extern peacemakr_free_cb peacemakr_global_free;

#endif // PEACEMAKR_CORE_CRYPTO_MEMORY_H
