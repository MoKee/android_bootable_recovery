/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _APPLYPATCH_MOKEE_H
#define _APPLYPATCH_MOKEE_H

#include <stdint.h>
#include <sys/stat.h>

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <openssl/sha.h>

// Forward declaration to avoid including "edify/expr.h" in the header.
struct Value;

int mokee_applypatch(const char* source_filename,
                     const char* target_filename,
                     const char* target_sha1_str,
                     size_t target_size,
                     const std::vector<std::string>& patch_sha1_str,
                     const std::vector<std::unique_ptr<Value>>& patch_data,
                     const Value* bonus_data);
int mokee_applypatch_check(const char* filename,
                           const std::vector<std::string>& patch_sha1_str);

#endif  // _APPLYPATCH_MOKEE_H
