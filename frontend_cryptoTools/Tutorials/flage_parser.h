#pragma once
#include <map>
#include <iostream>
#include <string>
#include "cryptoTools/Common/CLP.h"

int RegisterKey(const std::string& key_str, int* var_ptr, int default_value);
std::string RegisterKey(const std::string& key_str, std::string* var_ptr, const std::string& default_value);
bool RegisterKey(const std::string& key_str, bool* var_ptr, bool default_value);

#define DEFINE_i32(key, default_value) int flage_##key = RegisterKey(#key, &flage_##key, default_value)
#define DECLEAR_i32(key) extern int flage_##key

#define DEFINE_str(key, default_value) std::string flage_##key = RegisterKey(#key, &flage_##key, default_value)
#define DECLEAR_str(key) extern std::string flage_##key

#define DEFINE_boo(key, default_value) bool flage_##key = RegisterKey(#key, &flage_##key, default_value)
#define DECLEAR_boo(key) extern bool flage_##key
void ParseCmdFlags(osuCrypto::CLP cmd);
