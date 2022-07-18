#include "flage_parser.h"

class Flags {
public:
    static Flags& Instance();
private:
    Flags() = default;
    ~Flags() = default;
public:
    std::map<std::string, int*> sflage_keys_i32;
    std::map<std::string, std::string*> sflage_keys_str;
    std::map<std::string, bool*> sflage_keys_boo;
};

Flags& Flags::Instance() {
    static Flags ins;
    return ins;
}

void ParseCmdFlags(osuCrypto::CLP cmd) {
#define Cout(key, value) std::cout << key << ":" << value << std::endl;
    for (auto& item : Flags::Instance().sflage_keys_i32) {
        if (cmd.hasValue(item.first)) {
            *(item.second) = cmd.get<int>(item.first);
        }
        Cout(item.first, *item.second);
    }
    for (auto& item : Flags::Instance().sflage_keys_str) {
        if (cmd.hasValue(item.first)) {
            *(item.second) = cmd.get<std::string>(item.first);
        }
        Cout(item.first, *item.second);
    }
    for (auto& item : Flags::Instance().sflage_keys_boo) {
        if (cmd.hasValue(item.first)) {
            std::string tmp = cmd.get<std::string>(item.first);
            if (tmp == "true") {
                *(item.second) = true;
            } else {
                *(item.second) = false;
            }
        }
        Cout(item.first, *item.second);
    }
}

int RegisterKey(const std::string& key_str, int* var_ptr, int default_value) {
    Flags::Instance().sflage_keys_i32.emplace(key_str, var_ptr);
    return default_value;
}

std::string RegisterKey(const std::string& key_str, std::string* var_ptr,
                        const std::string& default_value) {
    Flags::Instance().sflage_keys_str.emplace(key_str, var_ptr);
    return default_value;
}

bool RegisterKey(const std::string& key_str, bool* var_ptr, bool default_value) {
    Flags::Instance().sflage_keys_boo.emplace(key_str, var_ptr);
    return default_value;
}
