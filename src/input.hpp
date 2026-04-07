#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace fecchunter {

struct SignatureInput {
    std::string message;
    std::string hash_hex;
    std::string r_hex;
    std::string s_hex;
};

struct ConstraintsInput {
    int nonce_max_bits{0};
    int privkey_max_bits{0};
    long long related_delta_max{0};
    long long related_a_abs_max{0};
    long long related_b_abs_max{0};
    unsigned long long unix_time_min{0};
    unsigned long long unix_time_max{0};
};

struct CurveInput {
    std::string name;
    std::optional<std::string> p_hex;
    std::optional<std::string> a_hex;
    std::optional<std::string> b_hex;
    std::optional<std::string> gx_hex;
    std::optional<std::string> gy_hex;
    std::optional<std::string> n_hex;
    std::optional<std::string> h_hex;
};

struct PublicKeyInput {
    std::optional<std::string> compressed_hex;
    std::optional<std::string> x_hex;
    std::optional<std::string> y_hex;
    std::optional<std::string> raw_hex;
    std::optional<std::string> source_kind;
};

struct ChallengeInput {
    std::string schema_version{"1.0"};
    std::string title;
    std::string mode;
    CurveInput curve;
    PublicKeyInput public_key;
    ConstraintsInput constraints;
    std::map<std::string, std::string> facts;
    std::vector<SignatureInput> signatures;
};

ChallengeInput load_challenge_json(const std::string& path);

} // namespace fecchunter
