#include "analysis.hpp"

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>
#include <unordered_set>
#include <cstdint>
#include <random>
#include <ctime>

namespace fecchunter {

namespace {

struct CheckInfo {
    std::string id;
    std::string fault_name;
    std::string category;
    std::string severity;
};

Point parse_public_key(const Curve& curve, const PublicKeyInput& pk) {
    if (!curve.active_algebra_supported) {
        throw std::runtime_error("public key parsing for this family is passive-only in the active algebra engine");
    }
    if (pk.compressed_hex) {
        auto P = decompress_pubkey(curve, *pk.compressed_hex);
        if (!P) throw std::runtime_error("failed to decompress public key");
        return *P;
    }
    if (pk.raw_hex) {
        auto P = parse_pubkey_text(curve, *pk.raw_hex);
        if (P) return *P;
    }
    if (pk.x_hex && pk.y_hex) {
        Point P(hex_to_mpz(*pk.x_hex), hex_to_mpz(*pk.y_hex));
        if (!is_on_curve(curve, P)) throw std::runtime_error("public key is not on curve");
        return P;
    }
    throw std::runtime_error("public key is missing or could not be parsed for the active algebra engine");
}

mpz_class parse_hash_hex(const std::string& s) { return hex_to_mpz(s); }

std::string lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string bool_word_local(bool v) { return v ? "yes" : "no"; }

std::string normalized_input_kind_local(const ChallengeInput& in) {
    if (in.public_key.compressed_hex) return "sec1_compressed";
    if (in.public_key.x_hex && in.public_key.y_hex) return "affine_coordinates";
    if (in.public_key.raw_hex) return "raw_hex";
    return "missing";
}

std::string analysis_path_kind_local(const AnalysisResult& result) {
    if (result.curve.active_algebra_supported && result.public_key_parsed) return "active_algebra";
    if (!result.curve.active_algebra_supported) return "passive_family";
    return "passive_parse_preserved";
}

std::string why_no_recovery_text_local(const AnalysisResult& result, const ChallengeInput& in) {
    std::size_t recovered = 0;
    for (const auto& module : result.modules) if (module.recovered && module.private_key) ++recovered;
    if (recovered) return "recovery demonstrated";
    if (!result.public_key_parsed) return "public key did not parse algebraically; only passive parser/oracle/provenance checks could run";
    if (!result.curve.active_algebra_supported) return "this curve family is in passive-analysis mode in the active algebra engine";
    if (in.signatures.empty()) return "no signatures were supplied, so nonce and signature-recovery engines stayed inactive";
    return "current artifacts did not demonstrate a recoverable weakness";
}

std::optional<std::string> fact_get(const ChallengeInput& in, const std::string& key) {
    auto it = in.facts.find(key);
    if (it == in.facts.end()) return std::nullopt;
    return it->second;
}

bool fact_is_true(const ChallengeInput& in, const std::string& key) {
    auto v = fact_get(in, key);
    if (!v) return false;
    const auto t = lower_copy(*v);
    return t == "true" || t == "1" || t == "yes" || t == "on";
}

bool fact_in(const ChallengeInput& in, const std::string& key, const std::vector<std::string>& vals) {
    auto v = fact_get(in, key);
    if (!v) return false;
    const auto t = lower_copy(*v);
    for (const auto& x : vals) {
        if (t == lower_copy(x)) return true;
    }
    return false;
}

std::optional<mpz_class> fact_get_mpz(const ChallengeInput& in, const std::string& key) {
    auto v = fact_get(in, key);
    if (!v) return std::nullopt;
    std::string s = *v;
    s.erase(std::remove_if(s.begin(), s.end(), [](unsigned char c) { return std::isspace(c) || c == '_'; }), s.end());
    if (s.empty()) return std::nullopt;
    mpz_class z;
    if (mpz_set_str(z.get_mpz_t(), s.c_str(), 0) == 0) return z;
    try {
        return hex_to_mpz(s);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<unsigned long long> fact_get_ull(const ChallengeInput& in, const std::string& key) {
    auto z = fact_get_mpz(in, key);
    if (!z || *z < 0) return std::nullopt;
    return z->get_ui();
}


ModuleResult make_base(const CheckInfo& info, bool active = false) {
    ModuleResult r;
    r.id = info.id;
    r.fault_name = info.fault_name;
    r.category = info.category;
    r.severity = info.severity;
    r.active_attack = active;
    return r;
}

int compute_heuristic_score(const ModuleResult& r) {
    int score = 0;
    const std::string sev = lower_copy(r.severity);
    if (sev == "critical") score += 55;
    else if (sev == "high") score += 40;
    else if (sev == "medium") score += 25;
    else if (sev == "low") score += 10;
    if (r.status == "HIT") score += 15;
    if (r.active_attack) score += 10;
    if (r.recovered && r.private_key) score += 20;
    if (r.category == "curve" || r.category == "validation" || r.category == "rng") score += 5;
    return std::min(100, score);
}

std::string extract_line_value(const ModuleResult& r, const std::string& prefix) {
    for (const auto& line : r.lines) {
        if (line.rfind(prefix, 0) == 0) return line.substr(prefix.size());
    }
    return {};
}

void finalize_module_metadata(ModuleResult& r) {
    if (r.recovered && r.private_key) {
        r.impact = "Private key compromise feasible";
        r.confidence = "Practically validated";
        r.validation_state = "recovery_succeeded";
    } else if (r.status == "HIT" && r.active_attack) {
        r.impact = "Recovery path available under audited conditions";
        r.confidence = "Strong analytical evidence";
        r.validation_state = "candidate_for_recovery_validation";
    } else if (r.status == "HIT") {
        r.confidence = "Mathematically grounded";
        r.validation_state = "finding_confirmed";
    } else if (r.status == "PASS") {
        r.confidence = "Checked";
        r.validation_state = "no_issue_detected";
    }
    const std::string explicit_impact = extract_line_value(r, "impact = ");
    if (!explicit_impact.empty()) r.impact = explicit_impact;
    if (r.impact == "none") {
        if (r.status == "HIT") {
            if (lower_copy(r.severity) == "critical") r.impact = "Cryptographic collapse likely";
            else if (lower_copy(r.severity) == "high") r.impact = "Serious security weakening";
            else if (lower_copy(r.severity) == "medium") r.impact = "Security weakening";
            else r.impact = "Informational risk";
        } else {
            r.impact = "No direct compromise evidenced";
        }
    }
    r.heuristic_score = compute_heuristic_score(r);
}

static inline std::uint64_t splitmix64_next(std::uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = x;
    z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31U);
}

static inline std::uint32_t pcg32_output(std::uint64_t oldstate) {
    const std::uint32_t xorshifted = static_cast<std::uint32_t>(((oldstate >> 18U) ^ oldstate) >> 27U);
    const std::uint32_t rot = static_cast<std::uint32_t>(oldstate >> 59U);
    return (xorshifted >> rot) | (xorshifted << ((32U - rot) & 31U));
}

static inline std::uint32_t xorshift32_next(std::uint32_t state) {
    state ^= (state << 13U);
    state ^= (state >> 17U);
    state ^= (state << 5U);
    return state;
}

static inline std::uint64_t xorshift64star_next(std::uint64_t state) {
    state ^= (state >> 12U);
    state ^= (state << 25U);
    state ^= (state >> 27U);
    return state * 2685821657736338717ULL;
}

static inline std::uint32_t mwc1616_next(std::uint32_t& z, std::uint32_t& w) {
    z = 36969U * (z & 65535U) + (z >> 16U);
    w = 18000U * (w & 65535U) + (w >> 16U);
    return (z << 16U) + (w & 65535U);
}

static inline std::uint64_t rotl64(std::uint64_t x, unsigned k) {
    return (x << k) | (x >> (64U - k));
}

struct Sfc64State {
    std::uint64_t a{0};
    std::uint64_t b{0};
    std::uint64_t c{0};
    std::uint64_t counter{1};
};

static inline Sfc64State sfc64_seeded(std::uint64_t seed) {
    Sfc64State st;
    st.a = seed ^ 0x9E3779B97F4A7C15ULL;
    st.b = seed ^ 0xD1B54A32D192ED03ULL;
    st.c = seed ^ 0x94D049BB133111EBULL;
    st.counter = 1ULL;
    for (int i = 0; i < 12; ++i) {
        const std::uint64_t res = st.a + st.b + st.counter++;
        st.a = st.b ^ (st.b >> 11U);
        st.b = st.c + (st.c << 3U);
        st.c = rotl64(st.c, 24U) + res;
    }
    return st;
}

static inline std::uint64_t sfc64_next(Sfc64State& st) {
    const std::uint64_t res = st.a + st.b + st.counter++;
    st.a = st.b ^ (st.b >> 11U);
    st.b = st.c + (st.c << 3U);
    st.c = rotl64(st.c, 24U) + res;
    return res;
}

static inline std::uint64_t wyrand_next(std::uint64_t state) {
    state += 0xA0761D6478BD642FULL;
    const unsigned __int128 wide = static_cast<unsigned __int128>(state) * static_cast<unsigned __int128>(state ^ 0xE7037ED1A0B428DBULL);
    return static_cast<std::uint64_t>(wide) ^ static_cast<std::uint64_t>(wide >> 64U);
}

ModuleResult curve_discriminant_module(const CheckInfo& info, const Curve& curve) {
    ModuleResult out = make_base(info, false);
    const mpz_class four_a3 = mod(mpz_class(4) * curve.a * curve.a * curve.a, curve.p);
    const mpz_class twentyseven_b2 = mod(mpz_class(27) * curve.b * curve.b, curve.p);
    const mpz_class disc = mod(four_a3 + twentyseven_b2, curve.p);
    out.lines.push_back("field_bits = " + std::to_string(mpz_sizeinbase(curve.p.get_mpz_t(), 2)));
    out.lines.push_back("discriminant_mod_p = 0x" + mpz_to_hex(disc));
    if (disc == 0) {
        out.status = "HIT";
        out.lines.push_back("impact = singular curves invalidate the group law and destroy ECC security assumptions");
    } else {
        out.status = "PASS";
        out.lines.push_back("rationale = non-zero discriminant preserves a valid short-Weierstrass group law");
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult generator_not_on_curve_module(const CheckInfo& info, const Curve& curve) {
    ModuleResult out = make_base(info, false);
    const bool ok = is_on_curve(curve, curve.G) && !curve.G.inf;
    out.lines.push_back(std::string("generator_on_curve = ") + (ok ? "true" : "false"));
    if (!ok) {
        out.status = "HIT";
        out.lines.push_back("impact = an invalid generator collapses all derived subgroup reasoning");
    } else {
        out.status = "PASS";
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult generator_order_mismatch_module(const CheckInfo& info, const Curve& curve) {
    ModuleResult out = make_base(info, false);
    const Point test = scalar_mul(curve, curve.n, curve.G);
    const bool ok = test.inf;
    out.lines.push_back(std::string("n_times_G_is_infinity = ") + (ok ? "true" : "false"));
    if (!ok) {
        out.status = "HIT";
        out.lines.push_back("impact = the declared subgroup order does not annihilate the generator");
    } else {
        out.status = "PASS";
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult public_key_subgroup_mismatch_module(const CheckInfo& info, const Curve& curve, const Point& Q) {
    ModuleResult out = make_base(info, false);
    const Point test = scalar_mul(curve, curve.n, Q);
    const bool ok = !Q.inf && test.inf;
    out.lines.push_back(std::string("public_key_at_infinity = ") + (Q.inf ? "true" : "false"));
    out.lines.push_back(std::string("n_times_Q_is_infinity = ") + (test.inf ? "true" : "false"));
    if (!ok) {
        out.status = "HIT";
        out.lines.push_back("impact = public key subgroup mismatch can invalidate signature and ECDH security claims");
    } else {
        out.status = "PASS";
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult nontrivial_cofactor_notice_module(const CheckInfo& info, const Curve& curve) {
    ModuleResult out = make_base(info, false);
    out.lines.push_back("cofactor = " + curve.h.get_str());
    if (curve.h > 1) {
        out.status = "HIT";
        out.lines.push_back("impact = non-trivial cofactor curves need explicit subgroup checks or cofactor clearing");
    } else {
        out.status = "PASS";
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult field_modulus_not_prime_module(const CheckInfo& info, const Curve& curve) {
    ModuleResult out = make_base(info, false);
    const int primality = mpz_probab_prime_p(curve.p.get_mpz_t(), 25);
    out.lines.push_back("field_modulus_bits = " + std::to_string(mpz_sizeinbase(curve.p.get_mpz_t(), 2)));
    out.lines.push_back("probable_prime_result = " + std::to_string(primality));
    if ((curve.p & 1) == 0 || primality == 0) {
        out.status = "HIT";
        out.lines.push_back("impact = a non-prime field modulus destroys the intended finite-field structure and invalidates ECC security claims");
    } else {
        out.status = "PASS";
        out.lines.push_back("rationale = the field modulus looks prime under a probabilistic primality check");
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult subgroup_order_not_prime_module(const CheckInfo& info, const Curve& curve) {
    ModuleResult out = make_base(info, false);
    const int primality = mpz_probab_prime_p(curve.n.get_mpz_t(), 25);
    out.lines.push_back("subgroup_order_bits = " + std::to_string(mpz_sizeinbase(curve.n.get_mpz_t(), 2)));
    out.lines.push_back("probable_prime_result = " + std::to_string(primality));
    if (curve.n <= 1 || (curve.n & 1) == 0 || primality == 0) {
        out.status = "HIT";
        out.lines.push_back("impact = a non-prime subgroup order opens the door to subgroup decomposition and invalid security assumptions");
    } else {
        out.status = "PASS";
        out.lines.push_back("rationale = the claimed subgroup order looks prime under a probabilistic primality check");
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult generator_at_infinity_module(const CheckInfo& info, const Curve& curve) {
    ModuleResult out = make_base(info, false);
    out.lines.push_back(std::string("generator_at_infinity = ") + (curve.G.inf ? "true" : "false"));
    if (curve.G.inf) {
        out.status = "HIT";
        out.lines.push_back("impact = the point at infinity cannot serve as a secure base point for ECC");
    } else {
        out.status = "PASS";
        out.lines.push_back("rationale = the configured generator is a concrete affine point");
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult basic_validation_module(const Curve& curve, const Point& Q, const ChallengeInput& in, bool pubkey_parsed, const std::string& parse_error) {
    ModuleResult out;
    out.id = "basic_validation";
    out.fault_name = "Basic challenge validation";
    out.category = "sanity";
    out.severity = "info";
    out.status = "PASS";
    out.lines.push_back("curve_name = " + curve.name);
    out.lines.push_back("curve_family = " + curve.family);
    out.lines.push_back(std::string("active_algebra_supported = ") + (curve.active_algebra_supported ? "true" : "false"));
    out.lines.push_back("signatures = " + std::to_string(in.signatures.size()));
    out.lines.push_back("facts = " + std::to_string(in.facts.size()));
    out.lines.push_back(std::string("public_key_parsed = ") + (pubkey_parsed ? "true" : "false"));
    if (pubkey_parsed) out.lines.push_back(std::string("public_key_on_curve = ") + (is_on_curve(curve, Q) ? "true" : "false"));
    else out.lines.push_back("parse_error = " + parse_error);
    if (curve.h != 1) {
        out.lines.push_back("cofactor = " + curve.h.get_str());
    }
    finalize_module_metadata(out);
    return out;
}

ModuleResult make_fact_risk(const ChallengeInput& in, const CheckInfo& info, const std::string& key,
                            const std::vector<std::string>& risky_values, const std::string& impact) {
    ModuleResult r = make_base(info, false);
    const auto v = fact_get(in, key);
    if (!v) {
        r.status = "INFO";
        r.lines.push_back("evidence = no matching fact was supplied in the JSON input");
        r.lines.push_back("expected_fact = " + key);
        finalize_module_metadata(r);
        return r;
    }
    if (fact_in(in, key, risky_values)) {
        r.status = "HIT";
        r.lines.push_back("evidence = fact " + key + " = " + *v);
        r.lines.push_back("impact = " + impact);
        finalize_module_metadata(r);
        return r;
    }
    r.status = "PASS";
    r.lines.push_back("evidence = fact " + key + " = " + *v);
    r.lines.push_back("rationale = supplied fact does not match the risky pattern for this fault class");
    finalize_module_metadata(r);
    return r;
}

ModuleResult make_bool_risk(const ChallengeInput& in, const CheckInfo& info, const std::string& key,
                            const std::string& impact, bool risky_when_true = true) {
    ModuleResult r = make_base(info, false);
    const auto v = fact_get(in, key);
    if (!v) {
        r.status = "INFO";
        r.lines.push_back("evidence = no matching fact was supplied in the JSON input");
        r.lines.push_back("expected_fact = " + key);
        finalize_module_metadata(r);
        return r;
    }
    const bool truth = fact_is_true(in, key);
    if ((risky_when_true && truth) || (!risky_when_true && !truth)) {
        r.status = "HIT";
        r.lines.push_back("evidence = fact " + key + " = " + *v);
        r.lines.push_back("impact = " + impact);
        finalize_module_metadata(r);
        return r;
    }
    r.status = "PASS";
    r.lines.push_back("evidence = fact " + key + " = " + *v);
    r.lines.push_back("rationale = supplied fact indicates a safer configuration for this fault class");
    finalize_module_metadata(r);
    return r;
}

std::vector<CheckInfo> catalog() {
    return {
        {"invalid_public_key_encoding_acceptance", "Invalid public key encoding acceptance", "validation", "high"},
        {"point_at_infinity_acceptance", "Point at infinity acceptance", "validation", "critical"},
        {"off_curve_public_key_acceptance", "Off-curve public key acceptance", "validation", "critical"},
        {"subgroup_check_missing", "Missing subgroup membership check", "validation", "critical"},
        {"cofactor_clearing_missing", "Missing cofactor clearing", "validation", "high"},
        {"invalid_curve_acceptance", "Invalid-curve point acceptance", "validation", "critical"},
        {"twist_point_acceptance", "Twist point acceptance", "validation", "critical"},
        {"untrusted_custom_curve_parameters", "Untrusted custom curve parameters", "curve", "high"},
        {"generator_unchecked", "Generator point not validated", "curve", "high"},
        {"curve_order_unchecked", "Curve order not validated", "curve", "high"},
        {"curve_discriminant_failure", "Singular or degenerate curve parameters", "curve", "critical"},
        {"field_modulus_not_prime", "Field modulus is not prime", "curve", "critical"},
        {"subgroup_order_not_prime", "Claimed subgroup order is not prime", "curve", "critical"},
        {"generator_at_infinity", "Generator is the point at infinity", "curve", "critical"},
        {"generator_not_on_curve", "Generator point not on curve", "curve", "critical"},
        {"generator_order_mismatch", "Generator order mismatch", "curve", "critical"},
        {"public_key_subgroup_mismatch", "Public key is not in the claimed subgroup", "curve", "critical"},
        {"nontrivial_cofactor_notice", "Non-trivial cofactor requires explicit handling", "curve", "medium"},
        {"tiny_public_key_multiple_scan", "Public key falls in a tiny scalar range", "keygen", "critical"},
        {"signature_component_range_failure", "Out-of-range signature component", "ecdsa", "high"},
        {"high_s_malleability_acceptance", "High-S malleability acceptance", "ecdsa", "medium"},
        {"duplicate_message_hashes", "Duplicate message hash across signatures", "ecdsa", "medium"},
        {"repeated_r_values", "Repeated ECDSA r values", "ecdsa", "critical"},
        {"exact_nonce_reuse", "Exact ECDSA nonce reuse", "ecdsa", "critical"},
        {"related_nonce_delta_scan", "Linearly related ECDSA nonces", "ecdsa", "critical"},
        {"counter_nonce_sequence_scan", "Counter-sequenced ECDSA nonces", "rng", "critical"},
        {"nonce_affine_relation_scan", "Affine ECDSA nonce relation", "ecdsa", "critical"},
        {"small_nonce_bsgs", "Small ECDSA nonce", "ecdsa", "critical"},
        {"small_private_key_bsgs", "Small private key range", "keygen", "critical"},
        {"pid_scalar_nonce_scan", "PID-sized scalar nonce generation", "rng", "critical"},
        {"unix_time_scalar_nonce_scan", "Unix-time scalar nonce generation", "rng", "critical"},
        {"nonce_source_time_seeded", "Time-seeded nonce generation", "rng", "critical"},
        {"nonce_source_rand", "rand()-based nonce generation", "rng", "critical"},
        {"nonce_source_counter", "Counter-based nonce generation", "rng", "critical"},
        {"nonce_source_lcg", "LCG-based nonce generation", "rng", "critical"},
        {"nonce_source_predictable_file_seed", "Predictable file-seeded nonce generation", "rng", "high"},
        {"nonce_not_rfc6979", "Nonce generation not tied to RFC6979 or equivalent deterministic DRBG", "rng", "high"},
        {"nonce_partial_lsb_leak", "Partial nonce leakage in low bits", "rng", "critical"},
        {"nonce_partial_msb_leak", "Partial nonce leakage in high bits", "rng", "critical"},
        {"nonce_fixed_high_bits", "Nonce with fixed high bits", "rng", "critical"},
        {"nonce_fixed_low_bits", "Nonce with fixed low bits", "rng", "critical"},
        {"nonce_statistical_bias", "Biased nonce distribution", "rng", "critical"},
        {"rng_state_reuse_after_fork", "RNG state reuse after fork", "rng", "critical"},
        {"rng_state_reuse_after_crash", "RNG state reuse after crash or restart", "rng", "high"},
        {"rng_cross_thread_race", "Cross-thread RNG race or unsafely shared state", "rng", "high"},
        {"deterministic_nonce_cross_message_reuse", "Deterministic nonce reuse across distinct messages", "rng", "critical"},
        {"key_derived_from_password", "Private key derived from password material", "keygen", "critical"},
        {"key_derived_from_timestamp", "Private key derived from timestamp material", "keygen", "critical"},
        {"key_from_small_range", "Private key drawn from a tiny range", "keygen", "critical"},
        {"key_from_predictable_seed", "Private key derived from predictable seed material", "keygen", "critical"},
        {"cross_protocol_scalar_reuse", "Cross-protocol scalar reuse", "protocol", "critical"},
        {"x_coordinate_only_ecdh", "ECDH uses x-coordinate only as the shared secret", "ecdh", "high"},
        {"shared_secret_without_kdf", "Shared secret used without a KDF", "ecdh", "critical"},
        {"raw_shared_secret_as_symmetric_key", "Raw shared secret used directly as a symmetric key", "ecdh", "critical"},
        {"truncated_shared_secret", "Truncated shared secret before KDF or confirmation", "ecdh", "high"},
        {"missing_key_confirmation", "Missing key confirmation", "ecdh", "medium"},
        {"missing_domain_separation_in_hashing", "Missing domain separation in hashing", "protocol", "medium"},
        {"hash_to_integer_mismatch", "Hash-to-integer mismatch or truncation confusion", "protocol", "high"},
        {"oracle_success_fail_leak", "Success/fail oracle exposure", "oracle", "critical"},
        {"oracle_x_coordinate_leak", "Raw x-coordinate oracle exposure", "oracle", "critical"},
        {"oracle_decrypt_validity_leak", "Decrypt-validity oracle exposure", "oracle", "critical"},
        {"oracle_timing_leak_declared", "Timing side channel declared in oracle path", "oracle", "high"},
        {"weak_compressed_point_parser", "Weak compressed-point parser", "parser", "high"},
        {"verifier_accepts_out_of_range_r_or_s", "Verifier accepts out-of-range r or s", "verification", "critical"},
        {"verifier_accepts_zero_r_or_s", "Verifier accepts zero-valued r or s", "verification", "critical"},
        {"verifier_accepts_mixed_curve_domain", "Verifier accepts mixed-curve domain parameters", "verification", "critical"},
        {"verifier_skips_public_key_validation", "Verifier skips public-key validation", "verification", "critical"},
        {"shared_secret_reuse_across_sessions", "Shared secret reused across sessions", "ecdh", "high"},
        {"no_ephemeral_key_rotation", "No ephemeral key rotation", "ecdh", "high"},
        {"signature_nonce_shared_with_ecdh", "ECDSA nonce or scalar reused in ECDH context", "protocol", "critical"},
        {"replay_protection_absent", "Replay protection absent", "protocol", "medium"},
        {"protocol_error_messages_too_specific", "Protocol error messages reveal too much detail", "protocol", "medium"},
        {"counter_based_nonce_generation", "Counter-based nonce generation", "rng", "critical"},
        {"pid_based_nonce_generation", "PID-based nonce generation", "rng", "critical"},
        {"message_only_nonce_derivation", "Nonce derived from message material without RFC6979 discipline", "rng", "critical"},
        {"nonce_reseeding_on_every_signature", "Nonce generator reseeded on every signature", "rng", "high"},
        {"custom_rng_without_health_tests", "Custom RNG without health tests", "rng", "high"},
        {"nonce_partial_lsb_bruteforce", "Partial low-bit ECDSA nonce leakage", "rng", "critical"},
        {"nonce_partial_msb_bruteforce", "Partial high-bit ECDSA nonce leakage", "rng", "critical"},
        {"message_hash_scalar_nonce", "Message-hash derived nonce generation", "rng", "critical"},
        {"unix_time_pid_nonce_scan", "Unix-time and PID derived nonce generation", "rng", "critical"},
        {"lcg_raw_state_nonce_scan", "LCG raw-state nonce generation", "rng", "critical"},
        {"c_rand15_nonce_scan", "C rand()-style 15-bit nonce generation", "rng", "critical"},
        {"message_hash_plus_counter_nonce_scan", "Message-hash plus counter nonce generation", "rng", "critical"},
        {"lcg_raw_state_sequence_scan", "LCG state-stream nonce sequence", "rng", "critical"},
        {"c_rand15_sequence_scan", "C rand()-style nonce sequence", "rng", "critical"},
        {"message_hash_xor_counter_nonce_scan", "Message-hash XOR counter nonce generation", "rng", "critical"},
        {"unix_time_pid_counter_nonce_scan", "Unix-time, PID, and counter nonce generation", "rng", "critical"},
        {"nonce_source_mt19937", "MT19937-based nonce generation", "rng", "high"},
        {"nonce_source_xorshift", "Xorshift-based nonce generation", "rng", "high"},
        {"device_id_plus_counter_nonce", "Device-ID plus counter nonce generation", "rng", "critical"},
        {"oracle_padding_validity_leak", "Padding-validity oracle exposure", "oracle", "critical"},
        {"parser_accepts_hybrid_pubkeys", "Hybrid SEC1 public key acceptance", "parser", "high"},
        {"parser_accepts_noncanonical_integers", "Non-canonical integer encoding acceptance", "parser", "high"},
        {"scalar_blinding_absent", "Scalar blinding absent", "implementation", "medium"},
        {"complete_formula_absent", "Complete group formulas absent", "implementation", "medium"},
        {"transcript_binding_absent", "Transcript binding absent", "protocol", "high"},
        {"static_ephemeral_key_usage", "Static ephemeral ECDH key usage", "ecdh", "high"},
        {"device_identifier_seeded_nonce", "Device-identifier seeded nonce generation", "rng", "critical"},
        {"compressed_point_length_relaxed", "Relaxed public-key length checks", "parser", "high"},
        {"signature_context_reuse", "Signature context reuse across domains", "protocol", "medium"},
        {"message_hash_plus_pid_nonce_scan", "Message-hash plus PID nonce generation", "rng", "critical"},
        {"message_hash_xor_pid_nonce_scan", "Message-hash XOR PID nonce generation", "rng", "critical"},
        {"unix_time_plus_counter_nonce_scan", "Unix-time plus counter nonce generation", "rng", "critical"},
        {"unix_time_xor_counter_nonce_scan", "Unix-time XOR counter nonce generation", "rng", "critical"},
        {"nonce_source_splitmix64", "SplitMix64-based nonce generation", "rng", "high"},
        {"nonce_source_pcg32", "PCG32-based nonce generation", "rng", "high"},
        {"splitmix64_nonce_scan", "SplitMix64-seeded nonce generation", "rng", "critical"},
        {"pcg32_nonce_scan", "PCG32-seeded nonce generation", "rng", "critical"},
        {"mt19937_nonce_scan", "MT19937-seeded nonce generation", "rng", "critical"},
        {"xorshift32_nonce_scan", "Xorshift32-seeded nonce generation", "rng", "critical"},
        {"xorshift64_nonce_scan", "Xorshift64*-seeded nonce generation", "rng", "critical"},
        {"splitmix64_sequence_scan", "SplitMix64 sequence nonce generation", "rng", "critical"},
        {"pcg32_sequence_scan", "PCG32 sequence nonce generation", "rng", "critical"},
        {"message_hash_plus_time_pid_nonce_scan", "Message-hash plus unix-time plus PID nonce generation", "rng", "critical"},
        {"message_hash_xor_time_pid_nonce_scan", "Message-hash XOR unix-time plus PID nonce generation", "rng", "critical"},
        {"message_hash_plus_time_nonce_scan", "Message-hash plus unix-time nonce generation", "rng", "critical"},
        {"message_hash_xor_time_nonce_scan", "Message-hash XOR unix-time nonce generation", "rng", "critical"},
        {"nonce_source_sfc64", "SFC64-based nonce generation", "rng", "high"},
        {"nonce_source_wyrand", "WyRand-based nonce generation", "rng", "high"},
        {"parser_accepts_duplicate_keys", "Parser accepts duplicate JSON keys", "parser", "medium"},
        {"parser_accepts_mixed_case_hex", "Parser accepts mixed-case hexadecimal ambiguities", "parser", "medium"},
        {"oracle_length_leak", "Length-based oracle exposure", "oracle", "medium"},
        {"subgroup_confinement_oracle_hint", "Subgroup confinement oracle hint", "oracle", "high"},
        {"deterministic_nonce_without_domain_tag", "Deterministic nonce without domain tag", "rng", "high"},
        {"weak_point_decompression_checks", "Weak point decompression checks", "parser", "high"},
        {"parser_accepts_trailing_garbage", "Parser accepts trailing garbage after key material", "parser", "medium"},
        {"signature_scalar_range_check_missing", "Signature scalar range check missing", "verification", "high"},
        {"nonce_source_mwc1616", "MWC1616-based nonce generation", "rng", "high"},
        {"mwc1616_nonce_scan", "MWC1616-seeded nonce generation", "rng", "critical"},
        {"sfc64_nonce_scan", "SFC64-seeded nonce generation", "rng", "critical"},
        {"wyrand_nonce_scan", "WyRand-seeded nonce generation", "rng", "critical"},
        {"parser_accepts_signed_hex", "Parser accepts signed hexadecimal scalars", "parser", "medium"},
        {"subgroup_order_unchecked", "Subgroup order not validated", "validation", "high"},
        {"tiny_seed_window_declared", "Tiny RNG seed window declared", "rng", "critical"},
        {"tiny_counter_window_declared", "Tiny counter window declared", "rng", "high"},
        {"tiny_unix_time_window_declared", "Tiny unix-time window declared", "rng", "high"},
        {"splitmix64_xor_counter_nonce_scan", "SplitMix64 XOR counter nonce generation", "rng", "critical"},
        {"pcg32_plus_counter_nonce_scan", "PCG32 plus counter nonce generation", "rng", "critical"},
        {"device_identifier_seeded_nonce_scan", "Device-identifier seeded nonce generation", "rng", "critical"},
        {"device_id_plus_counter_nonce_scan", "Device-ID plus counter nonce generation", "rng", "critical"},
        {"device_id_xor_counter_nonce_scan", "Device-ID XOR counter nonce generation", "rng", "critical"},
        {"unix_time_device_id_nonce_scan", "Unix-time plus device-ID nonce generation", "rng", "critical"},
        {"nonce_source_device_id", "Device-identifier backed nonce source", "rng", "high"},
        {"nonce_source_serial_number", "Serial-number backed nonce source", "rng", "high"},
        {"nonce_source_machine_id", "Machine-identifier backed nonce source", "rng", "high"},
        {"nonce_source_build_id", "Build-identifier backed nonce source", "rng", "high"},
        {"all_zero_shared_secret_acceptance", "All-zero shared secret acceptance", "ecdh", "critical"},
        {"contributory_ecdh_absent", "Contributory ECDH check absent", "ecdh", "high"},
        {"twist_security_unchecked", "Twist security not explicitly checked", "validation", "high"},
        {"curve_seed_provenance_missing", "Curve seed provenance missing", "curve", "medium"},
        {"parser_accepts_leading_zero_scalars", "Parser accepts leading-zero scalars", "parser", "medium"},
        {"parser_accepts_duplicate_pubkey_forms", "Parser accepts duplicated public-key forms", "parser", "medium"},
        {"batch_verifier_missing_per_signature_binding", "Batch verifier missing per-signature binding", "verification", "high"},
        {"cofactor_not_reflected_in_protocol", "Protocol ignores non-trivial cofactor handling", "protocol", "high"},
                {"ecdsa_hash_binding_absent", "ECDSA hash binding absent", "ecdsa", "high"},
        {"ecdsa_duplicate_nonce_domain_reuse", "ECDSA nonce state reused across domains", "ecdsa", "critical"},
        {"ecdsa_context_domain_separation_missing", "ECDSA signing context lacks domain separation", "ecdsa", "high"},
        {"ecdsa_batch_randomizer_reuse", "ECDSA batch verifier randomizer reuse", "ecdsa", "high"},
        {"ecdsa_nonce_fault_countermeasures_absent", "ECDSA nonce fault countermeasures absent", "ecdsa", "medium"},
        {"low_order_peer_point_acceptance", "Low-order peer point acceptance", "ecdh", "critical"},
        {"peer_key_type_confusion", "Peer key type confusion in ECDH path", "ecdh", "high"},
        {"mixed_curve_ecdh_acceptance", "Mixed-curve ECDH acceptance", "ecdh", "critical"},
        {"peer_key_revalidation_after_parse_missing", "Peer key not revalidated after parsing", "ecdh", "high"},
        {"ecdh_kdf_transcript_binding_missing", "ECDH KDF lacks transcript binding", "ecdh", "high"},
        {"ecdh_kdf_context_missing", "ECDH KDF lacks context separation", "ecdh", "medium"},
        {"ecdh_peer_identity_unbound", "ECDH peer identity not bound into key schedule", "ecdh", "high"},
        {"ecdh_unknown_key_share_risk", "Unknown key-share risk in ECDH flow", "ecdh", "high"},
        {"parser_accepts_oid_mismatch", "Parser accepts OID/domain mismatch", "parser", "high"},
        {"parser_accepts_field_length_mismatch", "Parser accepts field-length mismatch", "parser", "high"},
        {"parser_accepts_sec1_prefix_confusion", "Parser accepts SEC1 prefix confusion", "parser", "high"},
        {"parser_accepts_empty_integers", "Parser accepts empty INTEGER values", "parser", "medium"},
        {"parser_accepts_duplicate_der_fields", "Parser accepts duplicate DER fields", "parser", "high"},
        {"parser_accepts_multiple_pem_objects", "Parser accepts multiple PEM objects without isolation", "parser", "medium"},
        {"parser_accepts_mixed_case_hex_scalars", "Parser accepts mixed-case scalar text without canonicalization", "parser", "low"},
        {"parser_accepts_uncompressed_when_policy_requires_compressed", "Parser ignores compressed-point policy", "parser", "medium"},
        {"parser_error_oracle", "Parser error oracle exposure", "oracle", "high"},
        {"subgroup_classification_oracle", "Subgroup classification oracle exposure", "oracle", "critical"},
        {"invalid_curve_classification_oracle", "Invalid-curve classification oracle exposure", "oracle", "critical"},
        {"all_zero_shared_secret_oracle", "All-zero shared-secret oracle exposure", "oracle", "high"},
        {"verification_error_oracle", "Verification error oracle exposure", "oracle", "high"},
        {"twist_classification_oracle", "Twist classification oracle exposure", "oracle", "critical"},
        {"curve_order_proof_missing", "Curve order proof missing", "curve", "high"},
        {"generator_provenance_missing", "Generator provenance missing", "curve", "medium"},
        {"cofactor_provenance_missing", "Cofactor provenance missing", "curve", "medium"},
        {"twist_order_unchecked", "Twist order unchecked", "curve", "high"},
        {"custom_curve_security_rationale_missing", "Custom curve security rationale missing", "curve", "medium"},
        {"domain_parameter_identifier_mismatch", "Domain-parameter identifier mismatch", "curve", "high"},
        {"subgroup_generator_binding_missing", "Subgroup/generator binding proof missing", "curve", "high"},
        {"trace_of_frobenius_unchecked", "Trace of Frobenius not checked", "curve", "medium"},
        {"oracle_mac_validity_leak", "MAC-validity oracle exposure", "oracle", "critical"},
        {"ecdsa_low_s_policy_missing", "ECDSA low-S enforcement missing", "ecdsa", "medium"},
        {"ecdsa_zero_hash_policy_missing", "ECDSA zero-hash policy missing", "ecdsa", "low"},
        {"ecdsa_context_string_missing", "ECDSA context string missing", "ecdsa", "medium"},
        {"ecdsa_signer_role_binding_missing", "ECDSA signer role binding missing", "ecdsa", "high"},
        {"ecdsa_signer_key_commitment_missing", "ECDSA signer key commitment missing", "ecdsa", "high"},
        {"ecdsa_nonce_reuse_alarm_missing", "ECDSA nonce reuse alarm missing", "ecdsa", "high"},
        {"ecdsa_nonce_monobit_health_test_missing", "ECDSA nonce health tests missing", "ecdsa", "medium"},
        {"ecdsa_signature_length_policy_missing", "ECDSA signature length policy missing", "ecdsa", "medium"},
        {"ecdsa_signature_encoding_canonicalization_missing", "ECDSA signature canonicalization missing", "ecdsa", "high"},
        {"ecdsa_signer_accepts_external_nonce", "ECDSA signer accepts external nonce input", "ecdsa", "critical"},
        {"ecdsa_signer_allows_zero_nonce", "ECDSA signer allows zero nonce", "ecdsa", "critical"},
        {"ecdsa_signer_allows_nonce_equal_order", "ECDSA signer allows nonce equal to group order", "ecdsa", "high"},
        {"ecdsa_prehash_identifier_unbound", "ECDSA prehash identifier unbound", "ecdsa", "medium"},
        {"ecdsa_hash_algorithm_unpinned", "ECDSA hash algorithm unpinned", "ecdsa", "high"},
        {"ecdsa_nonce_retry_on_zero_missing", "ECDSA zero-nonce retry missing", "ecdsa", "medium"},
        {"verifier_accepts_duplicate_signature_encodings", "Verifier accepts duplicate signature encodings", "verification", "high"},
        {"verifier_accepts_negative_signature_scalars", "Verifier accepts negative signature scalars", "verification", "critical"},
        {"verifier_accepts_overlong_signature_integers", "Verifier accepts overlong signature INTEGER values", "verification", "high"},
        {"ecdsa_nonce_recovery_on_duplicate_r_unchecked", "Duplicate-r response plan missing", "ecdsa", "medium"},
        {"ecdsa_signer_reuses_precomputation_across_keys", "ECDSA precomputation reused across keys", "ecdsa", "medium"},
        {"ecdsa_cross_curve_signature_acceptance", "ECDSA cross-curve signature acceptance", "verification", "critical"},
        {"ecdsa_message_prefix_policy_missing", "ECDSA message prefix policy missing", "ecdsa", "medium"},
        {"ecdsa_signer_allows_raw_message_without_prehash_policy", "ECDSA raw-message policy missing", "ecdsa", "medium"},
        {"ecdsa_verifier_accepts_hash_length_mismatch", "ECDSA verifier accepts hash-length mismatch", "verification", "high"},
        {"ecdsa_aux_randomness_unbound", "ECDSA auxiliary randomness unbound", "ecdsa", "low"},
        {"ecdsa_signature_counter_unchecked", "ECDSA signing counter unchecked", "ecdsa", "low"},
        {"ecdsa_fault_injection_retry_policy_missing", "ECDSA fault retry policy missing", "ecdsa", "medium"},
        {"ecdsa_signer_state_rollback_detection_missing", "ECDSA signer state rollback detection missing", "ecdsa", "high"},
        {"ecdh_static_static_no_forward_secrecy", "Static-static ECDH without forward secrecy", "ecdh", "medium"},
        {"ecdh_ephemeral_reuse_detection_missing", "ECDH ephemeral reuse detection missing", "ecdh", "high"},
        {"ecdh_public_key_validation_order_wrong", "ECDH validation order incorrect", "ecdh", "high"},
        {"ecdh_zero_coordinate_peer_acceptance", "ECDH accepts zero-coordinate peer keys", "ecdh", "high"},
        {"ecdh_cofactor_mode_undocumented", "ECDH cofactor mode undocumented", "ecdh", "medium"},
        {"ecdh_mixed_role_key_reuse", "ECDH mixed-role key reuse", "ecdh", "high"},
        {"ecdh_shared_secret_serialized_without_length", "ECDH shared secret serialized without length framing", "ecdh", "medium"},
        {"ecdh_no_key_commitment", "ECDH key commitment absent", "ecdh", "high"},
        {"ecdh_channel_binding_missing", "ECDH channel binding missing", "ecdh", "high"},
        {"ecdh_peer_curve_identifier_unbound", "ECDH peer curve identifier unbound", "ecdh", "medium"},
        {"ecdh_shared_secret_reflection_risk", "ECDH shared secret reflection risk", "ecdh", "medium"},
        {"ecdh_unknown_key_share_detection_missing", "ECDH unknown key-share detection missing", "ecdh", "high"},
        {"ecdh_no_explicit_role_separation", "ECDH explicit role separation missing", "ecdh", "medium"},
        {"ecdh_precomputation_cache_unbound", "ECDH precomputation cache unbound", "ecdh", "medium"},
        {"ecdh_session_id_unbound", "ECDH session identifier unbound", "ecdh", "medium"},
        {"ecdh_key_confirmation_optional_by_default", "ECDH key confirmation optional by default", "ecdh", "medium"},
        {"ecdh_rejects_infinity_late", "ECDH rejects infinity too late", "ecdh", "high"},
        {"ecdh_same_key_used_for_signing_and_kex", "Same key used for ECDH and signing", "ecdh", "high"},
        {"ecdh_transcript_hash_algorithm_unpinned", "ECDH transcript hash algorithm unpinned", "ecdh", "medium"},
        {"ecdh_peer_key_cache_without_revocation", "ECDH peer key cache ignores revocation", "ecdh", "medium"},
        {"ecdh_replay_window_unbounded", "ECDH replay window unbounded", "ecdh", "medium"},
        {"ecdh_accepts_small_subgroup_cleartext_hints", "ECDH accepts subgroup hints from peer", "ecdh", "high"},
        {"ecdh_handshake_role_confusion", "ECDH handshake role confusion", "ecdh", "high"},
        {"ecdh_zero_padding_policy_missing", "ECDH zero-padding policy missing", "ecdh", "low"},
        {"ecdh_peer_fingerprint_unchecked", "ECDH peer fingerprint unchecked", "ecdh", "medium"},
        {"ecdh_secret_export_without_context", "ECDH secret export without context", "ecdh", "high"},
        {"parser_accepts_indefinite_length_der", "Parser accepts indefinite-length DER", "parser", "high"},
        {"parser_accepts_negative_integers", "Parser accepts negative INTEGER encodings", "parser", "high"},
        {"parser_accepts_overlong_length_encodings", "Parser accepts overlong length encodings", "parser", "medium"},
        {"parser_accepts_nul_in_pem", "Parser accepts embedded NUL in PEM", "parser", "medium"},
        {"parser_accepts_duplicate_spki_algorithm", "Parser accepts duplicate SPKI algorithm fields", "parser", "high"},
        {"parser_accepts_truncated_bitstring", "Parser accepts truncated BIT STRING", "parser", "high"},
        {"parser_accepts_nonminimal_oid", "Parser accepts non-minimal OID encoding", "parser", "medium"},
        {"parser_accepts_unused_bits_nonzero", "Parser accepts non-zero unused bits", "parser", "medium"},
        {"parser_accepts_whitespace_inside_hex", "Parser accepts whitespace inside hex scalars", "parser", "low"},
        {"parser_accepts_coordinate_overflow", "Parser accepts coordinate overflow", "parser", "critical"},
        {"parser_accepts_scalar_overflow_reduction", "Parser reduces out-of-range scalars silently", "parser", "critical"},
        {"parser_accepts_unknown_pem_label", "Parser accepts unknown PEM labels", "parser", "medium"},
        {"parser_accepts_extra_octet_wrap", "Parser accepts extra OCTET STRING wrapping", "parser", "medium"},
        {"parser_accepts_mixed_spki_and_sec1", "Parser accepts mixed SPKI and SEC1 envelopes", "parser", "high"},
        {"parser_accepts_duplicate_curve_identifiers", "Parser accepts duplicate curve identifiers", "parser", "high"},
        {"parser_accepts_embedded_nul_text", "Parser accepts embedded NUL text scalars", "parser", "low"},
        {"parser_accepts_invalid_base64_padding", "Parser accepts invalid base64 padding", "parser", "low"},
        {"parser_accepts_noncanonical_pem_boundaries", "Parser accepts non-canonical PEM boundaries", "parser", "low"},
        {"parser_accepts_unterminated_pem", "Parser accepts unterminated PEM blocks", "parser", "medium"},
        {"parser_accepts_invalid_asn1_tag_class", "Parser accepts invalid ASN.1 tag class", "parser", "medium"},
        {"parser_accepts_oid_alias_without_policy", "Parser accepts OID aliases without policy", "parser", "medium"},
        {"parser_accepts_zero_length_octet_string", "Parser accepts zero-length OCTET STRING", "parser", "medium"},
        {"parser_accepts_missing_null_parameters", "Parser accepts missing NULL parameters ambiguously", "parser", "low"},
        {"parser_accepts_explicit_parameters_when_named_required", "Parser accepts explicit parameters when named curve required", "parser", "high"},
        {"parser_accepts_named_curve_when_explicit_required", "Parser accepts named curve when explicit parameters required", "parser", "medium"},
        {"parser_accepts_mixed_endianness_text", "Parser accepts mixed-endianness textual scalars", "parser", "high"},
        {"parser_accepts_ber_where_der_required", "Parser accepts BER where DER required", "parser", "high"},
        {"parser_accepts_length_prefix_mismatch", "Parser accepts length-prefix mismatch", "parser", "high"},
        {"parser_accepts_duplicate_integer_sign_bits", "Parser accepts duplicate INTEGER sign bits", "parser", "medium"},
        {"parser_accepts_odd_length_hex_without_normalization", "Parser accepts odd-length hex without normalization policy", "parser", "low"},
        {"oracle_curve_identifier_leak", "Curve identifier oracle exposure", "oracle", "medium"},
        {"oracle_parser_depth_leak", "Parser depth oracle exposure", "oracle", "medium"},
        {"oracle_scalar_range_leak", "Scalar range oracle exposure", "oracle", "high"},
        {"oracle_nonce_fault_alarm_leak", "Nonce fault alarm oracle exposure", "oracle", "medium"},
        {"oracle_kdf_context_leak", "KDF context oracle exposure", "oracle", "medium"},
        {"oracle_identity_binding_leak", "Identity-binding oracle exposure", "oracle", "medium"},
        {"oracle_compressed_vs_uncompressed_leak", "Encoding-policy oracle exposure", "oracle", "medium"},
        {"oracle_named_vs_explicit_curve_leak", "Named-vs-explicit curve oracle exposure", "oracle", "medium"},
        {"oracle_padding_length_leak", "Padding-length oracle exposure", "oracle", "medium"},
        {"oracle_batch_membership_leak", "Batch-membership oracle exposure", "oracle", "high"},
        {"oracle_duplicate_signature_encoding_leak", "Duplicate-signature-encoding oracle exposure", "oracle", "medium"},
        {"oracle_low_order_classification_leak", "Low-order classification oracle exposure", "oracle", "critical"},
        {"oracle_cofactor_mode_leak", "Cofactor-mode oracle exposure", "oracle", "medium"},
        {"oracle_curve_provenance_leak", "Curve provenance oracle exposure", "oracle", "low"},
        {"oracle_seed_source_leak", "Seed-source oracle exposure", "oracle", "medium"},
        {"oracle_der_canonicalization_leak", "DER canonicalization oracle exposure", "oracle", "medium"},
        {"oracle_pem_label_leak", "PEM-label oracle exposure", "oracle", "low"},
        {"oracle_hash_algorithm_leak", "Hash-algorithm oracle exposure", "oracle", "medium"},
        {"oracle_role_binding_leak", "Role-binding oracle exposure", "oracle", "medium"},
        {"oracle_replay_window_leak", "Replay-window oracle exposure", "oracle", "medium"},
        {"oracle_transcript_binding_leak", "Transcript-binding oracle exposure", "oracle", "high"},
        {"oracle_ephemeral_reuse_leak", "Ephemeral-reuse oracle exposure", "oracle", "high"},
        {"curve_prime_generation_proof_missing", "Prime generation proof missing", "curve", "medium"},
        {"curve_order_factorization_unchecked", "Curve order factorization unchecked", "curve", "high"},
        {"curve_twist_factorization_unchecked", "Twist order factorization unchecked", "curve", "high"},
        {"curve_embedding_degree_unchecked", "Embedding degree unchecked", "curve", "medium"},
        {"curve_mov_bound_unchecked", "MOV bound unchecked", "curve", "medium"},
        {"curve_frey_ruck_unchecked", "Frey-Ruck bound unchecked", "curve", "medium"},
        {"curve_cm_discriminant_undocumented", "CM discriminant undocumented", "curve", "low"},
        {"curve_endomorphism_undocumented", "Curve endomorphism undocumented", "curve", "medium"},
        {"curve_complete_parameter_set_missing", "Complete parameter set missing", "curve", "high"},
        {"curve_base_field_encoding_mismatch", "Curve base-field encoding mismatch", "curve", "high"},
        {"curve_security_level_undocumented", "Curve security level undocumented", "curve", "medium"},
        {"curve_generation_seed_reuse_risk", "Curve generation seed reuse risk", "curve", "low"},
        {"curve_parameter_generation_process_missing", "Curve generation process missing", "curve", "medium"},
        {"curve_rigidity_claim_unsubstantiated", "Curve rigidity claim unsubstantiated", "curve", "medium"},
        {"curve_rational_torsion_unchecked", "Rational torsion unchecked", "curve", "medium"},
        {"curve_small_factor_scan_missing", "Curve small-factor scan missing", "curve", "high"},
        {"curve_quadratic_twist_cofactor_unchecked", "Quadratic twist cofactor unchecked", "curve", "high"},
        {"curve_isogeny_class_undocumented", "Curve isogeny class undocumented", "curve", "low"},
        {"curve_anomalous_check_missing", "Anomalous-curve check missing", "curve", "high"},
        {"curve_supersingularity_check_missing", "Supersingularity check missing", "curve", "high"},
        {"curve_cofactor_decomposition_missing", "Cofactor decomposition missing", "curve", "medium"},
        {"curve_parameter_versioning_missing", "Curve parameter versioning missing", "curve", "low"},
        {"curve_documentation_hash_missing", "Curve documentation hash missing", "curve", "low"},

        {"backend_pubkey_validation_differential", "Public-key validation differs across backends", "backend", "critical"},
        {"backend_signature_canonicalization_differential", "Signature canonicalization differs across backends", "backend", "high"},
        {"backend_low_s_policy_differential", "Low-S policy differs across backends", "backend", "high"},
        {"backend_invalid_curve_rejection_differential", "Invalid-curve rejection differs across backends", "backend", "critical"},
        {"backend_der_strictness_differential", "DER strictness differs across backends", "backend", "high"},
        {"backend_oid_resolution_differential", "OID resolution differs across backends", "backend", "medium"},
        {"backend_point_parser_differential", "Point parser behavior differs across backends", "backend", "high"},
        {"backend_ecdh_shared_secret_format_differential", "ECDH shared-secret formatting differs across backends", "backend", "medium"},
        {"backend_explicit_parameter_policy_differential", "Explicit-parameter policy differs across backends", "backend", "high"},
        {"backend_named_curve_alias_differential", "Named-curve alias resolution differs across backends", "backend", "medium"},
        {"backend_error_surface_differential", "Backend error surface differs in security-relevant ways", "backend", "medium"},
        {"backend_scalar_range_policy_differential", "Scalar-range policy differs across backends", "backend", "high"},
        {"backend_spki_vs_sec1_differential", "SPKI-vs-SEC1 interpretation differs across backends", "backend", "high"},
        {"backend_pem_label_differential", "PEM-label handling differs across backends", "backend", "medium"},
        {"backend_explicit_curve_parameter_differential", "Explicit-curve-parameter handling differs across backends", "backend", "high"},
        {"parser_accepts_spki_without_named_curve", "Parser accepts SPKI without a named-curve OID", "parser", "high"},
        {"parser_accepts_spki_bitstring_padding", "Parser accepts padded SPKI BIT STRING keys", "parser", "medium"},
        {"parser_accepts_raw_ec_point_without_spki", "Parser accepts raw EC points where SPKI is required", "parser", "medium"},
        {"curve_explicit_parameter_proof_missing", "Explicit curve parameters lack proof bundle", "curve", "high"},
        {"curve_spki_oid_missing", "Curve SPKI OID missing from documentation", "curve", "medium"},
        {"curve_alias_registry_mismatch", "Curve alias registry mismatch", "curve", "medium"},
        {"curve_hasse_bound_unchecked", "Curve order claim not checked against Hasse bound", "curve", "medium"},
        {"curve_twist_security_margin_undocumented", "Twist security margin undocumented", "curve", "high"},
        {"curve_prime_subgroup_ratio_unchecked", "Prime-subgroup ratio unchecked", "curve", "medium"},
        {"curve_generator_cofactor_alignment_unchecked", "Generator/cofactor alignment unchecked", "curve", "medium"},
        {"curve_twist_trace_unchecked", "Twist trace not checked", "curve", "medium"},
        {"curve_order_claim_source_missing", "Curve order claim source missing", "curve", "medium"},
    };
}


bool pubkey_matches(const Curve& curve, const Point& Q, const mpz_class& d);

ModuleResult tiny_seed_window_module(const CheckInfo& info, const ChallengeInput& in) {
    ModuleResult out = make_base(info, false);
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) {
        out.status = "INFO";
        out.lines.push_back("evidence = no explicit rng.seed_min/rng.seed_max search window was declared");
        return out;
    }
    const unsigned long long span = *seed_max - *seed_min + 1ULL;
    out.lines.push_back("seed_window = " + std::to_string(span));
    if (span <= (1ULL << 24)) {
        out.status = "HIT";
        out.lines.push_back("impact = a tiny declared seed window is small enough for practical offline nonce recovery against raw-RNG ECDSA workflows");
    } else {
        out.status = "PASS";
        out.lines.push_back("rationale = the declared seed window is not tiny enough for this opportunistic offline audit tier");
    }
    return out;
}

ModuleResult tiny_counter_window_module(const CheckInfo& info, const ChallengeInput& in) {
    ModuleResult out = make_base(info, false);
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!cmin || !cmax || *cmin > *cmax) {
        out.status = "INFO";
        out.lines.push_back("evidence = no explicit rng.counter_min/rng.counter_max window was declared");
        return out;
    }
    const unsigned long long span = *cmax - *cmin + 1ULL;
    out.lines.push_back("counter_window = " + std::to_string(span));
    if (span <= (1ULL << 20)) {
        out.status = "HIT";
        out.lines.push_back("impact = a tiny counter window materially reduces the search space for offline nonce reconstruction");
    } else {
        out.status = "PASS";
        out.lines.push_back("rationale = the declared counter window exceeds this offline audit tier");
    }
    return out;
}

ModuleResult tiny_unix_time_window_module(const CheckInfo& info, const ChallengeInput& in) {
    ModuleResult out = make_base(info, false);
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) {
        out.status = "INFO";
        out.lines.push_back("evidence = no valid unix-time window was declared");
        return out;
    }
    const unsigned long long span = in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL;
    out.lines.push_back("unix_time_window = " + std::to_string(span));
    if (span <= (1ULL << 24)) {
        out.status = "HIT";
        out.lines.push_back("impact = a narrow unix-time window is routinely searchable offline when time-derived nonces are suspected");
    } else {
        out.status = "PASS";
        out.lines.push_back("rationale = the declared unix-time window is broader than this opportunistic offline audit tier");
    }
    return out;
}


ModuleResult device_identifier_seeded_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a device-identifier nonce scan");
        return out;
    }
    if (!fact_in(in, "rng.generator", {"device_id", "device_identifier", "machine_id", "mac_address", "serial_number"})) {
        out.status = "SKIP";
        out.lines.push_back("rationale = no device-identifier generator was declared");
        return out;
    }
    const auto did_min = fact_get_ull(in, "rng.device_id_min");
    const auto did_max = fact_get_ull(in, "rng.device_id_max");
    if (!did_min || !did_max || *did_min > *did_max) {
        out.status = "SKIP";
        out.lines.push_back("rationale = rng.device_id_min and rng.device_id_max must define a valid device-id window");
        return out;
    }
    const unsigned long long span = *did_max - *did_min + 1ULL;
    if (span > (1ULL << 24)) {
        out.status = "SKIP";
        out.lines.push_back("rationale = the current offline build caps device-id enumeration to 2^24 values");
        return out;
    }
    const auto z = parse_hash_hex(in.signatures[0].hash_hex);
    const auto r = hex_to_mpz(in.signatures[0].r_hex);
    const auto s = hex_to_mpz(in.signatures[0].s_hex);
    for (unsigned long long did = *did_min; did <= *did_max; ++did) {
        const mpz_class k = mod(mpz_class(static_cast<unsigned long>(did)), curve.n);
        if (k == 0) {
            if (did == *did_max) break;
            continue;
        }
        const Point R = scalar_mul(curve, k, curve.G);
        if (mod(R.x, curve.n) != r) {
            if (did == *did_max) break;
            continue;
        }
        try {
            const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
            if (!pubkey_matches(curve, Q, d)) {
                if (did == *did_max) break;
                continue;
            }
            out.status = "HIT";
            out.recovered = true;
            out.private_key = d;
            out.lines.push_back("generator = " + lower_copy(*fact_get(in, "rng.generator")));
            out.lines.push_back("recovered_device_id = " + std::to_string(did));
            out.lines.push_back("recovered_nonce = " + k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
            out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
            out.lines.push_back("impact = persistent device identifiers create tiny searchable nonce spaces and can fully expose the signing key");
            return out;
        } catch (const std::exception&) {}
        if (did == *did_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied device-identifier nonce model");
    return out;
}

ModuleResult device_id_plus_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a device-id plus counter scan");
        return out;
    }
    if (!fact_in(in, "rng.generator", {"device_id_plus_counter", "device_identifier_plus_counter", "device_counter"})) {
        out.status = "SKIP";
        out.lines.push_back("rationale = no device-id plus counter generator was declared");
        return out;
    }
    const auto did_min = fact_get_ull(in, "rng.device_id_min");
    const auto did_max = fact_get_ull(in, "rng.device_id_max");
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!did_min || !did_max || *did_min > *did_max || !cmin || !cmax || *cmin > *cmax) {
        out.status = "SKIP";
        out.lines.push_back("rationale = device-id and counter windows must be declared");
        return out;
    }
    const unsigned long long did_span = *did_max - *did_min + 1ULL;
    const unsigned long long ctr_span = *cmax - *cmin + 1ULL;
    if (did_span > (1ULL << 22) || ctr_span > (1ULL << 20) || did_span * ctr_span > (1ULL << 28)) {
        out.status = "SKIP";
        out.lines.push_back("rationale = the current offline build caps the combined device-id plus counter search space");
        return out;
    }
    const auto z = parse_hash_hex(in.signatures[0].hash_hex);
    const auto r = hex_to_mpz(in.signatures[0].r_hex);
    const auto s = hex_to_mpz(in.signatures[0].s_hex);
    for (unsigned long long did = *did_min; did <= *did_max; ++did) {
        for (unsigned long long ctr = *cmin; ctr <= *cmax; ++ctr) {
            const mpz_class k = mod(mpz_class(static_cast<unsigned long>(did + ctr)), curve.n);
            if (k == 0) {
                if (ctr == *cmax && did == *did_max) break;
                continue;
            }
            const Point R = scalar_mul(curve, k, curve.G);
            if (mod(R.x, curve.n) != r) {
                if (ctr == *cmax) break;
                continue;
            }
            try {
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (!pubkey_matches(curve, Q, d)) {
                    if (ctr == *cmax) break;
                    continue;
                }
                out.status = "HIT";
                out.recovered = true;
                out.private_key = d;
                out.lines.push_back("generator = device_id_plus_counter");
                out.lines.push_back("recovered_device_id = " + std::to_string(did));
                out.lines.push_back("recovered_counter = " + std::to_string(ctr));
                out.lines.push_back("recovered_nonce = " + k.get_str());
                out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
                out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
                out.lines.push_back("impact = adding a tiny counter to a persistent device identifier still leaves a tractable offline nonce search");
                return out;
            } catch (const std::exception&) {}
            if (ctr == *cmax) break;
        }
        if (did == *did_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied device-id plus counter model");
    return out;
}

ModuleResult device_id_xor_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a device-id XOR counter scan");
        return out;
    }
    if (!fact_in(in, "rng.generator", {"device_id_xor_counter", "device_identifier_xor_counter", "machine_id_xor_counter"})) {
        out.status = "SKIP";
        out.lines.push_back("rationale = no device-id XOR counter generator was declared");
        return out;
    }
    const auto did_min = fact_get_ull(in, "rng.device_id_min");
    const auto did_max = fact_get_ull(in, "rng.device_id_max");
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!did_min || !did_max || *did_min > *did_max || !cmin || !cmax || *cmin > *cmax) {
        out.status = "SKIP";
        out.lines.push_back("rationale = device-id and counter windows must be declared");
        return out;
    }
    const unsigned long long did_span = *did_max - *did_min + 1ULL;
    const unsigned long long ctr_span = *cmax - *cmin + 1ULL;
    if (did_span > (1ULL << 22) || ctr_span > (1ULL << 20) || did_span * ctr_span > (1ULL << 28)) {
        out.status = "SKIP";
        out.lines.push_back("rationale = the current offline build caps the combined device-id XOR counter search space");
        return out;
    }
    const auto z = parse_hash_hex(in.signatures[0].hash_hex);
    const auto r = hex_to_mpz(in.signatures[0].r_hex);
    const auto s = hex_to_mpz(in.signatures[0].s_hex);
    for (unsigned long long did = *did_min; did <= *did_max; ++did) {
        for (unsigned long long ctr = *cmin; ctr <= *cmax; ++ctr) {
            const mpz_class k = mod(mpz_class(static_cast<unsigned long>(did ^ ctr)), curve.n);
            if (k == 0) {
                if (ctr == *cmax && did == *did_max) break;
                continue;
            }
            const Point R = scalar_mul(curve, k, curve.G);
            if (mod(R.x, curve.n) != r) {
                if (ctr == *cmax) break;
                continue;
            }
            try {
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (!pubkey_matches(curve, Q, d)) {
                    if (ctr == *cmax) break;
                    continue;
                }
                out.status = "HIT";
                out.recovered = true;
                out.private_key = d;
                out.lines.push_back("generator = device_id_xor_counter");
                out.lines.push_back("recovered_device_id = " + std::to_string(did));
                out.lines.push_back("recovered_counter = " + std::to_string(ctr));
                out.lines.push_back("recovered_nonce = " + k.get_str());
                out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
                out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
                out.lines.push_back("impact = XORing a device identifier with a tiny counter still leaves a bounded offline search for the ECDSA nonce");
                return out;
            } catch (const std::exception&) {}
            if (ctr == *cmax) break;
        }
        if (did == *did_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied device-id XOR counter model");
    return out;
}

ModuleResult unix_time_device_id_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a unix-time plus device-id scan");
        return out;
    }
    if (!fact_in(in, "rng.generator", {"unix_time_plus_device_id", "time_plus_device_id", "unix_time_device_id"})) {
        out.status = "SKIP";
        out.lines.push_back("rationale = no unix-time plus device-id generator was declared");
        return out;
    }
    const auto did_min = fact_get_ull(in, "rng.device_id_min");
    const auto did_max = fact_get_ull(in, "rng.device_id_max");
    if (!did_min || !did_max || *did_min > *did_max) {
        out.status = "SKIP";
        out.lines.push_back("rationale = rng.device_id_min and rng.device_id_max must define a valid device-id window");
        return out;
    }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) {
        out.status = "SKIP";
        out.lines.push_back("rationale = a valid unix-time window is required");
        return out;
    }
    const unsigned long long did_span = *did_max - *did_min + 1ULL;
    const unsigned long long time_span = in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL;
    if (did_span > (1ULL << 20) || time_span > (1ULL << 24) || did_span * time_span > (1ULL << 28)) {
        out.status = "SKIP";
        out.lines.push_back("rationale = the current offline build caps the combined unix-time plus device-id search space");
        return out;
    }
    const auto z = parse_hash_hex(in.signatures[0].hash_hex);
    const auto r = hex_to_mpz(in.signatures[0].r_hex);
    const auto s = hex_to_mpz(in.signatures[0].s_hex);
    for (unsigned long long ts = in.constraints.unix_time_min; ts <= in.constraints.unix_time_max; ++ts) {
        for (unsigned long long did = *did_min; did <= *did_max; ++did) {
            const mpz_class k = mod(mpz_class(static_cast<unsigned long>(ts + did)), curve.n);
            if (k == 0) {
                if (did == *did_max && ts == in.constraints.unix_time_max) break;
                continue;
            }
            const Point R = scalar_mul(curve, k, curve.G);
            if (mod(R.x, curve.n) != r) {
                if (did == *did_max) break;
                continue;
            }
            try {
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (!pubkey_matches(curve, Q, d)) {
                    if (did == *did_max) break;
                    continue;
                }
                out.status = "HIT";
                out.recovered = true;
                out.private_key = d;
                out.lines.push_back("generator = unix_time_plus_device_id");
                out.lines.push_back("recovered_unix_time = " + std::to_string(ts));
                out.lines.push_back("recovered_device_id = " + std::to_string(did));
                out.lines.push_back("recovered_nonce = " + k.get_str());
                out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
                out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
                out.lines.push_back("impact = combining wall-clock time with a stable device identifier still leaves a searchable nonce space");
                return out;
            } catch (const std::exception&) {}
            if (did == *did_max) break;
        }
        if (ts == in.constraints.unix_time_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied unix-time plus device-id model");
    return out;
}

ModuleResult splitmix64_xor_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a SplitMix64 XOR counter search"); return out; }
    if (!fact_in(in, "rng.generator", {"splitmix64_xor_counter", "splitmix64_counter_xor"})) { out.status = "SKIP"; out.lines.push_back("rationale = no SplitMix64 XOR counter generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max || !cmin || !cmax || *cmin > *cmax) { out.status = "SKIP"; out.lines.push_back("rationale = rng.seed_min/rng.seed_max and rng.counter_min/rng.counter_max must define valid windows"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps SplitMix64 seed enumeration to 2^24 values"); return out; }
    if (*cmax - *cmin + 1ULL > (1ULL << 20)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps counter enumeration to 2^20 values"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0, winner_ctr = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                std::uint64_t state = static_cast<std::uint64_t>(seed);
                std::uint64_t output = 0;
                for (unsigned long long t = 0; t <= discard; ++t) output = splitmix64_next(state + t);
                for (unsigned long long ctr = *cmin; ctr <= *cmax && !found.load(std::memory_order_relaxed); ++ctr) {
                    const mpz_class k = mod(mpz_class(static_cast<unsigned long>(output ^ ctr)), curve.n);
                    if (k <= 0 || k >= curve.n) continue;
                    const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_ctr = ctr; winner_k = k; winner_d = d; } }
                    }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = splitmix64_xor_counter"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_counter = " + std::to_string(winner_ctr)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = xoring a tiny counter into raw SplitMix64 output still leaves the ECDSA nonce fully enumerable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied SplitMix64 XOR counter window"); return out;
}

ModuleResult pcg32_plus_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a PCG32 plus counter search"); return out; }
    if (!fact_in(in, "rng.generator", {"pcg32_plus_counter", "pcg32_counter_plus"})) { out.status = "SKIP"; out.lines.push_back("rationale = no PCG32 plus counter generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max || !cmin || !cmax || *cmin > *cmax) { out.status = "SKIP"; out.lines.push_back("rationale = rng.seed_min/rng.seed_max and rng.counter_min/rng.counter_max must define valid windows"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps PCG32 seed enumeration to 2^24 values"); return out; }
    if (*cmax - *cmin + 1ULL > (1ULL << 20)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps counter enumeration to 2^20 values"); return out; }
    const unsigned long long inc = fact_get_ull(in, "rng.pcg.inc").value_or(1442695040888963407ULL);
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0, winner_ctr = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                std::uint64_t state = static_cast<std::uint64_t>(seed);
                std::uint32_t outv = 0;
                for (unsigned long long t = 0; t <= discard; ++t) {
                    const std::uint64_t oldstate = state;
                    state = oldstate * 6364136223846793005ULL + (inc | 1ULL);
                    outv = pcg32_output(oldstate);
                }
                for (unsigned long long ctr = *cmin; ctr <= *cmax && !found.load(std::memory_order_relaxed); ++ctr) {
                    const mpz_class k = mod(mpz_class(static_cast<unsigned long>(outv + ctr)), curve.n);
                    if (k <= 0 || k >= curve.n) continue;
                    const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_ctr = ctr; winner_k = k; winner_d = d; } }
                    }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = pcg32_plus_counter"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_counter = " + std::to_string(winner_ctr)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = adding a tiny counter to raw PCG32 output still yields an offline-searchable ECDSA nonce stream"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied PCG32 plus counter window"); return out;
}

ModuleResult signature_component_range_module(const CheckInfo& info, const Curve& curve, const ChallengeInput& in) {
    ModuleResult out = make_base(info, false);
    if (in.signatures.empty()) {
        out.status = "INFO";
        out.lines.push_back("evidence = no signatures were supplied for a component range audit");
        return out;
    }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto r = hex_to_mpz(in.signatures[i].r_hex);
        const auto s = hex_to_mpz(in.signatures[i].s_hex);
        if (r <= 0 || r >= curve.n || s <= 0 || s >= curve.n) {
            out.status = "HIT";
            out.lines.push_back("signature_index = " + std::to_string(i));
            out.lines.push_back("impact = malformed signature components can collapse verifier assumptions or trigger unsafe edge cases");
            return out;
        }
    }
    out.status = "PASS";
    out.lines.push_back("evidence = all supplied signatures have 0 < r,s < n");
    return out;
}

ModuleResult high_s_policy_module(const CheckInfo& info, const Curve& curve, const ChallengeInput& in) {
    ModuleResult out = make_base(info, false);
    if (in.signatures.empty()) {
        out.status = "INFO";
        out.lines.push_back("evidence = no signatures were supplied for a high-S audit");
        return out;
    }
    const mpz_class half_n = curve.n / 2;
    std::size_t count = 0;
    for (const auto& sig : in.signatures) {
        if (hex_to_mpz(sig.s_hex) > half_n) ++count;
    }
    if (count > 0) {
        out.status = "HIT";
        out.lines.push_back("evidence = " + std::to_string(count) + " supplied signature(s) use high-S form");
        out.lines.push_back("impact = accepting high-S values preserves malleability classes unless the protocol normalizes them");
        return out;
    }
    out.status = "PASS";
    out.lines.push_back("evidence = all supplied signatures are already in low-S form");
    return out;
}

ModuleResult duplicate_hash_module(const CheckInfo& info, const ChallengeInput& in) {
    ModuleResult out = make_base(info, false);
    if (in.signatures.size() < 2) {
        out.status = "INFO";
        out.lines.push_back("evidence = at least two signatures are needed to test for duplicate message digests");
        return out;
    }
    std::map<std::string, int> seen;
    for (const auto& sig : in.signatures) ++seen[normalize_hex(sig.hash_hex)];
    for (const auto& kv : seen) {
        if (kv.second > 1) {
            out.status = "HIT";
            out.lines.push_back("evidence = digest " + kv.first + " appears " + std::to_string(kv.second) + " times");
            out.lines.push_back("impact = repeated digests can amplify nonce and malleability failures across repeated signing workflows");
            return out;
        }
    }
    out.status = "PASS";
    out.lines.push_back("evidence = all supplied message digests are distinct");
    return out;
}

ModuleResult repeated_r_module(const CheckInfo& info, const ChallengeInput& in) {
    ModuleResult out = make_base(info, false);
    if (in.signatures.size() < 2) {
        out.status = "INFO";
        out.lines.push_back("evidence = at least two signatures are needed to test for repeated r values");
        return out;
    }
    std::map<std::string, int> seen;
    for (const auto& sig : in.signatures) ++seen[normalize_hex(sig.r_hex)];
    for (const auto& kv : seen) {
        if (kv.second > 1) {
            out.status = "HIT";
            out.lines.push_back("evidence = r value " + kv.first + " appears " + std::to_string(kv.second) + " times");
            out.lines.push_back("impact = repeated r values are a classic marker for nonce reuse or sign-flipped nonces");
            return out;
        }
    }
    out.status = "PASS";
    out.lines.push_back("evidence = no repeated r values were observed");
    return out;
}

bool pubkey_matches(const Curve& curve, const Point& Q, const mpz_class& d) {
    return point_key(scalar_mul(curve, d, curve.G)) == point_key(Q);
}

ModuleResult exact_nonce_reuse_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.size() < 2) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least two signatures are needed for an exact nonce reuse attack");
        return out;
    }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z1 = parse_hash_hex(in.signatures[i].hash_hex);
        const auto r1 = hex_to_mpz(in.signatures[i].r_hex);
        const auto s1 = hex_to_mpz(in.signatures[i].s_hex);
        for (std::size_t j = i + 1; j < in.signatures.size(); ++j) {
            const auto z2 = parse_hash_hex(in.signatures[j].hash_hex);
            const auto r2 = hex_to_mpz(in.signatures[j].r_hex);
            const auto s2 = hex_to_mpz(in.signatures[j].s_hex);
            if (r1 != r2) continue;
            for (const auto& s2eff : {s2, mod(-s2, curve.n)}) {
                try {
                    const mpz_class denom = mod(s1 - s2eff, curve.n);
                    if (denom == 0) continue;
                    const mpz_class k = mod((z1 - z2) * inv_mod(denom, curve.n), curve.n);
                    const mpz_class d = mod((s1 * k - z1) * inv_mod(r1, curve.n), curve.n);
                    if (pubkey_matches(curve, Q, d)) {
                        out.status = "HIT";
                        out.recovered = true;
                        out.private_key = d;
                        out.lines.push_back("signature_pair = " + std::to_string(i) + "," + std::to_string(j));
                        out.lines.push_back("recovered_nonce = " + k.get_str());
                        out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
                        out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
                        out.lines.push_back("impact = a single reused ECDSA nonce exposes the long-term signing key");
                        if (s2eff != s2) out.lines.push_back("note = the solver matched a sign-flipped s variant for the second signature");
                        return out;
                    }
                } catch (const std::exception&) {}
            }
        }
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no solvable exact nonce reuse pair was recovered from the supplied signatures");
    return out;
}

ModuleResult related_nonce_delta_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.size() < 2) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least two signatures are needed for a related-nonce delta scan");
        return out;
    }
    if (in.constraints.related_delta_max <= 0) {
        out.status = "SKIP";
        out.lines.push_back("rationale = constraints.related_delta_max was not supplied");
        return out;
    }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z1 = parse_hash_hex(in.signatures[i].hash_hex);
        const auto r1 = hex_to_mpz(in.signatures[i].r_hex);
        const auto s1 = hex_to_mpz(in.signatures[i].s_hex);
        for (std::size_t j = i + 1; j < in.signatures.size(); ++j) {
            const auto z2 = parse_hash_hex(in.signatures[j].hash_hex);
            const auto r2 = hex_to_mpz(in.signatures[j].r_hex);
            const auto s2 = hex_to_mpz(in.signatures[j].s_hex);
            const mpz_class denom = mod(s2 * r1 - s1 * r2, curve.n);
            if (denom == 0) continue;
            std::atomic<bool> found(false);
            mpz_class winner_d, winner_k1;
            long long winner_delta = 0;
#pragma omp parallel for schedule(static)
            for (long long delta = -in.constraints.related_delta_max; delta <= in.constraints.related_delta_max; ++delta) {
                if (delta == 0 || found.load(std::memory_order_relaxed)) continue;
                try {
                    const mpz_class dlt = (delta >= 0) ? mpz_class(static_cast<unsigned long>(delta)) : -mpz_class(static_cast<unsigned long>(-delta));
                    const mpz_class num = mod(s1 * z2 - s2 * z1 - dlt * s1 * s2, curve.n);
                    const mpz_class d = mod(num * inv_mod(denom, curve.n), curve.n);
                    const mpz_class k1 = mod((z1 + r1 * d) * inv_mod(s1, curve.n), curve.n);
                    const mpz_class k2 = mod((z2 + r2 * d) * inv_mod(s2, curve.n), curve.n);
                    if (mod(k2 - k1, curve.n) != mod(dlt, curve.n)) continue;
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        {
                            if (!found.load(std::memory_order_relaxed)) {
                                found.store(true, std::memory_order_relaxed);
                                winner_delta = delta;
                                winner_d = d;
                                winner_k1 = k1;
                            }
                        }
                    }
                } catch (const std::exception&) {}
            }
            if (found.load()) {
                out.status = "HIT";
                out.recovered = true;
                out.private_key = winner_d;
                out.lines.push_back("signature_pair = " + std::to_string(i) + "," + std::to_string(j));
                out.lines.push_back("delta = " + std::to_string(winner_delta));
                out.lines.push_back("recovered_k1 = " + winner_k1.get_str());
                out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str());
                out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}");
                out.lines.push_back("impact = linear relations between nonces collapse ECDSA secrecy with just a few signatures");
                return out;
            }
        }
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no linear nonce relation was recovered in the requested delta window");
    out.lines.push_back("delta_window = [" + std::to_string(-in.constraints.related_delta_max) + ", " + std::to_string(in.constraints.related_delta_max) + "]");
    return out;
}

ModuleResult counter_nonce_sequence_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.size() < 2) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least two signatures are needed for a counter-sequence nonce recovery");
        return out;
    }
    if (!fact_in(in, "rng.generator", {"global_counter", "counter", "incrementing_counter", "monotonic_counter"})) {
        out.status = "SKIP";
        out.lines.push_back("rationale = no counter-like nonce generator was declared");
        return out;
    }
    if (in.constraints.related_delta_max <= 0) {
        out.status = "SKIP";
        out.lines.push_back("rationale = constraints.related_delta_max must bound the counter step search");
        return out;
    }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z1 = parse_hash_hex(in.signatures[i].hash_hex);
        const auto r1 = hex_to_mpz(in.signatures[i].r_hex);
        const auto s1 = hex_to_mpz(in.signatures[i].s_hex);
        for (std::size_t j = i + 1; j < in.signatures.size(); ++j) {
            const auto z2 = parse_hash_hex(in.signatures[j].hash_hex);
            const auto r2 = hex_to_mpz(in.signatures[j].r_hex);
            const auto s2 = hex_to_mpz(in.signatures[j].s_hex);
            const long long stride = static_cast<long long>(j - i);
            const mpz_class denom = mod(s2 * r1 - s1 * r2, curve.n);
            if (denom == 0) continue;
            std::atomic<bool> found(false);
            mpz_class winner_d, winner_k1;
            long long winner_step = 0;
#pragma omp parallel for schedule(static)
            for (long long step = -in.constraints.related_delta_max; step <= in.constraints.related_delta_max; ++step) {
                if (step == 0 || found.load(std::memory_order_relaxed)) continue;
                try {
                    const long long delta_ll = step * stride;
                    const mpz_class dlt = (delta_ll >= 0) ? mpz_class(static_cast<unsigned long>(delta_ll)) : -mpz_class(static_cast<unsigned long>(-delta_ll));
                    const mpz_class num = mod(s1 * z2 - s2 * z1 - dlt * s1 * s2, curve.n);
                    const mpz_class d = mod(num * inv_mod(denom, curve.n), curve.n);
                    const mpz_class k1 = mod((z1 + r1 * d) * inv_mod(s1, curve.n), curve.n);
                    const mpz_class k2 = mod((z2 + r2 * d) * inv_mod(s2, curve.n), curve.n);
                    if (mod(k2 - k1, curve.n) != mod(dlt, curve.n)) continue;
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        {
                            if (!found.load(std::memory_order_relaxed)) {
                                found.store(true, std::memory_order_relaxed);
                                winner_step = step;
                                winner_d = d;
                                winner_k1 = k1;
                            }
                        }
                    }
                } catch (const std::exception&) {}
            }
            if (found.load()) {
                out.status = "HIT";
                out.recovered = true;
                out.private_key = winner_d;
                out.lines.push_back("signature_pair = " + std::to_string(i) + "," + std::to_string(j));
                out.lines.push_back("counter_step = " + std::to_string(winner_step));
                out.lines.push_back("recovered_k1 = " + winner_k1.get_str());
                out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str());
                out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}");
                out.lines.push_back("impact = counter-driven nonce sequences are algebraically recoverable once two signatures from the same stream are available");
                return out;
            }
        }
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no counter-sequence nonce relation was recovered in the requested step window");
    out.lines.push_back("step_window = [" + std::to_string(-in.constraints.related_delta_max) + ", " + std::to_string(in.constraints.related_delta_max) + "]");
    return out;
}

ModuleResult nonce_affine_relation_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.size() < 2) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least two signatures are needed for an affine nonce scan");
        return out;
    }
    if (in.constraints.related_a_abs_max <= 0 || in.constraints.related_b_abs_max <= 0) {
        out.status = "SKIP";
        out.lines.push_back("rationale = constraints.related_a_abs_max and constraints.related_b_abs_max are required");
        return out;
    }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z1 = parse_hash_hex(in.signatures[i].hash_hex);
        const auto r1 = hex_to_mpz(in.signatures[i].r_hex);
        const auto s1 = hex_to_mpz(in.signatures[i].s_hex);
        for (std::size_t j = i + 1; j < in.signatures.size(); ++j) {
            const auto z2 = parse_hash_hex(in.signatures[j].hash_hex);
            const auto r2 = hex_to_mpz(in.signatures[j].r_hex);
            const auto s2 = hex_to_mpz(in.signatures[j].s_hex);
            std::atomic<bool> found(false);
            long long win_a = 0, win_b = 0;
            mpz_class winner_d, winner_k1;
#pragma omp parallel for collapse(2) schedule(static)
            for (long long a = -in.constraints.related_a_abs_max; a <= in.constraints.related_a_abs_max; ++a) {
                for (long long b = -in.constraints.related_b_abs_max; b <= in.constraints.related_b_abs_max; ++b) {
                    if (found.load(std::memory_order_relaxed) || a == 0) continue;
                    try {
                        const mpz_class aa = (a >= 0) ? mpz_class(static_cast<unsigned long>(a)) : -mpz_class(static_cast<unsigned long>(-a));
                        const mpz_class bb = (b >= 0) ? mpz_class(static_cast<unsigned long>(b)) : -mpz_class(static_cast<unsigned long>(-b));
                        const mpz_class denom = mod(s2 * aa * r1 - r2 * s1, curve.n);
                        if (denom == 0) continue;
                        const mpz_class num = mod(z2 * r1 - r2 * z1 - s2 * bb * r1, curve.n);
                        const mpz_class k1 = mod(num * inv_mod(denom, curve.n), curve.n);
                        const mpz_class d = mod((s1 * k1 - z1) * inv_mod(r1, curve.n), curve.n);
                        const mpz_class k2 = mod((z2 + r2 * d) * inv_mod(s2, curve.n), curve.n);
                        if (mod(k2 - (aa * k1 + bb), curve.n) != 0) continue;
                        if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                            {
                                if (!found.load(std::memory_order_relaxed)) {
                                    found.store(true, std::memory_order_relaxed);
                                    win_a = a; win_b = b; winner_d = d; winner_k1 = k1;
                                }
                            }
                        }
                    } catch (const std::exception&) {}
                }
            }
            if (found.load()) {
                out.status = "HIT";
                out.recovered = true;
                out.private_key = winner_d;
                out.lines.push_back("signature_pair = " + std::to_string(i) + "," + std::to_string(j));
                out.lines.push_back("relation = k2 = a*k1 + b");
                out.lines.push_back("a = " + std::to_string(win_a));
                out.lines.push_back("b = " + std::to_string(win_b));
                out.lines.push_back("recovered_k1 = " + winner_k1.get_str());
                out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str());
                out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}");
                out.lines.push_back("impact = affine structure in ECDSA nonces is enough to recover the long-term key offline");
                return out;
            }
        }
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no affine nonce relation was recovered inside the configured scan window");
    return out;
}


ModuleResult partial_nonce_lsb_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a partial low-bit nonce search");
        return out;
    }
    const auto lsb_bits = fact_get_ull(in, "nonce.leak.lsb_bits");
    const auto unknown_bits = fact_get_ull(in, "nonce.leak.unknown_bits");
    const auto lsb_value = fact_get_mpz(in, "nonce.leak.lsb_value");
    if (!lsb_bits || !unknown_bits || !lsb_value) {
        out.status = "SKIP";
        out.lines.push_back("rationale = facts nonce.leak.lsb_bits, nonce.leak.lsb_value, and nonce.leak.unknown_bits are required");
        return out;
    }
    if (*unknown_bits == 0 || *unknown_bits > 30 || *lsb_bits >= 256) {
        out.status = "SKIP";
        out.lines.push_back("rationale = nonce.leak.unknown_bits must be in the range 1..30 for the current bounded solver");
        return out;
    }
    const std::uint64_t bound = 1ULL << *unknown_bits;
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex);
        const auto r = hex_to_mpz(in.signatures[i].r_hex);
        const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false);
        mpz_class winner_d, winner_k;
#pragma omp parallel for schedule(static)
        for (std::uint64_t x = 0; x < bound; ++x) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                mpz_class k = *lsb_value + (mpz_class(x) << *lsb_bits);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    {
                        if (!found.load(std::memory_order_relaxed)) {
                            found.store(true, std::memory_order_relaxed);
                            winner_d = d;
                            winner_k = k;
                        }
                    }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) {
            out.status = "HIT";
            out.recovered = true;
            out.private_key = winner_d;
            out.lines.push_back("signature_index = " + std::to_string(i));
            out.lines.push_back("known_lsb_bits = " + std::to_string(*lsb_bits));
            out.lines.push_back("unknown_bits = " + std::to_string(*unknown_bits));
            out.lines.push_back("recovered_nonce = " + winner_k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str());
            out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}");
            out.lines.push_back("impact = leaking enough nonce low bits turns ECDSA key recovery into a bounded offline search");
            return out;
        }
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied low-bit nonce leakage model");
    return out;
}

ModuleResult partial_nonce_msb_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a partial high-bit nonce search");
        return out;
    }
    const auto msb_bits = fact_get_ull(in, "nonce.leak.msb_bits");
    const auto unknown_bits = fact_get_ull(in, "nonce.leak.unknown_bits");
    const auto msb_value = fact_get_mpz(in, "nonce.leak.msb_value");
    if (!msb_bits || !unknown_bits || !msb_value) {
        out.status = "SKIP";
        out.lines.push_back("rationale = facts nonce.leak.msb_bits, nonce.leak.msb_value, and nonce.leak.unknown_bits are required");
        return out;
    }
    if (*unknown_bits == 0 || *unknown_bits > 30 || *msb_bits >= 256) {
        out.status = "SKIP";
        out.lines.push_back("rationale = nonce.leak.unknown_bits must be in the range 1..30 for the current bounded solver");
        return out;
    }
    const std::uint64_t bound = 1ULL << *unknown_bits;
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex);
        const auto r = hex_to_mpz(in.signatures[i].r_hex);
        const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false);
        mpz_class winner_d, winner_k;
#pragma omp parallel for schedule(static)
        for (std::uint64_t x = 0; x < bound; ++x) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                mpz_class k = ((*msb_value) << *unknown_bits) + mpz_class(x);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    {
                        if (!found.load(std::memory_order_relaxed)) {
                            found.store(true, std::memory_order_relaxed);
                            winner_d = d;
                            winner_k = k;
                        }
                    }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) {
            out.status = "HIT";
            out.recovered = true;
            out.private_key = winner_d;
            out.lines.push_back("signature_index = " + std::to_string(i));
            out.lines.push_back("known_msb_bits = " + std::to_string(*msb_bits));
            out.lines.push_back("unknown_bits = " + std::to_string(*unknown_bits));
            out.lines.push_back("recovered_nonce = " + winner_k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str());
            out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}");
            out.lines.push_back("impact = leaking enough nonce high bits turns ECDSA key recovery into a bounded offline search");
            return out;
        }
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied high-bit nonce leakage model");
    return out;
}

ModuleResult message_hash_scalar_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a message-hash nonce test");
        return out;
    }
    if (!fact_in(in, "rng.generator", {"message_hash_scalar", "message_hash_mod_n", "hash_as_nonce"}) && !fact_is_true(in, "rng.message_only")) {
        out.status = "SKIP";
        out.lines.push_back("rationale = no message-hash nonce derivation model was declared");
        return out;
    }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex);
        const auto r = hex_to_mpz(in.signatures[i].r_hex);
        const auto s = hex_to_mpz(in.signatures[i].s_hex);
        try {
            const mpz_class k = mod(z, curve.n);
            const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
            if (pubkey_matches(curve, Q, d)) {
                out.status = "HIT";
                out.recovered = true;
                out.private_key = d;
                out.lines.push_back("signature_index = " + std::to_string(i));
                out.lines.push_back("recovered_nonce = hash(message) mod n");
                out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
                out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
                out.lines.push_back("impact = deriving ECDSA nonces directly from message hashes destroys unpredictability and usually leaks the long-term key");
                return out;
            }
        } catch (const std::exception&) {}
    }
    out.status = "MISS";
    out.lines.push_back("rationale = the message-hash scalar model did not match the supplied signatures");
    return out;
}

ModuleResult unix_time_pid_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a time-plus-pid nonce search");
        return out;
    }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) {
        out.status = "SKIP";
        out.lines.push_back("rationale = constraints.unix_time_min and constraints.unix_time_max must define a valid search window");
        return out;
    }
    const auto pid = fact_get_ull(in, "rng.pid");
    if (!pid) {
        out.status = "SKIP";
        out.lines.push_back("rationale = fact rng.pid is required for the current unix-time and PID nonce model");
        return out;
    }
    std::string generator = lower_copy(fact_get(in, "rng.generator").value_or(""));
    if (generator != "unix_time_plus_pid" && generator != "time_plus_pid" && generator != "unix_time_xor_pid" && generator != "time_xor_pid") {
        out.status = "SKIP";
        out.lines.push_back("rationale = no unix-time/PID nonce formula was declared");
        return out;
    }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex);
        const auto r = hex_to_mpz(in.signatures[i].r_hex);
        const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false);
        mpz_class winner_d, winner_k;
        unsigned long long winner_t = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                mpz_class k = (generator.find("xor") != std::string::npos) ? mpz_class(static_cast<unsigned long>(t ^ *pid)) : mpz_class(static_cast<unsigned long>(t + *pid));
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    {
                        if (!found.load(std::memory_order_relaxed)) {
                            found.store(true, std::memory_order_relaxed);
                            winner_t = t;
                            winner_d = d;
                            winner_k = k;
                        }
                    }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) {
            out.status = "HIT";
            out.recovered = true;
            out.private_key = winner_d;
            out.lines.push_back("signature_index = " + std::to_string(i));
            out.lines.push_back("generator = " + generator);
            out.lines.push_back("recovered_unix_time = " + std::to_string(winner_t));
            out.lines.push_back("pid = " + std::to_string(*pid));
            out.lines.push_back("recovered_nonce = " + winner_k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str());
            out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}");
            out.lines.push_back("impact = mixing wall-clock time with a tiny PID search space is still catastrophic for ECDSA nonce secrecy");
            return out;
        }
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied unix-time and PID nonce model");
    return out;
}


ModuleResult lcg_raw_state_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for an LCG raw-state nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"lcg_raw_state", "ansi_c_lcg_state", "lcg_state"})) { out.status = "SKIP"; out.lines.push_back("rationale = no LCG raw-state nonce generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    const auto seed_span = *seed_max - *seed_min + 1ULL;
    if (seed_span > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps LCG seed enumeration to 2^24 seeds"); return out; }
    const mpz_class a = fact_get_mpz(in, "rng.lcg.a").value_or(mpz_class("1103515245"));
    const mpz_class c = fact_get_mpz(in, "rng.lcg.c").value_or(mpz_class("12345"));
    const mpz_class m = fact_get_mpz(in, "rng.lcg.m").value_or(mpz_class("2147483648"));
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                mpz_class state = mpz_class(static_cast<unsigned long>(seed));
                for (unsigned long long t = 0; t <= discard; ++t) state = mod(a * state + c, m);
                const mpz_class k = mod(state, curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = lcg_raw_state"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = linear-congruential raw-state nonces are fully reconstructible from tiny seed windows"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied LCG seed window"); return out;
}

ModuleResult c_rand15_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a C rand()-style nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"c_rand15", "ansi_c_rand", "rand15"})) { out.status = "SKIP"; out.lines.push_back("rationale = no C rand()-style generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    const auto seed_span = *seed_max - *seed_min + 1ULL;
    if (seed_span > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps C rand()-style seed enumeration to 2^24 seeds"); return out; }
    const mpz_class a = fact_get_mpz(in, "rng.lcg.a").value_or(mpz_class("1103515245"));
    const mpz_class c = fact_get_mpz(in, "rng.lcg.c").value_or(mpz_class("12345"));
    const mpz_class m = fact_get_mpz(in, "rng.lcg.m").value_or(mpz_class("2147483648"));
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                mpz_class state = mpz_class(static_cast<unsigned long>(seed));
                for (unsigned long long t = 0; t <= discard; ++t) state = mod(a * state + c, m);
                const mpz_class k = mod((state >> 16) & mpz_class(0x7fff), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = c_rand15"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = small rand()-style outputs are catastrophic when fed directly into ECDSA nonce generation"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied C rand()-style seed window"); return out;
}

ModuleResult message_hash_plus_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a hash-plus-counter nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"message_hash_plus_counter", "hash_plus_counter", "message_hash_counter"})) { out.status = "SKIP"; out.lines.push_back("rationale = no message-hash plus counter model was declared"); return out; }
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!cmin || !cmax || *cmin > *cmax) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.counter_min and rng.counter_max must define a valid search window"); return out; }
    const auto span = *cmax - *cmin + 1ULL;
    if (span > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps counter enumeration to 2^24 values"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_ctr = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long ctr = *cmin; ctr <= *cmax; ++ctr) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                const mpz_class k = mod(z + mpz_class(static_cast<unsigned long>(ctr)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_ctr = ctr; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = message_hash_plus_counter"); out.lines.push_back("recovered_counter = " + std::to_string(winner_ctr)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = adding a tiny counter to the message hash still leaves ECDSA nonces fully enumerable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied hash-plus-counter window"); return out;
}



ModuleResult lcg_raw_state_sequence_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.size() < 2) { out.status = "SKIP"; out.lines.push_back("rationale = at least two signatures are needed for an LCG sequence search"); return out; }
    if (!fact_in(in, "rng.generator", {"lcg_sequence", "lcg_raw_state_sequence", "ansi_c_lcg_sequence"})) { out.status = "SKIP"; out.lines.push_back("rationale = no LCG sequence generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    const auto seed_span = *seed_max - *seed_min + 1ULL;
    if (seed_span > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps LCG sequence enumeration to 2^24 seeds"); return out; }
    const mpz_class a = fact_get_mpz(in, "rng.lcg.a").value_or(mpz_class("1103515245"));
    const mpz_class c = fact_get_mpz(in, "rng.lcg.c").value_or(mpz_class("12345"));
    const mpz_class m = fact_get_mpz(in, "rng.lcg.m").value_or(mpz_class("2147483648"));
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    const auto z1 = parse_hash_hex(in.signatures[0].hash_hex); const auto r1 = hex_to_mpz(in.signatures[0].r_hex); const auto s1 = hex_to_mpz(in.signatures[0].s_hex);
    const auto z2 = parse_hash_hex(in.signatures[1].hash_hex); const auto r2 = hex_to_mpz(in.signatures[1].r_hex); const auto s2 = hex_to_mpz(in.signatures[1].s_hex);
    std::atomic<bool> found(false); mpz_class winner_d, winner_k1, winner_k2; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
    for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
        if (found.load(std::memory_order_relaxed)) continue;
        try {
            mpz_class state = mpz_class(static_cast<unsigned long>(seed));
            for (unsigned long long t = 0; t <= discard; ++t) state = mod(a * state + c, m);
            const mpz_class k1 = mod(state, curve.n);
            state = mod(a * state + c, m);
            const mpz_class k2 = mod(state, curve.n);
            if (k1 <= 0 || k1 >= curve.n || k2 <= 0 || k2 >= curve.n) continue;
            const mpz_class d1 = mod((s1 * k1 - z1) * inv_mod(r1, curve.n), curve.n);
            const mpz_class d2 = mod((s2 * k2 - z2) * inv_mod(r2, curve.n), curve.n);
            if (d1 != d2) continue;
            if (pubkey_matches(curve, Q, d1)) {
#pragma omp critical
                { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k1 = k1; winner_k2 = k2; winner_d = d1; } }
            }
        } catch (const std::exception&) {}
    }
    if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_pair = 0,1"); out.lines.push_back("generator = lcg_sequence"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_k1 = " + winner_k1.get_str()); out.lines.push_back("recovered_k2 = " + winner_k2.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = successive outputs from an LCG-backed nonce stream can fully expose the long-term ECDSA key"); return out; }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied LCG sequence window"); return out;
}

ModuleResult c_rand15_sequence_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.size() < 2) { out.status = "SKIP"; out.lines.push_back("rationale = at least two signatures are needed for a rand()-sequence search"); return out; }
    if (!fact_in(in, "rng.generator", {"c_rand15_sequence", "ansi_c_rand_sequence", "rand15_sequence"})) { out.status = "SKIP"; out.lines.push_back("rationale = no C rand()-style sequence generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    const auto seed_span = *seed_max - *seed_min + 1ULL;
    if (seed_span > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps rand()-sequence enumeration to 2^24 seeds"); return out; }
    const mpz_class a = fact_get_mpz(in, "rng.lcg.a").value_or(mpz_class("1103515245"));
    const mpz_class c = fact_get_mpz(in, "rng.lcg.c").value_or(mpz_class("12345"));
    const mpz_class m = fact_get_mpz(in, "rng.lcg.m").value_or(mpz_class("2147483648"));
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    const auto z1 = parse_hash_hex(in.signatures[0].hash_hex); const auto r1 = hex_to_mpz(in.signatures[0].r_hex); const auto s1 = hex_to_mpz(in.signatures[0].s_hex);
    const auto z2 = parse_hash_hex(in.signatures[1].hash_hex); const auto r2 = hex_to_mpz(in.signatures[1].r_hex); const auto s2 = hex_to_mpz(in.signatures[1].s_hex);
    std::atomic<bool> found(false); mpz_class winner_d, winner_k1, winner_k2; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
    for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
        if (found.load(std::memory_order_relaxed)) continue;
        try {
            mpz_class state = mpz_class(static_cast<unsigned long>(seed));
            for (unsigned long long t = 0; t <= discard; ++t) state = mod(a * state + c, m);
            const mpz_class k1 = mod((state >> 16) & mpz_class(0x7fff), curve.n);
            state = mod(a * state + c, m);
            const mpz_class k2 = mod((state >> 16) & mpz_class(0x7fff), curve.n);
            if (k1 <= 0 || k1 >= curve.n || k2 <= 0 || k2 >= curve.n) continue;
            const mpz_class d1 = mod((s1 * k1 - z1) * inv_mod(r1, curve.n), curve.n);
            const mpz_class d2 = mod((s2 * k2 - z2) * inv_mod(r2, curve.n), curve.n);
            if (d1 != d2) continue;
            if (pubkey_matches(curve, Q, d1)) {
#pragma omp critical
                { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k1 = k1; winner_k2 = k2; winner_d = d1; } }
            }
        } catch (const std::exception&) {}
    }
    if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_pair = 0,1"); out.lines.push_back("generator = c_rand15_sequence"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_k1 = " + winner_k1.get_str()); out.lines.push_back("recovered_k2 = " + winner_k2.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = successive rand()-style outputs used as ECDSA nonces can fully expose the long-term key"); return out; }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied rand()-sequence window"); return out;
}

ModuleResult message_hash_xor_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a hash-xor-counter nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"message_hash_xor_counter", "hash_xor_counter", "message_hash_counter_xor"})) { out.status = "SKIP"; out.lines.push_back("rationale = no message-hash XOR counter model was declared"); return out; }
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!cmin || !cmax || *cmin > *cmax) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.counter_min and rng.counter_max must define a valid search window"); return out; }
    const auto span = *cmax - *cmin + 1ULL;
    if (span > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps counter enumeration to 2^24 values"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_ctr = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long ctr = *cmin; ctr <= *cmax; ++ctr) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                const mpz_class k = mod(z ^ mpz_class(static_cast<unsigned long>(ctr)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_ctr = ctr; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = message_hash_xor_counter"); out.lines.push_back("recovered_counter = " + std::to_string(winner_ctr)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = xoring a tiny counter into the message hash still leaves ECDSA nonces fully enumerable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied hash-xor-counter window"); return out;
}

ModuleResult unix_time_pid_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a time+pid+counter nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"unix_time_pid_counter", "time_pid_counter", "unix_time_plus_pid_plus_counter"})) { out.status = "SKIP"; out.lines.push_back("rationale = no time+pid+counter model was declared"); return out; }
    const auto pid = fact_get_ull(in, "rng.pid");
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!pid || !cmin || !cmax || *cmin > *cmax) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.pid, rng.counter_min and rng.counter_max must define a valid search window"); return out; }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) { out.status = "SKIP"; out.lines.push_back("rationale = constraints.unix_time_min and unix_time_max must define a valid search window"); return out; }
    if (in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps unix-time enumeration to 2^24 values"); return out; }
    const auto span = *cmax - *cmin + 1ULL;
    if (span > (1ULL << 20)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps counter enumeration to 2^20 values for time+pid+counter models"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_t=0, winner_c=0;
#pragma omp parallel for schedule(static)
        for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
            if (found.load(std::memory_order_relaxed)) continue;
            for (unsigned long long ctr = *cmin; ctr <= *cmax && !found.load(std::memory_order_relaxed); ++ctr) {
                try {
                    const mpz_class k = mod(mpz_class(static_cast<unsigned long>(t)) + mpz_class(static_cast<unsigned long>(*pid)) + mpz_class(static_cast<unsigned long>(ctr)), curve.n);
                    if (k <= 0 || k >= curve.n) continue;
                    const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_t = t; winner_c = ctr; winner_k = k; winner_d = d; } }
                    }
                } catch (const std::exception&) {}
            }
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = unix_time_pid_counter"); out.lines.push_back("recovered_unix_time = " + std::to_string(winner_t)); out.lines.push_back("pid = " + std::to_string(*pid)); out.lines.push_back("recovered_counter = " + std::to_string(winner_c)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = mixing time, PID, and a tiny counter still leaves the ECDSA nonce space small enough for offline recovery"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied time+pid+counter search window"); return out;
}

ModuleResult message_hash_plus_pid_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a hash-plus-pid nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"message_hash_plus_pid", "hash_plus_pid"})) { out.status = "SKIP"; out.lines.push_back("rationale = no message-hash plus PID model was declared"); return out; }
    const auto pid_min = fact_get_ull(in, "rng.pid_min");
    const auto pid_max = fact_get_ull(in, "rng.pid_max");
    if (!pid_min || !pid_max || *pid_min > *pid_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.pid_min and rng.pid_max must define a valid search window"); return out; }
    if (*pid_max - *pid_min + 1ULL > (1ULL << 22)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps PID enumeration to 2^22 values"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_pid = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long pid = *pid_min; pid <= *pid_max; ++pid) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                const mpz_class k = mod(z + mpz_class(static_cast<unsigned long>(pid)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_pid = pid; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = message_hash_plus_pid"); out.lines.push_back("recovered_pid = " + std::to_string(winner_pid)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = adding a tiny PID to the message hash still leaves the ECDSA nonce fully enumerable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied hash-plus-pid window"); return out;
}

ModuleResult message_hash_xor_pid_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a hash-xor-pid nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"message_hash_xor_pid", "hash_xor_pid"})) { out.status = "SKIP"; out.lines.push_back("rationale = no message-hash XOR PID model was declared"); return out; }
    const auto pid_min = fact_get_ull(in, "rng.pid_min");
    const auto pid_max = fact_get_ull(in, "rng.pid_max");
    if (!pid_min || !pid_max || *pid_min > *pid_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.pid_min and rng.pid_max must define a valid search window"); return out; }
    if (*pid_max - *pid_min + 1ULL > (1ULL << 22)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps PID enumeration to 2^22 values"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_pid = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long pid = *pid_min; pid <= *pid_max; ++pid) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                const mpz_class k = mod(z ^ mpz_class(static_cast<unsigned long>(pid)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_pid = pid; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = message_hash_xor_pid"); out.lines.push_back("recovered_pid = " + std::to_string(winner_pid)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = xoring a tiny PID into the message hash still leaves the ECDSA nonce fully enumerable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied hash-xor-pid window"); return out;
}

ModuleResult unix_time_plus_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a time-plus-counter nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"unix_time_plus_counter", "time_plus_counter"})) { out.status = "SKIP"; out.lines.push_back("rationale = no unix-time plus counter model was declared"); return out; }
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!cmin || !cmax || *cmin > *cmax) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.counter_min and rng.counter_max must define a valid search window"); return out; }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) { out.status = "SKIP"; out.lines.push_back("rationale = constraints.unix_time_min and unix_time_max must define a valid search window"); return out; }
    if (in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps unix-time enumeration to 2^24 values"); return out; }
    if (*cmax - *cmin + 1ULL > (1ULL << 20)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps counter enumeration to 2^20 values"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_t = 0, winner_c = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
            if (found.load(std::memory_order_relaxed)) continue;
            for (unsigned long long ctr = *cmin; ctr <= *cmax && !found.load(std::memory_order_relaxed); ++ctr) {
                try {
                    const mpz_class k = mod(mpz_class(static_cast<unsigned long>(t)) + mpz_class(static_cast<unsigned long>(ctr)), curve.n);
                    if (k <= 0 || k >= curve.n) continue;
                    const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_t = t; winner_c = ctr; winner_k = k; winner_d = d; } }
                    }
                } catch (const std::exception&) {}
            }
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = unix_time_plus_counter"); out.lines.push_back("recovered_unix_time = " + std::to_string(winner_t)); out.lines.push_back("recovered_counter = " + std::to_string(winner_c)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = combining wall-clock time with a tiny counter still leaves the ECDSA nonce searchable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied time-plus-counter window"); return out;
}

ModuleResult unix_time_xor_counter_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a time-xor-counter nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"unix_time_xor_counter", "time_xor_counter"})) { out.status = "SKIP"; out.lines.push_back("rationale = no unix-time XOR counter model was declared"); return out; }
    const auto cmin = fact_get_ull(in, "rng.counter_min");
    const auto cmax = fact_get_ull(in, "rng.counter_max");
    if (!cmin || !cmax || *cmin > *cmax) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.counter_min and rng.counter_max must define a valid search window"); return out; }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) { out.status = "SKIP"; out.lines.push_back("rationale = constraints.unix_time_min and unix_time_max must define a valid search window"); return out; }
    if (in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps unix-time enumeration to 2^24 values"); return out; }
    if (*cmax - *cmin + 1ULL > (1ULL << 20)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps counter enumeration to 2^20 values"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_t = 0, winner_c = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
            if (found.load(std::memory_order_relaxed)) continue;
            for (unsigned long long ctr = *cmin; ctr <= *cmax && !found.load(std::memory_order_relaxed); ++ctr) {
                try {
                    const mpz_class k = mod(mpz_class(static_cast<unsigned long>(t)) ^ mpz_class(static_cast<unsigned long>(ctr)), curve.n);
                    if (k <= 0 || k >= curve.n) continue;
                    const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_t = t; winner_c = ctr; winner_k = k; winner_d = d; } }
                    }
                } catch (const std::exception&) {}
            }
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = unix_time_xor_counter"); out.lines.push_back("recovered_unix_time = " + std::to_string(winner_t)); out.lines.push_back("recovered_counter = " + std::to_string(winner_c)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = xoring wall-clock time with a tiny counter still leaves the ECDSA nonce searchable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied time-xor-counter window"); return out;
}

ModuleResult splitmix64_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a SplitMix64 nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"splitmix64", "splitmix64_nonce", "splitmix64_seed"})) { out.status = "SKIP"; out.lines.push_back("rationale = no SplitMix64 nonce generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps SplitMix64 seed enumeration to 2^24 values"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                std::uint64_t state = static_cast<std::uint64_t>(seed);
                std::uint64_t output = 0;
                for (unsigned long long t = 0; t <= discard; ++t) output = splitmix64_next(state + t);
                const mpz_class k = mod(mpz_class(static_cast<unsigned long>(output)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = splitmix64"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = SplitMix64 seeds are enumerable in tiny windows and its outputs must never feed ECDSA nonces directly"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied SplitMix64 seed window"); return out;
}

ModuleResult pcg32_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a PCG32 nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"pcg32", "pcg32_nonce", "pcg32_seed"})) { out.status = "SKIP"; out.lines.push_back("rationale = no PCG32 nonce generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps PCG32 seed enumeration to 2^24 values"); return out; }
    const unsigned long long inc = fact_get_ull(in, "rng.pcg.inc").value_or(1442695040888963407ULL);
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                std::uint64_t state = static_cast<std::uint64_t>(seed);
                std::uint32_t outv = 0;
                for (unsigned long long t = 0; t <= discard; ++t) {
                    const std::uint64_t oldstate = state;
                    state = oldstate * 6364136223846793005ULL + (inc | 1ULL);
                    outv = pcg32_output(oldstate);
                }
                const mpz_class k = mod(mpz_class(static_cast<unsigned long>(outv)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = pcg32"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = small PCG32 seed windows still collapse ECDSA secrecy when raw outputs are used as nonces"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied PCG32 seed window"); return out;
}

ModuleResult mt19937_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for an MT19937 nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"mt19937", "mt19937_nonce", "mersenne_twister"})) { out.status = "SKIP"; out.lines.push_back("rationale = no MT19937 nonce generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps MT19937 seed enumeration to 2^24 values"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                std::mt19937 mt(static_cast<std::uint32_t>(seed));
                std::uint32_t outv = 0;
                for (unsigned long long t = 0; t <= discard; ++t) outv = static_cast<std::uint32_t>(mt());
                const mpz_class k = mod(mpz_class(static_cast<unsigned long>(outv)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = mt19937"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = enumerating a tiny MT19937 seed window is enough to recover ECDSA secrets when raw outputs are used as nonces"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied MT19937 seed window"); return out;
}

ModuleResult xorshift32_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a Xorshift32 nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"xorshift32", "xorshift", "xorshift32_nonce"})) { out.status = "SKIP"; out.lines.push_back("rationale = no Xorshift32 nonce generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps Xorshift32 seed enumeration to 2^24 values"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                std::uint32_t state = static_cast<std::uint32_t>(seed);
                std::uint32_t outv = 0;
                for (unsigned long long t = 0; t <= discard; ++t) outv = state = xorshift32_next(state);
                const mpz_class k = mod(mpz_class(static_cast<unsigned long>(outv)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = xorshift32"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = raw Xorshift32 outputs from a small seed window are fully searchable offline and fatal to ECDSA secrecy"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied Xorshift32 seed window"); return out;
}

ModuleResult xorshift64_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a Xorshift64* nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"xorshift64star", "xorshift64", "xorshift64_nonce"})) { out.status = "SKIP"; out.lines.push_back("rationale = no Xorshift64* nonce generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps Xorshift64* seed enumeration to 2^24 values"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                std::uint64_t state = static_cast<std::uint64_t>(seed ? seed : 1ULL);
                std::uint64_t outv = 0;
                for (unsigned long long t = 0; t <= discard; ++t) { state = xorshift64star_next(state); outv = state; }
                const mpz_class k = mod(mpz_class(static_cast<unsigned long>(outv)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = xorshift64star"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = raw Xorshift64* outputs from a tiny seed window still collapse ECDSA secrecy offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied Xorshift64* seed window"); return out;
}

ModuleResult splitmix64_sequence_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.size() < 2) { out.status = "SKIP"; out.lines.push_back("rationale = at least two signatures are needed for a SplitMix64 sequence search"); return out; }
    if (!fact_in(in, "rng.generator", {"splitmix64_sequence", "splitmix64_stream", "splitmix64_seq"})) { out.status = "SKIP"; out.lines.push_back("rationale = no SplitMix64 sequence generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps SplitMix64 sequence enumeration to 2^24 seeds"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    const auto z1 = parse_hash_hex(in.signatures[0].hash_hex); const auto r1 = hex_to_mpz(in.signatures[0].r_hex); const auto s1 = hex_to_mpz(in.signatures[0].s_hex);
    const auto z2 = parse_hash_hex(in.signatures[1].hash_hex); const auto r2 = hex_to_mpz(in.signatures[1].r_hex); const auto s2 = hex_to_mpz(in.signatures[1].s_hex);
    std::atomic<bool> found(false); mpz_class winner_d, winner_k1, winner_k2; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
    for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
        if (found.load(std::memory_order_relaxed)) continue;
        try {
            const std::uint64_t k1_raw = splitmix64_next(static_cast<std::uint64_t>(seed + discard));
            const std::uint64_t k2_raw = splitmix64_next(static_cast<std::uint64_t>(seed + discard + 1ULL));
            const mpz_class k1 = mod(mpz_class(static_cast<unsigned long>(k1_raw)), curve.n);
            const mpz_class k2 = mod(mpz_class(static_cast<unsigned long>(k2_raw)), curve.n);
            if (k1 <= 0 || k1 >= curve.n || k2 <= 0 || k2 >= curve.n) continue;
            const mpz_class d1 = mod((s1 * k1 - z1) * inv_mod(r1, curve.n), curve.n);
            const mpz_class d2 = mod((s2 * k2 - z2) * inv_mod(r2, curve.n), curve.n);
            if (d1 != d2) continue;
            if (pubkey_matches(curve, Q, d1)) {
#pragma omp critical
                { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k1 = k1; winner_k2 = k2; winner_d = d1; } }
            }
        } catch (const std::exception&) {}
    }
    if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_pair = 0,1"); out.lines.push_back("generator = splitmix64_sequence"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_k1 = " + winner_k1.get_str()); out.lines.push_back("recovered_k2 = " + winner_k2.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = successive SplitMix64 outputs from a tiny seed window fully expose the long-term ECDSA key"); return out; }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied SplitMix64 sequence window"); return out;
}

ModuleResult pcg32_sequence_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.size() < 2) { out.status = "SKIP"; out.lines.push_back("rationale = at least two signatures are needed for a PCG32 sequence search"); return out; }
    if (!fact_in(in, "rng.generator", {"pcg32_sequence", "pcg32_stream", "pcg32_seq"})) { out.status = "SKIP"; out.lines.push_back("rationale = no PCG32 sequence generator was declared"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min");
    const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid search window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps PCG32 sequence enumeration to 2^24 seeds"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    const auto z1 = parse_hash_hex(in.signatures[0].hash_hex); const auto r1 = hex_to_mpz(in.signatures[0].r_hex); const auto s1 = hex_to_mpz(in.signatures[0].s_hex);
    const auto z2 = parse_hash_hex(in.signatures[1].hash_hex); const auto r2 = hex_to_mpz(in.signatures[1].r_hex); const auto s2 = hex_to_mpz(in.signatures[1].s_hex);
    constexpr std::uint64_t mul = 6364136223846793005ULL;
    constexpr std::uint64_t inc = 1442695040888963407ULL;
    std::atomic<bool> found(false); mpz_class winner_d, winner_k1, winner_k2; unsigned long long winner_seed = 0;
#pragma omp parallel for schedule(static)
    for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
        if (found.load(std::memory_order_relaxed)) continue;
        try {
            std::uint64_t state = static_cast<std::uint64_t>(seed);
            std::uint32_t out1 = 0;
            for (unsigned long long t = 0; t <= discard; ++t) {
                std::uint64_t oldstate = state;
                state = oldstate * mul + inc;
                out1 = pcg32_output(oldstate);
            }
            std::uint64_t oldstate = state;
            state = oldstate * mul + inc;
            std::uint32_t out2 = pcg32_output(oldstate);
            const mpz_class k1 = mod(mpz_class(static_cast<unsigned long>(out1)), curve.n);
            const mpz_class k2 = mod(mpz_class(static_cast<unsigned long>(out2)), curve.n);
            if (k1 <= 0 || k1 >= curve.n || k2 <= 0 || k2 >= curve.n) continue;
            const mpz_class d1 = mod((s1 * k1 - z1) * inv_mod(r1, curve.n), curve.n);
            const mpz_class d2 = mod((s2 * k2 - z2) * inv_mod(r2, curve.n), curve.n);
            if (d1 != d2) continue;
            if (pubkey_matches(curve, Q, d1)) {
#pragma omp critical
                { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_seed = seed; winner_k1 = k1; winner_k2 = k2; winner_d = d1; } }
            }
        } catch (const std::exception&) {}
    }
    if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_pair = 0,1"); out.lines.push_back("generator = pcg32_sequence"); out.lines.push_back("recovered_seed = " + std::to_string(winner_seed)); out.lines.push_back("recovered_k1 = " + winner_k1.get_str()); out.lines.push_back("recovered_k2 = " + winner_k2.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = successive PCG32 outputs from a tiny seed window can fully expose the long-term ECDSA key"); return out; }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied PCG32 sequence window"); return out;
}

ModuleResult message_hash_plus_time_pid_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a hash-plus-time-plus-PID search"); return out; }
    if (!fact_in(in, "rng.generator", {"message_hash_plus_time_pid", "hash_plus_time_pid"})) { out.status = "SKIP"; out.lines.push_back("rationale = no message-hash plus unix-time plus PID model was declared"); return out; }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) { out.status = "SKIP"; out.lines.push_back("rationale = constraints.unix_time_min and unix_time_max must define a valid search window"); return out; }
    const auto pid_min = fact_get_ull(in, "rng.pid_min"); const auto pid_max = fact_get_ull(in, "rng.pid_max");
    if (!pid_min || !pid_max || *pid_min > *pid_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.pid_min and rng.pid_max must define a valid PID window"); return out; }
    const unsigned long long time_span = in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL;
    const unsigned long long pid_span = *pid_max - *pid_min + 1ULL;
    if (time_span * pid_span > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps hash-plus-time-plus-PID enumeration to 2^24 combinations"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_t = 0, winner_pid = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
            if (found.load(std::memory_order_relaxed)) continue;
            for (unsigned long long pid = *pid_min; pid <= *pid_max; ++pid) {
                if (found.load(std::memory_order_relaxed)) break;
                try {
                    const mpz_class k = mod(z + mpz_class(static_cast<unsigned long>(t)) + mpz_class(static_cast<unsigned long>(pid)), curve.n);
                    if (k <= 0 || k >= curve.n) continue;
                    const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_t = t; winner_pid = pid; winner_k = k; winner_d = d; } }
                    }
                } catch (const std::exception&) {}
            }
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = message_hash_plus_time_pid"); out.lines.push_back("recovered_unix_time = " + std::to_string(winner_t)); out.lines.push_back("recovered_pid = " + std::to_string(winner_pid)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = mixing the message hash with tiny time and PID windows still leaves ECDSA nonces fully enumerable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied hash-plus-time-plus-PID window"); return out;
}

ModuleResult message_hash_xor_time_pid_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a hash-xor-time-plus-PID search"); return out; }
    if (!fact_in(in, "rng.generator", {"message_hash_xor_time_pid", "hash_xor_time_pid"})) { out.status = "SKIP"; out.lines.push_back("rationale = no message-hash XOR unix-time plus PID model was declared"); return out; }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) { out.status = "SKIP"; out.lines.push_back("rationale = constraints.unix_time_min and unix_time_max must define a valid search window"); return out; }
    const auto pid_min = fact_get_ull(in, "rng.pid_min"); const auto pid_max = fact_get_ull(in, "rng.pid_max");
    if (!pid_min || !pid_max || *pid_min > *pid_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.pid_min and rng.pid_max must define a valid PID window"); return out; }
    const unsigned long long time_span = in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL;
    const unsigned long long pid_span = *pid_max - *pid_min + 1ULL;
    if (time_span * pid_span > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps hash-xor-time-plus-PID enumeration to 2^24 combinations"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_t = 0, winner_pid = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
            if (found.load(std::memory_order_relaxed)) continue;
            for (unsigned long long pid = *pid_min; pid <= *pid_max; ++pid) {
                if (found.load(std::memory_order_relaxed)) break;
                try {
                    const mpz_class k = mod((z ^ mpz_class(static_cast<unsigned long>(t))) + mpz_class(static_cast<unsigned long>(pid)), curve.n);
                    if (k <= 0 || k >= curve.n) continue;
                    const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                    if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                        { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_t = t; winner_pid = pid; winner_k = k; winner_d = d; } }
                    }
                } catch (const std::exception&) {}
            }
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = message_hash_xor_time_pid"); out.lines.push_back("recovered_unix_time = " + std::to_string(winner_t)); out.lines.push_back("recovered_pid = " + std::to_string(winner_pid)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = xoring time into the message hash and adding a tiny PID still leaves ECDSA nonces fully enumerable offline"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied hash-xor-time-plus-PID window"); return out;
}

ModuleResult message_hash_plus_time_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a hash-plus-time nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"message_hash_plus_time", "hash_plus_time", "message_hash_time"})) { out.status = "SKIP"; out.lines.push_back("rationale = no message-hash plus unix-time model was declared"); return out; }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) { out.status = "SKIP"; out.lines.push_back("rationale = constraints.unix_time_min and unix_time_max must define a valid search window"); return out; }
    if (in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps unix-time enumeration to 2^24 values"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_t = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                const mpz_class k = mod(z + mpz_class(static_cast<unsigned long>(t)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_t = t; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = message_hash_plus_time"); out.lines.push_back("recovered_unix_time = " + std::to_string(winner_t)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = adding wall-clock time to the message hash still leaves ECDSA nonces enumerable in a tiny offline window"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied hash-plus-time window"); return out;
}

ModuleResult message_hash_xor_time_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a hash-xor-time nonce search"); return out; }
    if (!fact_in(in, "rng.generator", {"message_hash_xor_time", "hash_xor_time", "message_hash_time_xor"})) { out.status = "SKIP"; out.lines.push_back("rationale = no message-hash XOR unix-time model was declared"); return out; }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) { out.status = "SKIP"; out.lines.push_back("rationale = constraints.unix_time_min and unix_time_max must define a valid search window"); return out; }
    if (in.constraints.unix_time_max - in.constraints.unix_time_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps unix-time enumeration to 2^24 values"); return out; }
    for (std::size_t i = 0; i < in.signatures.size(); ++i) {
        const auto z = parse_hash_hex(in.signatures[i].hash_hex); const auto r = hex_to_mpz(in.signatures[i].r_hex); const auto s = hex_to_mpz(in.signatures[i].s_hex);
        std::atomic<bool> found(false); mpz_class winner_d, winner_k; unsigned long long winner_t = 0;
#pragma omp parallel for schedule(static)
        for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
            if (found.load(std::memory_order_relaxed)) continue;
            try {
                const mpz_class k = mod(z ^ mpz_class(static_cast<unsigned long>(t)), curve.n);
                if (k <= 0 || k >= curve.n) continue;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (pubkey_matches(curve, Q, d)) {
#pragma omp critical
                    { if (!found.load(std::memory_order_relaxed)) { found.store(true, std::memory_order_relaxed); winner_t = t; winner_k = k; winner_d = d; } }
                }
            } catch (const std::exception&) {}
        }
        if (found.load()) { out.status = "HIT"; out.recovered = true; out.private_key = winner_d; out.lines.push_back("signature_index = " + std::to_string(i)); out.lines.push_back("generator = message_hash_xor_time"); out.lines.push_back("recovered_unix_time = " + std::to_string(winner_t)); out.lines.push_back("recovered_nonce = " + winner_k.get_str()); out.lines.push_back("recovered_private_key_decimal = " + winner_d.get_str()); out.lines.push_back("flag = FLAG{" + winner_d.get_str() + "}"); out.lines.push_back("impact = xoring wall-clock time into the message hash still leaves ECDSA nonces enumerable in a tiny offline window"); return out; }
    }
    out.status = "MISS"; out.lines.push_back("rationale = no private key was recovered from the supplied hash-xor-time window"); return out;
}

ModuleResult small_nonce_bsgs_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a bounded nonce search");
        return out;
    }
    if (in.constraints.nonce_max_bits <= 0) {
        out.status = "SKIP";
        out.lines.push_back("rationale = constraints.nonce_max_bits was not supplied");
        return out;
    }
    if (in.constraints.nonce_max_bits > 30) {
        out.status = "SKIP";
        out.lines.push_back("rationale = this offline build intentionally caps BSGS at 30 bits for bounded lab work");
        return out;
    }
    const std::uint64_t bound = (std::uint64_t{1} << in.constraints.nonce_max_bits) - 1;
    for (std::size_t idx = 0; idx < in.signatures.size(); ++idx) {
        const auto z = parse_hash_hex(in.signatures[idx].hash_hex);
        const auto r = hex_to_mpz(in.signatures[idx].r_hex);
        const auto s = hex_to_mpz(in.signatures[idx].s_hex);
        const auto R_candidates = reconstruct_r_points(curve, r);
        for (const auto& R : R_candidates) {
            auto k_hit = bsgs_discrete_log(curve, curve.G, R, bound);
            if (!k_hit || *k_hit == 0) continue;
            try {
                const mpz_class k = *k_hit;
                const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
                if (!pubkey_matches(curve, Q, d)) continue;
                out.status = "HIT";
                out.recovered = true;
                out.private_key = d;
                out.lines.push_back("signature_index = " + std::to_string(idx));
                out.lines.push_back("bound_bits = " + std::to_string(in.constraints.nonce_max_bits));
                out.lines.push_back("recovered_nonce = " + k.get_str());
                out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
                out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
                out.lines.push_back("impact = a bounded nonce search over even 30 bits is fatal to ECDSA secrecy");
                return out;
            } catch (const std::exception&) {}
        }
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no nonce was recovered within the requested bound");
    out.lines.push_back("bound_bits = " + std::to_string(in.constraints.nonce_max_bits));
    return out;
}

ModuleResult small_privkey_bsgs_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.constraints.privkey_max_bits <= 0) {
        out.status = "SKIP";
        out.lines.push_back("rationale = constraints.privkey_max_bits was not supplied");
        return out;
    }
    if (in.constraints.privkey_max_bits > 30) {
        out.status = "SKIP";
        out.lines.push_back("rationale = this offline build intentionally caps BSGS at 30 bits for bounded lab work");
        return out;
    }
    const std::uint64_t bound = (std::uint64_t{1} << in.constraints.privkey_max_bits) - 1;
    auto hit = bsgs_discrete_log(curve, curve.G, Q, bound);
    if (!hit) {
        out.status = "MISS";
        out.lines.push_back("rationale = no private key was found within the requested bound");
        out.lines.push_back("bound_bits = " + std::to_string(in.constraints.privkey_max_bits));
        return out;
    }
    const mpz_class d = *hit;
    if (!pubkey_matches(curve, Q, d)) {
        out.status = "MISS";
        out.lines.push_back("rationale = a candidate key was found but did not reproduce the supplied public key");
        return out;
    }
    out.status = "HIT";
    out.recovered = true;
    out.private_key = d;
    out.lines.push_back("bound_bits = " + std::to_string(in.constraints.privkey_max_bits));
    out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
    out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
    out.lines.push_back("impact = a private key restricted to a tiny range collapses under bounded discrete-log search");
    return out;
}

mpz_class timestamp_to_scalar(const std::string& generator, unsigned long long t, const mpz_class& n) {
    if (generator == "unix_time_scalar") return mod(mpz_class(static_cast<unsigned long>(t)), n);
    if (generator == "unix_time_plus_one") return mod(mpz_class(static_cast<unsigned long>(t + 1ULL)), n);
    throw std::runtime_error("unsupported timestamp generator model");
}

ModuleResult unix_time_scalar_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a time-seeded scalar scan");
        return out;
    }
    const auto gen = fact_get(in, "rng.generator");
    if (!gen || !fact_in(in, "rng.generator", {"unix_time_scalar", "unix_time_plus_one"})) {
        out.status = "SKIP";
        out.lines.push_back("rationale = facts.rng.generator is missing or does not describe a supported timestamp-scalar model");
        return out;
    }
    if (in.constraints.unix_time_min == 0 || in.constraints.unix_time_max == 0 || in.constraints.unix_time_min > in.constraints.unix_time_max) {
        out.status = "SKIP";
        out.lines.push_back("rationale = constraints.unix_time_min and constraints.unix_time_max must define a valid scan window");
        return out;
    }
    const auto z = parse_hash_hex(in.signatures[0].hash_hex);
    const auto r = hex_to_mpz(in.signatures[0].r_hex);
    const auto s = hex_to_mpz(in.signatures[0].s_hex);
    for (unsigned long long t = in.constraints.unix_time_min; t <= in.constraints.unix_time_max; ++t) {
        try {
            const mpz_class k = timestamp_to_scalar(*gen, t, curve.n);
            if (k == 0) continue;
            const Point R = scalar_mul(curve, k, curve.G);
            if (mod(R.x, curve.n) != r) continue;
            const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
            if (!pubkey_matches(curve, Q, d)) continue;
            out.status = "HIT";
            out.recovered = true;
            out.private_key = d;
            out.lines.push_back("generator = " + *gen);
            out.lines.push_back("recovered_unix_time = " + std::to_string(t));
            out.lines.push_back("recovered_nonce = " + k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
            out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
            out.lines.push_back("impact = using wall-clock time directly as an ECC nonce makes the key recoverable from a tiny search window");
            return out;
        } catch (const std::exception&) {}
        if (t == in.constraints.unix_time_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no timestamp-derived nonce was recovered inside the configured unix-time window");
    return out;
}

ModuleResult tiny_public_key_multiple_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    int bits = 16;
    if (const auto v = fact_get_ull(in, "key.small_range_bits")) bits = static_cast<int>(*v);
    else if (in.constraints.privkey_max_bits > 0) bits = std::min(bits, in.constraints.privkey_max_bits);
    if (bits <= 0) bits = 16;
    if (bits > 20) {
        out.status = "SKIP";
        out.lines.push_back("rationale = v16 caps opportunistic tiny-key scans at 20 bits in this offline build");
        return out;
    }
    const std::uint64_t bound = (std::uint64_t{1} << bits) - 1ULL;
    auto hit = bsgs_discrete_log(curve, curve.G, Q, bound);
    if (!hit) {
        out.status = "PASS";
        out.lines.push_back("rationale = the supplied public key is not in the opportunistic tiny-key window");
        out.lines.push_back("scan_bound_bits = " + std::to_string(bits));
        return out;
    }
    const mpz_class d = *hit;
    if (!pubkey_matches(curve, Q, d)) {
        out.status = "MISS";
        out.lines.push_back("rationale = a bounded-search candidate did not reproduce the supplied public key");
        return out;
    }
    out.status = "HIT";
    out.recovered = true;
    out.private_key = d;
    out.lines.push_back("scan_bound_bits = " + std::to_string(bits));
    out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
    out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
    out.lines.push_back("impact = the audited public key sits inside a tiny bounded range and is recoverable offline");
    return out;
}

ModuleResult pid_scalar_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) {
        out.status = "SKIP";
        out.lines.push_back("rationale = at least one signature is needed for a PID-scalar scan");
        return out;
    }
    if (!fact_in(in, "rng.generator", {"pid", "pid_scalar", "pid_plus_one"})) {
        out.status = "SKIP";
        out.lines.push_back("rationale = facts.rng.generator is missing or does not describe a supported PID-scalar model");
        return out;
    }
    const auto pid_min = fact_get_ull(in, "rng.pid_min");
    const auto pid_max = fact_get_ull(in, "rng.pid_max");
    if (!pid_min || !pid_max || *pid_min > *pid_max) {
        out.status = "SKIP";
        out.lines.push_back("rationale = facts rng.pid_min and rng.pid_max must define a valid PID window");
        return out;
    }
    const auto z = parse_hash_hex(in.signatures[0].hash_hex);
    const auto r = hex_to_mpz(in.signatures[0].r_hex);
    const auto s = hex_to_mpz(in.signatures[0].s_hex);
    const auto gen = lower_copy(*fact_get(in, "rng.generator"));
    for (unsigned long long pid = *pid_min; pid <= *pid_max; ++pid) {
        const mpz_class k = mod(mpz_class(static_cast<unsigned long>(pid + (gen == "pid_plus_one" ? 1ULL : 0ULL))), curve.n);
        if (k == 0) { if (pid == *pid_max) break; continue; }
        const Point R = scalar_mul(curve, k, curve.G);
        if (mod(R.x, curve.n) != r) { if (pid == *pid_max) break; continue; }
        try {
            const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
            if (!pubkey_matches(curve, Q, d)) { if (pid == *pid_max) break; continue; }
            out.status = "HIT";
            out.recovered = true;
            out.private_key = d;
            out.lines.push_back("generator = " + gen);
            out.lines.push_back("recovered_pid = " + std::to_string(pid));
            out.lines.push_back("recovered_nonce = " + k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
            out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
            out.lines.push_back("impact = a PID-sized nonce search space is tiny enough to recover the ECDSA private key offline");
            return out;
        } catch (const std::exception&) {}
        if (pid == *pid_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied PID-scalar nonce model");
    return out;
}

ModuleResult mwc1616_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for an MWC1616 seed scan"); return out; }
    if (!fact_in(in, "rng.generator", {"mwc1616", "multiply_with_carry"})) { out.status = "SKIP"; out.lines.push_back("rationale = facts.rng.generator is missing or does not describe MWC1616"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min"); const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid seed window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps MWC1616 seed enumeration to 2^24 values"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    const auto z = parse_hash_hex(in.signatures[0].hash_hex); const auto r = hex_to_mpz(in.signatures[0].r_hex); const auto s = hex_to_mpz(in.signatures[0].s_hex);
    for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
        std::uint32_t zst = static_cast<std::uint32_t>(((seed >> 16U) & 0xFFFFULL) | 1ULL);
        std::uint32_t wst = static_cast<std::uint32_t>((seed & 0xFFFFULL) | 1ULL);
        if (zst == 0) zst = 362436069U;
        if (wst == 0) wst = 521288629U;
        for (unsigned long long i = 0; i < discard; ++i) (void)mwc1616_next(zst, wst);
        const mpz_class k = mod(mpz_class(mwc1616_next(zst, wst)), curve.n);
        if (k == 0) { if (seed == *seed_max) break; continue; }
        const Point R = scalar_mul(curve, k, curve.G);
        if (mod(R.x, curve.n) != r) { if (seed == *seed_max) break; continue; }
        try {
            const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
            if (!pubkey_matches(curve, Q, d)) { if (seed == *seed_max) break; continue; }
            out.status = "HIT"; out.recovered = true; out.private_key = d;
            out.lines.push_back("signature_index = 0");
            out.lines.push_back("generator = mwc1616");
            out.lines.push_back("recovered_seed = " + std::to_string(seed));
            out.lines.push_back("recovered_nonce = " + k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
            out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
            out.lines.push_back("impact = tiny MWC1616 seed windows are enumerable offline and fatal to ECDSA secrecy");
            return out;
        } catch (const std::exception&) {}
        if (seed == *seed_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied MWC1616 seed window");
    return out;
}

ModuleResult sfc64_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for an SFC64 seed scan"); return out; }
    if (!fact_in(in, "rng.generator", {"sfc64"})) { out.status = "SKIP"; out.lines.push_back("rationale = facts.rng.generator is missing or does not describe SFC64"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min"); const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid seed window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps SFC64 seed enumeration to 2^24 values"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    const auto z = parse_hash_hex(in.signatures[0].hash_hex); const auto r = hex_to_mpz(in.signatures[0].r_hex); const auto s = hex_to_mpz(in.signatures[0].s_hex);
    for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
        auto st = sfc64_seeded(seed);
        for (unsigned long long i = 0; i < discard; ++i) (void)sfc64_next(st);
        const mpz_class k = mod(mpz_class(sfc64_next(st)), curve.n);
        if (k == 0) { if (seed == *seed_max) break; continue; }
        const Point R = scalar_mul(curve, k, curve.G);
        if (mod(R.x, curve.n) != r) { if (seed == *seed_max) break; continue; }
        try {
            const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
            if (!pubkey_matches(curve, Q, d)) { if (seed == *seed_max) break; continue; }
            out.status = "HIT"; out.recovered = true; out.private_key = d;
            out.lines.push_back("signature_index = 0");
            out.lines.push_back("generator = sfc64");
            out.lines.push_back("recovered_seed = " + std::to_string(seed));
            out.lines.push_back("recovered_nonce = " + k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
            out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
            out.lines.push_back("impact = narrow SFC64 seed windows are searchable offline and can fully expose the ECDSA key");
            return out;
        } catch (const std::exception&) {}
        if (seed == *seed_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied SFC64 seed window");
    return out;
}

ModuleResult wyrand_nonce_module(const CheckInfo& info, const Curve& curve, const Point& Q, const ChallengeInput& in) {
    ModuleResult out = make_base(info, true);
    if (in.signatures.empty()) { out.status = "SKIP"; out.lines.push_back("rationale = at least one signature is needed for a WyRand seed scan"); return out; }
    if (!fact_in(in, "rng.generator", {"wyrand"})) { out.status = "SKIP"; out.lines.push_back("rationale = facts.rng.generator is missing or does not describe WyRand"); return out; }
    const auto seed_min = fact_get_ull(in, "rng.seed_min"); const auto seed_max = fact_get_ull(in, "rng.seed_max");
    if (!seed_min || !seed_max || *seed_min > *seed_max) { out.status = "SKIP"; out.lines.push_back("rationale = facts rng.seed_min and rng.seed_max must define a valid seed window"); return out; }
    if (*seed_max - *seed_min + 1ULL > (1ULL << 24)) { out.status = "SKIP"; out.lines.push_back("rationale = the current offline build caps WyRand seed enumeration to 2^24 values"); return out; }
    const auto discard = fact_get_ull(in, "rng.discard_outputs").value_or(0ULL);
    const auto z = parse_hash_hex(in.signatures[0].hash_hex); const auto r = hex_to_mpz(in.signatures[0].r_hex); const auto s = hex_to_mpz(in.signatures[0].s_hex);
    for (unsigned long long seed = *seed_min; seed <= *seed_max; ++seed) {
        std::uint64_t state = static_cast<std::uint64_t>(seed);
        for (unsigned long long i = 0; i < discard; ++i) (void)wyrand_next(state);
        const mpz_class k = mod(mpz_class(wyrand_next(state)), curve.n);
        if (k == 0) { if (seed == *seed_max) break; continue; }
        const Point R = scalar_mul(curve, k, curve.G);
        if (mod(R.x, curve.n) != r) { if (seed == *seed_max) break; continue; }
        try {
            const mpz_class d = mod((s * k - z) * inv_mod(r, curve.n), curve.n);
            if (!pubkey_matches(curve, Q, d)) { if (seed == *seed_max) break; continue; }
            out.status = "HIT"; out.recovered = true; out.private_key = d;
            out.lines.push_back("signature_index = 0");
            out.lines.push_back("generator = wyrand");
            out.lines.push_back("recovered_seed = " + std::to_string(seed));
            out.lines.push_back("recovered_nonce = " + k.get_str());
            out.lines.push_back("recovered_private_key_decimal = " + d.get_str());
            out.lines.push_back("flag = FLAG{" + d.get_str() + "}");
            out.lines.push_back("impact = narrow WyRand seed windows are searchable offline and fatal to ECDSA secrecy");
            return out;
        } catch (const std::exception&) {}
        if (seed == *seed_max) break;
    }
    out.status = "MISS";
    out.lines.push_back("rationale = no private key was recovered from the supplied WyRand seed window");
    return out;
}

ModuleResult fact_dispatch(const CheckInfo& info, const ChallengeInput& in) {
    const std::string& id = info.id;
    if (id == "invalid_public_key_encoding_acceptance") return make_bool_risk(in, info, "validation.accept_invalid_public_key_encoding", "malformed or ambiguously encoded public keys can bypass parser expectations and feed dangerous edge cases");
    if (id == "point_at_infinity_acceptance") return make_bool_risk(in, info, "validation.accept_infinity", "accepting the point at infinity can trivialize protocols and collapse key agreement edge cases");
    if (id == "off_curve_public_key_acceptance") return make_bool_risk(in, info, "validation.accept_off_curve_points", "off-curve inputs enable invalid-point and twist style attacks against implementations that skip validation");
    if (id == "subgroup_check_missing") return make_bool_risk(in, info, "validation.subgroup_check", "missing subgroup checks enable confinement attacks and invalid-point workflows", false);
    if (id == "cofactor_clearing_missing") return make_bool_risk(in, info, "validation.cofactor_clearing", "missing cofactor clearing leaves implementations exposed on curves and protocols where cofactors matter", false);
    if (id == "invalid_curve_acceptance") return make_bool_risk(in, info, "validation.accept_invalid_curve_points", "accepting invalid-curve inputs allows carefully chosen small-order points to leak scalar information");
    if (id == "twist_point_acceptance") return make_bool_risk(in, info, "validation.accept_twist_points", "twist acceptance can hand attackers low-order structure outside the main curve");
    if (id == "untrusted_custom_curve_parameters") return make_bool_risk(in, info, "curve.parameters.trusted_source", "untrusted curve parameters can hide hostile group structure or invalid security assumptions", false);
    if (id == "generator_unchecked") return make_bool_risk(in, info, "validation.generator_checked", "an unchecked generator can invalidate every higher-level security assumption on top of the curve", false);
    if (id == "curve_order_unchecked") return make_bool_risk(in, info, "validation.curve_order_checked", "unchecked curve order values can break subgroup reasoning and signature validation", false);
    if (id == "nonce_source_time_seeded") return make_fact_risk(in, info, "rng.seed", {"time", "time()", "wallclock"}, "time-seeded RNG state is frequently guessable and can lead directly to nonce recovery");
    if (id == "nonce_source_rand") return make_fact_risk(in, info, "rng.source", {"rand", "std::rand", "c_rand"}, "rand()-class generators are not suitable for cryptographic nonce generation");
    if (id == "nonce_source_counter") return make_fact_risk(in, info, "rng.source", {"counter", "bounded_counter"}, "counter-based nonces create structure that is often algebraically exploitable");
    if (id == "nonce_source_lcg") return make_fact_risk(in, info, "rng.source", {"lcg", "linear_congruential"}, "LCGs leak linear structure and are disastrous for ECC nonce generation");
    if (id == "nonce_source_predictable_file_seed") return make_fact_risk(in, info, "rng.seed", {"pid_file", "config_file", "hostname_file", "predictable_file"}, "predictable file-derived seeds can often be reconstructed offline by an attacker");
    if (id == "nonce_not_rfc6979") return make_bool_risk(in, info, "nonce.rfc6979", "deterministic nonces anchored in a strong construction reduce a large class of RNG failures", false);
    if (id == "nonce_partial_lsb_leak") return make_bool_risk(in, info, "nonce.partial_lsb_leak", "even a few leaked low bits per signature can become a lattice attack input");
    if (id == "nonce_partial_msb_leak") return make_bool_risk(in, info, "nonce.partial_msb_leak", "leaked high bits across many signatures are enough for hidden-number style recovery");
    if (id == "nonce_fixed_high_bits") return make_bool_risk(in, info, "nonce.fixed_high_bits", "fixed high nonce bits shrink the hidden search space and bias the lattice structure");
    if (id == "nonce_fixed_low_bits") return make_bool_risk(in, info, "nonce.fixed_low_bits", "fixed low nonce bits leak structure and can dramatically reduce attack cost");
    if (id == "nonce_statistical_bias") return make_bool_risk(in, info, "nonce.bias_detected", "biased nonces can often be exploited statistically or with lattice methods");
    if (id == "rng_state_reuse_after_fork") return make_bool_risk(in, info, "rng.state_reuse_after_fork", "forked processes that reuse RNG state frequently repeat nonces or scalars");
    if (id == "rng_state_reuse_after_crash") return make_bool_risk(in, info, "rng.state_reuse_after_restart", "state reuse after restart can recreate old scalars or nonce streams");
    if (id == "rng_cross_thread_race") return make_bool_risk(in, info, "rng.cross_thread_race", "shared unsynchronized RNG state can duplicate or correlate outputs across threads");
    if (id == "deterministic_nonce_cross_message_reuse") return make_bool_risk(in, info, "nonce.deterministic_cross_message_reuse", "deterministic nonces must still bind to the message and key; otherwise reuse is fatal");
    if (id == "key_derived_from_password") return make_fact_risk(in, info, "key.source", {"password", "passphrase"}, "password-derived keys need a carefully engineered KDF and still often collapse in offline guessing attacks");
    if (id == "key_derived_from_timestamp") return make_fact_risk(in, info, "key.source", {"timestamp", "time", "datetime"}, "timestamp-derived keys are usually enumerable offline");
    if (id == "key_from_small_range") return make_fact_risk(in, info, "key.source", {"small_range"}, "tiny private-key ranges collapse under bounded discrete-log search");
    if (id == "key_from_predictable_seed") return make_fact_risk(in, info, "key.source", {"predictable_seed", "username_seed", "hostname_seed"}, "predictable seed material turns key search into an offline enumeration problem");
    if (id == "cross_protocol_scalar_reuse") return make_bool_risk(in, info, "cross_protocol.scalar_reuse", "reusing the same scalar material across signature and key-agreement roles destroys compartmentalization");
    if (id == "x_coordinate_only_ecdh") return make_bool_risk(in, info, "ecdh.use_x_coordinate_only", "using only x(P) as a secret without proper validation and KDF handling is fragile and frequently unsafe");
    if (id == "shared_secret_without_kdf") return make_bool_risk(in, info, "ecdh.use_kdf", "raw shared secrets should be fed through a context-binding KDF before use", false);
    if (id == "raw_shared_secret_as_symmetric_key") return make_bool_risk(in, info, "ecdh.use_raw_shared_secret_as_key", "directly reusing the raw shared secret as an AES or MAC key is brittle and often non-uniform");
    if (id == "truncated_shared_secret") return make_bool_risk(in, info, "ecdh.truncate_shared_secret", "truncation before KDF or confirmation can throw away entropy and distort interoperability");
    if (id == "missing_key_confirmation") return make_bool_risk(in, info, "protocol.key_confirmation", "without key confirmation, unknown-key-share and oracle-style confusions become easier", false);
    if (id == "missing_domain_separation_in_hashing") return make_bool_risk(in, info, "protocol.domain_separation", "reusing the same hash flow across roles without domain separation invites cross-protocol confusion", false);
    if (id == "hash_to_integer_mismatch") return make_bool_risk(in, info, "protocol.hash_to_int_mismatch", "hash truncation or conversion mismatches break interoperability and can create exploitable verifier disagreements");
    if (id == "oracle_success_fail_leak") return make_fact_risk(in, info, "oracle.kind", {"success_fail", "boolean"}, "a binary success/fail oracle is often enough to drive adaptive key-recovery workflows");
    if (id == "oracle_x_coordinate_leak") return make_fact_risk(in, info, "oracle.kind", {"x_coordinate", "xonly"}, "returning raw shared-secret coordinates can hand attackers direct algebraic side information");
    if (id == "oracle_decrypt_validity_leak") return make_bool_risk(in, info, "oracle.decrypt_validity", "decrypt-validity oracles are often enough to adaptively filter candidate shared secrets");
    if (id == "oracle_mac_validity_leak") return make_bool_risk(in, info, "oracle.mac_validity", "MAC-validity oracles can be enough to filter candidate shared secrets and transcripts adaptively");
    if (id == "oracle_timing_leak_declared") return make_bool_risk(in, info, "oracle.timing_leak", "timing differences around parsing, validation, or decryption can act as a side channel");
    if (id == "weak_compressed_point_parser") return make_bool_risk(in, info, "parser.weak_compressed_point_parser", "weak parsers can accept malformed encodings that bypass security invariants");
    if (id == "verifier_accepts_out_of_range_r_or_s") return make_bool_risk(in, info, "verification.accepts_out_of_range_rs", "accepting out-of-range signature components breaks core ECDSA verification assumptions");
    if (id == "verifier_accepts_zero_r_or_s") return make_bool_risk(in, info, "verification.accepts_zero_rs", "accepting zero-valued signature components is catastrophic verifier behavior");
    if (id == "verifier_accepts_mixed_curve_domain") return make_bool_risk(in, info, "verification.accepts_mixed_curve_domain", "accepting mixed domain parameters invalidates the meaning of the public key and generator");
    if (id == "verifier_skips_public_key_validation") return make_bool_risk(in, info, "verification.skips_public_key_validation", "verifiers must reject malformed or hostile public keys before doing group operations");
    if (id == "shared_secret_reuse_across_sessions") return make_bool_risk(in, info, "session.reuse_shared_secret", "reusing the same derived secret across sessions kills forward secrecy and compounds compromise");
    if (id == "no_ephemeral_key_rotation") return make_bool_risk(in, info, "session.rotate_ephemeral_keys", "without fresh ephemeral keys, many protocols regress toward long-term secret exposure", false);
    if (id == "signature_nonce_shared_with_ecdh") return make_bool_risk(in, info, "cross_protocol.scalar_reuse", "shared scalar material across ECDSA and ECDH lets one bug poison multiple primitives");
    if (id == "replay_protection_absent") return make_bool_risk(in, info, "protocol.replay_protection", "missing replay protection can turn valid transcripts into reusable attack material", false);
    if (id == "protocol_error_messages_too_specific") return make_fact_risk(in, info, "oracle.error_detail", {"verbose", "specific", "detailed"}, "overly specific errors improve attacker feedback during adaptive probing");
    if (id == "parser_accepts_hybrid_pubkeys") return make_bool_risk(in, info, "parser.accept_hybrid_pubkeys", "hybrid SEC1 encodings are obsolete and accepting them widens the parser attack surface");
    if (id == "parser_accepts_noncanonical_integers") return make_bool_risk(in, info, "parser.accept_noncanonical_integers", "accepting non-canonical integers can produce ambiguous encodings and verifier disagreements");
    if (id == "scalar_blinding_absent") return make_bool_risk(in, info, "implementation.scalar_blinding", "lack of scalar blinding weakens resistance against timing and power leakage", false);
    if (id == "complete_formula_absent") return make_bool_risk(in, info, "implementation.complete_group_formulas", "incomplete formulas increase the risk of exceptional-case side channels and input-dependent behavior", false);
    if (id == "transcript_binding_absent") return make_bool_risk(in, info, "protocol.transcript_binding", "without transcript binding, signatures and key agreement outputs can be replayed or transplanted across sessions", false);
    if (id == "static_ephemeral_key_usage") return make_bool_risk(in, info, "ecdh.static_ephemeral", "reusing an ephemeral ECDH key turns a supposedly fresh exchange into a replayable long-lived secret");
    if (id == "device_identifier_seeded_nonce") return make_fact_risk(in, info, "rng.generator", {"device_id", "machine_id", "mac_address", "hostname_seed", "device_identifier"}, "device identifiers are low-entropy, persistent inputs and must never drive ECC nonce generation");
    if (id == "compressed_point_length_relaxed") return make_bool_risk(in, info, "parser.relaxed_pubkey_length", "relaxed length checks can let malformed public keys slip into deeper parsing code paths");
    if (id == "signature_context_reuse") return make_bool_risk(in, info, "protocol.signature_context_reuse", "reusing the same signature context across protocol roles undermines domain separation");
    if (id == "nonce_source_splitmix64") return make_fact_risk(in, info, "rng.source", {"splitmix64"}, "SplitMix64 is fast and useful for simulation, but it is not an approved cryptographic nonce generator for ECC signatures");
    if (id == "nonce_source_pcg32") return make_fact_risk(in, info, "rng.source", {"pcg32"}, "PCG32 is statistically decent for general use but is not a cryptographic nonce source for ECC signatures");
    if (id == "nonce_source_mwc1616") return make_fact_risk(in, info, "rng.source", {"mwc1616", "multiply_with_carry"}, "MWC1616 is a compact statistical PRNG, not a cryptographic ECC nonce source");
    if (id == "nonce_source_device_id") return make_fact_risk(in, info, "rng.source", {"device_id", "device_identifier", "machine_id", "mac_address"}, "persistent device identifiers create tiny enumerable spaces and must never back ECC nonces");
    if (id == "nonce_source_serial_number") return make_fact_risk(in, info, "rng.source", {"serial_number", "disk_serial", "board_serial"}, "serial numbers are stable, low-entropy values and are fatal if reused as nonce material");
    if (id == "nonce_source_machine_id") return make_fact_risk(in, info, "rng.source", {"machine_id", "hostname_seed", "mac_address"}, "machine identifiers are persistent and enumerable, making them dangerous nonce sources");
    if (id == "nonce_source_build_id") return make_fact_risk(in, info, "rng.source", {"build_id", "firmware_build", "compile_time"}, "build identifiers are predictable deployment artifacts and should never seed ECC nonces");
    if (id == "parser_accepts_trailing_garbage") return make_bool_risk(in, info, "parser.accept_trailing_garbage", "accepting trailing garbage after encoded points or scalars can create ambiguous parsing states and security bypasses");
    if (id == "parser_accepts_signed_hex") return make_bool_risk(in, info, "parser.accept_signed_hex", "accepting signed hexadecimal scalars can create multiple hostile textual encodings for the same value");
    if (id == "signature_scalar_range_check_missing") return make_bool_risk(in, info, "verification.scalar_range_check", "missing scalar range checks lets malformed signature values pass deeper into verification code", false);
    if (id == "subgroup_order_unchecked") return make_bool_risk(in, info, "validation.subgroup_order_checked", "unchecked subgroup order metadata undermines subgroup confinement assumptions", false);
    if (id == "counter_based_nonce_generation") return make_fact_risk(in, info, "rng.generator", {"counter", "monotonic_counter", "global_counter", "counter_plus_time"}, "counter-driven nonce generation makes future ECDSA nonces predictable once the state leaks or is inferred");
    if (id == "pid_based_nonce_generation") return make_fact_risk(in, info, "rng.generator", {"pid", "pid_tid", "time_pid", "time_pid_tid"}, "process identifiers are tiny search spaces and must never feed nonce derivation directly");
    if (id == "message_only_nonce_derivation") return make_bool_risk(in, info, "rng.message_only", "deriving nonces from message material alone breaks unpredictability unless RFC6979 or an equivalent construction is implemented exactly");
    if (id == "nonce_reseeding_on_every_signature") return make_bool_risk(in, info, "rng.reseed_every_signature", "frequent reseeding from low-entropy sources often collapses nonce diversity in practice");
    if (id == "custom_rng_without_health_tests") return make_bool_risk(in, info, "rng.custom_without_health_tests", "custom RNGs need online health checks and failure handling; otherwise silent degradation is likely");
    if (id == "lcg_raw_state_nonce_scan") return make_fact_risk(in, info, "rng.generator", {"lcg_raw_state", "ansi_c_lcg_state", "lcg_state"}, "LCG raw-state outputs are fully predictable from a tiny seed window");
    if (id == "c_rand15_nonce_scan") return make_fact_risk(in, info, "rng.generator", {"c_rand15", "ansi_c_rand", "rand15"}, "rand()-style 15-bit outputs are far too small and structured for ECDSA nonces");
    if (id == "message_hash_plus_counter_nonce_scan") return make_fact_risk(in, info, "rng.generator", {"message_hash_plus_counter", "hash_plus_counter", "message_hash_counter"}, "adding a tiny counter to the message hash still leaves the nonce search space embarrassingly small");
    if (id == "message_hash_scalar_nonce") return make_fact_risk(in, info, "rng.generator", {"message_hash_scalar", "message_hash_mod_n", "hash_as_nonce"}, "using the message digest itself as the nonce destroys the unpredictability requirement of ECDSA");
    if (id == "unix_time_pid_nonce_scan") return make_fact_risk(in, info, "rng.generator", {"unix_time_plus_pid", "time_plus_pid", "unix_time_xor_pid", "time_xor_pid"}, "time plus PID formulas live in a tiny and highly enumerable search space");
    if (id == "unix_time_scalar_nonce_scan") return make_fact_risk(in, info, "rng.generator", {"unix_time_scalar", "unix_time_plus_one"}, "wall-clock time used directly as a scalar creates a tiny offline search space");
    if (id == "all_zero_shared_secret_acceptance") return make_bool_risk(in, info, "ecdh.accept_all_zero_shared_secret", "accepting an all-zero shared secret can turn invalid-peer inputs into protocol confusion and key-confirmation bypasses");
    if (id == "contributory_ecdh_absent") return make_bool_risk(in, info, "protocol.contributory_ecdh", "without contributory ECDH checks, attacker-chosen inputs can collapse the shared-secret space", false);
    if (id == "twist_security_unchecked") return make_bool_risk(in, info, "validation.twist_security_checked", "explicit twist-security validation helps catch dangerous low-order acceptance paths", false);
    if (id == "curve_seed_provenance_missing") return make_bool_risk(in, info, "curve.seed_provenance_documented", "missing parameter provenance makes hostile or accidentally weak custom curves harder to audit", false);
    if (id == "parser_accepts_leading_zero_scalars") return make_bool_risk(in, info, "parser.accept_leading_zero_scalars", "leading-zero scalar acceptance can create ambiguous encodings and parser differentials");
    if (id == "parser_accepts_duplicate_pubkey_forms") return make_bool_risk(in, info, "parser.accept_duplicate_pubkey_forms", "accepting multiple textual or binary forms for the same public key widens canonicalization attack surface");
    if (id == "batch_verifier_missing_per_signature_binding") return make_bool_risk(in, info, "verification.per_signature_binding", "batch verification must bind each signature independently to avoid transcript mixups", false);
    if (id == "cofactor_not_reflected_in_protocol") return make_bool_risk(in, info, "protocol.cofactor_handling", "protocols on non-trivial-cofactor curves need explicit cofactor handling to avoid subgroup surprises", false);
    if (id == "ecdsa_hash_binding_absent") return make_bool_risk(in, info, "ecdsa.hash_binding", "without binding the exact hashed message into signing and verification semantics, cross-message confusion can appear", false);
    if (id == "ecdsa_duplicate_nonce_domain_reuse") return make_bool_risk(in, info, "ecdsa.nonce_state_isolated_per_domain", "reusing nonce state across signing domains or tenants can recreate cross-domain r collisions", false);
    if (id == "ecdsa_context_domain_separation_missing") return make_bool_risk(in, info, "ecdsa.domain_separation", "ECDSA contexts reused across protocol domains invite transcript confusion and nonce cross-contamination", false);
    if (id == "ecdsa_batch_randomizer_reuse") return make_bool_risk(in, info, "verification.batch_randomizer_unique", "reusing the same batch randomizer weakens fault isolation and can invalidate security arguments", false);
    if (id == "ecdsa_nonce_fault_countermeasures_absent") return make_bool_risk(in, info, "ecdsa.nonce_fault_countermeasures", "nonce-fault countermeasures help catch glitched or repeated k generation before signatures leave the signer", false);
    if (id == "low_order_peer_point_acceptance") return make_bool_risk(in, info, "validation.accept_low_order_points", "accepting low-order peer points can collapse the ECDH shared-secret space and leak scalar information");
    if (id == "peer_key_type_confusion") return make_bool_risk(in, info, "ecdh.peer_key_type_confusion", "confusing Montgomery, Edwards, or Weierstrass peer-key encodings can route hostile inputs around validation");
    if (id == "mixed_curve_ecdh_acceptance") return make_bool_risk(in, info, "ecdh.accept_mixed_curve_peer_keys", "accepting peer keys from the wrong curve breaks the meaning of the shared secret and can enable confinement attacks");
    if (id == "peer_key_revalidation_after_parse_missing") return make_bool_risk(in, info, "ecdh.revalidate_after_parse", "decoded peer keys should be revalidated before scalar multiplication because parser acceptance alone is not enough", false);
    if (id == "ecdh_kdf_transcript_binding_missing") return make_bool_risk(in, info, "ecdh.kdf_transcript_binding", "binding the ECDH transcript into the KDF is required to stop transcript transplantation and unknown-key-share confusion", false);
    if (id == "ecdh_kdf_context_missing") return make_bool_risk(in, info, "ecdh.kdf_context_binding", "a context-free KDF output is easier to reuse across roles and protocols than intended", false);
    if (id == "ecdh_peer_identity_unbound") return make_bool_risk(in, info, "ecdh.peer_identity_binding", "without binding peer identity into the key schedule, authenticated channel semantics can silently drift", false);
    if (id == "ecdh_unknown_key_share_risk") return make_bool_risk(in, info, "ecdh.unknown_key_share_protection", "UKS protection is needed so both sides agree on who contributed to the established key", false);
    if (id == "parser_accepts_oid_mismatch") return make_bool_risk(in, info, "parser.accept_oid_mismatch", "accepting an OID that does not match the supplied domain parameters can produce dangerous parser differentials");
    if (id == "parser_accepts_field_length_mismatch") return make_bool_risk(in, info, "parser.accept_field_length_mismatch", "field-length mismatches can hide truncated or padded hostile values from downstream checks");
    if (id == "parser_accepts_sec1_prefix_confusion") return make_bool_risk(in, info, "parser.accept_sec1_prefix_confusion", "ambiguous SEC1 prefixes can let malformed compressed or hybrid points bypass format policy");
    if (id == "parser_accepts_empty_integers") return make_bool_risk(in, info, "parser.accept_empty_integers", "empty integer acceptance can create alternate encodings for zero and other edge values");
    if (id == "parser_accepts_duplicate_der_fields") return make_bool_risk(in, info, "parser.accept_duplicate_der_fields", "duplicate DER fields create ambiguity about which value downstream logic actually used");
    if (id == "parser_accepts_multiple_pem_objects") return make_bool_risk(in, info, "parser.accept_multiple_pem_objects", "accepting multiple PEM objects in one blob can produce parser differentials and silent object substitution");
    if (id == "parser_accepts_mixed_case_hex_scalars") return make_bool_risk(in, info, "parser.accept_mixed_case_hex_scalars", "mixed textual forms widen canonicalization drift and can mask duplicate inputs");
    if (id == "parser_accepts_uncompressed_when_policy_requires_compressed") return make_bool_risk(in, info, "parser.require_compressed_points", "ignoring an agreed compressed-point policy weakens canonicalization and can bypass allowlists", false);
    if (id == "parser_error_oracle") return make_bool_risk(in, info, "oracle.parser_error_classes", "different parser errors can leak which validation layer failed and guide adaptive hostile inputs");
    if (id == "subgroup_classification_oracle") return make_bool_risk(in, info, "oracle.subgroup_classification", "telling the caller whether a point failed subgroup checks gives attackers a confinement oracle");
    if (id == "invalid_curve_classification_oracle") return make_bool_risk(in, info, "oracle.invalid_curve_classification", "distinguishing invalid-curve failures from other failures gives attackers feedback for point crafting");
    if (id == "all_zero_shared_secret_oracle") return make_bool_risk(in, info, "oracle.all_zero_shared_secret", "revealing whether a shared secret collapsed to zero can drive adaptive malicious-peer workflows");
    if (id == "verification_error_oracle") return make_bool_risk(in, info, "oracle.verification_error_classes", "detailed verification failures can become a signature-validation oracle");
    if (id == "twist_classification_oracle") return make_bool_risk(in, info, "oracle.twist_classification", "classifying twist failures separately can hand attackers a guided path toward hostile low-order inputs");
    if (id == "curve_order_proof_missing") return make_bool_risk(in, info, "curve.order_proof_documented", "without an order proof, auditors cannot trust the claimed subgroup size or resulting security level", false);
    if (id == "generator_provenance_missing") return make_bool_risk(in, info, "curve.generator_provenance_documented", "missing generator provenance makes it harder to rule out hostile or accidental generator choices", false);
    if (id == "cofactor_provenance_missing") return make_bool_risk(in, info, "curve.cofactor_documented", "cofactor values must be documented because protocol handling depends on them", false);
    if (id == "twist_order_unchecked") return make_bool_risk(in, info, "curve.twist_order_checked", "unchecked twist order leaves auditors blind to dangerous low-order structure outside the main curve", false);
    if (id == "custom_curve_security_rationale_missing") return make_bool_risk(in, info, "curve.security_rationale_documented", "custom curves need a written security rationale so parameter choices are auditable", false);
    if (id == "domain_parameter_identifier_mismatch") return make_bool_risk(in, info, "curve.identifier_matches_parameters", "mismatched identifiers and parameters can trick software into believing the wrong security domain");
    if (id == "subgroup_generator_binding_missing") return make_bool_risk(in, info, "curve.subgroup_generator_binding_documented", "auditors need an explicit statement that the published generator really spans the claimed subgroup", false);
    if (id == "trace_of_frobenius_unchecked") return make_bool_risk(in, info, "curve.trace_checked", "trace sanity checks help catch malformed or dangerously misunderstood custom-curve instances", false);
    if (id == "ecdsa_low_s_policy_missing") return make_bool_risk(in, info, "ecdsa.low_s_enforced", "without low-S normalization or rejection, signatures remain malleable and harder to canonicalize", false);
    if (id == "ecdsa_zero_hash_policy_missing") return make_bool_risk(in, info, "ecdsa.reject_zero_hash", "explicit zero-hash handling prevents edge-case signatures from drifting across implementations", false);
    if (id == "ecdsa_context_string_missing") return make_bool_risk(in, info, "ecdsa.context_string_bound", "binding a context string into the signing domain reduces cross-protocol confusion", false);
    if (id == "ecdsa_signer_role_binding_missing") return make_bool_risk(in, info, "ecdsa.role_binding", "signing roles should be bound so the same key is not silently reused across incompatible protocol directions", false);
    if (id == "ecdsa_signer_key_commitment_missing") return make_bool_risk(in, info, "ecdsa.key_commitment", "binding the expected signing key identity into higher-level protocol state prevents cross-key confusion", false);
    if (id == "ecdsa_nonce_reuse_alarm_missing") return make_bool_risk(in, info, "ecdsa.nonce_reuse_alarm", "signers should alarm and halt when repeated nonce indicators appear", false);
    if (id == "ecdsa_nonce_monobit_health_test_missing") return make_bool_risk(in, info, "ecdsa.nonce_health_tests", "lightweight health tests catch catastrophic RNG collapse before signatures ship", false);
    if (id == "ecdsa_signature_length_policy_missing") return make_bool_risk(in, info, "ecdsa.signature_length_policy", "explicit signature-length policy avoids acceptance drift across transports and parsers", false);
    if (id == "ecdsa_signature_encoding_canonicalization_missing") return make_bool_risk(in, info, "ecdsa.signature_canonicalization", "canonical signature encoding prevents duplicate encodings of the same mathematical signature", false);
    if (id == "ecdsa_signer_accepts_external_nonce") return make_bool_risk(in, info, "ecdsa.accept_external_nonce", "allowing callers to inject k directly is a common route to catastrophic nonce misuse");
    if (id == "ecdsa_signer_allows_zero_nonce") return make_bool_risk(in, info, "ecdsa.allow_zero_nonce", "a zero or invalid nonce destroys ECDSA correctness and can leak private material");
    if (id == "ecdsa_signer_allows_nonce_equal_order") return make_bool_risk(in, info, "ecdsa.allow_nonce_equal_order", "nonces must be reduced and checked strictly inside the valid scalar range");
    if (id == "ecdsa_prehash_identifier_unbound") return make_bool_risk(in, info, "ecdsa.prehash_identifier_bound", "the signing transcript should bind which hash function and prehash mode were used", false);
    if (id == "ecdsa_hash_algorithm_unpinned") return make_bool_risk(in, info, "ecdsa.hash_algorithm_pinned", "unpinned hash selection can create verification drift and downgrade surprises", false);
    if (id == "ecdsa_nonce_retry_on_zero_missing") return make_bool_risk(in, info, "ecdsa.retry_on_zero_nonce", "signers should retry or fail closed when k lands on an invalid scalar", false);
    if (id == "verifier_accepts_duplicate_signature_encodings") return make_bool_risk(in, info, "verification.accept_duplicate_signature_encodings", "duplicate encodings widen parser differentials and complicate signing policy");
    if (id == "verifier_accepts_negative_signature_scalars") return make_bool_risk(in, info, "verification.accept_negative_signature_scalars", "negative scalar acceptance in DER or textual parsers can reintroduce alternate hostile encodings");
    if (id == "verifier_accepts_overlong_signature_integers") return make_bool_risk(in, info, "verification.accept_overlong_signature_integers", "overlong INTEGER acceptance is a classic ASN.1 canonicalization failure");
    if (id == "ecdsa_nonce_recovery_on_duplicate_r_unchecked") return make_bool_risk(in, info, "ecdsa.duplicate_r_response", "implementations should quarantine keys and investigate when repeated r values are detected", false);
    if (id == "ecdsa_signer_reuses_precomputation_across_keys") return make_bool_risk(in, info, "ecdsa.reuse_precomputation_across_keys", "reusing signer precomputation across keys risks subtle cross-key state contamination");
    if (id == "ecdsa_cross_curve_signature_acceptance") return make_bool_risk(in, info, "verification.accept_cross_curve_signature", "accepting signatures under the wrong curve collapses domain separation");
    if (id == "ecdsa_message_prefix_policy_missing") return make_bool_risk(in, info, "ecdsa.message_prefix_policy", "domain prefixes help stop signing the same raw bytes in multiple semantic contexts", false);
    if (id == "ecdsa_signer_allows_raw_message_without_prehash_policy") return make_bool_risk(in, info, "ecdsa.raw_message_policy", "signers should document whether they sign raw messages, prehashes, or both", false);
    if (id == "ecdsa_verifier_accepts_hash_length_mismatch") return make_bool_risk(in, info, "verification.accept_hash_length_mismatch", "mismatched digest lengths can create cross-implementation verification drift");
    if (id == "ecdsa_aux_randomness_unbound") return make_bool_risk(in, info, "ecdsa.aux_randomness_bound", "if auxiliary randomness is used, it must be bound to the exact signing context", false);
    if (id == "ecdsa_signature_counter_unchecked") return make_bool_risk(in, info, "ecdsa.signing_counter_checked", "signing counters help correlate incidents and detect repeated or rolled-back signer state", false);
    if (id == "ecdsa_fault_injection_retry_policy_missing") return make_bool_risk(in, info, "ecdsa.fault_retry_policy", "fault handling must be explicit so glitched signatures do not leak structure", false);
    if (id == "ecdsa_signer_state_rollback_detection_missing") return make_bool_risk(in, info, "ecdsa.rollback_detection", "rollback detection helps catch VM snapshots or device restores that replay nonce state", false);
    if (id == "ecdh_static_static_no_forward_secrecy") return make_bool_risk(in, info, "ecdh.static_static_without_pfs", "static-static key agreement preserves no forward secrecy if long-term keys leak");
    if (id == "ecdh_ephemeral_reuse_detection_missing") return make_bool_risk(in, info, "ecdh.ephemeral_reuse_detection", "reused ephemeral keys break unlinkability and can magnify compromise windows", false);
    if (id == "ecdh_public_key_validation_order_wrong") return make_bool_risk(in, info, "ecdh.validation_before_scalar_mul", "peer keys must be validated before scalar multiplication or attacker-controlled points can slip deeper", false);
    if (id == "ecdh_zero_coordinate_peer_acceptance") return make_bool_risk(in, info, "ecdh.accept_zero_coordinate_peer", "zero-coordinate peers often indicate malformed or hostile inputs that deserve immediate rejection");
    if (id == "ecdh_cofactor_mode_undocumented") return make_bool_risk(in, info, "ecdh.cofactor_mode_documented", "auditors need to know whether plain, cofactor, or Decaf-style handling is in use", false);
    if (id == "ecdh_mixed_role_key_reuse") return make_bool_risk(in, info, "ecdh.mixed_role_key_reuse", "reusing the same key material across initiator and responder roles invites transcript confusion");
    if (id == "ecdh_shared_secret_serialized_without_length") return make_bool_risk(in, info, "ecdh.shared_secret_length_framed", "unframed secret serialization can create concatenation ambiguities in transcripts", false);
    if (id == "ecdh_no_key_commitment") return make_bool_risk(in, info, "ecdh.key_commitment", "without key commitment, peers can disagree about which public key actually fed the channel", false);
    if (id == "ecdh_channel_binding_missing") return make_bool_risk(in, info, "ecdh.channel_binding", "channel binding ties the derived key to the intended authenticated context", false);
    if (id == "ecdh_peer_curve_identifier_unbound") return make_bool_risk(in, info, "ecdh.peer_curve_identifier_bound", "curve identifiers should be bound so mixed-family inputs cannot drift across adapters", false);
    if (id == "ecdh_shared_secret_reflection_risk") return make_bool_risk(in, info, "ecdh.reflection_protection", "reflection protection helps stop a peer from feeding your own keying material back to you", false);
    if (id == "ecdh_unknown_key_share_detection_missing") return make_bool_risk(in, info, "ecdh.uks_detection", "UKS detection helps catch mismatched peer identity binding during testing", false);
    if (id == "ecdh_no_explicit_role_separation") return make_bool_risk(in, info, "ecdh.role_separation", "key schedules should distinguish initiator and responder contributions", false);
    if (id == "ecdh_precomputation_cache_unbound") return make_bool_risk(in, info, "ecdh.precomputation_cache_bound", "cached precomputation must be tied to the exact curve and key identity to avoid confusion", false);
    if (id == "ecdh_session_id_unbound") return make_bool_risk(in, info, "ecdh.session_id_bound", "binding a session identifier reduces replay and transcript-splicing risk", false);
    if (id == "ecdh_key_confirmation_optional_by_default") return make_bool_risk(in, info, "ecdh.key_confirmation_default_on", "opting out of key confirmation by default increases silent failure risk", false);
    if (id == "ecdh_rejects_infinity_late") return make_bool_risk(in, info, "ecdh.reject_infinity_pre_kdf", "the point at infinity must be rejected before any downstream secret handling", false);
    if (id == "ecdh_same_key_used_for_signing_and_kex") return make_bool_risk(in, info, "ecdh.separate_signing_and_kex_keys", "separate keys reduce cross-protocol risk and simplify incident response", false);
    if (id == "ecdh_transcript_hash_algorithm_unpinned") return make_bool_risk(in, info, "ecdh.transcript_hash_pinned", "unpinned transcript hashing can produce silent peer mismatches", false);
    if (id == "ecdh_peer_key_cache_without_revocation") return make_bool_risk(in, info, "ecdh.peer_key_cache_revocation_aware", "cached peer keys should respect revocation or rotation signals", false);
    if (id == "ecdh_replay_window_unbounded") return make_bool_risk(in, info, "ecdh.bounded_replay_window", "bounded replay windows reduce the blast radius of repeated handshakes", false);
    if (id == "ecdh_accepts_small_subgroup_cleartext_hints") return make_bool_risk(in, info, "ecdh.accept_subgroup_hints", "peer-supplied subgroup hints can steer implementations toward dangerous validation shortcuts");
    if (id == "ecdh_handshake_role_confusion") return make_bool_risk(in, info, "ecdh.role_confusion", "ambiguous handshake roles can create key schedule mismatches and UKS-style problems");
    if (id == "ecdh_zero_padding_policy_missing") return make_bool_risk(in, info, "ecdh.zero_padding_policy", "shared-secret serialization needs an explicit padding policy to stay interoperable", false);
    if (id == "ecdh_peer_fingerprint_unchecked") return make_bool_risk(in, info, "ecdh.peer_fingerprint_checked", "out-of-band peer fingerprint checks are essential in pinned-key deployments", false);
    if (id == "ecdh_secret_export_without_context") return make_bool_risk(in, info, "ecdh.secret_export_context", "exported shared secrets need context labels so downstream consumers cannot confuse them", false);
    if (id == "parser_accepts_indefinite_length_der") return make_bool_risk(in, info, "parser.accept_indefinite_length_der", "DER requires definite lengths; indefinite-length acceptance widens BER-style ambiguity");
    if (id == "parser_accepts_negative_integers") return make_bool_risk(in, info, "parser.accept_negative_integers", "negative INTEGER acceptance can create alternate encodings for hostile scalar values");
    if (id == "parser_accepts_overlong_length_encodings") return make_bool_risk(in, info, "parser.accept_overlong_length_encodings", "overlong ASN.1 lengths are a classic canonicalization failure");
    if (id == "parser_accepts_nul_in_pem") return make_bool_risk(in, info, "parser.accept_nul_in_pem", "embedded NUL bytes can confuse downstream text or filesystem handling");
    if (id == "parser_accepts_duplicate_spki_algorithm") return make_bool_risk(in, info, "parser.accept_duplicate_spki_algorithm", "duplicate algorithm identifiers create ambiguity about which domain was intended");
    if (id == "parser_accepts_truncated_bitstring") return make_bool_risk(in, info, "parser.accept_truncated_bitstring", "truncated bit strings can hide malformed keys behind forgiving decoders");
    if (id == "parser_accepts_nonminimal_oid") return make_bool_risk(in, info, "parser.accept_nonminimal_oid", "non-minimal OID encodings widen parser differentials and policy bypasses");
    if (id == "parser_accepts_unused_bits_nonzero") return make_bool_risk(in, info, "parser.accept_unused_bits_nonzero", "non-zero unused bits in BIT STRING objects violate canonical encoding rules");
    if (id == "parser_accepts_whitespace_inside_hex") return make_bool_risk(in, info, "parser.accept_whitespace_inside_hex", "forgiving textual parsers can accidentally normalize maliciously edited material");
    if (id == "parser_accepts_coordinate_overflow") return make_bool_risk(in, info, "parser.accept_coordinate_overflow", "coordinates outside the field must never be accepted or silently reduced");
    if (id == "parser_accepts_scalar_overflow_reduction") return make_bool_risk(in, info, "parser.reduce_scalar_overflow", "silent scalar reduction masks malformed inputs and destroys canonical validation");
    if (id == "parser_accepts_unknown_pem_label") return make_bool_risk(in, info, "parser.accept_unknown_pem_label", "unknown PEM labels can hide unexpected object types from callers");
    if (id == "parser_accepts_extra_octet_wrap") return make_bool_risk(in, info, "parser.accept_extra_octet_wrap", "extra wrapping layers create alternate encodings of the same object");
    if (id == "parser_accepts_mixed_spki_and_sec1") return make_bool_risk(in, info, "parser.accept_mixed_spki_and_sec1", "mixed envelope handling increases object-confusion risk");
    if (id == "parser_accepts_duplicate_curve_identifiers") return make_bool_risk(in, info, "parser.accept_duplicate_curve_identifiers", "duplicate curve identifiers can produce split-brain domain selection");
    if (id == "parser_accepts_embedded_nul_text") return make_bool_risk(in, info, "parser.accept_embedded_nul_text", "embedded NUL text handling can produce truncation differentials in wrappers");
    if (id == "parser_accepts_invalid_base64_padding") return make_bool_risk(in, info, "parser.accept_invalid_base64_padding", "forgiving base64 decoders can normalize hostile edits silently");
    if (id == "parser_accepts_noncanonical_pem_boundaries") return make_bool_risk(in, info, "parser.accept_noncanonical_pem_boundaries", "non-canonical PEM boundaries widen input-normalization attack surface");
    if (id == "parser_accepts_unterminated_pem") return make_bool_risk(in, info, "parser.accept_unterminated_pem", "unterminated PEM acceptance can leak object-boundary ambiguity into wrappers");
    if (id == "parser_accepts_invalid_asn1_tag_class") return make_bool_risk(in, info, "parser.accept_invalid_asn1_tag_class", "unexpected tag classes should fail closed in strict ECC object parsers");
    if (id == "parser_accepts_oid_alias_without_policy") return make_bool_risk(in, info, "parser.accept_oid_alias_without_policy", "alias handling should be explicit so allowlists remain deterministic");
    if (id == "parser_accepts_zero_length_octet_string") return make_bool_risk(in, info, "parser.accept_zero_length_octet_string", "zero-length wrappers around key material are ambiguous and should be rejected");
    if (id == "parser_accepts_missing_null_parameters") return make_bool_risk(in, info, "parser.accept_missing_null_parameters", "algorithm parameters need a deterministic normalization policy");
    if (id == "parser_accepts_explicit_parameters_when_named_required") return make_bool_risk(in, info, "parser.accept_explicit_parameters_when_named_required", "explicit parameters can bypass named-curve policy and review expectations");
    if (id == "parser_accepts_named_curve_when_explicit_required") return make_bool_risk(in, info, "parser.accept_named_curve_when_explicit_required", "when explicit domain review is required, named-curve shorthand should not bypass it");
    if (id == "parser_accepts_mixed_endianness_text") return make_bool_risk(in, info, "parser.accept_mixed_endianness_text", "mixed-endianness text handling can silently reinterpret coordinates and scalars");
    if (id == "parser_accepts_ber_where_der_required") return make_bool_risk(in, info, "parser.accept_ber_where_der_required", "BER acceptance in DER-only contexts widens canonicalization drift");
    if (id == "parser_accepts_length_prefix_mismatch") return make_bool_risk(in, info, "parser.accept_length_prefix_mismatch", "declared and actual length mismatches should fail before any deeper processing");
    if (id == "parser_accepts_duplicate_integer_sign_bits") return make_bool_risk(in, info, "parser.accept_duplicate_integer_sign_bits", "duplicate sign-bit padding creates alternate non-canonical encodings");
    if (id == "parser_accepts_odd_length_hex_without_normalization") return make_bool_risk(in, info, "parser.accept_odd_length_hex_without_normalization", "odd-length hex parsing should be explicit to avoid hidden nibble shifts");
    if (id == "oracle_curve_identifier_leak") return make_bool_risk(in, info, "oracle.curve_identifier_leak", "revealing the exact curve family can help attackers tailor malformed inputs");
    if (id == "oracle_parser_depth_leak") return make_bool_risk(in, info, "oracle.parser_depth_leak", "leaking parse depth reveals how far hostile inputs progressed into the decoder");
    if (id == "oracle_scalar_range_leak") return make_bool_risk(in, info, "oracle.scalar_range_leak", "telling callers whether a scalar failed a range check gives adaptive feedback");
    if (id == "oracle_nonce_fault_alarm_leak") return make_bool_risk(in, info, "oracle.nonce_fault_alarm_leak", "detailed signer alarm behavior can leak internal nonce-generation state");
    if (id == "oracle_kdf_context_leak") return make_bool_risk(in, info, "oracle.kdf_context_leak", "revealing which KDF context branch executed helps adaptive protocol probing");
    if (id == "oracle_identity_binding_leak") return make_bool_risk(in, info, "oracle.identity_binding_leak", "distinct identity-binding failures give attackers extra transcript feedback");
    if (id == "oracle_compressed_vs_uncompressed_leak") return make_bool_risk(in, info, "oracle.encoding_policy_leak", "revealing whether compressed or uncompressed inputs failed can aid parser probing");
    if (id == "oracle_named_vs_explicit_curve_leak") return make_bool_risk(in, info, "oracle.named_vs_explicit_curve_leak", "separate errors for named and explicit parameters disclose parser policy internals");
    if (id == "oracle_padding_length_leak") return make_bool_risk(in, info, "oracle.padding_length_leak", "padding-length leakage can help attackers steer crafted transport payloads");
    if (id == "oracle_batch_membership_leak") return make_bool_risk(in, info, "oracle.batch_membership_leak", "revealing which batch element failed gives attackers a guided verifier oracle");
    if (id == "oracle_duplicate_signature_encoding_leak") return make_bool_risk(in, info, "oracle.duplicate_signature_encoding_leak", "separate duplicate-encoding errors leak canonicalization policy");
    if (id == "oracle_low_order_classification_leak") return make_bool_risk(in, info, "oracle.low_order_classification_leak", "classifying low-order points directly feeds subgroup-confinement workflows");
    if (id == "oracle_cofactor_mode_leak") return make_bool_risk(in, info, "oracle.cofactor_mode_leak", "revealing cofactor-handling mode makes it easier to tailor hostile peer points");
    if (id == "oracle_curve_provenance_leak") return make_bool_risk(in, info, "oracle.curve_provenance_leak", "provenance details belong in documentation, not adaptive error channels");
    if (id == "oracle_seed_source_leak") return make_bool_risk(in, info, "oracle.seed_source_leak", "leaking whether time, PID, or device IDs influenced state helps offline enumeration");
    if (id == "oracle_der_canonicalization_leak") return make_bool_risk(in, info, "oracle.der_canonicalization_leak", "error differences around DER strictness help attackers tune malformed encodings");
    if (id == "oracle_pem_label_leak") return make_bool_risk(in, info, "oracle.pem_label_leak", "PEM-label specific errors reveal accepted object types to adaptive callers");
    if (id == "oracle_hash_algorithm_leak") return make_bool_risk(in, info, "oracle.hash_algorithm_leak", "revealing hash-policy failures can aid downgrade and confusion attempts");
    if (id == "oracle_role_binding_leak") return make_bool_risk(in, info, "oracle.role_binding_leak", "role-binding distinctions should not become an adaptive oracle");
    if (id == "oracle_replay_window_leak") return make_bool_risk(in, info, "oracle.replay_window_leak", "leaking replay-window boundaries improves adaptive replay timing");
    if (id == "oracle_transcript_binding_leak") return make_bool_risk(in, info, "oracle.transcript_binding_leak", "detailed transcript-binding failures create a protocol-structure oracle");
    if (id == "oracle_ephemeral_reuse_leak") return make_bool_risk(in, info, "oracle.ephemeral_reuse_leak", "revealing reused-ephemeral detection gives attackers state feedback they should not get");
    if (id == "curve_prime_generation_proof_missing") return make_bool_risk(in, info, "curve.prime_generation_proof_documented", "prime-generation provenance helps auditors trust the published base field", false);
    if (id == "curve_order_factorization_unchecked") return make_bool_risk(in, info, "curve.order_factorization_checked", "partial factorization checks help surface dangerous small factors in the full group order", false);
    if (id == "curve_twist_factorization_unchecked") return make_bool_risk(in, info, "curve.twist_factorization_checked", "twist factorization is central to invalid-point and low-order risk review", false);
    if (id == "curve_embedding_degree_unchecked") return make_bool_risk(in, info, "curve.embedding_degree_checked", "embedding-degree review helps screen for MOV-style surprises", false);
    if (id == "curve_mov_bound_unchecked") return make_bool_risk(in, info, "curve.mov_bound_checked", "MOV-style transfer bounds are part of a serious custom-curve audit", false);
    if (id == "curve_frey_ruck_unchecked") return make_bool_risk(in, info, "curve.frey_ruck_checked", "pairing-related sanity checks matter for nonstandard custom curves", false);
    if (id == "curve_cm_discriminant_undocumented") return make_bool_risk(in, info, "curve.cm_discriminant_documented", "CM-related provenance should be documented when relevant to parameter generation", false);
    if (id == "curve_endomorphism_undocumented") return make_bool_risk(in, info, "curve.endomorphism_documented", "endomorphism structure changes implementation and side-channel considerations", false);
    if (id == "curve_complete_parameter_set_missing") return make_bool_risk(in, info, "curve.complete_parameter_set_documented", "auditors need the full parameter set, not only a curve name or fragment", false);
    if (id == "curve_base_field_encoding_mismatch") return make_bool_risk(in, info, "curve.base_field_encoding_matches", "field-encoding mismatches can make parsers and arithmetic disagree about the domain");
    if (id == "curve_security_level_undocumented") return make_bool_risk(in, info, "curve.security_level_documented", "published security targets help reviewers judge whether a curve is fit for purpose", false);
    if (id == "curve_generation_seed_reuse_risk") return make_bool_risk(in, info, "curve.seed_reuse_risk", "reused generation seeds can undermine claims of rigidity or independence");
    if (id == "curve_parameter_generation_process_missing") return make_bool_risk(in, info, "curve.generation_process_documented", "a parameter-generation narrative is essential for serious third-party review", false);
    if (id == "curve_rigidity_claim_unsubstantiated") return make_bool_risk(in, info, "curve.rigidity_claim_substantiated", "rigidity claims need evidence, not just marketing language", false);
    if (id == "curve_rational_torsion_unchecked") return make_bool_risk(in, info, "curve.rational_torsion_checked", "torsion review helps surface hidden subgroup hazards in custom curves", false);
    if (id == "curve_small_factor_scan_missing") return make_bool_risk(in, info, "curve.small_factor_scan_done", "small-factor scans are low-cost and high-value for custom-curve sanity", false);
    if (id == "curve_quadratic_twist_cofactor_unchecked") return make_bool_risk(in, info, "curve.twist_cofactor_checked", "twist cofactors matter when reviewing invalid-point resistance", false);
    if (id == "curve_isogeny_class_undocumented") return make_bool_risk(in, info, "curve.isogeny_class_documented", "isogeny-class notes help reviewers place a custom curve in a known family", false);
    if (id == "curve_anomalous_check_missing") return make_bool_risk(in, info, "curve.anomalous_checked", "anomalous curves must be ruled out explicitly in a serious ECC audit", false);
    if (id == "curve_supersingularity_check_missing") return make_bool_risk(in, info, "curve.supersingularity_checked", "supersingularity status should be explicit so security assumptions remain clear", false);
    if (id == "curve_cofactor_decomposition_missing") return make_bool_risk(in, info, "curve.cofactor_decomposition_documented", "cofactor decomposition helps explain how subgroup structure is handled", false);
    if (id == "curve_parameter_versioning_missing") return make_bool_risk(in, info, "curve.parameter_versioning_documented", "versioning matters when audited parameters evolve over time", false);
    if (id == "curve_documentation_hash_missing") return make_bool_risk(in, info, "curve.documentation_hash_recorded", "recording documentation hashes helps reviewers pin exactly what was audited", false);

    if (id == "backend_pubkey_validation_differential") return make_bool_risk(in, info, "backend.diff.pubkey_validation", "if backends disagree on public-key validation, hostile keys can slip through one adapter while others reject them");
    if (id == "backend_signature_canonicalization_differential") return make_bool_risk(in, info, "backend.diff.signature_canonicalization", "signature canonicalization differences widen replay and parser-confusion surfaces");
    if (id == "backend_low_s_policy_differential") return make_bool_risk(in, info, "backend.diff.low_s_policy", "different low-S policies produce verifier disagreement and duplicate-signature ambiguity");
    if (id == "backend_invalid_curve_rejection_differential") return make_bool_risk(in, info, "backend.diff.invalid_curve_rejection", "different invalid-curve behavior makes it easier to route hostile points toward the weakest backend");
    if (id == "backend_der_strictness_differential") return make_bool_risk(in, info, "backend.diff.der_strictness", "DER strictness differentials create parser confusion and portability bugs with security impact");
    if (id == "backend_oid_resolution_differential") return make_bool_risk(in, info, "backend.diff.oid_resolution", "curve-OID resolution must be pinned so one backend cannot reinterpret another backend's input");
    if (id == "backend_point_parser_differential") return make_bool_risk(in, info, "backend.diff.point_parser", "point-decoding disagreement can split validation outcomes and invalidate audit assumptions");
    if (id == "backend_ecdh_shared_secret_format_differential") return make_bool_risk(in, info, "backend.diff.ecdh_shared_secret_format", "ECDH output-format disagreement can break transcript binding and key confirmation");
    if (id == "backend_explicit_parameter_policy_differential") return make_bool_risk(in, info, "backend.diff.explicit_parameter_policy", "explicit-parameter policy must be consistent or hostile objects may route differently across environments");
    if (id == "backend_named_curve_alias_differential") return make_bool_risk(in, info, "backend.diff.named_curve_aliases", "alias resolution differences can bind the same object to different domains across backends");
    if (id == "backend_error_surface_differential") return make_bool_risk(in, info, "backend.diff.error_surface", "backend-specific error surfaces can become an oracle when multiple adapters are exposed");
    if (id == "backend_scalar_range_policy_differential") return make_bool_risk(in, info, "backend.diff.scalar_range_policy", "scalar-range disagreement can make malformed keys or signatures valid in only part of the estate");
    if (id == "curve_hasse_bound_unchecked") return make_bool_risk(in, info, "curve.hasse_bound_checked", "serious ECC review should confirm that claimed orders sit inside the Hasse bound", false);
    if (id == "curve_twist_security_margin_undocumented") return make_bool_risk(in, info, "curve.twist_security_margin_documented", "twist security needs an explicit margin statement when hostile points are in scope", false);
    if (id == "curve_prime_subgroup_ratio_unchecked") return make_bool_risk(in, info, "curve.prime_subgroup_ratio_checked", "reviewers should know how much of the full group sits inside the intended prime-order subgroup", false);
    if (id == "curve_generator_cofactor_alignment_unchecked") return make_bool_risk(in, info, "curve.generator_cofactor_alignment_checked", "generator and cofactor alignment should be checked so subgroup claims remain coherent", false);
    if (id == "curve_twist_trace_unchecked") return make_bool_risk(in, info, "curve.twist_trace_checked", "tracking the twist trace helps validate order and invalid-point assumptions", false);
    if (id == "curve_order_claim_source_missing") return make_bool_risk(in, info, "curve.order_claim_source_documented", "auditors need a documented source for the claimed curve order, not only the number itself", false);
    if (id == "backend_spki_vs_sec1_differential") return make_bool_risk(in, info, "backend.diff.spki_vs_sec1", "backend disagreement between SPKI and raw SEC1 decoding creates dangerous portability gaps");
    if (id == "backend_pem_label_differential") return make_bool_risk(in, info, "backend.diff.pem_label", "PEM label handling should be deterministic across backends to avoid object confusion");
    if (id == "backend_explicit_curve_parameter_differential") return make_bool_risk(in, info, "backend.diff.explicit_curve_parameters", "explicit-parameter handling must be pinned across backends or one path may accept hostile domains");
    if (id == "parser_accepts_spki_without_named_curve") return make_bool_risk(in, info, "parser.accept_spki_without_named_curve", "SPKI objects without a named-curve OID should not be accepted ambiguously");
    if (id == "parser_accepts_spki_bitstring_padding") return make_bool_risk(in, info, "parser.accept_spki_bitstring_padding", "padded SPKI BIT STRING keys widen parser differential and canonicalization risk");
    if (id == "parser_accepts_raw_ec_point_without_spki") return make_bool_risk(in, info, "parser.accept_raw_ec_point_without_spki", "accepting naked EC points where SPKI is required weakens object typing and policy control");
    if (id == "curve_explicit_parameter_proof_missing") return make_bool_risk(in, info, "curve.explicit_parameter_proof_documented", "explicit curve parameters need a proof bundle and rationale so auditors can validate the domain", false);
    if (id == "curve_spki_oid_missing") return make_bool_risk(in, info, "curve.spki_oid_documented", "serious reviews should record the SPKI/OID identity that callers are expected to consume", false);
    if (id == "curve_alias_registry_mismatch") return make_bool_risk(in, info, "curve.alias_registry_consistent", "curve aliases must resolve deterministically or allowlists and reports become ambiguous", false);
    if (id == "nonce_affine_relation_scan") {
        ModuleResult r = make_base(info, false);
        if (in.constraints.related_a_abs_max > 0 && in.constraints.related_b_abs_max > 0) {
            r.status = "INFO";
            r.lines.push_back("evidence = affine nonce scan window is configured and an active solver is available");
        } else {
            r.status = "INFO";
            r.lines.push_back("evidence = affine nonce relation support is present but no scan window was requested");
        }
        return r;
    }
    ModuleResult r = make_base(info, false);
    r.status = "INFO";
    r.lines.push_back("rationale = no dispatcher was registered for this fault class");
    return r;
}

std::string json_escape(const std::string& s) {
    std::ostringstream oss;
    for (unsigned char c : s) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c < 0x20) {
                    oss << "\\u" << std::hex << std::uppercase;
                    oss.width(4);
                    oss.fill('0');
                    oss << static_cast<int>(c);
                    oss << std::dec;
                } else {
                    oss << static_cast<char>(c);
                }
        }
    }
    return oss.str();
}


bool needs_curve_algebra(const std::string& id) {
    static const std::unordered_set<std::string> kIds = {
        "curve_discriminant_failure", "field_modulus_not_prime", "subgroup_order_not_prime",
        "generator_at_infinity", "generator_not_on_curve", "generator_order_mismatch",
        "public_key_subgroup_mismatch", "nontrivial_cofactor_notice"
    };
    return kIds.find(id) != kIds.end();
}
bool needs_algebraic_public_key(const std::string& id) {
    static const std::unordered_set<std::string> kIds = {
        "public_key_subgroup_mismatch", "tiny_public_key_multiple_scan", "exact_nonce_reuse", "related_nonce_delta_scan",
        "counter_nonce_sequence_scan", "nonce_affine_relation_scan", "nonce_partial_lsb_bruteforce", "nonce_partial_msb_bruteforce",
        "lcg_raw_state_nonce_scan", "c_rand15_nonce_scan", "lcg_raw_state_sequence_scan", "c_rand15_sequence_scan",
        "message_hash_plus_counter_nonce_scan", "message_hash_xor_counter_nonce_scan", "unix_time_pid_counter_nonce_scan",
        "message_hash_plus_pid_nonce_scan", "message_hash_xor_pid_nonce_scan", "unix_time_plus_counter_nonce_scan",
        "unix_time_xor_counter_nonce_scan", "splitmix64_nonce_scan", "pcg32_nonce_scan", "splitmix64_xor_counter_nonce_scan",
        "pcg32_plus_counter_nonce_scan", "device_identifier_seeded_nonce_scan", "device_id_plus_counter_nonce_scan",
        "device_id_xor_counter_nonce_scan", "unix_time_device_id_nonce_scan", "mt19937_nonce_scan", "xorshift32_nonce_scan",
        "xorshift64_nonce_scan", "splitmix64_sequence_scan", "pcg32_sequence_scan", "message_hash_plus_time_pid_nonce_scan",
        "message_hash_xor_time_pid_nonce_scan", "message_hash_plus_time_nonce_scan", "message_hash_xor_time_nonce_scan",
        "mwc1616_nonce_scan", "sfc64_nonce_scan", "wyrand_nonce_scan", "message_hash_scalar_nonce", "unix_time_pid_nonce_scan",
        "small_nonce_bsgs", "small_private_key_bsgs", "pid_scalar_nonce_scan", "unix_time_scalar_nonce_scan"
    };
    return kIds.find(id) != kIds.end();
}

ModuleResult skip_for_unparsed_public_key(const CheckInfo& info, const std::string& why) {
    ModuleResult r = make_base(info, false);
    r.status = "SKIP";
    r.lines.push_back("rationale = active algebra for the supplied public key was unavailable");
    if (!why.empty()) r.lines.push_back("parse_error = " + why);
    finalize_module_metadata(r);
    return r;
}

std::optional<std::string> best_effort_public_key_hex(const PublicKeyInput& pk) {
    if (pk.compressed_hex) return normalize_hex(*pk.compressed_hex);
    if (pk.raw_hex) return normalize_hex(*pk.raw_hex);
    if (pk.x_hex && pk.y_hex) return normalize_hex(*pk.x_hex) + ":" + normalize_hex(*pk.y_hex);
    return std::nullopt;
}

} // namespace

AnalysisResult run_all_modules(const ChallengeInput& in) {
    AnalysisResult result;
    try {
        result.curve = curve_from_named_or_custom(in.curve.name, in.curve.p_hex, in.curve.a_hex, in.curve.b_hex,
                                                  in.curve.gx_hex, in.curve.gy_hex, in.curve.n_hex, in.curve.h_hex);
    } catch (const std::exception&) {
        if (const auto passive = passive_curve_descriptor(in.curve.name)) result.curve = *passive;
        else throw;
    }
    result.original_public_key_hex = best_effort_public_key_hex(in.public_key);
    result.public_key_source_kind = in.public_key.source_kind.value_or("");
    try {
        result.public_key = parse_public_key(result.curve, in.public_key);
        result.public_key_parsed = true;
    } catch (const std::exception& e) {
        result.public_key_parsed = false;
        result.public_key_parse_error = e.what();
        result.public_key = result.curve.G.inf ? Point() : result.curve.G;
        const bool allow_passive = fact_is_true(in, "parser.invalid_pubkey_template") || !result.curve.active_algebra_supported ||
                                   in.mode == "parser" || in.mode == "oracle" || in.mode == "curve_provenance" || in.mode == "ecdh_oracle";
        if (!allow_passive) throw;
    }
    result.modules.push_back(basic_validation_module(result.curve, result.public_key, in, result.public_key_parsed, result.public_key_parse_error));

    for (const auto& info : catalog()) {
        if (!result.curve.active_algebra_supported && needs_curve_algebra(info.id)) {
            result.modules.push_back(skip_for_unparsed_public_key(info, "active curve algebra is unavailable for this family in v30"));
            continue;
        }
        if (!result.public_key_parsed && needs_algebraic_public_key(info.id)) {
            result.modules.push_back(skip_for_unparsed_public_key(info, result.public_key_parse_error));
            continue;
        }
        if (info.id == "curve_discriminant_failure") {
            result.modules.push_back(curve_discriminant_module(info, result.curve));
        } else if (info.id == "field_modulus_not_prime") {
            result.modules.push_back(field_modulus_not_prime_module(info, result.curve));
        } else if (info.id == "subgroup_order_not_prime") {
            result.modules.push_back(subgroup_order_not_prime_module(info, result.curve));
        } else if (info.id == "generator_at_infinity") {
            result.modules.push_back(generator_at_infinity_module(info, result.curve));
        } else if (info.id == "generator_not_on_curve") {
            result.modules.push_back(generator_not_on_curve_module(info, result.curve));
        } else if (info.id == "generator_order_mismatch") {
            result.modules.push_back(generator_order_mismatch_module(info, result.curve));
        } else if (info.id == "public_key_subgroup_mismatch") {
            result.modules.push_back(public_key_subgroup_mismatch_module(info, result.curve, result.public_key));
        } else if (info.id == "tiny_seed_window_declared") {
            result.modules.push_back(tiny_seed_window_module(info, in));
        } else if (info.id == "tiny_counter_window_declared") {
            result.modules.push_back(tiny_counter_window_module(info, in));
        } else if (info.id == "tiny_unix_time_window_declared") {
            result.modules.push_back(tiny_unix_time_window_module(info, in));
        } else if (info.id == "nontrivial_cofactor_notice") {
            result.modules.push_back(nontrivial_cofactor_notice_module(info, result.curve));
        } else if (info.id == "tiny_public_key_multiple_scan") {
            result.modules.push_back(tiny_public_key_multiple_module(info, result.curve, result.public_key, in));
        } else if (info.id == "signature_component_range_failure") {
            result.modules.push_back(signature_component_range_module(info, result.curve, in));
        } else if (info.id == "high_s_malleability_acceptance") {
            result.modules.push_back(high_s_policy_module(info, result.curve, in));
        } else if (info.id == "duplicate_message_hashes") {
            result.modules.push_back(duplicate_hash_module(info, in));
        } else if (info.id == "repeated_r_values") {
            result.modules.push_back(repeated_r_module(info, in));
        } else if (info.id == "exact_nonce_reuse") {
            result.modules.push_back(exact_nonce_reuse_module(info, result.curve, result.public_key, in));
        } else if (info.id == "related_nonce_delta_scan") {
            result.modules.push_back(related_nonce_delta_module(info, result.curve, result.public_key, in));
        } else if (info.id == "counter_nonce_sequence_scan") {
            result.modules.push_back(counter_nonce_sequence_module(info, result.curve, result.public_key, in));
        } else if (info.id == "nonce_affine_relation_scan") {
            result.modules.push_back(nonce_affine_relation_module(info, result.curve, result.public_key, in));
        } else if (info.id == "nonce_partial_lsb_bruteforce") {
            result.modules.push_back(partial_nonce_lsb_module(info, result.curve, result.public_key, in));
        } else if (info.id == "nonce_partial_msb_bruteforce") {
            result.modules.push_back(partial_nonce_msb_module(info, result.curve, result.public_key, in));
        } else if (info.id == "lcg_raw_state_nonce_scan") {
            result.modules.push_back(lcg_raw_state_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "c_rand15_nonce_scan") {
            result.modules.push_back(c_rand15_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "lcg_raw_state_sequence_scan") {
            result.modules.push_back(lcg_raw_state_sequence_module(info, result.curve, result.public_key, in));
        } else if (info.id == "c_rand15_sequence_scan") {
            result.modules.push_back(c_rand15_sequence_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_plus_counter_nonce_scan") {
            result.modules.push_back(message_hash_plus_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_xor_counter_nonce_scan") {
            result.modules.push_back(message_hash_xor_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "unix_time_pid_counter_nonce_scan") {
            result.modules.push_back(unix_time_pid_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_plus_pid_nonce_scan") {
            result.modules.push_back(message_hash_plus_pid_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_xor_pid_nonce_scan") {
            result.modules.push_back(message_hash_xor_pid_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "unix_time_plus_counter_nonce_scan") {
            result.modules.push_back(unix_time_plus_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "unix_time_xor_counter_nonce_scan") {
            result.modules.push_back(unix_time_xor_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "splitmix64_nonce_scan") {
            result.modules.push_back(splitmix64_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "pcg32_nonce_scan") {
            result.modules.push_back(pcg32_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "splitmix64_xor_counter_nonce_scan") {
            result.modules.push_back(splitmix64_xor_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "pcg32_plus_counter_nonce_scan") {
            result.modules.push_back(pcg32_plus_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "device_identifier_seeded_nonce_scan") {
            result.modules.push_back(device_identifier_seeded_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "device_id_plus_counter_nonce_scan") {
            result.modules.push_back(device_id_plus_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "device_id_xor_counter_nonce_scan") {
            result.modules.push_back(device_id_xor_counter_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "unix_time_device_id_nonce_scan") {
            result.modules.push_back(unix_time_device_id_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "mt19937_nonce_scan") {
            result.modules.push_back(mt19937_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "xorshift32_nonce_scan") {
            result.modules.push_back(xorshift32_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "xorshift64_nonce_scan") {
            result.modules.push_back(xorshift64_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "splitmix64_sequence_scan") {
            result.modules.push_back(splitmix64_sequence_module(info, result.curve, result.public_key, in));
        } else if (info.id == "pcg32_sequence_scan") {
            result.modules.push_back(pcg32_sequence_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_plus_time_pid_nonce_scan") {
            result.modules.push_back(message_hash_plus_time_pid_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_xor_time_pid_nonce_scan") {
            result.modules.push_back(message_hash_xor_time_pid_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_plus_time_nonce_scan") {
            result.modules.push_back(message_hash_plus_time_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_xor_time_nonce_scan") {
            result.modules.push_back(message_hash_xor_time_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "mwc1616_nonce_scan") {
            result.modules.push_back(mwc1616_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "sfc64_nonce_scan") {
            result.modules.push_back(sfc64_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "wyrand_nonce_scan") {
            result.modules.push_back(wyrand_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "message_hash_scalar_nonce") {
            result.modules.push_back(message_hash_scalar_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "unix_time_pid_nonce_scan") {
            result.modules.push_back(unix_time_pid_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "small_nonce_bsgs") {
            result.modules.push_back(small_nonce_bsgs_module(info, result.curve, result.public_key, in));
        } else if (info.id == "small_private_key_bsgs") {
            result.modules.push_back(small_privkey_bsgs_module(info, result.curve, result.public_key, in));
        } else if (info.id == "pid_scalar_nonce_scan") {
            result.modules.push_back(pid_scalar_nonce_module(info, result.curve, result.public_key, in));
        } else if (info.id == "unix_time_scalar_nonce_scan") {
            result.modules.push_back(unix_time_scalar_nonce_module(info, result.curve, result.public_key, in));
        } else {
            result.modules.push_back(fact_dispatch(info, in));
        }
    }
    for (auto& module : result.modules) finalize_module_metadata(module);
    return result;
}

namespace {

int severity_rank(const std::string& sev) {
    const std::string s = lower_copy(sev);
    if (s == "critical") return 4;
    if (s == "high") return 3;
    if (s == "medium") return 2;
    if (s == "low") return 1;
    return 0;
}

std::vector<const ModuleResult*> collect_hits_sorted(const AnalysisResult& result) {
    std::vector<const ModuleResult*> hits;
    for (const auto& module : result.modules) {
        if (module.status == "HIT") hits.push_back(&module);
    }
    std::stable_sort(hits.begin(), hits.end(), [](const ModuleResult* a, const ModuleResult* b) {
        const int ar = (a->recovered && a->private_key ? 1 : 0);
        const int br = (b->recovered && b->private_key ? 1 : 0);
        if (ar != br) return ar > br;
        const int aa = (a->active_attack ? 1 : 0);
        const int ba = (b->active_attack ? 1 : 0);
        if (aa != ba) return aa > ba;
        const int as = severity_rank(a->severity);
        const int bs = severity_rank(b->severity);
        if (as != bs) return as > bs;
        return a->id < b->id;
    });
    return hits;
}

std::string recovery_class_for(const ModuleResult& module) {
    if (module.recovered && module.private_key) return "key_recovery";
    if (module.active_attack) return "active_attack_no_key";
    return "diagnostic_only";
}

std::string recoverability_status_for(const ModuleResult& module) {
    if (module.recovered && module.private_key) return "R5_trivial_or_lab_proven";
    if (module.status == "HIT" && module.active_attack) return "R3_engine_supported_but_not_recovered";
    if (module.status == "HIT" && severity_rank(module.severity) >= 3) return "R2_structural_high_risk";
    if (module.status == "HIT") return "R1_structural_risk";
    return "R0_no_current_recovery_evidence";
}

std::vector<std::string> remediation_for(const ModuleResult& module) {
    std::vector<std::string> fixes;
    const auto add = [&](const std::string& s) { fixes.push_back(s); };
    if (module.id.find("nonce") != std::string::npos || module.category == "rng") {
        add("replace ad-hoc nonce generation with RFC6979 or a vetted cryptographic DRBG");
        add("add regression tests that fail on repeated, biased, or structured nonces");
    }
    if (module.id.find("subgroup") != std::string::npos || module.id.find("twist") != std::string::npos || module.id.find("invalid_curve") != std::string::npos) {
        add("perform full public-key validation before scalar multiplication");
        add("enforce subgroup membership checks and reject low-order or twist points");
    }
    if (module.category == "parser" || module.id.find("parser") != std::string::npos) {
        add("accept only canonical encodings and reject malformed, duplicated, or trailing-garbage inputs");
    }
    if (module.category == "ecdh") {
        add("run ECDH outputs through a transcript-bound KDF and enforce contributory behavior");
    }
    if (module.category == "verification") {
        add("enforce strict scalar range checks and bind each verification to one exact domain and key");
    }
    if (module.id == "exact_nonce_reuse" || module.id == "repeated_r_values" || module.id == "related_nonce_delta_scan" || module.id == "nonce_affine_relation_scan") {
        fixes.clear();
        add("rotate to deterministic RFC6979-style nonces immediately and retire affected signing keys");
        add("search historical signatures for repeated or structured r values and reissue signatures after key rotation");
    } else if (module.id == "device_identifier_seeded_nonce_scan" || module.id == "device_id_plus_counter_nonce_scan" || module.id == "device_id_xor_counter_nonce_scan" || module.id == "unix_time_device_id_nonce_scan") {
        fixes.clear();
        add("remove device identifiers, serial numbers, and wall-clock inputs from nonce derivation completely");
        add("rotate the signing key because the audit demonstrated a searchable nonce formula");
    } else if (module.id == "small_private_key_bsgs" || module.id == "tiny_public_key_multiple_scan") {
        fixes.clear();
        add("regenerate the long-term key from a full-entropy source and invalidate the weak key immediately");
        add("add key-generation self-tests that reject undersized or patterned private scalars");
    } else if (module.id == "high_s_malleability_acceptance") {
        fixes.clear();
        add("normalize signatures to low-S form at signing and verification boundaries");
        add("add replay and duplicate-signature tests to confirm malleability is closed");
    } else if (module.id == "all_zero_shared_secret_acceptance") {
        fixes.clear();
        add("reject all-zero shared secrets before KDF or key confirmation");
        add("add malicious-peer regression vectors that force invalid and low-order peer inputs");
    }
    if (fixes.empty()) {
        add("tighten validation, add a regression test for the supplied evidence, and document the safer invariant");
    }
    return fixes;
}

std::vector<std::string> required_artifacts_for(const ModuleResult& module, const ChallengeInput& in) {
    std::vector<std::string> needs;
    if (module.recovered && module.private_key) return needs;
    if (module.id == "counter_based_nonce_generation") {
        if (in.signatures.size() < 2) needs.push_back("at least two signatures from the same counter stream");
        needs.push_back("counter start or step metadata, or enough signatures to infer them");
    } else if (module.id == "cross_protocol_scalar_reuse") {
        needs.push_back("real ECDH oracle transcripts or accepted malicious-point captures");
        needs.push_back("query and response samples from the same target implementation");
    } else if (module.id == "high_s_malleability_acceptance") {
        needs.push_back("verifier behavior, replay path, or protocol transcript");
    } else if (module.id == "device_identifier_seeded_nonce") {
        needs.push_back("device identifier candidates or multiple signatures from the same device family");
    } else if (module.id == "invalid_curve_acceptance" || module.id == "off_curve_public_key_acceptance" || module.id == "twist_point_acceptance") {
        needs.push_back("accepted hostile points or an interactive invalid-point oracle");
    } else if (module.id == "oracle_x_coordinate_leak" || module.id == "oracle_decrypt_validity_leak" || module.id == "oracle_mac_validity_leak") {
        needs.push_back("recorded oracle transcripts with attacker-chosen inputs");
    } else if (module.id == "all_zero_shared_secret_acceptance") {
        needs.push_back("peer inputs or harness traces showing the zero shared secret being accepted");
    } else if (module.id == "device_identifier_seeded_nonce" || module.id == "device_identifier_seeded_nonce_scan" || module.id == "device_id_plus_counter_nonce_scan" || module.id == "device_id_xor_counter_nonce_scan" || module.id == "unix_time_device_id_nonce_scan") {
        needs.push_back("device-id, serial, or machine-identifier range hints from the audited implementation");
    }
    return needs;
}

void append_required_artifacts(std::ostringstream& oss, const ModuleResult& module, const ChallengeInput& in) {
    const auto needs = required_artifacts_for(module, in);
    if (needs.empty()) return;
    oss << "    required_artifacts = [";
    for (std::size_t i = 0; i < needs.size(); ++i) {
        if (i) oss << "; ";
        oss << needs[i];
    }
    oss << "]\n";
}

void append_module_block(std::ostringstream& oss, const ModuleResult& module, const std::string& label, const ChallengeInput& in) {
    oss << label << " " << module.id << "\n";
    oss << "    fault_name = " << module.fault_name << "\n";
    oss << "    category = " << module.category << "\n";
    oss << "    severity = " << module.severity << "\n";
    oss << "    impact = " << module.impact << "\n";
    oss << "    confidence = " << module.confidence << "\n";
    oss << "    validation_state = " << module.validation_state << "\n";
    oss << "    heuristic_score = " << module.heuristic_score << "\n";
    oss << "    mode = " << (module.active_attack ? "active_attack" : "offline_structural_check") << "\n";
    oss << "    recovery_class = " << recovery_class_for(module) << "\n";
    oss << "    recoverability_status = " << recoverability_status_for(module) << "\n";
    for (const auto& line : module.lines) oss << "    " << line << "\n";
    append_required_artifacts(oss, module, in);
    const auto fixes = remediation_for(module);
    if (!fixes.empty()) {
        oss << "    remediation = [";
        for (std::size_t i = 0; i < fixes.size(); ++i) {
            if (i) oss << "; ";
            oss << fixes[i];
        }
        oss << "]\n";
    }
}

} // namespace

std::string render_report(const AnalysisResult& result, const ChallengeInput& in, bool verbose) {
    std::ostringstream oss;
    std::size_t recovered = 0;
    for (const auto& module : result.modules) {
        if (module.recovered && module.private_key) ++recovered;
    }
    const auto hits = collect_hits_sorted(result);

    oss << "FrogECCHunter\n";
    oss << "schema_version = " << in.schema_version << "\n";
    oss << "title = " << in.title << "\n";
    oss << "mode = " << in.mode << "\n";
    oss << "curve = " << result.curve.name << "\n";
    oss << "signatures = " << in.signatures.size() << "\n";
    oss << "checks = " << result.modules.size() << "\n";
    oss << "output_mode = " << (verbose ? "verbose" : "primary_hit") << "\n";
    oss << "input_source_kind = " << (result.public_key_source_kind.empty() ? "unknown" : result.public_key_source_kind) << "\n";
    oss << "input_normalization.kind = " << normalized_input_kind_local(in) << "\n";
    oss << "analysis_path = " << analysis_path_kind_local(result) << "\n";
    if (!result.public_key_parsed) {
        oss << "public_key_parsed = false\n";
        oss << "parse_error = " << result.public_key_parse_error << "\n";
        if (result.original_public_key_hex) oss << "preserved_input = " << *result.original_public_key_hex << "\n";
        if (!result.public_key_source_kind.empty()) oss << "source_kind = " << result.public_key_source_kind << "\n";
        oss << "note = continuing in passive parser/oracle/provenance mode where possible\n";
    }
    oss << "\n";

    if (verbose) {
        for (const auto& module : result.modules) {
            append_module_block(oss, module, "[" + module.status + "]", in);
            oss << "\n";
        }
    } else {
        if (!hits.empty()) {
            append_module_block(oss, *hits.front(), "[PRIMARY]", in);
            oss << "\n";
            if (hits.size() > 1) {
                oss << "Secondary findings\n";
                oss << "    count = " << (hits.size() - 1) << "\n";
                for (std::size_t i = 1; i < hits.size(); ++i) {
                    oss << "    " << hits[i]->id << " [" << hits[i]->severity << "]\n";
                }
                oss << "\n";
            }
        } else {
            oss << "No structural findings were confirmed by the configured checks.\n\n";
        }
    }

    std::map<std::string, int> sev_hits;
    for (const auto& module : result.modules) if (module.status == "HIT") sev_hits[lower_copy(module.severity)]++;
    oss << "Capability matrix\n";
    oss << "    active_algebra = " << bool_word_local(result.curve.active_algebra_supported) << "\n";
    oss << "    public_key_parsed = " << bool_word_local(result.public_key_parsed) << "\n";
    oss << "    path = " << analysis_path_kind_local(result) << "\n\n";
    oss << "Summary\n";
    oss << "    total_checks = " << result.modules.size() << "\n";
    oss << "    hit_count = " << hits.size() << "\n";
    oss << "    recovered_key_count = " << recovered << "\n";
    oss << "    critical_hits = " << sev_hits["critical"] << "\n";
    oss << "    high_hits = " << sev_hits["high"] << "\n";
    oss << "    why_no_recovery = " << why_no_recovery_text_local(result, in) << "\n\n";
    oss << "Recovered keys\n";
    bool any_key = false;
    for (const auto* module : hits) {
        if (module->recovered && module->private_key) {
            any_key = true;
            oss << "    " << module->id << " -> FLAG{" << module->private_key->get_str() << "}\n";
        }
    }
    if (!any_key) oss << "    none\n";
    return oss.str();
}

std::string render_report_txt(const AnalysisResult& result, const ChallengeInput& in) {
    std::ostringstream oss;
    const auto hits = collect_hits_sorted(result);
    std::size_t recovered = 0;
    std::map<std::string, int> sev_hits;
    for (const auto& module : result.modules) {
        if (module.recovered && module.private_key) ++recovered;
        if (module.status == "HIT") sev_hits[lower_copy(module.severity)]++;
    }

    oss << "FrogECCHunter v30 report\n";
    oss << "schema_version: " << in.schema_version << "\n";
    oss << "title: " << in.title << "\n";
    oss << "mode: " << in.mode << "\n";
    oss << "curve: " << result.curve.name << "\n";
    oss << "signatures: " << in.signatures.size() << "\n";
    oss << "checks: " << result.modules.size() << "\n\n";
    oss << "Input normalization\n";
    oss << "  source_kind: " << (result.public_key_source_kind.empty() ? "unknown" : result.public_key_source_kind) << "\n";
    oss << "  normalized_input_kind: " << normalized_input_kind_local(in) << "\n";
    oss << "  analysis_path: " << analysis_path_kind_local(result) << "\n";
    oss << "  public_key_parsed: " << bool_word_local(result.public_key_parsed) << "\n\n";
    oss << "Capability matrix\n";
    oss << "  active_algebra: " << bool_word_local(result.curve.active_algebra_supported) << "\n";
    oss << "  passive_family_mode: " << bool_word_local(!result.curve.active_algebra_supported) << "\n\n";
    oss << "Executive summary\n";
    oss << "  total_checks: " << result.modules.size() << "\n";
    oss << "  hit_count: " << hits.size() << "\n";
    oss << "  recovered_key_count: " << recovered << "\n";
    oss << "  critical_hits: " << sev_hits["critical"] << "\n";
    oss << "  high_hits: " << sev_hits["high"] << "\n";
    oss << "  medium_hits: " << sev_hits["medium"] << "\n";
    oss << "  low_hits: " << sev_hits["low"] << "\n";
    oss << "  why_no_recovery: " << why_no_recovery_text_local(result, in) << "\n\n";

    if (hits.empty()) {
        oss << "Primary fault: none confirmed\n";
        oss << "Recovered private key: none\n";
        return oss.str();
    }

    const auto& primary = *hits.front();
    oss << "Primary finding\n";
    oss << "  module: " << primary.id << "\n";
    oss << "  fault_name: " << primary.fault_name << "\n";
    oss << "  category: " << primary.category << "\n";
    oss << "  severity: " << primary.severity << "\n";
    oss << "  impact: " << primary.impact << "\n";
    oss << "  confidence: " << primary.confidence << "\n";
    oss << "  validation_state: " << primary.validation_state << "\n";
    oss << "  heuristic_score: " << primary.heuristic_score << "\n";
    oss << "  mode: " << (primary.active_attack ? "active_attack" : "offline_structural_check") << "\n";
    oss << "  recovery_class: " << recovery_class_for(primary) << "\n";
    oss << "  recoverability_status: " << recoverability_status_for(primary) << "\n";
    for (const auto& line : primary.lines) oss << "  " << line << "\n";
    for (const auto& need : required_artifacts_for(primary, in)) oss << "  required_artifact: " << need << "\n";
    for (const auto& fix : remediation_for(primary)) oss << "  remediation: " << fix << "\n";
    oss << "\n";

    oss << "Recovered private key\n";
    if (primary.recovered && primary.private_key) {
        oss << "  decimal: " << primary.private_key->get_str() << "\n";
        oss << "  flag: FLAG{" << primary.private_key->get_str() << "}\n";
    } else {
        oss << "  none\n";
    }
    oss << "\n";

    oss << "Top risk findings\n";
    for (std::size_t i = 0; i < hits.size() && i < 5; ++i) {
        const auto& m = *hits[i];
        oss << "  - " << m.id << " | " << m.severity << " | " << recoverability_status_for(m) << " | " << m.fault_name << "\n";
    }
    oss << "\n";

    oss << "Remediation plan\n";
    for (std::size_t i = 0; i < hits.size() && i < 5; ++i) {
        const auto& m = *hits[i];
        oss << "  [" << m.id << "]\n";
        for (const auto& fix : remediation_for(m)) oss << "    - " << fix << "\n";
    }
    oss << "\n";

    oss << "Secondary finding count: " << (hits.size() - 1) << "\n";
    if (hits.size() > 1) {
        oss << "Secondary findings\n";
        for (std::size_t i = 1; i < hits.size(); ++i) {
            oss << "  - " << hits[i]->id << " | " << hits[i]->fault_name << " | " << hits[i]->severity << " | " << recoverability_status_for(*hits[i]) << "\n";
        }
    }
    return oss.str();
}

std::string render_report_json(const AnalysisResult& result, const ChallengeInput& in) {
    std::ostringstream oss;
    const auto hits = collect_hits_sorted(result);
    std::size_t recovered = 0;
    for (const auto& module : result.modules) {
        if (module.recovered && module.private_key) ++recovered;
    }
    const ModuleResult* primary = hits.empty() ? nullptr : hits.front();
    oss << "{\n";
    oss << "  \"tool\": \"FrogECCHunter\",\n";
    oss << "  \"schema_version\": \"" << json_escape(in.schema_version) << "\",\n";
    oss << "  \"title\": \"" << json_escape(in.title) << "\",\n";
    oss << "  \"mode\": \"" << json_escape(in.mode) << "\",\n";
    oss << "  \"curve\": \"" << json_escape(result.curve.name) << "\",\n";
    oss << "  \"public_key\": {\n";
    oss << "    \"parsed\": " << (result.public_key_parsed ? "true" : "false") << ",\n";
    if (result.public_key_parsed && !result.public_key.inf) {
        oss << "    \"x\": \"" << mpz_to_hex(result.public_key.x, true, 64) << "\",\n";
        oss << "    \"y\": \"" << mpz_to_hex(result.public_key.y, true, 64) << "\",\n";
        oss << "    \"compressed\": \"" << compress_pubkey(result.public_key) << "\"\n";
    } else {
        if (result.original_public_key_hex) oss << "    \"preserved_input\": \"" << json_escape(*result.original_public_key_hex) << "\",\n";
        if (!result.public_key_source_kind.empty()) oss << "    \"source_kind\": \"" << json_escape(result.public_key_source_kind) << "\",\n";
        oss << "    \"parse_error\": \"" << json_escape(result.public_key_parse_error) << "\"\n";
    }
    oss << "  },\n";
    oss << "  \"input_normalization\": {\n";
    oss << "    \"input_kind\": \"" << json_escape(normalized_input_kind_local(in)) << "\",\n";
    oss << "    \"analysis_path\": \"" << json_escape(analysis_path_kind_local(result)) << "\",\n";
    oss << "    \"public_key_parsed\": " << (result.public_key_parsed ? "true" : "false") << "\n";
    oss << "  },\n";
    oss << "  \"capability_matrix\": {\n";
    oss << "    \"active_algebra\": " << (result.curve.active_algebra_supported ? "true" : "false") << ",\n";
    oss << "    \"passive_family_mode\": " << (!result.curve.active_algebra_supported ? "true" : "false") << "\n";
    oss << "  },\n";
    oss << "  \"summary\": {\n";
    oss << "    \"signature_count\": " << in.signatures.size() << ",\n";
    oss << "    \"fact_count\": " << in.facts.size() << ",\n";
    oss << "    \"total_checks\": " << result.modules.size() << ",\n";
    oss << "    \"hit_count\": " << hits.size() << ",\n";
    oss << "    \"recovered_key_count\": " << recovered << ",\n";
    std::map<std::string, int> sev_hits_json;
    for (const auto& module : result.modules) if (module.status == "HIT") sev_hits_json[lower_copy(module.severity)]++;
    oss << "    \"critical_hits\": " << sev_hits_json["critical"] << ",\n";
    oss << "    \"high_hits\": " << sev_hits_json["high"] << ",\n";
    oss << "    \"medium_hits\": " << sev_hits_json["medium"] << ",\n";
    oss << "    \"low_hits\": " << sev_hits_json["low"] << ",\n";
    oss << "    \"why_no_recovery\": \"" << json_escape(why_no_recovery_text_local(result, in)) << "\"\n";
    oss << "  },\n";
    oss << "  \"primary_finding\": ";
    if (primary) {
        oss << "{\n";
        oss << "    \"id\": \"" << json_escape(primary->id) << "\",\n";
        oss << "    \"fault_name\": \"" << json_escape(primary->fault_name) << "\",\n";
        oss << "    \"category\": \"" << json_escape(primary->category) << "\",\n";
        oss << "    \"severity\": \"" << json_escape(primary->severity) << "\",\n";
        oss << "    \"impact\": \"" << json_escape(primary->impact) << "\",\n";
        oss << "    \"confidence\": \"" << json_escape(primary->confidence) << "\",\n";
        oss << "    \"validation_state\": \"" << json_escape(primary->validation_state) << "\",\n";
        oss << "    \"heuristic_score\": " << primary->heuristic_score << ",\n";
        oss << "    \"mode\": \"" << (primary->active_attack ? "active_attack" : "offline_structural_check") << "\",\n";
        oss << "    \"recovery_class\": \"" << recovery_class_for(*primary) << "\",\n";
        oss << "    \"recoverability_status\": \"" << recoverability_status_for(*primary) << "\",\n";
        oss << "    \"recovered\": " << (primary->recovered ? "true" : "false");
        if (primary->private_key) oss << ",\n    \"private_key_decimal\": \"" << primary->private_key->get_str() << "\"";
        const auto primary_needs = required_artifacts_for(*primary, in);
        const auto primary_fixes = remediation_for(*primary);
        if (!primary_fixes.empty()) {
            oss << ",\n    \"remediation\": [\n";
            for (std::size_t j = 0; j < primary_fixes.size(); ++j) {
                oss << "      \"" << json_escape(primary_fixes[j]) << "\"";
                if (j + 1 != primary_fixes.size()) oss << ",";
                oss << "\n";
            }
            oss << "    ]";
        }
        if (!primary_needs.empty()) {
            oss << ",\n    \"required_artifacts\": [\n";
            for (std::size_t j = 0; j < primary_needs.size(); ++j) {
                oss << "      \"" << json_escape(primary_needs[j]) << "\"";
                if (j + 1 != primary_needs.size()) oss << ",";
                oss << "\n";
            }
            oss << "    ]";
        }
        if (!primary->lines.empty()) {
            oss << ",\n    \"evidence\": [\n";
            for (std::size_t j = 0; j < primary->lines.size(); ++j) {
                oss << "      \"" << json_escape(primary->lines[j]) << "\"";
                if (j + 1 != primary->lines.size()) oss << ",";
                oss << "\n";
            }
            oss << "    ]\n";
        } else {
            oss << "\n";
        }
        oss << "  },\n";
    } else {
        oss << "null,\n";
    }
    oss << "  \"secondary_finding_count\": " << (hits.empty() ? 0 : hits.size() - 1) << ",\n";
    oss << "  \"modules\": [\n";
    for (std::size_t i = 0; i < result.modules.size(); ++i) {
        const auto& m = result.modules[i];
        oss << "    {\n";
        oss << "      \"id\": \"" << json_escape(m.id) << "\",\n";
        oss << "      \"fault_name\": \"" << json_escape(m.fault_name) << "\",\n";
        oss << "      \"category\": \"" << json_escape(m.category) << "\",\n";
        oss << "      \"severity\": \"" << json_escape(m.severity) << "\",\n";
        oss << "      \"status\": \"" << json_escape(m.status) << "\",\n";
        oss << "      \"impact\": \"" << json_escape(m.impact) << "\",\n";
        oss << "      \"confidence\": \"" << json_escape(m.confidence) << "\",\n";
        oss << "      \"validation_state\": \"" << json_escape(m.validation_state) << "\",\n";
        oss << "      \"heuristic_score\": " << m.heuristic_score << ",\n";
        oss << "      \"mode\": \"" << (m.active_attack ? "active_attack" : "offline_structural_check") << "\",\n";
        oss << "      \"recovery_class\": \"" << recovery_class_for(m) << "\",\n";
        oss << "      \"recoverability_status\": \"" << recoverability_status_for(m) << "\",\n";
        oss << "      \"recovered\": " << (m.recovered ? "true" : "false");
        if (m.private_key) oss << ",\n      \"private_key_decimal\": \"" << m.private_key->get_str() << "\"";
        const auto module_needs = required_artifacts_for(m, in);
        const auto module_fixes = remediation_for(m);
        if (!module_fixes.empty()) {
            oss << ",\n      \"remediation\": [\n";
            for (std::size_t j = 0; j < module_fixes.size(); ++j) {
                oss << "        \"" << json_escape(module_fixes[j]) << "\"";
                if (j + 1 != module_fixes.size()) oss << ",";
                oss << "\n";
            }
            oss << "      ]";
        }
        if (!module_needs.empty()) {
            oss << ",\n      \"required_artifacts\": [\n";
            for (std::size_t j = 0; j < module_needs.size(); ++j) {
                oss << "        \"" << json_escape(module_needs[j]) << "\"";
                if (j + 1 != module_needs.size()) oss << ",";
                oss << "\n";
            }
            oss << "      ]";
        }
        if (!m.lines.empty()) {
            oss << ",\n      \"evidence\": [\n";
            for (std::size_t j = 0; j < m.lines.size(); ++j) {
                oss << "        \"" << json_escape(m.lines[j]) << "\"";
                if (j + 1 != m.lines.size()) oss << ",";
                oss << "\n";
            }
            oss << "      ]\n";
        } else {
            oss << "\n";
        }
        oss << "    }";
        if (i + 1 != result.modules.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ],\n";
    oss << "  \"recovered_keys\": [\n";
    bool first = true;
    for (const auto* m : hits) {
        if (m->recovered && m->private_key) {
            if (!first) oss << ",\n";
            first = false;
            oss << "    { \"module\": \"" << json_escape(m->id) << "\", \"flag\": \"FLAG{" << m->private_key->get_str() << "}\" }";
        }
    }
    if (!first) oss << "\n";
    oss << "  ]\n";
    oss << "}\n";
    return oss.str();
}

std::string render_check_explanation(const std::string& check_id) {
    const auto checks = catalog();
    for (const auto& info : checks) {
        if (info.id != check_id) continue;
        std::ostringstream oss;
        oss << "FrogECCHunter check explanation\n";
        oss << "id = " << info.id << "\n";
        oss << "fault_name = " << info.fault_name << "\n";
        oss << "category = " << info.category << "\n";
        oss << "severity = " << info.severity << "\n";
        oss << "note = this check reports a confirmed finding only when the required artifacts or facts are present in the input\n";
        if (info.category == "ecdsa" || info.category == "rng") oss << "typical_artifacts = signatures and nonce-related evidence\n";
        else if (info.category == "ecdh" || info.category == "oracle") oss << "typical_artifacts = peer-key handling facts, shared-secret handling facts, or oracle transcripts\n";
        else if (info.category == "parser" || info.category == "backend" || info.category == "curve" || info.category == "validation" || info.category == "protocol") oss << "typical_artifacts = parser facts, validation facts, provenance facts, or preserved malformed input\n";
        else oss << "typical_artifacts = challenge-specific structural evidence\n";
        return oss.str();
    }
    throw std::runtime_error("unknown check id: " + check_id);
}

} // namespace fecchunter
