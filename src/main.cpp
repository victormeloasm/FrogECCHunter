#include "analysis.hpp"
#include "ecc.hpp"
#include "input.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace fecchunter;
namespace fs = std::filesystem;

namespace {

struct CaseRun {
    std::string path;
    ChallengeInput input;
    AnalysisResult result;
};

struct RunOptions {
    std::string report_json_path;
    std::string report_txt_path;
    std::string report_dir;
    std::string report_md_path;
    std::string report_sarif_path;
    std::string evidence_pack_dir;
    std::string backend;
    std::vector<std::string> diff_backends;
    std::vector<std::string> family_filters;
    std::string severity_min;
    bool verbose{false};
    bool strict{false};
};

std::string canonical_raw_family_name(std::string curve_name);
bool is_raw_curve_family(const std::string& curve_name);

std::string trim_copy(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

std::string lower_ascii(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string canonical_token(std::string s) {
    s = lower_ascii(trim_copy(std::move(s)));
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c)) out.push_back(static_cast<char>(c));
    }
    return out;
}

std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item = trim_copy(item);
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

std::string join_csv(const std::vector<std::string>& items) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i) oss << ',';
        oss << items[i];
    }
    return oss.str();
}


std::string bool_word(bool v) { return v ? "yes" : "no"; }

void validate_challenge_input_strict(const ChallengeInput& in) {
    if (trim_copy(in.title).empty()) throw std::runtime_error("strict mode: title must not be empty");
    if (trim_copy(in.mode).empty()) throw std::runtime_error("strict mode: mode must not be empty");
    if (trim_copy(in.curve.name).empty()) throw std::runtime_error("strict mode: curve.name must not be empty");
    const bool has_pk = in.public_key.compressed_hex || (in.public_key.x_hex && in.public_key.y_hex) || in.public_key.raw_hex;
    if (!has_pk) throw std::runtime_error("strict mode: public_key is missing compressed, x/y, or raw_hex material");
    if ((in.public_key.x_hex && !in.public_key.y_hex) || (!in.public_key.x_hex && in.public_key.y_hex)) {
        throw std::runtime_error("strict mode: public_key x/y coordinates must be supplied together");
    }
    if (in.curve.name == "custom") {
        if (!(in.curve.p_hex && in.curve.a_hex && in.curve.b_hex && in.curve.gx_hex && in.curve.gy_hex && in.curve.n_hex)) {
            throw std::runtime_error("strict mode: custom curve requires p, a, b, gx, gy, and n");
        }
    }
    if (in.mode == "ecdsa" && in.signatures.empty()) throw std::runtime_error("strict mode: ecdsa mode requires at least one signature");
}

std::string normalized_input_kind(const ChallengeInput& in) {
    if (in.public_key.compressed_hex) return "sec1_compressed";
    if (in.public_key.x_hex && in.public_key.y_hex) return "affine_coordinates";
    if (in.public_key.raw_hex) return "raw_hex";
    return "missing";
}

std::string analysis_path_kind(const AnalysisResult& result) {
    if (result.curve.active_algebra_supported && result.public_key_parsed) return "active_algebra";
    if (!result.curve.active_algebra_supported) return "passive_family";
    return "passive_parse_preserved";
}

std::string why_no_recovery_text(const AnalysisResult& result, const ChallengeInput& in) {
    std::size_t recovered = 0;
    for (const auto& module : result.modules) if (module.recovered && module.private_key) ++recovered;
    if (recovered) return "recovery demonstrated";
    if (!result.public_key_parsed) return "public key did not parse algebraically; only passive parser/oracle/provenance checks could run";
    if (!result.curve.active_algebra_supported) return "this curve family is in passive-analysis mode in the active algebra engine";
    if (in.signatures.empty()) return "no signatures were supplied, so nonce and signature-recovery engines stayed inactive";
    return "current artifacts did not demonstrate a recoverable weakness";
}

void print_usage() {
    std::cerr << "Usage:\n";
    std::cerr << "  fecchunter --all <challenge.json> [--report-json <report.json>] [--report-txt <report.txt>] [--report-md <report.md>] [--report-sarif <report.sarif>] [--family <csv>] [--severity-min <info|low|medium|high|critical>] [--backend <name>] [--diff-backends <csv>] [--evidence-pack <dir>] [--strict] [--verbose]\n";
    std::cerr << "  fecchunter --all-dir <directory> [--report-dir <outdir>] [--family <csv>] [--severity-min <info|low|medium|high|critical>] [--backend <name>] [--diff-backends <csv>] [--evidence-pack <dir>] [--strict] [--verbose]\n";
    std::cerr << "  fecchunter --make-json-from-pubkey <curve> <pubkey|@file> <output.json> [--mode ecdsa|ecdh|ecdh_oracle|parser|oracle|curve_provenance] [--backend <name>] [--diff-backends <csv>] [--allow-invalid-pubkey] [--emit-minimal-json] [--p <hex>] [--a <hex>] [--b <hex>] [--gx <hex>] [--gy <hex>] [--n <hex>] [--h <hex>]\n";
    std::cerr << "  fecchunter --list-curves\n";
    std::cerr << "  fecchunter --self-test\n";
    std::cerr << "  fecchunter --explain-check <check-id>\n";
    std::cerr << "  fecchunter --version\n";
    std::cerr << "  fecchunter --help\n\n";
    std::cerr << "Default text output shows the highest-priority finding only. Use --verbose to show every check.\n";
    std::cerr << "Use --family and --severity-min to focus large sweeps without changing --all or --all-dir.\n";
    std::cerr << "Use --evidence-pack to write a reproducible bundle with reports, manifest, and per-finding notes.\n\n";
    std::cerr << "Named short-Weierstrass curves in this build: ";
    const auto names = supported_named_curves();
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i) std::cerr << ", ";
        std::cerr << names[i];
    }
    std::cerr << ".\n";
    std::cerr << "Raw-family scaffolding is also available for Ed25519, Ed448, X25519, X448, Curve25519, Curve448, Edwards25519, and Edwards448.\n\n";
    std::cerr << "Accepted pubkey formats for --make-json-from-pubkey:\n";
    std::cerr << "  compressed SEC1 hex starting with 02 or 03\n";
    std::cerr << "  uncompressed SEC1 hex starting with 04\n";
    std::cerr << "  malformed SEC1/SPKI inputs can be scaffolded with --allow-invalid-pubkey for parser/oracle workflows\n";
    std::cerr << "  x:y as two hexadecimal coordinates\n";
    std::cerr << "  @file to read the pubkey text from a file\n";
    std::cerr << "Useful family filters: ecdsa, verification, ecdh, parser, oracle, curve, provenance, rng, backend, protocol, validation.\n";
}

void write_text_file(const std::string& path, const std::string& data) {
    const fs::path target(path);
    if (!target.parent_path().empty()) fs::create_directories(target.parent_path());
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("failed to open output file: " + path);
    out << data;
    if (!out) throw std::runtime_error("failed to write output file: " + path);
}

std::string read_text_file_strict(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("failed to open input file: " + path);
    std::ostringstream oss;
    oss << in.rdbuf();
    if (!in.good() && !in.eof()) throw std::runtime_error("failed to read input file: " + path);
    return oss.str();
}

std::string bytes_to_upper_hex_main(const std::vector<unsigned char>& data) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char b : data) {
        out.push_back(kHex[(b >> 4U) & 0x0FU]);
        out.push_back(kHex[b & 0x0FU]);
    }
    return out;
}

std::vector<unsigned char> base64_decode_loose(const std::string& in) {
    static const std::string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::array<int, 256> table{};
    table.fill(-1);
    for (std::size_t i = 0; i < alpha.size(); ++i) table[static_cast<unsigned char>(alpha[i])] = static_cast<int>(i);
    std::vector<unsigned char> out;
    int val = 0;
    int valb = -8;
    for (unsigned char c : in) {
        if (std::isspace(c)) continue;
        if (c == '=') break;
        const int t = table[c];
        if (t < 0) continue;
        val = (val << 6) | t;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

struct PemBlockMain {
    std::string label;
    std::vector<unsigned char> der;
};

std::optional<PemBlockMain> parse_pem_block_main(const std::string& text) {
    const std::string begin_marker = "-----BEGIN ";
    const std::size_t begin = text.find(begin_marker);
    if (begin == std::string::npos) return std::nullopt;
    const std::size_t label_start = begin + begin_marker.size();
    const std::size_t label_end = text.find("-----", label_start);
    if (label_end == std::string::npos) return std::nullopt;
    const std::string label = text.substr(label_start, label_end - label_start);
    const std::string end_marker = "-----END " + label + "-----";
    const std::size_t body_start = text.find('\n', label_end);
    if (body_start == std::string::npos) return std::nullopt;
    const std::size_t end = text.find(end_marker, body_start + 1);
    if (end == std::string::npos) return std::nullopt;
    std::string body = text.substr(body_start + 1, end - (body_start + 1));
    return PemBlockMain{label, base64_decode_loose(body)};
}

struct DerReaderMain {
    const std::vector<unsigned char>& data;
    std::size_t pos{0};
};

std::size_t der_read_length_main(DerReaderMain& r) {
    if (r.pos >= r.data.size()) throw std::runtime_error("truncated DER length");
    unsigned char first = r.data[r.pos++];
    if ((first & 0x80U) == 0) return static_cast<std::size_t>(first);
    const std::size_t count = static_cast<std::size_t>(first & 0x7FU);
    if (count == 0 || count > sizeof(std::size_t) || r.pos + count > r.data.size()) throw std::runtime_error("invalid DER long-form length");
    std::size_t len = 0;
    for (std::size_t i = 0; i < count; ++i) len = (len << 8U) | r.data[r.pos++];
    return len;
}

std::vector<unsigned char> der_expect_tlv_main(DerReaderMain& r, unsigned char tag) {
    if (r.pos >= r.data.size() || r.data[r.pos++] != tag) throw std::runtime_error("unexpected DER tag");
    const std::size_t len = der_read_length_main(r);
    if (r.pos + len > r.data.size()) throw std::runtime_error("truncated DER value");
    std::vector<unsigned char> out(r.data.begin() + static_cast<long long>(r.pos), r.data.begin() + static_cast<long long>(r.pos + len));
    r.pos += len;
    return out;
}

std::string der_decode_oid_main(const std::vector<unsigned char>& bytes) {
    if (bytes.empty()) throw std::runtime_error("empty OID");
    std::ostringstream oss;
    const unsigned first = bytes[0];
    oss << (first / 40U) << '.' << (first % 40U);
    std::size_t i = 1;
    while (i < bytes.size()) {
        unsigned long value = 0;
        do {
            if (i >= bytes.size()) throw std::runtime_error("truncated OID");
            value = (value << 7U) | static_cast<unsigned long>(bytes[i] & 0x7FU);
        } while (bytes[i++] & 0x80U);
        oss << '.' << value;
    }
    return oss.str();
}

struct SpkiInfoMain {
    std::string algorithm_oid;
    std::optional<std::string> parameter_oid;
    std::vector<unsigned char> public_key_bytes;
    unsigned char unused_bits{0};
};

std::optional<SpkiInfoMain> parse_spki_der_main(const std::vector<unsigned char>& der) {
    try {
        DerReaderMain top{der};
        auto seq = der_expect_tlv_main(top, 0x30U);
        DerReaderMain body{seq};
        auto alg_seq = der_expect_tlv_main(body, 0x30U);
        DerReaderMain alg{alg_seq};
        const auto alg_oid_bytes = der_expect_tlv_main(alg, 0x06U);
        std::optional<std::string> param_oid;
        if (alg.pos < alg.data.size()) {
            if (alg.data[alg.pos] == 0x06U) param_oid = der_decode_oid_main(der_expect_tlv_main(alg, 0x06U));
            else if (alg.data[alg.pos] == 0x05U) (void)der_expect_tlv_main(alg, 0x05U);
        }
        auto bitstr = der_expect_tlv_main(body, 0x03U);
        if (bitstr.empty()) throw std::runtime_error("empty BIT STRING");
        SpkiInfoMain out;
        out.algorithm_oid = der_decode_oid_main(alg_oid_bytes);
        out.parameter_oid = param_oid;
        out.unused_bits = bitstr.front();
        out.public_key_bytes.assign(bitstr.begin() + 1, bitstr.end());
        return out;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool looks_like_pem_main(const std::string& s) {
    return s.find("-----BEGIN ") != std::string::npos;
}

bool looks_like_der_spki_main(const std::string& s) {
    if (s.empty() || static_cast<unsigned char>(s[0]) != 0x30U) return false;
    const bool all_printable = std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return c == '\n' || c == '\r' || c == '\t' || (c >= 0x20U && c <= 0x7EU);
    });
    return !all_printable;
}

struct ParsedPubkeyInputMain {
    std::string curve_name;
    std::string pubkey_payload;
    bool raw_family{false};
    std::string source_kind{"text"};
};

ParsedPubkeyInputMain parse_pubkey_argument_material_main(const std::string& requested_curve, const std::string& raw_input) {
    ParsedPubkeyInputMain out;
    out.curve_name = trim_copy(requested_curve);
    out.pubkey_payload = trim_copy(raw_input);
    const bool want_auto = canonical_token(out.curve_name) == "auto" || out.curve_name.empty();
    if (looks_like_pem_main(raw_input) || looks_like_der_spki_main(raw_input)) {
        std::vector<unsigned char> der;
        std::string pem_label;
        if (looks_like_pem_main(raw_input)) {
            const auto pem = parse_pem_block_main(raw_input);
            if (!pem) throw std::runtime_error("failed to parse PEM public key input");
            pem_label = pem->label;
            der = pem->der;
        } else {
            der.assign(raw_input.begin(), raw_input.end());
        }
        const auto spki = parse_spki_der_main(der);
        if (!spki) throw std::runtime_error("failed to parse SubjectPublicKeyInfo from supplied public key input");
        if (spki->unused_bits != 0) throw std::runtime_error("SPKI BIT STRING has non-zero unused bits");
        std::string detected_curve;
        bool raw_family = false;
        if (spki->algorithm_oid == "1.2.840.10045.2.1") {
            if (!spki->parameter_oid) throw std::runtime_error("EC SubjectPublicKeyInfo is missing a named-curve OID");
            const auto curve = curve_name_from_oid(*spki->parameter_oid);
            if (!curve) throw std::runtime_error("unsupported named-curve OID in SubjectPublicKeyInfo: " + *spki->parameter_oid);
            detected_curve = *curve;
            raw_family = is_raw_curve_family(detected_curve);
        } else if (const auto curve = curve_name_from_oid(spki->algorithm_oid)) {
            detected_curve = *curve;
            raw_family = true;
        } else {
            throw std::runtime_error("unsupported SubjectPublicKeyInfo algorithm OID: " + spki->algorithm_oid);
        }
        if (want_auto) out.curve_name = detected_curve;
        if (!want_auto && canonical_token(out.curve_name) != canonical_token(detected_curve)) {
            throw std::runtime_error("requested curve does not match SubjectPublicKeyInfo OID: requested=" + out.curve_name + " detected=" + detected_curve);
        }
        out.raw_family = raw_family;
        out.pubkey_payload = bytes_to_upper_hex_main(spki->public_key_bytes);
        out.source_kind = pem_label.empty() ? "der_spki" : ("pem:" + pem_label);
        return out;
    }
    out.raw_family = is_raw_curve_family(out.curve_name);
    return out;
}

std::string safe_batch_pubkey_key_main(const CaseRun& run) {
    if (run.result.public_key_parsed && !run.result.public_key.inf) {
        try { return compress_pubkey(run.result.public_key); } catch (const std::exception&) {}
    }
    if (run.result.original_public_key_hex) return *run.result.original_public_key_hex;
    return "UNPARSED";
}

std::string markdown_escape_main(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '\\': case '`': case '*': case '_': case '[': case ']': case '#': case '|':
                out.push_back('\\');
                out.push_back(c);
                break;
            default:
                out.push_back(c);
        }
    }
    return out;
}


std::string json_escape_main(const std::string& s) {
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

int severity_rank_main(const std::string& sev) {
    const std::string s = canonical_token(sev);
    if (s == "critical") return 4;
    if (s == "high") return 3;
    if (s == "medium") return 2;
    if (s == "low") return 1;
    return 0;
}

std::vector<const ModuleResult*> collect_hits_sorted_main(const AnalysisResult& result) {
    std::vector<const ModuleResult*> hits;
    for (const auto& module : result.modules) if (module.status == "HIT") hits.push_back(&module);
    std::stable_sort(hits.begin(), hits.end(), [](const ModuleResult* a, const ModuleResult* b) {
        const int ar = (a->recovered && a->private_key ? 1 : 0);
        const int br = (b->recovered && b->private_key ? 1 : 0);
        if (ar != br) return ar > br;
        const int aa = (a->active_attack ? 1 : 0);
        const int ba = (b->active_attack ? 1 : 0);
        if (aa != ba) return aa > ba;
        const int as = severity_rank_main(a->severity);
        const int bs = severity_rank_main(b->severity);
        if (as != bs) return as > bs;
        return a->id < b->id;
    });
    return hits;
}

std::string recoverability_status_main(const ModuleResult& module) {
    if (module.recovered && module.private_key) return "R5_trivial_or_lab_proven";
    if (module.status == "HIT" && module.active_attack) return "R3_engine_supported_but_not_recovered";
    if (module.status == "HIT" && severity_rank_main(module.severity) >= 3) return "R2_structural_high_risk";
    if (module.status == "HIT") return "R1_structural_risk";
    return "R0_no_current_recovery_evidence";
}

std::vector<std::string> remediation_for_main(const ModuleResult& module) {
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
    if (module.category == "backend" || module.id.find("backend_") == 0) {
        add("pin an allowed backend matrix and turn backend disagreements into failing regression tests");
        add("document which backend behavior is normative for parsing, validation, and canonicalization");
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

bool family_matches_module(const ModuleResult& module, const std::string& filter) {
    const std::string f = canonical_token(filter);
    const std::string c = canonical_token(module.category);
    const std::string id = canonical_token(module.id);
    if (f.empty()) return true;
    if (f == c) return true;
    if (f == "provenance" || f == "curveprovenance") return c == "curve";
    if (f == "signatures" || f == "signature") return c == "ecdsa" || c == "verification";
    if (f == "backenddiff" || f == "backend") return c == "backend";
    if (f == "validation") return c == "validation" || c == "verification";
    if (f == "all") return true;
    return id.find(f) != std::string::npos;
}

AnalysisResult filter_analysis_result(const AnalysisResult& result, const RunOptions& opts) {
    AnalysisResult filtered = result;
    filtered.modules.clear();
    const bool use_family = !opts.family_filters.empty();
    const int min_sev = opts.severity_min.empty() ? -1 : severity_rank_main(opts.severity_min);
    for (const auto& module : result.modules) {
        bool keep = true;
        if (use_family) {
            keep = false;
            for (const auto& fam : opts.family_filters) {
                if (family_matches_module(module, fam)) {
                    keep = true;
                    break;
                }
            }
        }
        if (keep && min_sev >= 0) {
            keep = severity_rank_main(module.severity) >= min_sev;
        }
        if (keep) filtered.modules.push_back(module);
    }
    return filtered;
}

std::string make_json_template_from_pubkey(const Curve& curve, const Point& Q, const std::string& mode,
                                           const std::string& backend, const std::vector<std::string>& diff_backends, const std::string& source_kind, bool minimal_json) {
    const std::size_t field_hex = curve_field_bytes(curve) * 2;
    const std::string qx = mpz_to_hex(Q.x, true, field_hex);
    const std::string qy = mpz_to_hex(Q.y, true, field_hex);
    const std::string qc = compress_pubkey(Q, curve_field_bytes(curve));

    std::string out;
    out += "{\n";
    out += "  \"schema_version\": \"1.0\",\n";
    out += "  \"title\": \"Challenge skeleton generated from a supplied public key\",\n";
    out += "  \"mode\": \"" + mode + "\",\n";
    out += "  \"curve\": {\n";
    out += "    \"name\": \"" + curve.name + "\",\n";
    out += "    \"family\": \"" + curve.family + "\"\n";
    out += "  },\n";
    out += "  \"public_key\": {\n";
    out += "    \"compressed\": \"" + qc + "\",\n";
    out += "    \"x\": \"" + qx + "\",\n";
    out += "    \"y\": \"" + qy + "\",\n";
    out += "    \"source_kind\": \"" + json_escape_main(source_kind.empty() ? std::string("unknown") : source_kind) + "\"\n";
    out += "  },\n";
    out += "  \"constraints\": {\n";
    out += "    \"nonce_max_bits\": 0,\n";
    out += "    \"privkey_max_bits\": 0,\n";
    out += "    \"related_delta_max\": 0,\n";
    out += "    \"related_a_abs_max\": 0,\n";
    out += "    \"related_b_abs_max\": 0,\n";
    out += "    \"unix_time_min\": 0,\n";
    out += "    \"unix_time_max\": 0\n";
    out += "  },\n";
    out += "  \"facts\": {\n";
    out += "    \"template.kind\": \"generated_from_valid_pubkey\",\n";
    out += "    \"parser.input_source_kind\": \"" + json_escape_main(source_kind.empty() ? std::string("unknown") : source_kind) + "\",\n";
    out += "    \"curve.family\": \"" + curve.family + "\"";
    if (!backend.empty()) out += ",\n    \"runtime.backend\": \"" + json_escape_main(backend) + "\"";
    if (!diff_backends.empty()) out += ",\n    \"runtime.diff_backends\": \"" + json_escape_main(join_csv(diff_backends)) + "\"";
    out += "\n  }";
    if (mode == "oracle" || mode == "ecdh_oracle") {
        out += ",\n  \"oracle\": {\n";
        out += "    \"kind\": \"unspecified\",\n";
        out += "    \"notes\": \"Populate captured oracle behavior, peer inputs, and validation facts from owned or synthetic material\"\n";
        out += "  }";
    }
    out += ",\n  \"signatures\": [\n  ]\n";
    out += "}\n";
    return out;
}

std::string render_recovered_key_audit_txt(const AnalysisResult& result, const ChallengeInput& in) {
    std::ostringstream oss;
    const auto hits = collect_hits_sorted_main(result);
    const auto now = std::time(nullptr);
    oss << "FrogECCHunter recovered-key audit\n";
    oss << "title: " << in.title << "\n";
    oss << "mode: " << in.mode << "\n";
    oss << "curve: " << result.curve.name << "\n";
    oss << "timestamp_unix: " << static_cast<long long>(now) << "\n\n";
    bool any = false;
    for (const auto* hit : hits) {
        if (!(hit->recovered && hit->private_key)) continue;
        any = true;
        oss << "[RECOVERED]\n";
        oss << "module: " << hit->id << "\n";
        oss << "fault_name: " << hit->fault_name << "\n";
        oss << "category: " << hit->category << "\n";
        oss << "severity: " << hit->severity << "\n";
        oss << "private_key_decimal: " << hit->private_key->get_str() << "\n";
        oss << "flag: FLAG{" << hit->private_key->get_str() << "}\n";
        for (const auto& line : hit->lines) oss << line << "\n";
        oss << "\n";
    }
    if (!any) oss << "No recovered private key in this audit.\n";
    return oss.str();
}

std::string default_audit_dir() {
    return "Audit";
}

std::string auto_report_txt_path_for(const std::string& in_path) {
    fs::path p(in_path);
    return (fs::path(default_audit_dir()) / (p.stem().string() + ".audit.txt")).string();
}

std::string auto_recovered_txt_path_for(const std::string& in_path) {
    fs::path p(in_path);
    return (fs::path(default_audit_dir()) / (p.stem().string() + ".recovered.txt")).string();
}

std::string auto_report_md_path_for(const std::string& in_path) {
    fs::path p(in_path);
    return (fs::path(default_audit_dir()) / (p.stem().string() + ".report.md")).string();
}

std::string auto_report_sarif_path_for(const std::string& in_path) {
    fs::path p(in_path);
    return (fs::path(default_audit_dir()) / (p.stem().string() + ".report.sarif")).string();
}

void inject_runtime_facts(ChallengeInput& in, const RunOptions& opts) {
    if (!opts.backend.empty()) in.facts["runtime.backend"] = opts.backend;
    if (!opts.diff_backends.empty()) in.facts["runtime.diff_backends"] = join_csv(opts.diff_backends);
}

std::string read_pubkey_argument(const std::string& arg) {
    if (!arg.empty() && arg[0] == '@') return read_text_file_strict(arg.substr(1));
    return trim_copy(arg);
}

std::string canonical_raw_family_name(std::string curve_name) {
    const std::string key = normalize_hex(curve_name);
    if (key == "ED25519" || key == "EDWARDS25519") return "Ed25519";
    if (key == "ED448" || key == "EDWARDS448") return "Ed448";
    if (key == "X25519" || key == "CURVE25519" || key == "MONTGOMERY25519") return "X25519";
    if (key == "X448" || key == "CURVE448" || key == "MONTGOMERY448") return "X448";
    return {};
}

bool is_raw_curve_family(const std::string& curve_name) {
    return !canonical_raw_family_name(curve_name).empty();
}

std::size_t raw_family_pubkey_bytes(const std::string& family) {
    if (family == "Ed25519" || family == "X25519") return 32;
    if (family == "Ed448" || family == "X448") return 56;
    return 0;
}

std::string make_raw_curve_template_from_pubkey(const std::string& curve_name, const std::string& pubkey_text,
                                                const std::string& mode, const std::string& backend,
                                                const std::vector<std::string>& diff_backends, const std::string& source_kind, bool minimal_json) {
    const std::string family = canonical_raw_family_name(curve_name);
    const std::string normalized = normalize_hex(pubkey_text);
    const std::size_t expect_bytes = raw_family_pubkey_bytes(family);
    if (expect_bytes && normalized.size() != expect_bytes * 2) {
        throw std::runtime_error("raw family public key must be exactly " + std::to_string(expect_bytes) + " bytes of hex for " + family);
    }
    const std::string family_kind = (family.rfind("Ed", 0) == 0) ? "edwards" : "montgomery";
    std::ostringstream out;
    out << "{\n";
    out << "  \"schema_version\": \"1.0\",\n";
    out << "  \"title\": \"Challenge skeleton generated from a supplied public key\",\n";
    out << "  \"mode\": \"" << json_escape_main(mode) << "\",\n";
    out << "  \"curve\": { \"name\": \"" << json_escape_main(family) << "\", \"family\": \"" << family_kind << "\" },\n";
    out << "  \"public_key\": { \"raw_hex\": \"" << json_escape_main(normalized) << "\", \"source_kind\": \"" << json_escape_main(source_kind.empty() ? std::string("unknown") : source_kind) << "\" },\n";
    out << "  \"constraints\": { \"nonce_max_bits\": 0, \"privkey_max_bits\": 0, \"related_delta_max\": 0, \"related_a_abs_max\": 0, \"related_b_abs_max\": 0, \"unix_time_min\": 0, \"unix_time_max\": 0 },\n";
    out << "  \"facts\": {\n";
    out << "    \"template.kind\": \"generated_from_valid_pubkey\",\n";
    out << "    \"parser.input_source_kind\": \"" << json_escape_main(source_kind.empty() ? std::string("unknown") : source_kind) << "\",\n";
    out << "    \"engine.family\": \"dedicated_non_weierstrass\",\n";
    out << "    \"curve.family\": \"" << family_kind << "\"";
    if (!backend.empty()) out << ",\n    \"runtime.backend\": \"" << json_escape_main(backend) << "\"";
    if (!diff_backends.empty()) out << ",\n    \"runtime.diff_backends\": \"" << json_escape_main(join_csv(diff_backends)) << "\"";
    out << "\n  }";
    if (mode == "oracle" || mode == "ecdh_oracle") {
        out << ",\n  \"oracle\": { \"kind\": \"unspecified\", \"notes\": \"Populate captured oracle behavior, peer inputs, and validation facts from owned or synthetic material\" }";
    }
    out << ",\n  \"signatures\": [\n  ]\n";
    out << "}\n";
    return out.str();
}

bool looks_like_sec1_point_hex_main(const std::string& s) {
    const std::string h = normalize_hex(s);
    if (h.size() < 2 || (h.size() % 2) != 0) return false;
    return h.rfind("02", 0) == 0 || h.rfind("03", 0) == 0 || h.rfind("04", 0) == 0;
}

std::string make_invalid_pubkey_template_from_material(const std::string& curve_name, const std::string& pubkey_text,
                                                       const std::string& mode, const std::string& backend,
                                                       const std::vector<std::string>& diff_backends,
                                                       const std::string& source_kind, bool minimal_json) {
    const std::string normalized = normalize_hex(pubkey_text);
    std::ostringstream out;
    out << "{\n";
    out << "  \"schema_version\": \"1.0\",\n";
    out << "  \"title\": \"Challenge skeleton generated from a supplied public key\",\n";
    out << "  \"mode\": \"" << json_escape_main(mode) << "\",\n";
    out << "  \"curve\": { \"name\": \"" << json_escape_main(curve_name) << "\", \"family\": \"short_weierstrass\" },\n";
    out << "  \"public_key\": {\n";
    if (looks_like_sec1_point_hex_main(normalized)) {
        out << "    \"compressed\": \"" << json_escape_main(normalized) << "\",\n";
    } else {
        out << "    \"raw_hex\": \"" << json_escape_main(normalized) << "\",\n";
    }
    out << "    \"source_kind\": \"" << json_escape_main(source_kind) << "\"\n";
    out << "  },\n";
    out << "  \"constraints\": { \"nonce_max_bits\": 0, \"privkey_max_bits\": 0, \"related_delta_max\": 0, \"related_a_abs_max\": 0, \"related_b_abs_max\": 0, \"unix_time_min\": 0, \"unix_time_max\": 0 },\n";
    out << "  \"facts\": {\n";
    out << "    \"template.kind\": \"invalid_pubkey_preserved\",\n";
    out << "    \"parser.invalid_pubkey_template\": true,\n";
    out << "    \"parser.input_source_kind\": \"" << json_escape_main(source_kind) << "\",\n";
    out << "    \"curve.family\": \"short_weierstrass\"";
    if (!backend.empty()) out << ",\n    \"runtime.backend\": \"" << json_escape_main(backend) << "\"";
    if (!diff_backends.empty()) out << ",\n    \"runtime.diff_backends\": \"" << json_escape_main(join_csv(diff_backends)) << "\"";
    out << "\n  },\n";
    out << "  \"artifacts\": { \"original_pubkey_hex\": \"" << json_escape_main(normalized) << "\", \"template_kind\": \"invalid_pubkey_preserved\" },\n";
    if (mode == "oracle" || mode == "ecdh_oracle") {
        out << "  \"oracle\": { \"kind\": \"unspecified\", \"notes\": \"Populate captured oracle behavior, peer inputs, and validation facts from owned or synthetic material\" },\n";
    }
    out << "  \"signatures\": [\n  ]\n";
    out << "}\n";
    return out.str();
}

void write_evidence_pack(const fs::path& out_dir, const std::string& input_path, const ChallengeInput& in,
                         const AnalysisResult& full_result, const AnalysisResult& shown_result,
                         const RunOptions& opts) {
    fs::create_directories(out_dir / "findings");
    write_text_file((out_dir / "report.txt").string(), render_report_txt(shown_result, in));
    write_text_file((out_dir / "report.json").string(), render_report_json(shown_result, in));
    write_text_file((out_dir / "report_full.txt").string(), render_report_txt(full_result, in));
    write_text_file((out_dir / "report_full.json").string(), render_report_json(full_result, in));
    write_text_file((out_dir / "input.original.json").string(), read_text_file_strict(input_path));
    const auto hits = collect_hits_sorted_main(shown_result);
    std::ostringstream top;
    top << "FrogECCHunter evidence pack\n";
    top << "input = " << fs::path(input_path).filename().string() << "\n";
    top << "curve = " << shown_result.curve.name << "\n";
    top << "shown_total_checks = " << shown_result.modules.size() << "\n";
    top << "full_total_checks = " << full_result.modules.size() << "\n";
    top << "hit_count = " << hits.size() << "\n";
    if (!opts.family_filters.empty()) top << "family_filter = " << join_csv(opts.family_filters) << "\n";
    if (!opts.severity_min.empty()) top << "severity_min = " << opts.severity_min << "\n";
    if (!opts.backend.empty()) top << "backend = " << opts.backend << "\n";
    if (!opts.diff_backends.empty()) top << "diff_backends = " << join_csv(opts.diff_backends) << "\n";
    top << "\nTop findings\n";
    for (std::size_t i = 0; i < hits.size() && i < 15; ++i) {
        top << "  - " << hits[i]->id << " | " << hits[i]->fault_name << " | " << hits[i]->severity << " | "
            << recoverability_status_main(*hits[i]) << "\n";
    }
    if (hits.empty()) top << "  none\n";
    write_text_file((out_dir / "TOP_FINDINGS.txt").string(), top.str());

    std::ostringstream manifest;
    manifest << "{\n";
    manifest << "  \"tool\": \"FrogECCHunter\",\n";
    manifest << "  \"evidence_pack_version\": \"v30\",\n";
    manifest << "  \"input_file\": \"" << json_escape_main(fs::path(input_path).filename().string()) << "\",\n";
    manifest << "  \"curve\": \"" << json_escape_main(shown_result.curve.name) << "\",\n";
    manifest << "  \"shown_total_checks\": " << shown_result.modules.size() << ",\n";
    manifest << "  \"full_total_checks\": " << full_result.modules.size() << ",\n";
    manifest << "  \"shown_hit_count\": " << hits.size() << ",\n";
    manifest << "  \"backend\": \"" << json_escape_main(opts.backend) << "\",\n";
    manifest << "  \"diff_backends\": [";
    for (std::size_t i = 0; i < opts.diff_backends.size(); ++i) {
        if (i) manifest << ", ";
        manifest << "\"" << json_escape_main(opts.diff_backends[i]) << "\"";
    }
    manifest << "],\n";
    manifest << "  \"family_filters\": [";
    for (std::size_t i = 0; i < opts.family_filters.size(); ++i) {
        if (i) manifest << ", ";
        manifest << "\"" << json_escape_main(opts.family_filters[i]) << "\"";
    }
    manifest << "],\n";
    manifest << "  \"severity_min\": \"" << json_escape_main(opts.severity_min) << "\",\n";
    manifest << "  \"findings\": [\n";
    for (std::size_t i = 0; i < hits.size(); ++i) {
        const auto& m = *hits[i];
        manifest << "    { \"id\": \"" << json_escape_main(m.id) << "\", \"severity\": \"" << json_escape_main(m.severity)
                 << "\", \"recoverability\": \"" << json_escape_main(recoverability_status_main(m)) << "\" }";
        if (i + 1 != hits.size()) manifest << ",";
        manifest << "\n";
    }
    manifest << "  ]\n}\n";
    write_text_file((out_dir / "manifest.json").string(), manifest.str());

    for (const auto* hit : hits) {
        std::ostringstream oss;
        oss << "id = " << hit->id << "\n";
        oss << "fault_name = " << hit->fault_name << "\n";
        oss << "category = " << hit->category << "\n";
        oss << "severity = " << hit->severity << "\n";
        oss << "status = " << hit->status << "\n";
        oss << "recoverability = " << recoverability_status_main(*hit) << "\n";
        oss << "impact = " << hit->impact << "\n";
        oss << "confidence = " << hit->confidence << "\n";
        oss << "validation_state = " << hit->validation_state << "\n";
        if (hit->recovered && hit->private_key) oss << "flag = FLAG{" << hit->private_key->get_str() << "}\n";
        oss << "\nEvidence\n";
        for (const auto& line : hit->lines) oss << "  " << line << "\n";
        oss << "\nRemediation\n";
        for (const auto& fix : remediation_for_main(*hit)) oss << "  - " << fix << "\n";
        write_text_file((out_dir / "findings" / (hit->id + ".txt")).string(), oss.str());
    }
}


std::string render_report_md_main(const AnalysisResult& result, const ChallengeInput& in) {
    std::ostringstream oss;
    const auto hits = collect_hits_sorted_main(result);
    std::map<std::string, int> sev_hits;
    std::map<std::string, int> category_hits;
    std::size_t recovered = 0;
    for (const auto& module : result.modules) {
        if (module.recovered && module.private_key) ++recovered;
        if (module.status == "HIT") {
            sev_hits[lower_ascii(module.severity)]++;
            category_hits[module.category]++;
        }
    }
    oss << "# FrogECCHunter Report\n\n";
    oss << "- **Title:** " << markdown_escape_main(in.title) << "\n";
    oss << "- **Mode:** `" << markdown_escape_main(in.mode) << "`\n";
    oss << "- **Curve:** `" << markdown_escape_main(result.curve.name) << "`\n";
    oss << "- **Checks:** `" << result.modules.size() << "`\n";
    oss << "- **Findings:** `" << hits.size() << "`\n";
    oss << "- **Recovered keys:** `" << recovered << "`\n\n";
    oss << "## Severity summary\n\n";
    for (const auto& sev : {std::string("critical"), std::string("high"), std::string("medium"), std::string("low")}) {
        oss << "- `" << sev << "`: " << sev_hits[sev] << "\n";
    }
    oss << "\n## Category summary\n\n";
    for (const auto& [cat, count] : category_hits) oss << "- `" << markdown_escape_main(cat) << "`: " << count << "\n";
    oss << "\n## Primary findings\n\n";
    if (hits.empty()) {
        oss << "No structural findings were confirmed by the configured checks.\n";
        return oss.str();
    }
    for (const auto* hit : hits) {
        oss << "### `" << markdown_escape_main(hit->id) << "`\n\n";
        oss << "- Fault: **" << markdown_escape_main(hit->fault_name) << "**\n";
        oss << "- Category: `" << markdown_escape_main(hit->category) << "`\n";
        oss << "- Severity: `" << markdown_escape_main(hit->severity) << "`\n";
        oss << "- Recoverability: `" << markdown_escape_main(recoverability_status_main(*hit)) << "`\n";
        if (hit->recovered && hit->private_key) oss << "- Recovered key: `FLAG{" << hit->private_key->get_str() << "}`\n";
        oss << "\nEvidence\n\n";
        for (const auto& line : hit->lines) oss << "- " << markdown_escape_main(line) << "\n";
        const auto fixes = remediation_for_main(*hit);
        if (!fixes.empty()) {
            oss << "\nRemediation\n\n";
            for (const auto& fix : fixes) oss << "- " << markdown_escape_main(fix) << "\n";
        }
        oss << "\n";
    }
    return oss.str();
}

std::string render_report_sarif_main(const AnalysisResult& result, const ChallengeInput& in, const std::string& artifact_uri) {
    std::ostringstream oss;
    const auto hits = collect_hits_sorted_main(result);
    std::set<std::string> emitted_rules;
    oss << "{\n";
    oss << "  \"version\": \"2.1.0\",\n";
    oss << "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n";
    oss << "  \"runs\": [\n";
    oss << "    {\n";
    oss << "      \"tool\": { \"driver\": { \"name\": \"FrogECCHunter\", \"version\": \"v30\", \"rules\": [\n";
    bool first_rule = true;
    for (const auto* hit : hits) {
        if (!emitted_rules.insert(hit->id).second) continue;
        if (!first_rule) oss << ",\n";
        first_rule = false;
        oss << "        { \"id\": \"" << json_escape_main(hit->id) << "\", \"name\": \"" << json_escape_main(hit->fault_name)
            << "\", \"shortDescription\": { \"text\": \"" << json_escape_main(hit->fault_name) << "\" }, \"properties\": { \"category\": \""
            << json_escape_main(hit->category) << "\", \"severity\": \"" << json_escape_main(hit->severity) << "\" } }";
    }
    oss << "\n      ] } },\n";
    oss << "      \"artifacts\": [ { \"location\": { \"uri\": \"" << json_escape_main(artifact_uri) << "\" } } ],\n";
    oss << "      \"results\": [\n";
    bool first_result = true;
    for (const auto* hit : hits) {
        if (!first_result) oss << ",\n";
        first_result = false;
        std::ostringstream msg;
        msg << hit->fault_name << " | recoverability=" << recoverability_status_main(*hit);
        if (hit->recovered && hit->private_key) msg << " | FLAG{" << hit->private_key->get_str() << "}";
        oss << "        { \"ruleId\": \"" << json_escape_main(hit->id) << "\", \"level\": \"";
        const int sev = severity_rank_main(hit->severity);
        oss << (sev >= 4 ? "error" : sev >= 3 ? "warning" : "note") << "\", \"message\": { \"text\": \"" << json_escape_main(msg.str()) << "\" }, ";
        oss << "\"locations\": [ { \"physicalLocation\": { \"artifactLocation\": { \"uri\": \"" << json_escape_main(artifact_uri) << "\" } } } ], ";
        oss << "\"properties\": { \"category\": \"" << json_escape_main(hit->category) << "\", \"severity\": \"" << json_escape_main(hit->severity)
            << "\", \"recoverability\": \"" << json_escape_main(recoverability_status_main(*hit)) << "\", \"mode\": \"" << json_escape_main(in.mode) << "\" } }";
    }
    oss << "\n      ]\n";
    oss << "    }\n";
    oss << "  ]\n";
    oss << "}\n";
    return oss.str();
}

int run_single(const std::string& in_path, const RunOptions& opts) {
    ChallengeInput in = load_challenge_json(in_path);
    if (opts.strict) validate_challenge_input_strict(in);
    inject_runtime_facts(in, opts);
    const AnalysisResult full_result = run_all_modules(in);
    const AnalysisResult shown_result = filter_analysis_result(full_result, opts);
    std::cout << render_report(shown_result, in, opts.verbose);
    if (!opts.report_json_path.empty()) {
        write_text_file(opts.report_json_path, render_report_json(shown_result, in));
        std::cout << "\nJSON report written to " << opts.report_json_path << "\n";
    }
    const std::string final_txt_path = opts.report_txt_path.empty() ? auto_report_txt_path_for(in_path) : opts.report_txt_path;
    write_text_file(final_txt_path, render_report_txt(shown_result, in));
    std::cout << "TXT report written to " << final_txt_path << "\n";
    const std::string final_md_path = opts.report_md_path.empty() ? auto_report_md_path_for(in_path) : opts.report_md_path;
    write_text_file(final_md_path, render_report_md_main(shown_result, in));
    std::cout << "Markdown report written to " << final_md_path << "\n";
    const std::string final_sarif_path = opts.report_sarif_path.empty() ? auto_report_sarif_path_for(in_path) : opts.report_sarif_path;
    write_text_file(final_sarif_path, render_report_sarif_main(shown_result, in, fs::path(in_path).filename().string()));
    std::cout << "SARIF report written to " << final_sarif_path << "\n";
    bool recovered = false;
    for (const auto* hit : collect_hits_sorted_main(shown_result)) recovered = recovered || (hit->recovered && hit->private_key);
    if (recovered) {
        const std::string recovered_path = auto_recovered_txt_path_for(in_path);
        write_text_file(recovered_path, render_recovered_key_audit_txt(shown_result, in));
        std::cout << "Recovered-key audit written to " << recovered_path << "\n";
    }
    if (!opts.evidence_pack_dir.empty()) {
        write_evidence_pack(opts.evidence_pack_dir, in_path, in, full_result, shown_result, opts);
        std::cout << "Evidence pack written to " << opts.evidence_pack_dir << "\n";
    }
    return 0;
}

std::string render_batch_summary_txt(const std::vector<CaseRun>& runs) {
    std::map<std::string, std::vector<std::string>> pubkey_to_files;
    std::map<std::string, std::vector<std::string>> r_to_files;
    std::map<std::string, std::vector<std::string>> hash_to_files;
    std::map<std::string, std::vector<std::string>> key_to_files;
    for (const auto& run : runs) {
        const auto file = fs::path(run.path).filename().string();
        pubkey_to_files[safe_batch_pubkey_key_main(run)].push_back(file);
        for (const auto& sig : run.input.signatures) {
            if (!sig.r_hex.empty()) r_to_files[normalize_hex(sig.r_hex)].push_back(file);
            if (!sig.hash_hex.empty()) hash_to_files[normalize_hex(sig.hash_hex)].push_back(file);
        }
        for (const auto* hit : collect_hits_sorted_main(run.result)) {
            if (hit->recovered && hit->private_key) key_to_files[hit->private_key->get_str()].push_back(file);
        }
    }
    auto overlap_count = [](const std::map<std::string, std::vector<std::string>>& mp) {
        std::size_t count = 0;
        for (const auto& [_, files] : mp) {
            std::vector<std::string> uniq = files;
            std::sort(uniq.begin(), uniq.end());
            uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
            if (uniq.size() >= 2) ++count;
        }
        return count;
    };
    auto dump_multi = [](std::ostringstream& oss, const std::string& title, const std::map<std::string, std::vector<std::string>>& mp) {
        oss << title << "\n";
        bool any = false;
        for (const auto& [k, files] : mp) {
            std::vector<std::string> uniq = files;
            std::sort(uniq.begin(), uniq.end());
            uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
            if (uniq.size() < 2) continue;
            any = true;
            oss << "  - value: " << k << "\n";
            oss << "    files:";
            for (const auto& f : uniq) oss << ' ' << f;
            oss << "\n";
        }
        if (!any) oss << "  none\n";
        oss << "\n";
    };
    std::ostringstream oss;
    oss << "FrogECCHunter batch summary\n";
    oss << "version: v30\n";
    oss << "files: " << runs.size() << "\n";
    oss << "overlap_groups.pubkeys: " << overlap_count(pubkey_to_files) << "\n";
    oss << "overlap_groups.r_values: " << overlap_count(r_to_files) << "\n";
    oss << "overlap_groups.hashes: " << overlap_count(hash_to_files) << "\n";
    oss << "overlap_groups.recovered_keys: " << overlap_count(key_to_files) << "\n\n";
    oss << "Per-file primary findings\n";
    for (const auto& run : runs) {
        const auto hits = collect_hits_sorted_main(run.result);
        oss << "  - " << fs::path(run.path).filename().string() << ": ";
        if (hits.empty()) {
            oss << "none\n";
        } else {
            oss << hits.front()->id << " | " << hits.front()->fault_name << " | " << hits.front()->severity;
            if (hits.front()->recovered && hits.front()->private_key) oss << " | FLAG{" << hits.front()->private_key->get_str() << "}";
            oss << "\n";
        }
    }
    oss << "\n";
    dump_multi(oss, "Repeated public keys across files", pubkey_to_files);
    dump_multi(oss, "Repeated ECDSA r values across files", r_to_files);
    dump_multi(oss, "Repeated message digests across files", hash_to_files);
    dump_multi(oss, "Repeated recovered private keys across files", key_to_files);
    return oss.str();
}

std::string render_batch_summary_json(const std::vector<CaseRun>& runs) {
    std::map<std::string, std::vector<std::string>> pubkey_to_files;
    std::map<std::string, std::vector<std::string>> r_to_files;
    std::map<std::string, std::vector<std::string>> hash_to_files;
    std::map<std::string, std::vector<std::string>> key_to_files;
    for (const auto& run : runs) {
        const auto file = fs::path(run.path).filename().string();
        pubkey_to_files[safe_batch_pubkey_key_main(run)].push_back(file);
        for (const auto& sig : run.input.signatures) {
            if (!sig.r_hex.empty()) r_to_files[normalize_hex(sig.r_hex)].push_back(file);
            if (!sig.hash_hex.empty()) hash_to_files[normalize_hex(sig.hash_hex)].push_back(file);
        }
        for (const auto* hit : collect_hits_sorted_main(run.result)) {
            if (hit->recovered && hit->private_key) key_to_files[hit->private_key->get_str()].push_back(file);
        }
    }
    auto overlap_count = [](const std::map<std::string, std::vector<std::string>>& mp) {
        std::size_t count = 0;
        for (const auto& [_, files] : mp) {
            std::vector<std::string> uniq = files;
            std::sort(uniq.begin(), uniq.end());
            uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
            if (uniq.size() >= 2) ++count;
        }
        return count;
    };
    auto append_items = [](std::ostringstream& oss, const std::map<std::string, std::vector<std::string>>& mp, const std::string& indent) {
        bool first = true;
        for (const auto& [k, files] : mp) {
            std::vector<std::string> uniq = files;
            std::sort(uniq.begin(), uniq.end());
            uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
            if (uniq.size() < 2) continue;
            if (!first) oss << ",\n";
            first = false;
            oss << indent << "{ \"value\": \"" << json_escape_main(k) << "\", \"files\": [";
            for (std::size_t i = 0; i < uniq.size(); ++i) {
                if (i) oss << ", ";
                oss << "\"" << json_escape_main(uniq[i]) << "\"";
            }
            oss << "] }";
        }
        if (first) oss << indent;
    };
    std::ostringstream oss;
    oss << "{\n  \"tool\": \"FrogECCHunter\",\n";
    oss << "  \"version\": \"v30\",\n";
    oss << "  \"file_count\": " << runs.size() << ",\n";
    oss << "  \"overlap_group_counts\": { \"pubkeys\": " << overlap_count(pubkey_to_files)
        << ", \"r_values\": " << overlap_count(r_to_files)
        << ", \"hashes\": " << overlap_count(hash_to_files)
        << ", \"recovered_keys\": " << overlap_count(key_to_files) << " },\n";
    oss << "  \"files\": [\n";
    for (std::size_t i = 0; i < runs.size(); ++i) {
        const auto hits = collect_hits_sorted_main(runs[i].result);
        oss << "    { \"file\": \"" << json_escape_main(fs::path(runs[i].path).filename().string()) << "\"";
        if (!hits.empty()) {
            oss << ", \"primary_module\": \"" << json_escape_main(hits.front()->id) << "\"";
            oss << ", \"primary_fault\": \"" << json_escape_main(hits.front()->fault_name) << "\"";
            oss << ", \"severity\": \"" << json_escape_main(hits.front()->severity) << "\"";
            if (hits.front()->recovered && hits.front()->private_key) oss << ", \"flag\": \"FLAG{" << hits.front()->private_key->get_str() << "}\"";
        }
        oss << " }";
        if (i + 1 != runs.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ],\n  \"repeated_pubkeys\": [\n";
    append_items(oss, pubkey_to_files, "    ");
    oss << "\n  ],\n  \"repeated_r_values\": [\n";
    append_items(oss, r_to_files, "    ");
    oss << "\n  ],\n  \"repeated_hashes\": [\n";
    append_items(oss, hash_to_files, "    ");
    oss << "\n  ],\n  \"repeated_recovered_keys\": [\n";
    append_items(oss, key_to_files, "    ");
    oss << "\n  ]\n}\n";
    return oss.str();
}

std::optional<std::string> parse_optional_value(const std::vector<std::string>& args, std::size_t& i, const std::string& flag) {
    if (i + 1 >= args.size()) throw std::runtime_error(flag + " requires a value");
    return args[++i];
}

RunOptions parse_run_options(const std::vector<std::string>& args, std::size_t start_index, bool allow_report_dir, std::string& input_target) {
    RunOptions opts;
    for (std::size_t i = start_index; i < args.size(); ++i) {
        if (args[i] == "--report-json") {
            opts.report_json_path = *parse_optional_value(args, i, "--report-json");
        } else if (args[i] == "--report-txt") {
            opts.report_txt_path = *parse_optional_value(args, i, "--report-txt");
        } else if (args[i] == "--report-md") {
            opts.report_md_path = *parse_optional_value(args, i, "--report-md");
        } else if (args[i] == "--report-sarif") {
            opts.report_sarif_path = *parse_optional_value(args, i, "--report-sarif");
        } else if (args[i] == "--report-dir" && allow_report_dir) {
            opts.report_dir = *parse_optional_value(args, i, "--report-dir");
        } else if (args[i] == "--evidence-pack") {
            opts.evidence_pack_dir = *parse_optional_value(args, i, "--evidence-pack");
        } else if (args[i] == "--family") {
            opts.family_filters = split_csv(*parse_optional_value(args, i, "--family"));
        } else if (args[i] == "--severity-min") {
            opts.severity_min = *parse_optional_value(args, i, "--severity-min");
        } else if (args[i] == "--backend") {
            opts.backend = *parse_optional_value(args, i, "--backend");
        } else if (args[i] == "--diff-backends") {
            opts.diff_backends = split_csv(*parse_optional_value(args, i, "--diff-backends"));
        } else if (args[i] == "--verbose") {
            opts.verbose = true;
        } else if (args[i] == "--strict") {
            opts.strict = true;
        } else if (input_target.empty()) {
            input_target = args[i];
        } else {
            throw std::runtime_error("unexpected argument: " + args[i]);
        }
    }
    return opts;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const std::vector<std::string> args(argv + 1, argv + argc);
        if (args.empty() || (args.size() == 1 && args[0] == "--help")) {
            print_usage();
            return 0;
        }
        if (args.size() == 1 && args[0] == "--list-curves") {
            for (const auto& name : supported_named_curves()) {
                std::cout << name;
                if (const auto oid = curve_oid_from_name(name)) std::cout << " | oid=" << *oid;
                std::cout << "\n";
            }
            std::cout << "Ed25519 | oid=1.3.101.112\nEd448 | oid=1.3.101.113\nX25519 | oid=1.3.101.110\nX448 | oid=1.3.101.111\n";
            return 0;
        }
        if (!args.empty() && args[0] == "--self-test") {
            if (args.size() > 2) throw std::runtime_error("--self-test accepts at most one optional output directory argument");
            const fs::path audit_dir = (args.size() == 2) ? fs::path(args[1]) : fs::path("AUDITTEST");
            fs::create_directories(audit_dir / "inputs");
            fs::create_directories(audit_dir / "generated_json");
            fs::create_directories(audit_dir / "reports_batch");
            fs::create_directories(audit_dir / "evidence_batch");
            fs::create_directories(audit_dir / "logs");
            fs::create_directories(audit_dir / "meta");



            auto generate_template_file = [&](const fs::path& out_path, const std::string& curve_name, const std::string& pubkey_arg, const std::string& mode, bool allow_invalid) {
                const auto parsed = parse_pubkey_argument_material_main(curve_name, pubkey_arg);
                if (parsed.raw_family) {
                    write_text_file(out_path.string(), make_raw_curve_template_from_pubkey(parsed.curve_name, parsed.pubkey_payload, mode, "", {}, parsed.source_kind, false));
                    return;
                }
                const Curve curve = curve_from_named_or_custom(parsed.curve_name, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
                const auto point = parse_pubkey_text(curve, trim_copy(parsed.pubkey_payload));
                if (!point) {
                    if (!allow_invalid) throw std::runtime_error("self-test failed to parse generated pubkey input for template generation");
                    write_text_file(out_path.string(), make_invalid_pubkey_template_from_material(parsed.curve_name, parsed.pubkey_payload, mode, "", {}, parsed.source_kind, false));
                    return;
                }
                write_text_file(out_path.string(), make_json_template_from_pubkey(curve, *point, mode, "", {}, parsed.source_kind, false));
            };

            auto verify_generated_pubkey_json = [&](const fs::path& json_path, const std::string& expected_curve, const std::string& expected_compressed) {
                ChallengeInput tmp = load_challenge_json(json_path.string());
                if (canonical_token(tmp.curve.name) != canonical_token(expected_curve)) throw std::runtime_error("self-test generated template curve mismatch for " + json_path.string());
                if (normalize_hex(tmp.public_key.compressed_hex.value_or("")) != normalize_hex(expected_compressed)) throw std::runtime_error("self-test generated template pubkey mismatch for " + json_path.string());
            };
            const fs::path samples_dir = "samples";
            if (!fs::exists(samples_dir) || !fs::is_directory(samples_dir)) {
                throw std::runtime_error("self-test requires the bundled samples/ directory next to the binary");
            }

            generate_template_file(audit_dir / "generated_json" / "pubkey_from_compressed_secp256k1.json", "secp256k1", "02DB0C51CC634A4096374B0B895584A3CA2FB3BEA4FD0EE2361F8DB63A650FCEE6", "parser", false);
            generate_template_file(audit_dir / "generated_json" / "pubkey_from_uncompressed_secp256k1.json", "secp256k1", "04DB0C51CC634A4096374B0B895584A3CA2FB3BEA4FD0EE2361F8DB63A650FCEE67EC0BD2BAEA1AE184BD16FD397B0E64D5D28257F85836486367FE33CC5B6E6A0", "parser", false);
            generate_template_file(audit_dir / "generated_json" / "pubkey_from_pem_auto_secp256k1.json", "auto", R"PEM(-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE2wxRzGNKQJY3SwuJVYSjyi+zvqT9DuI2
H422OmUPzuZ+wL0rrqGuGEvRb9OXsOZNXSglf4WDZIY2f+M8xbbmoA==
-----END PUBLIC KEY-----
)PEM", "parser", false);
            generate_template_file(audit_dir / "generated_json" / "pubkey_from_pem_auto_secp256r1.json", "auto", R"PEM(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4pZ/9QVIl3v4EI+POdDbYH2tWdK3
hwr9uabjjKyhY4zoNZje6uHVAcDux9z59oI9pK1BQARTbZjBwGME3rU/RA==
-----END PUBLIC KEY-----
)PEM", "parser", false);
            generate_template_file(audit_dir / "generated_json" / "raw_family_x25519.json", "X25519", "0100000000000000000000000000000000000000000000000000000000000000", "parser", false);
            generate_template_file(audit_dir / "generated_json" / "raw_family_ed25519.json", "Ed25519", "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A", "parser", false);
            generate_template_file(audit_dir / "generated_json" / "invalid_pubkey_preserved.json", "auto", R"PEM(-----BEGIN PUBLIC KEY-----
MDYwEAYHKoZIzj0CAQYFK4EEAAoDIgACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAU=
-----END PUBLIC KEY-----
)PEM", "parser", true);

            verify_generated_pubkey_json(audit_dir / "generated_json" / "pubkey_from_compressed_secp256k1.json", "secp256k1", "02DB0C51CC634A4096374B0B895584A3CA2FB3BEA4FD0EE2361F8DB63A650FCEE6");
            verify_generated_pubkey_json(audit_dir / "generated_json" / "pubkey_from_uncompressed_secp256k1.json", "secp256k1", "02DB0C51CC634A4096374B0B895584A3CA2FB3BEA4FD0EE2361F8DB63A650FCEE6");
            verify_generated_pubkey_json(audit_dir / "generated_json" / "pubkey_from_pem_auto_secp256k1.json", "secp256k1", "02DB0C51CC634A4096374B0B895584A3CA2FB3BEA4FD0EE2361F8DB63A650FCEE6");
            verify_generated_pubkey_json(audit_dir / "generated_json" / "pubkey_from_pem_auto_secp256r1.json", "prime256v1", "02E2967FF50548977BF8108F8F39D0DB607DAD59D2B7870AFDB9A6E38CACA1638C");

            std::ostringstream version_oss;
            version_oss << "FrogECCHunter v30\n";
            version_oss << "active_algebra = short_weierstrass\n";
            version_oss << "raw_family_mode = passive_analysis\n";
            version_oss << "reports = txt,json,markdown,sarif\n";
            version_oss << "schema_version = 1.0\n";
            version_oss << "features = strict,self-test,explain-check,input-normalization,capability-matrix\n";
            write_text_file((audit_dir / "meta" / "version.txt").string(), version_oss.str());

            std::ostringstream curves_oss;
            for (const auto& name : supported_named_curves()) {
                curves_oss << name;
                if (const auto oid = curve_oid_from_name(name)) curves_oss << " | oid=" << *oid;
                curves_oss << "\n";
            }
            curves_oss << "Ed25519 | oid=1.3.101.112\nEd448 | oid=1.3.101.113\nX25519 | oid=1.3.101.110\nX448 | oid=1.3.101.111\n";
            write_text_file((audit_dir / "meta" / "list_curves.txt").string(), curves_oss.str());
            write_text_file((audit_dir / "meta" / "explain_tiny_public_key_multiple_scan.txt").string(), render_check_explanation("tiny_public_key_multiple_scan"));

            ChallengeInput strict_invalid;
            strict_invalid.schema_version = "1.0";
            strict_invalid.mode = "parser";
            strict_invalid.curve.name = "secp256k1";
            std::string strict_failure = "none";
            try {
                validate_challenge_input_strict(strict_invalid);
            } catch (const std::exception& ex) {
                strict_failure = ex.what();
            }
            write_text_file((audit_dir / "meta" / "strict_failure_example.txt").string(), strict_failure + "\n");

            RunOptions opts;
            opts.report_dir = (audit_dir / "reports_batch").string();
            opts.evidence_pack_dir = (audit_dir / "evidence_batch").string();
            std::vector<CaseRun> runs;
            std::vector<fs::path> files;
            const std::vector<std::string> curated_samples = {
                "small_nonce_30bit.json",
                "related_nonce_delta1.json",
                "nonce_reuse_exact.json",
                "small_private_key_20bit.json",
                "ecdh_oracle_validation_failures.json",
                "high_s_malleability.json",
                "parser_and_binding_smells.json",
                "device_identifier_seeded_nonce.json",
                "backend_differential_findings.json",
                "v22_spki_backend_suite.json",
                "v20_structural_suite.json",
                "prng_and_parser_smells.json",
                "valid_pubkey_secp256k1_clean.json",
                "valid_pubkey_secp256k1_1337.json",
                "valid_pubkey_secp256r1_clean.json",
                "invalid_pubkey_template_playground.json",
                "raw_family_ed25519_playground.json",
                "raw_family_x448_playground.json"
            };
            for (const auto& name : curated_samples) {
                const fs::path p = samples_dir / name;
                if (!fs::exists(p)) throw std::runtime_error("self-test missing bundled sample: " + p.string());
                files.push_back(p);
            }
            for (const auto& entry : fs::directory_iterator(audit_dir / "generated_json")) {
                if (entry.is_regular_file() && entry.path().extension() == ".json") files.push_back(entry.path());
            }
            std::sort(files.begin(), files.end());

            std::ostringstream manifest;
            manifest << "FrogECCHunter self-test manifest\n";
            manifest << "version = v30\n";
            manifest << "audit_dir = " << audit_dir.string() << "\n";
            manifest << "case_count = " << files.size() << "\n\n";

            for (const auto& path : files) {
                const fs::path copied_input = audit_dir / "inputs" / path.filename();
                write_text_file(copied_input.string(), read_text_file_strict(path.string()));
                CaseRun run{path.string(), load_challenge_json(path.string()), {}};
                const AnalysisResult full = run_all_modules(run.input);
                run.result = filter_analysis_result(full, opts);
                write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".report.json")).string(), render_report_json(run.result, run.input));
                write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".report.txt")).string(), render_report_txt(run.result, run.input));
                write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".report.md")).string(), render_report_md_main(run.result, run.input));
                write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".report.sarif")).string(), render_report_sarif_main(run.result, run.input, path.filename().string()));
                bool recovered = false;
                for (const auto* hit : collect_hits_sorted_main(run.result)) recovered = recovered || (hit->recovered && hit->private_key);
                if (recovered) write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".recovered.txt")).string(), render_recovered_key_audit_txt(run.result, run.input));
                write_evidence_pack(fs::path(opts.evidence_pack_dir) / path.stem(), path.string(), run.input, full, run.result, opts);
                const auto hits = collect_hits_sorted_main(run.result);
                manifest << "[CASE] " << path.filename().string() << "\n";
                manifest << "  source_kind = " << (run.result.public_key_source_kind.empty() ? "unknown" : run.result.public_key_source_kind) << "\n";
                manifest << "  normalized_input_kind = " << normalized_input_kind(run.input) << "\n";
                manifest << "  analysis_path = " << analysis_path_kind(run.result) << "\n";
                manifest << "  public_key_parsed = " << bool_word(run.result.public_key_parsed) << "\n";
                manifest << "  total_checks = " << run.result.modules.size() << "\n";
                manifest << "  hit_count = " << hits.size() << "\n";
                manifest << "  why_no_recovery = " << why_no_recovery_text(run.result, run.input) << "\n";
                if (!run.result.public_key_parsed && !run.result.public_key_parse_error.empty()) manifest << "  parse_error = " << run.result.public_key_parse_error << "\n";
                if (!hits.empty()) manifest << "  primary_hit = " << hits.front()->id << " | " << hits.front()->severity << "\n";
                manifest << "\n";
                runs.push_back(std::move(run));
            }

            const auto batch_txt = render_batch_summary_txt(runs);
            write_text_file((audit_dir / "reports_batch" / "batch_summary.txt").string(), batch_txt);
            write_text_file((audit_dir / "reports_batch" / "batch_summary.json").string(), render_batch_summary_json(runs));
            write_text_file((audit_dir / "evidence_batch" / "batch_summary.txt").string(), batch_txt);
            write_text_file((audit_dir / "evidence_batch" / "batch_summary.json").string(), render_batch_summary_json(runs));
            write_text_file((audit_dir / "RUN_MANIFEST.txt").string(), manifest.str());
            write_text_file((audit_dir / "logs" / "self_test.log").string(), std::string("self-test completed successfully\n") + manifest.str());
            std::cout << "FrogECCHunter self-test: PASS\n";
            std::cout << "  audit_dir = " << audit_dir.string() << "\n";
            std::cout << "  cases = " << files.size() << "\n";
            std::cout << "  manifest = " << (audit_dir / "RUN_MANIFEST.txt").string() << "\n";
            return 0;
        }
        if (args.size() == 2 && args[0] == "--explain-check") {
            std::cout << render_check_explanation(args[1]);
            return 0;
        }
        if (args.size() == 1 && args[0] == "--version") {
            std::cout << "FrogECCHunter v30\n";
            std::cout << "active_algebra = short_weierstrass\n";
            std::cout << "raw_family_mode = passive_analysis\n";
            std::cout << "reports = txt,json,markdown,sarif\n";
            std::cout << "schema_version = 1.0\n";
            std::cout << "features = strict,self-test,explain-check,input-normalization,capability-matrix\n";
            return 0;
        }
        if (args.size() >= 4 && args[0] == "--make-json-from-pubkey") {
            std::string curve_name = args[1];
            const std::string pubkey_text = read_pubkey_argument(args[2]);
            const std::string out_path = args[3];
            std::string mode = "ecdsa";
            std::string backend;
            std::vector<std::string> diff_backends;
            std::optional<std::string> p_hex, a_hex, b_hex, gx_hex, gy_hex, n_hex, h_hex;
            bool allow_invalid_pubkey = false;
            bool emit_minimal_json = false;
            for (std::size_t i = 4; i < args.size(); ++i) {
                if (args[i] == "--mode") mode = *parse_optional_value(args, i, "--mode");
                else if (args[i] == "--backend") backend = *parse_optional_value(args, i, "--backend");
                else if (args[i] == "--diff-backends") diff_backends = split_csv(*parse_optional_value(args, i, "--diff-backends"));
                else if (args[i] == "--p") p_hex = *parse_optional_value(args, i, "--p");
                else if (args[i] == "--a") a_hex = *parse_optional_value(args, i, "--a");
                else if (args[i] == "--b") b_hex = *parse_optional_value(args, i, "--b");
                else if (args[i] == "--gx") gx_hex = *parse_optional_value(args, i, "--gx");
                else if (args[i] == "--gy") gy_hex = *parse_optional_value(args, i, "--gy");
                else if (args[i] == "--n") n_hex = *parse_optional_value(args, i, "--n");
                else if (args[i] == "--h") h_hex = *parse_optional_value(args, i, "--h");
                else if (args[i] == "--allow-invalid-pubkey") allow_invalid_pubkey = true;
                else if (args[i] == "--emit-minimal-json") emit_minimal_json = true;
                else throw std::runtime_error("unexpected argument: " + args[i]);
            }
            const auto parsed_material = parse_pubkey_argument_material_main(curve_name, pubkey_text);
            curve_name = parsed_material.curve_name;
            if (parsed_material.raw_family || is_raw_curve_family(curve_name)) {
                write_text_file(out_path, make_raw_curve_template_from_pubkey(curve_name, parsed_material.pubkey_payload, mode, backend, diff_backends, parsed_material.source_kind, emit_minimal_json));
                std::cout << "Generated challenge JSON skeleton\n";
                std::cout << "  curve = " << canonical_raw_family_name(curve_name) << "\n";
                std::cout << "  mode = " << mode << "\n";
                std::cout << "  raw_pubkey = " << normalize_hex(parsed_material.pubkey_payload) << "\n";
                std::cout << "  source = " << parsed_material.source_kind << "\n";
                std::cout << "  output = " << out_path << "\n";
                std::cout << "  note = dedicated non-Weierstrass scaffolding was selected\n";
                return 0;
            }
            const Curve curve = curve_from_named_or_custom(curve_name, p_hex, a_hex, b_hex, gx_hex, gy_hex, n_hex, h_hex);
            const auto P = parse_pubkey_text(curve, trim_copy(parsed_material.pubkey_payload));
            if (!P) {
                if (!allow_invalid_pubkey) {
                    throw std::runtime_error("failed to parse the supplied public key for the selected curve; use --allow-invalid-pubkey to scaffold malformed parser/oracle inputs");
                }
                write_text_file(out_path, make_invalid_pubkey_template_from_material(curve.name, parsed_material.pubkey_payload, mode, backend, diff_backends, parsed_material.source_kind, emit_minimal_json));
                std::cout << "Generated invalid-public-key analysis skeleton\n";
                std::cout << "  curve = " << curve.name << "\n";
                if (const auto oid = curve_oid_from_name(curve.name)) std::cout << "  oid = " << *oid << "\n";
                std::cout << "  mode = " << mode << "\n";
                std::cout << "  source = " << parsed_material.source_kind << "\n";
                std::cout << "  output = " << out_path << "\n";
                std::cout << "  note = malformed public-key bytes were preserved for parser/oracle analysis\n";
                return 0;
            }
            write_text_file(out_path, make_json_template_from_pubkey(curve, *P, mode, backend, diff_backends, parsed_material.source_kind, emit_minimal_json));
            std::cout << "Generated challenge JSON skeleton\n";
            std::cout << "  curve = " << curve.name << "\n";
            if (const auto oid = curve_oid_from_name(curve.name)) std::cout << "  oid = " << *oid << "\n";
            std::cout << "  mode = " << mode << "\n";
            std::cout << "  compressed_pubkey = " << compress_pubkey(*P) << "\n";
            std::cout << "  source = " << parsed_material.source_kind << "\n";
            std::cout << "  output = " << out_path << "\n";
            return 0;
        }
        if (!args.empty() && args[0] == "--all") {
            std::string in_path;
            RunOptions opts = parse_run_options(args, 1, false, in_path);
            if (in_path.empty()) throw std::runtime_error("--all requires a challenge JSON input path");
            return run_single(in_path, opts);
        }
        if (!args.empty() && args[0] == "--all-dir") {
            std::string dir;
            RunOptions opts = parse_run_options(args, 1, true, dir);
            if (dir.empty()) throw std::runtime_error("--all-dir requires a directory");
            if (opts.report_dir.empty()) opts.report_dir = default_audit_dir();
            fs::create_directories(opts.report_dir);
            if (!opts.evidence_pack_dir.empty()) fs::create_directories(opts.evidence_pack_dir);
            std::vector<CaseRun> runs;
            std::vector<fs::path> files;
            for (const auto& entry : fs::directory_iterator(dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".json") files.push_back(entry.path());
            }
            std::sort(files.begin(), files.end());
            for (const auto& path : files) {
                std::cout << "===== " << path.filename().string() << " =====\n";
                CaseRun run{path.string(), load_challenge_json(path.string()), {}};
                if (opts.strict) validate_challenge_input_strict(run.input);
                inject_runtime_facts(run.input, opts);
                const AnalysisResult full = run_all_modules(run.input);
                run.result = filter_analysis_result(full, opts);
                std::cout << render_report(run.result, run.input, opts.verbose);
                write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".report.json")).string(), render_report_json(run.result, run.input));
                write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".report.txt")).string(), render_report_txt(run.result, run.input));
                write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".report.md")).string(), render_report_md_main(run.result, run.input));
                write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".report.sarif")).string(), render_report_sarif_main(run.result, run.input, path.filename().string()));
                bool recovered = false;
                for (const auto* hit : collect_hits_sorted_main(run.result)) recovered = recovered || (hit->recovered && hit->private_key);
                if (recovered) write_text_file((fs::path(opts.report_dir) / (path.stem().string() + ".recovered.txt")).string(), render_recovered_key_audit_txt(run.result, run.input));
                if (!opts.evidence_pack_dir.empty()) {
                    write_evidence_pack(fs::path(opts.evidence_pack_dir) / path.stem(), path.string(), run.input, full, run.result, opts);
                }
                runs.push_back(std::move(run));
                std::cout << "\n";
            }
            if (!runs.empty()) {
                const auto batch_txt = render_batch_summary_txt(runs);
                std::cout << batch_txt;
                write_text_file((fs::path(opts.report_dir) / "batch_summary.txt").string(), batch_txt);
                write_text_file((fs::path(opts.report_dir) / "batch_summary.json").string(), render_batch_summary_json(runs));
                if (!opts.evidence_pack_dir.empty()) {
                    write_text_file((fs::path(opts.evidence_pack_dir) / "batch_summary.txt").string(), batch_txt);
                    write_text_file((fs::path(opts.evidence_pack_dir) / "batch_summary.json").string(), render_batch_summary_json(runs));
                }
            }
            return 0;
        }
        print_usage();
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "fatal: " << ex.what() << "\n";
        return 2;
    }
}
