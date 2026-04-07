#include "input.hpp"

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <stdexcept>
#include <string>

namespace fecchunter {

namespace {

using boost::property_tree::ptree;

template <typename T>
std::optional<T> get_optional(const ptree& pt, const std::string& key) {
    auto v = pt.get_optional<T>(key);
    if (v) {
        return *v;
    }
    return std::nullopt;
}

void flatten_facts(const ptree& pt, const std::string& prefix, std::map<std::string, std::string>& out) {
    if (pt.empty()) {
        out[prefix] = pt.get_value<std::string>();
        return;
    }
    for (const auto& child : pt) {
        const std::string next = prefix.empty() ? child.first : prefix + "." + child.first;
        flatten_facts(child.second, next, out);
    }
}

} // namespace

ChallengeInput load_challenge_json(const std::string& path) {
    ptree root;
    boost::property_tree::read_json(path, root);

    ChallengeInput in;
    in.schema_version = root.get<std::string>("schema_version", "1.0");
    in.title = root.get<std::string>("title", "Untitled challenge");
    in.mode = root.get<std::string>("mode", "ecdsa");

    if (const auto curve_child = root.get_child_optional("curve")) {
        const auto& c = *curve_child;
        in.curve.name = c.get<std::string>("name", "secp256k1");
        in.curve.p_hex = get_optional<std::string>(c, "p");
        in.curve.a_hex = get_optional<std::string>(c, "a");
        in.curve.b_hex = get_optional<std::string>(c, "b");
        in.curve.gx_hex = get_optional<std::string>(c, "gx");
        in.curve.gy_hex = get_optional<std::string>(c, "gy");
        in.curve.n_hex = get_optional<std::string>(c, "n");
        in.curve.h_hex = get_optional<std::string>(c, "h");
    } else {
        in.curve.name = "secp256k1";
    }

    if (const auto pk_child = root.get_child_optional("public_key")) {
        const auto& pk = *pk_child;
        in.public_key.compressed_hex = get_optional<std::string>(pk, "compressed");
        if (!in.public_key.compressed_hex) in.public_key.compressed_hex = get_optional<std::string>(pk, "sec1_compressed");
        in.public_key.x_hex = get_optional<std::string>(pk, "x");
        in.public_key.y_hex = get_optional<std::string>(pk, "y");
        in.public_key.raw_hex = get_optional<std::string>(pk, "raw_hex");
        if (!in.public_key.raw_hex) in.public_key.raw_hex = get_optional<std::string>(pk, "raw");
        in.public_key.source_kind = get_optional<std::string>(pk, "source_kind");
        if (!in.public_key.source_kind) {
            const bool has_embedded = in.public_key.compressed_hex || (in.public_key.x_hex && in.public_key.y_hex) || in.public_key.raw_hex;
            if (has_embedded) in.public_key.source_kind = std::string("json_embedded");
        }
    }

    if (const auto cons_child = root.get_child_optional("constraints")) {
        const auto& c = *cons_child;
        in.constraints.nonce_max_bits = c.get<int>("nonce_max_bits", 0);
        in.constraints.privkey_max_bits = c.get<int>("privkey_max_bits", 0);
        in.constraints.related_delta_max = c.get<long long>("related_delta_max", 0);
        in.constraints.related_a_abs_max = c.get<long long>("related_a_abs_max", 0);
        in.constraints.related_b_abs_max = c.get<long long>("related_b_abs_max", 0);
        in.constraints.unix_time_min = c.get<unsigned long long>("unix_time_min", 0);
        in.constraints.unix_time_max = c.get<unsigned long long>("unix_time_max", 0);
    }

    if (const auto facts_child = root.get_child_optional("facts")) {
        flatten_facts(*facts_child, "", in.facts);
    }

    if (const auto sigs_child = root.get_child_optional("signatures")) {
        for (const auto& item : *sigs_child) {
            const auto& pt = item.second;
            SignatureInput s;
            s.message = pt.get<std::string>("message", "");
            s.hash_hex = pt.get<std::string>("hash_hex", pt.get<std::string>("hash", ""));
            s.r_hex = pt.get<std::string>("r", "");
            s.s_hex = pt.get<std::string>("s", "");
            in.signatures.push_back(std::move(s));
        }
    }

    if (in.mode == "ecdsa" && in.signatures.empty()) {
        throw std::runtime_error("ECDSA mode requires at least one signature");
    }

    return in;
}

} // namespace fecchunter
