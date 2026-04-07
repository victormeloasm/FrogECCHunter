#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <gmpxx.h>

namespace fecchunter {

struct Point {
    mpz_class x{};
    mpz_class y{};
    bool inf{true};

    Point() = default;
    Point(mpz_class px, mpz_class py) : x(std::move(px)), y(std::move(py)), inf(false) {}
};

struct Curve {
    std::string name;
    std::string family{"short_weierstrass"};
    bool active_algebra_supported{true};
    mpz_class p;
    mpz_class a;
    mpz_class b;
    Point G;
    mpz_class n;
    mpz_class h;
};

std::string normalize_hex(std::string s);
mpz_class hex_to_mpz(const std::string& s);
std::string mpz_to_hex(const mpz_class& z, bool upper = true, std::size_t width = 0);
std::string point_key(const Point& P);
std::size_t curve_field_bytes(const Curve& curve);
std::string compress_pubkey(const Point& P, std::size_t field_bytes = 0);

Curve secp256k1();
std::vector<std::string> supported_named_curves();
std::optional<std::string> curve_name_from_oid(const std::string& oid);
std::optional<std::string> curve_oid_from_name(const std::string& name);
std::optional<Curve> passive_curve_descriptor(const std::string& name);

Curve curve_from_named_or_custom(
    const std::string& name,
    const std::optional<std::string>& p_hex,
    const std::optional<std::string>& a_hex,
    const std::optional<std::string>& b_hex,
    const std::optional<std::string>& gx_hex,
    const std::optional<std::string>& gy_hex,
    const std::optional<std::string>& n_hex,
    const std::optional<std::string>& h_hex
);

mpz_class mod(const mpz_class& x, const mpz_class& m);
mpz_class inv_mod(const mpz_class& x, const mpz_class& m);
mpz_class sqrt_mod_prime(const mpz_class& a, const mpz_class& p);

bool is_on_curve(const Curve& curve, const Point& P);
Point point_neg(const Curve& curve, const Point& P);
Point point_add(const Curve& curve, const Point& P, const Point& Q);
Point point_sub(const Curve& curve, const Point& P, const Point& Q);
Point scalar_mul(const Curve& curve, mpz_class k, const Point& P);
std::optional<Point> decompress_pubkey(const Curve& curve, const std::string& compressed_hex);
std::optional<Point> parse_pubkey_text(const Curve& curve, const std::string& pubkey_text);
std::vector<Point> reconstruct_r_points(const Curve& curve, const mpz_class& r);

std::optional<std::uint64_t> bsgs_discrete_log(
    const Curve& curve,
    const Point& base,
    const Point& target,
    std::uint64_t bound
);

} // namespace fecchunter
