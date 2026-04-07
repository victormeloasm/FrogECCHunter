#include "ecc.hpp"

#include <algorithm>
#include <cmath>
#include <cctype>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace fecchunter {

namespace {

std::string canonical_curve_name(std::string s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c)) {
            out.push_back(static_cast<char>(std::tolower(c)));
        }
    }
    return out;
}

Curve make_short_weierstrass(const std::string& name,
                             const std::string& p,
                             const std::string& a,
                             const std::string& b,
                             const std::string& gx,
                             const std::string& gy,
                             const std::string& n,
                             const std::string& h) {
    Curve c;
    c.name = name;
    c.family = "short_weierstrass";
    c.active_algebra_supported = true;
    c.p = hex_to_mpz(p);
    c.a = hex_to_mpz(a);
    c.b = hex_to_mpz(b);
    c.G = Point(hex_to_mpz(gx), hex_to_mpz(gy));
    c.n = hex_to_mpz(n);
    c.h = hex_to_mpz(h);
    return c;
}

} // namespace

std::string normalize_hex(std::string s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
    }
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (!std::isspace(static_cast<unsigned char>(c)) && c != '_') {
            out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    if (out.empty()) {
        return "0";
    }
    return out;
}

mpz_class hex_to_mpz(const std::string& s) {
    mpz_class z;
    const std::string hex = normalize_hex(s);
    if (mpz_set_str(z.get_mpz_t(), hex.c_str(), 16) != 0) {
        throw std::runtime_error("invalid hex integer: " + s);
    }
    return z;
}

std::string mpz_to_hex(const mpz_class& z, bool upper, std::size_t width) {
    std::string s = z.get_str(16);
    if (upper) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
            return static_cast<char>(std::toupper(c));
        });
    }
    if (width > s.size()) {
        s = std::string(width - s.size(), '0') + s;
    }
    return s;
}

std::string point_key(const Point& P) {
    if (P.inf) {
        return "INF";
    }
    return mpz_to_hex(P.x) + ":" + mpz_to_hex(P.y);
}

std::size_t curve_field_bytes(const Curve& curve) {
    if (curve.p == 0) return 0;
    const std::size_t bits = mpz_sizeinbase(curve.p.get_mpz_t(), 2);
    return (bits + 7u) / 8u;
}

std::string compress_pubkey(const Point& P, std::size_t field_bytes) {
    if (P.inf) {
        throw std::runtime_error("cannot compress the point at infinity");
    }
    if (field_bytes == 0) {
        const std::size_t bits = mpz_sizeinbase(P.x.get_mpz_t(), 2);
        field_bytes = std::max<std::size_t>(1, (bits + 7u) / 8u);
    }
    const bool odd = static_cast<bool>(mpz_odd_p(P.y.get_mpz_t()));
    const std::string prefix = odd ? "03" : "02";
    return prefix + mpz_to_hex(P.x, true, field_bytes * 2);
}

Curve secp256k1() {
    return make_short_weierstrass(
        "secp256k1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        "0",
        "7",
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "1"
    );
}


std::optional<std::string> curve_name_from_oid(const std::string& oid) {
    static const std::unordered_map<std::string, std::string> kMap = {
        {"1.3.132.0.10", "secp256k1"},
        {"1.2.840.10045.3.1.7", "prime256v1"},
        {"1.3.132.0.34", "secp384r1"},
        {"1.3.132.0.35", "secp521r1"},
        {"1.3.132.0.33", "secp224r1"},
        {"1.2.840.10045.3.1.1", "prime192v1"},
        {"1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1"},
        {"1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1"},
        {"1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1"},
        {"1.2.156.10197.1.301", "SM2"},
        {"1.3.101.110", "X25519"},
        {"1.3.101.111", "X448"},
        {"1.3.101.112", "Ed25519"},
        {"1.3.101.113", "Ed448"}
    };
    auto it = kMap.find(oid);
    if (it == kMap.end()) return std::nullopt;
    return it->second;
}

std::optional<std::string> curve_oid_from_name(const std::string& name) {
    const std::string key = canonical_curve_name(name);
    static const std::unordered_map<std::string, std::string> kMap = {
        {"secp256k1", "1.3.132.0.10"},
        {"prime256v1", "1.2.840.10045.3.1.7"},
        {"secp256r1", "1.2.840.10045.3.1.7"},
        {"p256", "1.2.840.10045.3.1.7"},
        {"secp384r1", "1.3.132.0.34"},
        {"p384", "1.3.132.0.34"},
        {"secp521r1", "1.3.132.0.35"},
        {"p521", "1.3.132.0.35"},
        {"secp224r1", "1.3.132.0.33"},
        {"p224", "1.3.132.0.33"},
        {"prime192v1", "1.2.840.10045.3.1.1"},
        {"secp192r1", "1.2.840.10045.3.1.1"},
        {"p192", "1.2.840.10045.3.1.1"},
        {"brainpoolp256r1", "1.3.36.3.3.2.8.1.1.7"},
        {"brainpoolp384r1", "1.3.36.3.3.2.8.1.1.11"},
        {"brainpoolp512r1", "1.3.36.3.3.2.8.1.1.13"},
        {"sm2", "1.2.156.10197.1.301"},
        {"x25519", "1.3.101.110"},
        {"x448", "1.3.101.111"},
        {"ed25519", "1.3.101.112"},
        {"ed448", "1.3.101.113"}
    };
    auto it = kMap.find(key);
    if (it == kMap.end()) return std::nullopt;
    return it->second;
}

std::vector<std::string> supported_named_curves() {
    return {
        "secp160k1", "secp160r1", "secp160r2",
        "secp192k1", "prime192v1", "secp192r1", "P-192", "prime192v2", "prime192v3",
        "prime239v1", "prime239v2", "prime239v3",
        "secp224k1", "secp224r1", "P-224", "secp256k1",
        "prime256v1", "secp256r1", "P-256",
        "secp384r1", "P-384", "secp521r1", "P-521",
        "brainpoolP160r1", "brainpoolP192r1", "brainpoolP224r1",
        "brainpoolP256r1", "brainpoolP320r1", "brainpoolP384r1", "brainpoolP512r1",
        "brainpoolP256t1", "brainpoolP384t1", "brainpoolP512t1",
        "SM2", "SM2P256V1"
    };
}


std::optional<Curve> passive_curve_descriptor(const std::string& name) {
    const std::string key = canonical_curve_name(name);
    Curve c;
    c.active_algebra_supported = false;
    if (key == "x25519" || key == "curve25519" || key == "montgomery25519") {
        c.name = "X25519"; c.family = "montgomery"; return c;
    }
    if (key == "x448" || key == "curve448" || key == "montgomery448") {
        c.name = "X448"; c.family = "montgomery"; return c;
    }
    if (key == "ed25519" || key == "edwards25519") {
        c.name = "Ed25519"; c.family = "edwards"; return c;
    }
    if (key == "ed448" || key == "edwards448") {
        c.name = "Ed448"; c.family = "edwards"; return c;
    }
    return std::nullopt;
}

Curve curve_from_named_or_custom(
    const std::string& name,
    const std::optional<std::string>& p_hex,
    const std::optional<std::string>& a_hex,
    const std::optional<std::string>& b_hex,
    const std::optional<std::string>& gx_hex,
    const std::optional<std::string>& gy_hex,
    const std::optional<std::string>& n_hex,
    const std::optional<std::string>& h_hex
) {
    const std::string key = canonical_curve_name(name);

    if (key.empty() || key == "secp256k1") return secp256k1();
    if (key == "secp160k1") {
        return make_short_weierstrass(
            "secp160k1",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
            "0",
            "7",
            "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB",
            "938CF935318FDCED6BC28286531733C3F03C4FEE",
            "0100000000000000000001B8FA16DFAB9ACA16B6B3",
            "1"
        );
    }
    if (key == "secp160r1") {
        return make_short_weierstrass(
            "secp160r1",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC",
            "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
            "4A96B5688EF573284664698968C38BB913CBFC82",
            "23A628553168947D59DCC912042351377AC5FB32",
            "0100000000000000000001F4C8F927AED3CA752257",
            "1"
        );
    }
    if (key == "secp160r2") {
        return make_short_weierstrass(
            "secp160r2",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70",
            "B4E134D3FB59EB8BAB57274904664D5AF50388BA",
            "52DCB034293A117E1F4FF11B30F7199D3144CE6D",
            "FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E",
            "0100000000000000000000351EE786A818F3A1A16B",
            "1"
        );
    }
    if (key == "secp192k1") {
        return make_short_weierstrass(
            "secp192k1",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
            "0",
            "3",
            "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D",
            "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D",
            "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D",
            "1"
        );
    }
    if (key == "prime192v1" || key == "secp192r1" || key == "nistp192" || key == "p192") {
        return make_short_weierstrass(
            "prime192v1",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
            "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
            "1"
        );
    }
    if (key == "prime192v2") {
        return make_short_weierstrass(
            "prime192v2",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
            "CC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953",
            "EEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A",
            "6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15",
            "FFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31",
            "1"
        );
    }
    if (key == "prime192v3") {
        return make_short_weierstrass(
            "prime192v3",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
            "22123DC2395A05CAA7423DAECCC94760A7D462256BD56916",
            "7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896",
            "38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0",
            "FFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13",
            "1"
        );
    }
    if (key == "prime239v1") {
        return make_short_weierstrass(
            "prime239v1",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
            "6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A",
            "0FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF",
            "7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B",
            "1"
        );
    }
    if (key == "prime239v2") {
        return make_short_weierstrass(
            "prime239v2",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
            "617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C",
            "38AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7",
            "5B0125E4DBEA0EC7206DA0FC01D9B081329FB555DE6EF460237DFF8BE4BA",
            "7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063",
            "1"
        );
    }
    if (key == "prime239v3") {
        return make_short_weierstrass(
            "prime239v3",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC",
            "255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E",
            "6768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A",
            "1607E6898F390C06BC1D552BAD226F3B6FCFE48B6E818499AF18E3ED6CF3",
            "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551",
            "1"
        );
    }
    if (key == "secp224k1") {
        return make_short_weierstrass(
            "secp224k1",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
            "0",
            "5",
            "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",
            "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
            "01000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",
            "1"
        );
    }
    if (key == "prime256v1" || key == "secp256r1" || key == "nistp256" || key == "p256") {
        return make_short_weierstrass(
            "prime256v1",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            "1"
        );
    }
    if (key == "secp384r1" || key == "nistp384" || key == "p384") {
        return make_short_weierstrass(
            "secp384r1",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            "1"
        );
    }
    if (key == "secp521r1" || key == "nistp521" || key == "p521") {
        return make_short_weierstrass(
            "secp521r1",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
            "1"
        );
    }
    if (key == "secp224r1" || key == "nistp224" || key == "p224") {
        return make_short_weierstrass(
            "secp224r1",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
            "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
            "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
            "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
            "1"
        );
    }
    if (key == "brainpoolp256r1") {
        return make_short_weierstrass(
            "brainpoolP256r1",
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
            "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
            "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
            "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
            "1"
        );
    }
    if (key == "brainpoolp384r1") {
        return make_short_weierstrass(
            "brainpoolP384r1",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
            "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
            "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
            "1"
        );
    }
    if (key == "brainpoolp512r1") {
        return make_short_weierstrass(
            "brainpoolP512r1",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEAA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
            "3DF91610A83441CAEAA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
            "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
            "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
            "1"
        );
    }

    if (key == "brainpoolp160r1") {
        return make_short_weierstrass(
            "brainpoolP160r1",
            "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
            "340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
            "1E589A8595423412134FAA2DBDEC95C8D8675E58",
            "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3",
            "1667CB477A1A8EC338F94741669C976316DA6321",
            "E95E4A5F737059DC60DF5991D45029409E60FC09",
            "1"
        );
    }
    if (key == "brainpoolp192r1") {
        return make_short_weierstrass(
            "brainpoolP192r1",
            "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
            "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
            "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
            "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
            "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
            "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1",
            "1"
        );
    }
    if (key == "brainpoolp224r1") {
        return make_short_weierstrass(
            "brainpoolP224r1",
            "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
            "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
            "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
            "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
            "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
            "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F",
            "1"
        );
    }
    if (key == "brainpoolp320r1") {
        return make_short_weierstrass(
            "brainpoolP320r1",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
            "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
            "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
            "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
            "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
            "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",
            "1"
        );
    }
    if (key == "brainpoolp256t1") {
        return make_short_weierstrass(
            "brainpoolP256t1",
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374",
            "662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04",
            "A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4",
            "2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE",
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
            "1"
        );
    }
    if (key == "brainpoolp384t1") {
        return make_short_weierstrass(
            "brainpoolP384t1",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC50",
            "7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805CED70355A33B471EE",
            "18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946A5F54D8D0AA2F418808CC",
            "25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC2B2912675BF5B9E582928",
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
            "1"
        );
    }
    if (key == "brainpoolp512t1") {
        return make_short_weierstrass(
            "brainpoolP512t1",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F0",
            "7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA2304976540F6450085F2DAE145C22553B465763689180EA2571867423E",
            "640ECE5C12788717B9C1BA06CBC2A6FEBA85842458C56DDE9DB1758D39C0313D82BA51735CDB3EA499AA77A7D6943A64F7A3F25FE26F06B51BAA2696FA9035DA",
            "5B534BD595F5AF0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEEF216BD71DF2DADF86A627306ECFF96DBB8BACE198B61E00F8B332",
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
            "1"
        );
    }
    if (key == "sm2" || key == "sm2p256v1") {
        return make_short_weierstrass(
            "SM2",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            "1"
        );
    }

    if (!p_hex || !a_hex || !b_hex || !gx_hex || !gy_hex || !n_hex) {
        throw std::runtime_error("unsupported named curve for the active algebra engine: " + name + "; raw families such as Ed25519/X25519 are scaffold-compatible in v30, while custom short-Weierstrass curves require p, a, b, gx, gy, and n");
    }
    Curve c;
    c.name = name.empty() ? "custom" : name;
    c.p = hex_to_mpz(*p_hex);
    c.a = hex_to_mpz(*a_hex);
    c.b = hex_to_mpz(*b_hex);
    c.G = Point(hex_to_mpz(*gx_hex), hex_to_mpz(*gy_hex));
    c.n = hex_to_mpz(*n_hex);
    c.h = h_hex ? hex_to_mpz(*h_hex) : mpz_class(1);
    return c;
}

mpz_class mod(const mpz_class& x, const mpz_class& m) {
    mpz_class r = x % m;
    if (r < 0) {
        r += m;
    }
    return r;
}

mpz_class inv_mod(const mpz_class& x, const mpz_class& m) {
    mpz_class inv;
    if (mpz_invert(inv.get_mpz_t(), mod(x, m).get_mpz_t(), m.get_mpz_t()) == 0) {
        throw std::runtime_error("modular inverse does not exist");
    }
    return inv;
}

mpz_class sqrt_mod_prime(const mpz_class& a, const mpz_class& p) {
    const mpz_class aa = mod(a, p);
    if (aa == 0) return 0;

    mpz_class legendre_exp = (p - 1) / 2;
    mpz_class legendre;
    mpz_powm(legendre.get_mpz_t(), aa.get_mpz_t(), legendre_exp.get_mpz_t(), p.get_mpz_t());
    if (legendre != 1) return -1;

    if (p % 4 == 3) {
        mpz_class exp = (p + 1) / 4;
        mpz_class y;
        mpz_powm(y.get_mpz_t(), aa.get_mpz_t(), exp.get_mpz_t(), p.get_mpz_t());
        return mod(y, p);
    }

    mpz_class q = p - 1;
    unsigned long s = 0;
    while ((q & 1) == 0) {
        q >>= 1;
        ++s;
    }

    mpz_class z = 2;
    while (true) {
        mpz_class t;
        mpz_powm(t.get_mpz_t(), z.get_mpz_t(), legendre_exp.get_mpz_t(), p.get_mpz_t());
        if (t == p - 1) break;
        ++z;
    }

    mpz_class c;
    mpz_powm(c.get_mpz_t(), z.get_mpz_t(), q.get_mpz_t(), p.get_mpz_t());
    mpz_class x;
    mpz_class exp = (q + 1) / 2;
    mpz_powm(x.get_mpz_t(), aa.get_mpz_t(), exp.get_mpz_t(), p.get_mpz_t());
    mpz_class t;
    mpz_powm(t.get_mpz_t(), aa.get_mpz_t(), q.get_mpz_t(), p.get_mpz_t());
    unsigned long m = s;

    while (t != 1) {
        unsigned long i = 1;
        mpz_class t2 = mod(t * t, p);
        while (i < m && t2 != 1) {
            t2 = mod(t2 * t2, p);
            ++i;
        }
        if (i == m) return -1;
        mpz_class b;
        mpz_class pow_exp = mpz_class(1) << (m - i - 1);
        mpz_powm(b.get_mpz_t(), c.get_mpz_t(), pow_exp.get_mpz_t(), p.get_mpz_t());
        x = mod(x * b, p);
        c = mod(b * b, p);
        t = mod(t * c, p);
        m = i;
    }

    return mod(x, p);
}

bool is_on_curve(const Curve& curve, const Point& P) {
    if (P.inf) {
        return true;
    }
    const mpz_class lhs = mod(P.y * P.y, curve.p);
    const mpz_class rhs = mod(P.x * P.x * P.x + curve.a * P.x + curve.b, curve.p);
    return lhs == rhs;
}

Point point_neg(const Curve& curve, const Point& P) {
    if (P.inf) {
        return P;
    }
    return Point(P.x, mod(-P.y, curve.p));
}

Point point_add(const Curve& curve, const Point& P, const Point& Q) {
    if (P.inf) {
        return Q;
    }
    if (Q.inf) {
        return P;
    }
    if (P.x == Q.x && mod(P.y + Q.y, curve.p) == 0) {
        return Point();
    }

    mpz_class lambda;
    if (P.x == Q.x && P.y == Q.y) {
        const mpz_class num = mod(3 * P.x * P.x + curve.a, curve.p);
        const mpz_class den = inv_mod(2 * P.y, curve.p);
        lambda = mod(num * den, curve.p);
    } else {
        const mpz_class num = mod(Q.y - P.y, curve.p);
        const mpz_class den = inv_mod(Q.x - P.x, curve.p);
        lambda = mod(num * den, curve.p);
    }

    const mpz_class xr = mod(lambda * lambda - P.x - Q.x, curve.p);
    const mpz_class yr = mod(lambda * (P.x - xr) - P.y, curve.p);
    return Point(xr, yr);
}

Point point_sub(const Curve& curve, const Point& P, const Point& Q) {
    return point_add(curve, P, point_neg(curve, Q));
}

Point scalar_mul(const Curve& curve, mpz_class k, const Point& P) {
    k = mod(k, curve.n);
    Point result;
    Point addend = P;
    while (k > 0) {
        if ((k & 1) != 0) {
            result = point_add(curve, result, addend);
        }
        addend = point_add(curve, addend, addend);
        k >>= 1;
    }
    return result;
}

std::optional<Point> decompress_pubkey(const Curve& curve, const std::string& compressed_hex) {
    const std::string s = normalize_hex(compressed_hex);
    const std::size_t field_hex = curve_field_bytes(curve) * 2;
    if (field_hex == 0) return std::nullopt;
    if (s.size() != 2 + field_hex || (s.rfind("02", 0) != 0 && s.rfind("03", 0) != 0)) {
        return std::nullopt;
    }
    const bool odd = s.substr(0, 2) == "03";
    const mpz_class x = hex_to_mpz(s.substr(2));
    const mpz_class rhs = mod(x * x * x + curve.a * x + curve.b, curve.p);
    const mpz_class y = sqrt_mod_prime(rhs, curve.p);
    if (y < 0) {
        return std::nullopt;
    }
    mpz_class y_sel = y;
    if (static_cast<bool>(mpz_odd_p(y_sel.get_mpz_t())) != odd) {
        y_sel = mod(-y_sel, curve.p);
    }
    Point P(x, y_sel);
    if (!is_on_curve(curve, P)) {
        return std::nullopt;
    }
    return P;
}

std::optional<Point> parse_pubkey_text(const Curve& curve, const std::string& pubkey_text) {
    const std::string s = normalize_hex(pubkey_text);
    const std::size_t field_hex = curve_field_bytes(curve) * 2;
    if (s.empty() || field_hex == 0) {
        return std::nullopt;
    }
    if ((s.rfind("02", 0) == 0 || s.rfind("03", 0) == 0) && s.size() == 2 + field_hex) {
        return decompress_pubkey(curve, s);
    }
    if (s.rfind("04", 0) == 0 && s.size() == 2 + 2 * field_hex) {
        Point P(hex_to_mpz(s.substr(2, field_hex)), hex_to_mpz(s.substr(2 + field_hex, field_hex)));
        if (!is_on_curve(curve, P)) {
            return std::nullopt;
        }
        return P;
    }
    const auto pos = pubkey_text.find(':');
    if (pos != std::string::npos) {
        Point P(hex_to_mpz(pubkey_text.substr(0, pos)), hex_to_mpz(pubkey_text.substr(pos + 1)));
        if (!is_on_curve(curve, P)) {
            return std::nullopt;
        }
        return P;
    }
    return std::nullopt;
}

std::vector<Point> reconstruct_r_points(const Curve& curve, const mpz_class& r) {
    std::vector<Point> out;
    mpz_class x = r;
    while (x < curve.p) {
        const mpz_class rhs = mod(x * x * x + curve.a * x + curve.b, curve.p);
        const mpz_class y = sqrt_mod_prime(rhs, curve.p);
        if (y >= 0) {
            Point P1(x, y);
            if (is_on_curve(curve, P1)) {
                out.push_back(P1);
                if (y != 0) {
                    out.emplace_back(x, mod(-y, curve.p));
                }
            }
        }
        x += curve.n;
    }
    return out;
}

std::optional<std::uint64_t> bsgs_discrete_log(
    const Curve& curve,
    const Point& base,
    const Point& target,
    std::uint64_t bound
) {
    if (target.inf) {
        return std::uint64_t{0};
    }
    const std::uint64_t m = static_cast<std::uint64_t>(std::ceil(std::sqrt(static_cast<long double>(bound))));

    std::unordered_map<std::string, std::uint32_t> table;
    table.reserve(static_cast<std::size_t>(m * 2 + 1));

    Point cur;
    for (std::uint64_t j = 0; j <= m; ++j) {
        const auto key = point_key(cur);
        if (!table.contains(key)) {
            table.emplace(key, static_cast<std::uint32_t>(j));
        }
        cur = point_add(curve, cur, base);
    }

    const Point giant_step = scalar_mul(curve, mpz_class(m), base);
    cur = target;
    for (std::uint64_t i = 0; i <= m; ++i) {
        const auto it = table.find(point_key(cur));
        if (it != table.end()) {
            const std::uint64_t k = i * m + it->second;
            if (k <= bound) {
                return k;
            }
        }
        cur = point_sub(curve, cur, giant_step);
    }

    return std::nullopt;
}

} // namespace fecchunter
