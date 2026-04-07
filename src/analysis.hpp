#pragma once

#include "ecc.hpp"
#include "input.hpp"

#include <optional>
#include <string>
#include <vector>

namespace fecchunter {

struct ModuleResult {
    std::string id;
    std::string fault_name;
    std::string category;
    std::string severity;
    std::string status;
    std::string impact{"none"};
    std::string confidence{"informational"};
    std::string validation_state{"not_applicable"};
    int heuristic_score{0};
    bool active_attack{false};
    std::vector<std::string> lines;
    bool recovered{false};
    std::optional<mpz_class> private_key;
};

struct AnalysisResult {
    Curve curve;
    Point public_key;
    bool public_key_parsed{true};
    std::string public_key_parse_error;
    std::optional<std::string> original_public_key_hex;
    std::string public_key_source_kind;
    std::vector<ModuleResult> modules;
};

AnalysisResult run_all_modules(const ChallengeInput& in);
std::string render_report(const AnalysisResult& result, const ChallengeInput& in, bool verbose = false);
std::string render_report_json(const AnalysisResult& result, const ChallengeInput& in);
std::string render_report_txt(const AnalysisResult& result, const ChallengeInput& in);
std::string render_check_explanation(const std::string& check_id);

} // namespace fecchunter
