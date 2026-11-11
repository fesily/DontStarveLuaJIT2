#include "core/PluginOptionRules.hpp"

#include <string>
#include <doctest/doctest.h>

using namespace ds::plugin;

TEST_CASE("test_plugin_option_rules/all_of_true") {
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = {"A", "B"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(true);
    c["B"] = ConfigValue::boolean(true);
    REQUIRE(EvaluateOptionRule(r, c));
}

TEST_CASE("test_plugin_option_rules/all_of_partial") {
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = {"A", "B"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(true);
    c["B"] = ConfigValue::boolean(false);
    REQUIRE_FALSE(EvaluateOptionRule(r, c));
}

TEST_CASE("test_plugin_option_rules/any_of_one") {
    OptionRule r;
    r.kind = OptionRuleKind::AnyOf;
    r.keys = {"A", "B"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(false);
    c["B"] = ConfigValue::boolean(true);
    REQUIRE(EvaluateOptionRule(r, c));
}

TEST_CASE("test_plugin_option_rules/any_of_none") {
    OptionRule r;
    r.kind = OptionRuleKind::AnyOf;
    r.keys = {"A", "B"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(false);
    c["B"] = ConfigValue::boolean(false);
    REQUIRE_FALSE(EvaluateOptionRule(r, c));
}

TEST_CASE("test_plugin_option_rules/shorthand_option") {
    // shorthand = AllOf single key
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = {"A"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(true);
    REQUIRE(EvaluateOptionRule(r, c));
}

TEST_CASE("test_plugin_option_rules/string_ne_off") {
    OptionRule r;
    r.kind = OptionRuleKind::StringNeq;
    r.pred_key = "EnableProfiler";
    r.pred_expected = "off";
    ConfigView c;
    c["EnableProfiler"] = ConfigValue::string("fzvp");
    REQUIRE(EvaluateOptionRule(r, c));
}

TEST_CASE("test_plugin_option_rules/string_off") {
    OptionRule r;
    r.kind = OptionRuleKind::StringNeq;
    r.pred_key = "EnableProfiler";
    r.pred_expected = "off";
    ConfigView c;
    c["EnableProfiler"] = ConfigValue::string("off");
    REQUIRE_FALSE(EvaluateOptionRule(r, c));
}

TEST_CASE("test_plugin_option_rules/string_eq_on") {
    OptionRule r;
    r.kind = OptionRuleKind::StringEq;
    r.pred_key = "EnableTracy";
    r.pred_expected = "on";
    ConfigView on, off;
    on["EnableTracy"] = ConfigValue::string("on");
    off["EnableTracy"] = ConfigValue::string("off");
    REQUIRE(EvaluateOptionRule(r, on));
    REQUIRE_FALSE(EvaluateOptionRule(r, off));
}

TEST_CASE("test_plugin_option_rules/when_false_via_host") {
    // can_load false with options on => Disabled (covered in host graph style here lightly)
    // Pure option rule still true:
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = {"A"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(true);
    REQUIRE(EvaluateOptionRule(r, c));
}

TEST_CASE("test_plugin_option_rules/always_on") {
    OptionRule r;
    r.kind = OptionRuleKind::AlwaysOn;
    REQUIRE(EvaluateOptionRule(r, ConfigView{}));
}
