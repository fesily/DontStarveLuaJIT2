#include "core/PluginOptionRules.hpp"

#include <cassert>
#include <cstdio>
#include <string>

using namespace ds::plugin;

static void test_all_of_true() {
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = {"A", "B"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(true);
    c["B"] = ConfigValue::boolean(true);
    assert(EvaluateOptionRule(r, c));
    printf("PASS: all_of_true\n");
}

static void test_all_of_partial() {
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = {"A", "B"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(true);
    c["B"] = ConfigValue::boolean(false);
    assert(!EvaluateOptionRule(r, c));
    printf("PASS: all_of_partial\n");
}

static void test_any_of_one() {
    OptionRule r;
    r.kind = OptionRuleKind::AnyOf;
    r.keys = {"A", "B"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(false);
    c["B"] = ConfigValue::boolean(true);
    assert(EvaluateOptionRule(r, c));
    printf("PASS: any_of_one\n");
}

static void test_any_of_none() {
    OptionRule r;
    r.kind = OptionRuleKind::AnyOf;
    r.keys = {"A", "B"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(false);
    c["B"] = ConfigValue::boolean(false);
    assert(!EvaluateOptionRule(r, c));
    printf("PASS: any_of_none\n");
}

static void test_shorthand_option() {
    // shorthand = AllOf single key
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = {"A"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(true);
    assert(EvaluateOptionRule(r, c));
    printf("PASS: shorthand_option\n");
}

static void test_string_ne_off() {
    OptionRule r;
    r.kind = OptionRuleKind::StringNeq;
    r.pred_key = "EnableProfiler";
    r.pred_expected = "off";
    ConfigView c;
    c["EnableProfiler"] = ConfigValue::string("fzvp");
    assert(EvaluateOptionRule(r, c));
    printf("PASS: string_ne_off\n");
}

static void test_string_off() {
    OptionRule r;
    r.kind = OptionRuleKind::StringNeq;
    r.pred_key = "EnableProfiler";
    r.pred_expected = "off";
    ConfigView c;
    c["EnableProfiler"] = ConfigValue::string("off");
    assert(!EvaluateOptionRule(r, c));
    printf("PASS: string_off\n");
}

static void test_string_eq_on() {
    OptionRule r;
    r.kind = OptionRuleKind::StringEq;
    r.pred_key = "EnableTracy";
    r.pred_expected = "on";
    ConfigView on, off;
    on["EnableTracy"] = ConfigValue::string("on");
    off["EnableTracy"] = ConfigValue::string("off");
    assert(EvaluateOptionRule(r, on));
    assert(!EvaluateOptionRule(r, off));
    printf("PASS: string_eq_on\n");
}

static void test_when_false_via_host() {
    // can_load false with options on => Disabled (covered in host graph style here lightly)
    // Pure option rule still true:
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = {"A"};
    ConfigView c;
    c["A"] = ConfigValue::boolean(true);
    assert(EvaluateOptionRule(r, c));
    printf("PASS: when_false_option_still_true\n");
}

static void test_always_on() {
    OptionRule r;
    r.kind = OptionRuleKind::AlwaysOn;
    assert(EvaluateOptionRule(r, ConfigView{}));
    printf("PASS: always_on\n");
}

int main() {
    test_all_of_true();
    test_all_of_partial();
    test_any_of_one();
    test_any_of_none();
    test_shorthand_option();
    test_string_ne_off();
    test_string_off();
    test_string_eq_on();
    test_when_false_via_host();
    test_always_on();
    printf("All option rule tests passed!\n");
    return 0;
}
