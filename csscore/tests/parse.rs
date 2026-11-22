//! Parser-level adversarial tests (docs/browser.md §5: "truncated
//! rules, unbalanced braces, empty selector/declaration, huge value
//! strings, unknown properties/at-rules, …").

mod support;

use csscore::{
    Decoration, Display, FontStyle, FontWeight, Length, ListStyle, Property, Stylesheet, Value,
};

/// The first declaration of the first rule.
fn first(css: &str) -> Option<csscore::Declaration> {
    Stylesheet::parse(css)
        .rules()
        .first()?
        .declarations()
        .first()
        .copied()
}

fn color_of(css: &str) -> Option<u8> {
    match first(css)?.value {
        Value::Color(index) => Some(index),
        _ => None,
    }
}

#[test]
fn parses_a_simple_rule() {
    let sheet = Stylesheet::parse("h1 { color: red }");
    assert_eq!(sheet.rule_count(), 1);
    let rule = sheet.rules().first().expect("one rule");
    assert_eq!(rule.selectors().len(), 1);
    assert_eq!(
        rule.declarations(),
        [csscore::Declaration {
            property: Property::Color,
            value: Value::Color(1),
            important: false,
        }]
    );
}

#[test]
fn keeps_source_order() {
    let sheet = Stylesheet::parse("p { color: red } div { color: green }");
    assert_eq!(sheet.rule_count(), 2);
    assert_eq!(sheet.rules().first().map(|r| r.order()), Some(0));
    assert_eq!(sheet.rules().get(1).map(|r| r.order()), Some(1));
}

#[test]
fn drops_unknown_properties_but_keeps_the_rule() {
    let decls = Stylesheet::parse("p { color-scheme: dark; color: red; float: left }")
        .rules()
        .first()
        .map(|r| r.declarations().len());
    assert_eq!(decls, Some(1));
}

#[test]
fn skips_at_rules_whole() {
    let sheet = Stylesheet::parse(
        "@media screen and (max-width: 10px) { h1 { color: red } } p { color: #00ff00 }",
    );
    assert_eq!(sheet.rule_count(), 1);
    assert_eq!(sheet.rules().first().map(|r| r.selectors().len()), Some(1));
}

#[test]
fn skips_at_statement_rules() {
    let sheet = Stylesheet::parse("@import url(\"x.css\"); p { color: red }");
    assert_eq!(sheet.rule_count(), 1);
    assert_eq!(
        sheet
            .rules()
            .first()
            .and_then(|r| r.declarations().first())
            .map(|d| d.value),
        Some(Value::Color(1))
    );
}

#[test]
fn survives_a_truncated_rule() {
    let sheet = Stylesheet::parse("h1 { color: red");
    assert_eq!(sheet.rule_count(), 1);
    assert_eq!(
        sheet
            .rules()
            .first()
            .and_then(|r| r.declarations().first())
            .map(|d| d.property),
        Some(Property::Color)
    );
}

#[test]
fn survives_unbalanced_braces() {
    for css in ["{{ h1 { color: red }", "}}} h1 { color: red }", "h1 {{{"] {
        let sheet = Stylesheet::parse(css);
        // No panic, no truncation mid-UTF-8: just bounded, deterministic
        // results. The stray-brace case recovers and parses the rule.
        let _ = sheet.rule_count();
    }
    // A stray top-level close brace is skipped as junk.
    let sheet = Stylesheet::parse("} p { color: red }");
    assert_eq!(sheet.rule_count(), 1);
}

#[test]
fn ignores_nested_braces() {
    let tree_style = "p { color: red; @media x { color: green } font-weight: bold }";
    let sheet = Stylesheet::parse(tree_style);
    let decls = sheet
        .rules()
        .first()
        .map(|r| r.declarations().to_vec())
        .unwrap_or_default();
    assert!(decls.iter().any(|d| d.property == Property::Color));
    assert!(decls.iter().any(|d| d.property == Property::FontWeight));
    // The nested block's `color: green` never became a declaration.
    assert!(
        !decls
            .iter()
            .any(|d| d.value == Value::Color(2) && d.property == Property::Color)
    );
}

#[test]
fn drops_empty_selector_lists() {
    assert_eq!(Stylesheet::parse("{ color: red }").rule_count(), 0);
    assert_eq!(Stylesheet::parse(",,, { color: red }").rule_count(), 0);
    assert_eq!(Stylesheet::parse(". { color: red }").rule_count(), 0);
}

#[test]
fn empty_declaration_block_keeps_a_parsed_rule() {
    let sheet = Stylesheet::parse("p { }");
    assert_eq!(sheet.rule_count(), 1);
    assert_eq!(
        sheet.rules().first().map(|r| r.declarations().len()),
        Some(0)
    );
}

#[test]
fn huge_value_drops_only_the_declaration() {
    let mut css = String::from("p { color: red; background-color: ");
    css.push_str(&"9".repeat(10_000));
    css.push_str("; font-weight: bold }");
    let sheet = Stylesheet::parse(&css);
    let decls = sheet
        .rules()
        .first()
        .map(|r| r.declarations().to_vec())
        .unwrap_or_default();
    assert_eq!(decls.len(), 2);
    assert!(decls.iter().any(|d| d.property == Property::Color));
    assert!(decls.iter().any(|d| d.property == Property::FontWeight));
}

#[test]
fn strips_comments() {
    let sheet = Stylesheet::parse("/* leading */ h1 /* mid */ { color: /*x*/ red } /* tail */");
    assert_eq!(sheet.rule_count(), 1);
    assert_eq!(color_of("h1 { color: /*x*/ red }"), Some(1));
}

#[test]
fn unterminated_comment_swallows_the_rest() {
    let sheet = Stylesheet::parse("h1 { color: red } /* never closed");
    assert_eq!(sheet.rule_count(), 1);
}

#[test]
fn comma_list_drops_only_bad_selectors() {
    let sheet = Stylesheet::parse("a:hover, h1, b > i { color: red }");
    assert_eq!(sheet.rule_count(), 1);
    assert_eq!(sheet.rules().first().map(|r| r.selectors().len()), Some(1));
}

#[test]
fn drops_unsupported_combinators_and_pseudos() {
    for selector in [
        "a > b",
        "a + b",
        "a ~ b",
        "a[href]",
        "a::before",
        "a :hover",
    ] {
        let css = format!("{selector} {{ color: red }}");
        assert_eq!(Stylesheet::parse(&css).rule_count(), 0, "{selector}");
    }
}

#[test]
fn control_and_unicode_values_are_ignored_not_fatal() {
    let sheet = Stylesheet::parse("p { color: \u{1F600}; font-weight: bold }");
    let decls = sheet
        .rules()
        .first()
        .map(|r| r.declarations().to_vec())
        .unwrap_or_default();
    assert_eq!(decls.len(), 1);
    assert_eq!(
        decls.first().map(|d| d.property),
        Some(Property::FontWeight)
    );
}

#[test]
fn important_is_parsed_and_stripped_from_the_value() {
    let decl = first("p { color: red !important }").expect("one declaration");
    assert!(decl.important);
    assert_eq!(decl.value, Value::Color(1));
    let decl = first("p { color: red ! IMPORTANT }").expect("one declaration");
    assert!(decl.important);
}

#[test]
fn shorthand_expands_four_sides() {
    let decls = Stylesheet::parse("div { margin: 1 2 3 4 }")
        .rules()
        .first()
        .map(|r| r.declarations().to_vec())
        .unwrap_or_default();
    let expected = [
        (Property::MarginTop, 1u16),
        (Property::MarginRight, 2),
        (Property::MarginBottom, 3),
        (Property::MarginLeft, 4),
    ];
    assert_eq!(decls.len(), 4);
    for (decl, (property, cells)) in decls.iter().zip(expected) {
        assert_eq!(decl.property, property);
        assert_eq!(decl.value, Value::Length(Length::Cells(cells)));
    }
}

#[test]
fn shorthand_two_and_three_values() {
    let two = Stylesheet::parse("div { padding: 2 3 }")
        .rules()
        .first()
        .map(|r| r.declarations().to_vec())
        .unwrap_or_default();
    let sides: Vec<_> = two.iter().map(|d| (d.property, d.value)).collect();
    assert_eq!(sides.len(), 4);
    assert_eq!(
        sides.first().copied(),
        Some((Property::PaddingTop, Value::Length(Length::Cells(2))))
    );
    assert_eq!(
        sides.get(3).copied(),
        Some((Property::PaddingLeft, Value::Length(Length::Cells(3))))
    );
    let three = Stylesheet::parse("div { margin: 1 2 3 }")
        .rules()
        .first()
        .map(|r| r.declarations().to_vec())
        .unwrap_or_default();
    assert_eq!(
        three.first().map(|d| d.value),
        Some(Value::Length(Length::Cells(1)))
    );
    assert_eq!(
        three.get(3).map(|d| d.value),
        Some(Value::Length(Length::Cells(2)))
    );
}

#[test]
fn shorthand_five_values_is_ignored() {
    let sheet = Stylesheet::parse("div { margin: 1 2 3 4 5 }");
    assert_eq!(sheet.rule_count(), 1);
}

#[test]
fn px_converts_to_cells_rounding_up() {
    assert_eq!(
        first("div { margin-left: 16px }").map(|d| d.value),
        Some(Value::Length(Length::Cells(2)))
    );
    assert_eq!(
        first("div { margin-left: 9px }").map(|d| d.value),
        Some(Value::Length(Length::Cells(2)))
    );
    assert_eq!(
        first("div { margin-left: 1px }").map(|d| d.value),
        Some(Value::Length(Length::Cells(1)))
    );
    assert_eq!(
        first("div { margin-left: 0px }").map(|d| d.value),
        Some(Value::Length(Length::Cells(0)))
    );
}

#[test]
fn percent_is_accepted_for_width_only() {
    assert_eq!(
        first("div { width: 50% }").map(|d| d.value),
        Some(Value::Length(Length::Percent(50)))
    );
    // `%` on height / margins / padding is not supported: the
    // declaration is dropped, the rule survives.
    let sheet = Stylesheet::parse("div { height: 50%; margin: 10% }");
    assert_eq!(sheet.rule_count(), 1);
    assert_eq!(
        sheet.rules().first().map(|r| r.declarations().len()),
        Some(0)
    );
}

#[test]
fn rejects_floats_negative_and_unsupported_units() {
    for value in ["1.5em", "-2px", "2em", "10vh", "auto", "1.5"] {
        let css = format!("div {{ margin-left: {value} }}");
        assert_eq!(first(&css), None, "{value}");
    }
}

#[test]
fn color_names_map_to_the_palette() {
    // Anchors the kernel's BROWSER_CSS_OK fixture constants.
    assert_eq!(color_of("p { color: black }"), Some(0));
    assert_eq!(color_of("p { color: red }"), Some(1));
    assert_eq!(color_of("p { color: green }"), Some(2));
    assert_eq!(color_of("p { color: yellow }"), Some(11));
    assert_eq!(color_of("p { color: blue }"), Some(4));
    assert_eq!(color_of("p { color: cyan }"), Some(14));
    assert_eq!(color_of("p { color: aqua }"), Some(14));
    assert_eq!(color_of("p { color: white }"), Some(15));
    assert_eq!(color_of("p { color: fuchsia }"), Some(13));
}

#[test]
fn hex_colors_map_to_the_palette() {
    assert_eq!(color_of("p { color: #f00 }"), Some(1));
    assert_eq!(color_of("p { color: #ff0000 }"), Some(1));
    assert_eq!(color_of("p { color: #0f0 }"), Some(2)); // lime → dark green slot
    assert_eq!(color_of("p { color: #FFFF00 }"), Some(11));
    assert_eq!(color_of("p { color: #zzz }"), None);
    assert_eq!(color_of("p { color: #12345 }"), None);
}

#[test]
fn rgb_function_maps_to_the_palette() {
    assert_eq!(color_of("p { color: rgb(0, 255, 255) }"), Some(14));
    assert_eq!(color_of("p { color: rgb(255,0,0) }"), Some(1));
    // Space-separated CSS Color 4 form is not supported: dropped.
    assert_eq!(color_of("p { color: rgb(255 0 0) }"), None);
    assert_eq!(color_of("p { color: rgb(999,0,0) }"), None);
}

#[test]
fn color_ties_resolve_to_the_brighter_candidate() {
    // (0,0,85) is exactly equidistant (7225) from index 0 (black) and
    // index 4 (blue): the later, brighter candidate wins.
    assert_eq!(csscore::nearest_vga(0, 0, 85), 4);
    // `fuchsia` is not a tie: 13 is strictly nearer than 5.
    assert_eq!(csscore::nearest_vga(255, 0, 255), 13);
}

#[test]
fn transparent_background_is_ignored() {
    assert_eq!(
        first("p { background-color: transparent }").map(|d| d.property),
        None
    );
}

#[test]
fn inline_block_folds_to_inline() {
    assert_eq!(
        first("p { display: inline-block }").map(|d| d.value),
        Some(Value::Display(Display::Inline))
    );
    assert_eq!(
        first("p { display: none }").map(|d| d.value),
        Some(Value::Display(Display::None))
    );
    assert_eq!(
        first("p { display: block }").map(|d| d.value),
        Some(Value::Display(Display::Block))
    );
    assert_eq!(first("p { display: flex }"), None);
}

#[test]
fn list_style_values() {
    assert_eq!(
        first("li { list-style-type: dash }").map(|d| d.value),
        Some(Value::ListStyle(ListStyle::Dash))
    );
    assert_eq!(
        first("li { list-style-type: square }").map(|d| d.value),
        Some(Value::ListStyle(ListStyle::Disc))
    );
    assert_eq!(
        first("li { list-style-type: none }").map(|d| d.value),
        Some(Value::ListStyle(ListStyle::None))
    );
    assert_eq!(first("li { list-style-type: upper-roman }"), None);
}

#[test]
fn font_weight_buckets() {
    assert_eq!(
        first("b { font-weight: bold }").map(|d| d.value),
        Some(Value::FontWeight(FontWeight::Bold))
    );
    assert_eq!(
        first("b { font-weight: 700 }").map(|d| d.value),
        Some(Value::FontWeight(FontWeight::Bold))
    );
    assert_eq!(
        first("b { font-weight: 900 }").map(|d| d.value),
        Some(Value::FontWeight(FontWeight::Bold))
    );
    assert_eq!(
        first("b { font-weight: 500 }").map(|d| d.value),
        Some(Value::FontWeight(FontWeight::Normal))
    );
    assert_eq!(first("b { font-weight: bolder }"), None);
}

#[test]
fn font_style_and_decoration() {
    assert_eq!(
        first("i { font-style: italic }").map(|d| d.value),
        Some(Value::FontStyle(FontStyle::Italic))
    );
    assert_eq!(
        first("i { font-style: oblique }").map(|d| d.value),
        Some(Value::FontStyle(FontStyle::Italic))
    );
    assert_eq!(
        first("u { text-decoration: underline }").map(|d| d.value),
        Some(Value::Decoration(Decoration::Underline))
    );
    assert_eq!(
        first("u { text-decoration-line: none }").map(|d| d.value),
        Some(Value::Decoration(Decoration::None))
    );
    assert_eq!(first("u { text-decoration: line-through }"), None);
}

#[test]
fn property_names_and_values_are_case_insensitive() {
    assert_eq!(color_of("p { COLOR: RED }"), Some(1));
    assert_eq!(
        first("p { DISPLAY: NONE }").map(|d| d.value),
        Some(Value::Display(Display::None))
    );
}

#[test]
fn input_is_bounded_by_the_rule_cap() {
    let mut css = String::new();
    for i in 0..(csscore::RULE_CAP + 50) {
        css.push_str("p { color: red }\n");
        let _ = i;
    }
    let sheet = Stylesheet::parse(&css);
    assert_eq!(sheet.rule_count(), csscore::RULE_CAP);
}

#[test]
fn selector_depth_is_capped() {
    let ok = "a b c d e f g h { color: red }";
    let deep = "a b c d e f g h i { color: red }";
    let sheet = Stylesheet::parse(ok);
    assert_eq!(sheet.rule_count(), 1);
    assert_eq!(sheet.rules().first().map(|r| r.selectors().len()), Some(1));
    let sheet = Stylesheet::parse(deep);
    assert_eq!(sheet.rule_count(), 0);
}

#[test]
fn class_count_per_compound_is_capped() {
    let mut selector = String::from("div");
    for i in 0..=csscore::CLASSES_PER_COMPOUND {
        selector.push_str(&format!(".c{i}"));
    }
    let css = format!("{selector} {{ color: red }}");
    assert_eq!(Stylesheet::parse(&css).rule_count(), 0);
}

#[test]
fn empty_input_is_an_empty_sheet() {
    assert!(Stylesheet::parse("").is_empty());
    assert!(Stylesheet::parse("   \n\t ").is_empty());
    assert!(Stylesheet::parse("/* only a comment */").is_empty());
}

#[test]
fn overlong_input_is_clamped_not_fatal() {
    let mut css = String::from("p { color: red }");
    css.push_str(&"/*".repeat(csscore::INPUT_CAP));
    let sheet = Stylesheet::parse(&css);
    assert_eq!(sheet.rule_count(), 1);
}
