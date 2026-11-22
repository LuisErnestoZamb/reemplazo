//! Cascade tests: specificity, source order, `!important`, inline
//! styles, descendant matching and computed-value assembly.

mod support;

use csscore::{Display, FontWeight, Length, ListStyle};
use support::{A, TestTree};

#[test]
fn type_selector_matches_by_name() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default());
    let div = tree.add(0, "div", A::default());
    assert_eq!(tree.style(p, "p { color: red }").color, Some(1));
    assert_eq!(tree.style(div, "p { color: red }").color, None);
}

#[test]
fn tag_matching_is_case_insensitive() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default());
    assert_eq!(tree.style(p, "P { color: red }").color, Some(1));
}

#[test]
fn class_selector_matches_one_of_several_tokens() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default().class("note  muted\twide"));
    assert_eq!(tree.style(div, ".muted { color: red }").color, Some(1));
    assert_eq!(tree.style(div, ".Missing { color: red }").color, None);
}

#[test]
fn class_matching_is_case_sensitive() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default().class("Note"));
    assert_eq!(tree.style(div, ".note { color: red }").color, None);
    assert_eq!(tree.style(div, ".Note { color: red }").color, Some(1));
}

#[test]
fn id_selector_matches() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default().id("lead"));
    assert_eq!(tree.style(div, "#lead { color: red }").color, Some(1));
    assert_eq!(tree.style(div, "#other { color: red }").color, None);
}

#[test]
fn universal_selector_matches_every_element() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default());
    let span = tree.add(div, "span", A::default());
    assert_eq!(tree.style(div, "* { color: red }").color, Some(1));
    assert_eq!(
        tree.style(span, "* { font-weight: bold }").font_weight,
        Some(FontWeight::Bold)
    );
}

#[test]
fn compound_selector_needs_every_part() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default().class("note").id("lead"));
    let span = tree.add(0, "span", A::default().class("note").id("lead"));
    let css = "div.note#lead { color: red }";
    assert_eq!(tree.style(div, css).color, Some(1));
    assert_eq!(tree.style(span, css).color, None);
}

#[test]
fn descendant_selector_walks_ancestors() {
    let mut tree = TestTree::new();
    let outer = tree.add(0, "div", A::default().class("outer"));
    let section = tree.add(outer, "section", A::default());
    let span = tree.add(section, "span", A::default());
    let outside = tree.add(0, "span", A::default());
    let css = ".outer span { color: red }";
    assert_eq!(tree.style(span, css).color, Some(1));
    assert_eq!(tree.style(outside, css).color, None);
    assert_eq!(tree.style(outer, css).color, None);
}

#[test]
fn descendant_order_matters() {
    let mut tree = TestTree::new();
    let span = tree.add(0, "span", A::default());
    let div = tree.add(span, "div", A::default());
    let css = "span div { color: red }";
    let reverse = "div span { color: red }";
    assert_eq!(tree.style(div, css).color, Some(1));
    assert_eq!(tree.style(span, css).color, None);
    assert_eq!(tree.style(div, reverse).color, None);
}

#[test]
fn specificity_id_beats_class_beats_type() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default().class("note").id("lead"));
    let css = "div { color: red } .note { color: green } #lead { color: aqua }";
    assert_eq!(tree.style(div, css).color, Some(14));
    let css = "div { color: red } .note { color: green }";
    assert_eq!(tree.style(div, css).color, Some(2));
    let css = "div { color: red }";
    assert_eq!(tree.style(div, css).color, Some(1));
}

#[test]
fn descendant_specificity_counts_every_compound() {
    let mut tree = TestTree::new();
    let outer = tree.add(0, "div", A::default().class("outer"));
    let span = tree.add(outer, "span", A::default().class("note"));
    let css = ".note { color: green } .outer span { color: red }";
    // (0,1,1) for `.outer span` beats (0,1,0) for `.note`.
    assert_eq!(tree.style(span, css).color, Some(1));
}

#[test]
fn later_rule_wins_on_equal_specificity() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default());
    let css = "p { color: red } p { color: green }";
    assert_eq!(tree.style(p, css).color, Some(2));
}

#[test]
fn earlier_higher_specificity_still_wins() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default().class("note"));
    let css = ".note { color: green } p { color: red }";
    assert_eq!(tree.style(p, css).color, Some(2));
}

#[test]
fn per_property_winners_merge_across_rules() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default().class("box"));
    let css = ".box { background-color: yellow } div { color: red }";
    let style = tree.style(div, css);
    assert_eq!(style.color, Some(1));
    assert_eq!(style.background, Some(11));
}

#[test]
fn inline_style_beats_the_sheet() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default().style("color: green"));
    assert_eq!(
        tree.style(p, "p { color: red } #x { color: aqua }").color,
        Some(2)
    );
}

#[test]
fn sheet_important_beats_inline_normal() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default().style("color: green"));
    assert_eq!(tree.style(p, "p { color: red !important }").color, Some(1));
}

#[test]
fn inline_important_beats_sheet_important() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default().style("color: green !important"));
    assert_eq!(tree.style(p, "p { color: red !important }").color, Some(2));
}

#[test]
fn important_beats_a_later_normal_declaration() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default());
    let css = "p { color: red !important } p { color: green }";
    assert_eq!(tree.style(p, css).color, Some(1));
}

#[test]
fn display_none_is_not_inherited() {
    let mut tree = TestTree::new();
    let outer = tree.add(0, "div", A::default().class("gone"));
    let inner = tree.add(outer, "span", A::default());
    let css = ".gone { display: none }";
    assert_eq!(tree.style(outer, css).display, Some(Display::None));
    // `display` does not inherit: the layout's walk skips the whole
    // subtree from the parent's value (documented).
    assert_eq!(tree.style(inner, css).display, None);
}

#[test]
fn non_elements_get_the_default_style() {
    let tree = TestTree::new();
    assert!(tree.style(0, "* { color: red }").is_default());
}

#[test]
fn shorthand_then_longhand_merges_by_declaration_order() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default());
    let style = tree.style(div, "div { margin: 1 2 3 4; margin-left: 7 }");
    assert_eq!(style.margin.top, 1);
    assert_eq!(style.margin.right, 2);
    assert_eq!(style.margin.bottom, 3);
    assert_eq!(style.margin.left, 7);
}

#[test]
fn padding_and_margin_are_separate_boxes() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default());
    let style = tree.style(div, "div { margin: 8px; padding: 2px 4px }");
    assert_eq!(style.margin.left, 1);
    assert_eq!(style.padding.top, 1);
    assert_eq!(style.padding.right, 1);
}

#[test]
fn width_percent_resolves_against_the_basis() {
    let mut tree = TestTree::new();
    let div = tree.add(0, "div", A::default());
    let style = tree.style(div, "div { width: 50% }");
    assert_eq!(style.width.map(|w| w.to_cells(80)), Some(40));
    let style = tree.style(div, "div { width: 24px }");
    assert_eq!(style.width, Some(Length::Cells(3)));
    assert_eq!(style.width.map(|w| w.to_cells(80)), Some(3));
}

#[test]
fn list_style_comes_through_the_cascade() {
    let mut tree = TestTree::new();
    let ul = tree.add(0, "ul", A::default().class("plain"));
    let li = tree.add(ul, "li", A::default());
    let style = tree.style(li, ".plain li { list-style-type: dash }");
    assert_eq!(style.list_style, Some(ListStyle::Dash));
    let style = tree.style(ul, ".plain { list-style-type: none }");
    assert_eq!(style.list_style, Some(ListStyle::None));
}

#[test]
fn an_element_without_matching_rules_is_default() {
    let mut tree = TestTree::new();
    let p = tree.add(0, "p", A::default());
    assert!(tree.style(p, ".nope { color: red }").is_default());
    assert!(tree.style(p, "").is_default());
}

#[test]
fn inline_declarations_parse_like_rule_bodies() {
    let mut tree = TestTree::new();
    let p = tree.add(
        0,
        "p",
        A::default().style("color: red; font-weight: 700; margin-left: 16px"),
    );
    let style = tree.style(p, "");
    assert_eq!(style.color, Some(1));
    assert_eq!(style.font_weight, Some(FontWeight::Bold));
    assert_eq!(style.margin.left, 2);
}

#[test]
fn inline_garbage_does_not_poison_valid_declarations() {
    let mut tree = TestTree::new();
    let p = tree.add(
        0,
        "p",
        A::default().style("bogus; color: green; ; width: 10em; display: none"),
    );
    let style = tree.style(p, "");
    assert_eq!(style.color, Some(2));
    assert_eq!(style.display, Some(Display::None));
    assert_eq!(style.width, None);
}

#[test]
fn display_block_and_inline_come_through() {
    let mut tree = TestTree::new();
    let span = tree.add(0, "span", A::default().class("card"));
    let style = tree.style(span, ".card { display: block }");
    assert_eq!(style.display, Some(Display::Block));
    let p = tree.add(0, "p", A::default().class("inline"));
    let style = tree.style(p, ".inline { display: inline }");
    assert_eq!(style.display, Some(Display::Inline));
}
