//! Adversarial host suite for the `dom` tree builder (B2 of
//! docs/browser.md §4): depth/node-cap bombs, unclosed-tag storms,
//! attribute chaos, table mis-nesting, implied closes, raw-text
//! elements, entity bounds, encoding edge cases — every fixture also
//! runs through the structural invariant walker in `common`.

mod common;

use common::check;
use dom::{ATTR_VALUE_CAP, ATTRS_PER_ELEMENT, BuildError, DEPTH_CAP, Document, NodeKind};

fn build(src: &str) -> Document {
    dom::build(src.as_bytes()).expect("fixture should build")
}

fn refused(src: &str) -> BuildError {
    dom::build(src.as_bytes()).expect_err("fixture should be refused fail-closed")
}

fn element(doc: &Document, id: usize) -> &dom::Element {
    match &doc.node(id).expect("node must exist").kind {
        NodeKind::Element(e) => e,
        other => panic!("expected an element, got {other:?}"),
    }
}

fn child_ids(doc: &Document, id: usize) -> Vec<usize> {
    doc.children(id).map(|(cid, _)| cid).collect()
}

fn named_children(doc: &Document, id: usize, name: &str) -> Vec<usize> {
    doc.children(id)
        .filter(|(_, n)| matches!(&n.kind, NodeKind::Element(e) if e.name == name))
        .map(|(cid, _)| cid)
        .collect()
}

fn first_text(doc: &Document, id: usize) -> Option<String> {
    doc.children(id).find_map(|(_, n)| match &n.kind {
        NodeKind::Text(t) => Some(t.clone()),
        _ => None,
    })
}

/// The text directly under `id`, concatenated in order (used where a
/// single run is expected).
fn texts(doc: &Document, id: usize) -> Vec<String> {
    doc.children(id)
        .filter_map(|(_, n)| match &n.kind {
            NodeKind::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

// --- bombs and caps -------------------------------------------------------

#[test]
fn deep_nesting_bomb_is_refused_fail_closed() {
    // 100 000 nested tags: an accidental recursive builder would blow
    // the host (and the kernel's 16 KiB) stack here — the iterative
    // one returns the depth refusal.
    let mut src = String::new();
    for _ in 0..100_000 {
        src.push_str("<div>");
    }
    src.push_str("payload");
    assert_eq!(refused(&src), BuildError::DepthCap);
}

#[test]
fn depth_cap_allows_exactly_cap_elements() {
    let src = format!(
        "{}x{}",
        "<div>".repeat(DEPTH_CAP),
        "</div>".repeat(DEPTH_CAP)
    );
    let doc = dom::build(src.as_bytes()).expect("exactly DEPTH_CAP deep must build");
    check(&doc);
    // Walk the single-child chain: DEPTH_CAP elements, no more.
    let mut depth = 0usize;
    let mut id = doc.root();
    while let Some(cid) = doc.node(id).and_then(|n| n.first_child) {
        if !matches!(doc.node(cid).map(|n| &n.kind), Some(NodeKind::Element(_))) {
            break;
        }
        id = cid;
        depth += 1;
    }
    assert_eq!(depth, DEPTH_CAP);
}

#[test]
fn depth_cap_refuses_one_more_level() {
    let src = format!(
        "{}x{}",
        "<div>".repeat(DEPTH_CAP + 1),
        "</div>".repeat(DEPTH_CAP + 1)
    );
    assert_eq!(refused(&src), BuildError::DepthCap);
}

#[test]
fn node_cap_refuses_sibling_sprawl() {
    // 2 nodes per `<p>x</p>` + root: 2500 units blow NODE_CAP long
    // before the end — refused, not truncated into a broken tree.
    let src = "<p>x</p>".repeat(2500);
    assert_eq!(refused(&src), BuildError::NodeCap);
}

#[test]
fn unclosed_tag_storm_still_yields_a_well_formed_tree() {
    // 12 × 5 = 60 open elements (under DEPTH_CAP), never closed:
    // EOF auto-closes everything and the arena stays consistent.
    let mut src = String::new();
    for _ in 0..12 {
        src.push_str("<div><span><section><p><b>");
    }
    src.push_str("deep text");
    let doc = dom::build(src.as_bytes()).expect("the storm must build");
    check(&doc);
    assert!(doc.node_count() > 60, "every open element must be stored");
}

// --- implied closes / adoption-agency-lite --------------------------------

#[test]
fn p_start_tag_closes_an_open_p() {
    let doc = build("<p>one<p>two");
    check(&doc);
    let kids = child_ids(&doc, doc.root());
    assert_eq!(kids.len(), 2, "two sibling p elements");
    for (kid, want) in kids.iter().zip(["one", "two"]) {
        assert_eq!(element(&doc, *kid).name, "p");
        assert_eq!(first_text(&doc, *kid).as_deref(), Some(want));
    }
}

#[test]
fn block_start_closes_p_across_inline_children() {
    // `<p>` under an inline `<span>`: the block start pops through
    // span and p (HTML5 closes p "in button scope").
    let doc = build("<p>one<span>two</span><div>three</div>");
    check(&doc);
    let kids = child_ids(&doc, doc.root());
    assert_eq!(kids.len(), 2, "div must be a sibling of p, not nested");
    assert_eq!(element(&doc, kids[0]).name, "p");
    assert_eq!(element(&doc, kids[1]).name, "div");
    let p_kids = child_ids(&doc, kids[0]);
    assert_eq!(p_kids.len(), 2, "text + span survived inside the p");
}

#[test]
fn li_start_closes_p_then_the_previous_li() {
    // `<p>` inside `li` stays open until the *next* `<li>`: the
    // p-closing walk finds the p first, then the li rule pops the
    // previous item.
    let doc = build("<ul><li>a<p>b<li>c");
    check(&doc);
    let ul = doc.find_element("ul").expect("ul exists");
    let lis = named_children(&doc, ul, "li");
    assert_eq!(lis.len(), 2, "two sibling items");
    assert_eq!(first_text(&doc, lis[0]).as_deref(), Some("a"));
    let inner_p = named_children(&doc, lis[0], "p");
    assert_eq!(inner_p.len(), 1, "the p stayed inside the first li");
    assert_eq!(first_text(&doc, inner_p[0]).as_deref(), Some("b"));
    assert_eq!(first_text(&doc, lis[1]).as_deref(), Some("c"));
}

#[test]
fn nested_list_keeps_the_outer_li_open() {
    // The li-closing walk stops at `ul`: the inner item must nest,
    // not become a sibling of the outer one.
    let doc = build("<ul><li>one<ul><li>two</ul></ul>");
    check(&doc);
    let outer_ul = doc.find_element("ul").expect("outer ul");
    let outer_lis = named_children(&doc, outer_ul, "li");
    assert_eq!(outer_lis.len(), 1);
    let inner_uls = named_children(&doc, outer_lis[0], "ul");
    assert_eq!(inner_uls.len(), 1, "nested ul lives under the outer li");
    let inner_lis = named_children(&doc, inner_uls[0], "li");
    assert_eq!(inner_lis.len(), 1);
    assert_eq!(first_text(&doc, inner_lis[0]).as_deref(), Some("two"));
}

#[test]
fn p_closing_walk_stops_at_list_scope() {
    // A block start inside a list item must not pop out of the list:
    // the second div nests under the li, not under the outer div.
    let doc = build("<div><p>one<ul><li>two<div>three</div>");
    check(&doc);
    let outer = doc.find_element("div").expect("outer div");
    let uls = named_children(&doc, outer, "ul");
    assert_eq!(uls.len(), 1);
    let lis = named_children(&doc, uls[0], "li");
    assert_eq!(lis.len(), 1);
    assert_eq!(
        named_children(&doc, lis[0], "div").len(),
        1,
        "the inner div belongs to the li (scope boundary honored)"
    );
}

#[test]
fn table_end_tag_pops_mis_nested_rows_and_cells() {
    let doc = build("<table><tr><td>x</table>y");
    check(&doc);
    // Close-on-mismatch: `</table>` popped td, tr and table; the
    // trailing text lands at the root.
    let y_at_root = doc
        .children(doc.root())
        .find(|(_, n)| matches!(&n.kind, NodeKind::Text(t) if t == "y"))
        .expect("y must be a root child");
    assert_eq!(y_at_root.1.parent, Some(doc.root()));
    assert_eq!(named_children(&doc, doc.root(), "table").len(), 1);
}

#[test]
fn formatting_end_tag_closes_through_mismatched_inners() {
    // Adoption-agency-lite: `</b>` closes i *and* b; the later stray
    // `</i>` is ignored (no active-formatting reconstruction).
    let doc = build("<b><i>bold</b>after</i>");
    check(&doc);
    let after = doc
        .children(doc.root())
        .find(|(_, n)| matches!(&n.kind, NodeKind::Text(t) if t == "after"))
        .expect("after must be a root child");
    assert_eq!(after.1.parent, Some(doc.root()), "b's end tag popped i too");
    let i = doc.find_element("i").expect("i node still in the arena");
    assert_eq!(
        doc.node(i).and_then(|n| n.parent),
        doc.find_element("b"),
        "the closed i kept its parent link"
    );
    assert_eq!(first_text(&doc, i).as_deref(), Some("bold"));
}

#[test]
fn stray_end_tags_are_ignored() {
    let doc = build("</p></div><p>kept");
    check(&doc);
    assert_eq!(
        common::element_names(&doc),
        vec!["p".to_string()],
        "only the real start tag created an element"
    );
    let p = doc.find_element("p").expect("p exists");
    assert_eq!(first_text(&doc, p).as_deref(), Some("kept"));
}

// --- raw text elements ----------------------------------------------------

#[test]
fn script_content_is_stored_verbatim() {
    let doc = build(r#"<script>var x = "&amp;";</script>"#);
    check(&doc);
    let script = doc.find_element("script").expect("script exists");
    assert_eq!(
        first_text(&doc, script).as_deref(),
        Some(r#"var x = "&amp;";"#),
        "raw text: no entity decoding inside script"
    );
}

#[test]
fn style_content_keeps_gt_and_braces() {
    let doc = build("<style>a > b { color: red }</style>");
    check(&doc);
    let style = doc.find_element("style").expect("style exists");
    assert_eq!(
        first_text(&doc, style).as_deref(),
        Some("a > b { color: red }")
    );
}

#[test]
fn script_without_end_tag_at_eof_still_builds() {
    let doc = build("<p>before</p><script>alert(1)");
    check(&doc);
    let script = doc.find_element("script").expect("script exists");
    assert_eq!(first_text(&doc, script).as_deref(), Some("alert(1)"));
}

#[test]
fn textarea_text_is_entity_decoded() {
    // textarea is RCDATA in HTML5: unlike script/style its text *is*
    // decoded (our tokenizer treats it as an ordinary element).
    let doc = build("<textarea>&lt;tag&gt; &amp; more</textarea>");
    check(&doc);
    let ta = doc.find_element("textarea").expect("textarea exists");
    assert_eq!(first_text(&doc, ta).as_deref(), Some("<tag> & more"));
}

// --- entities and attribute bounds ----------------------------------------

#[test]
fn entities_decode_in_text() {
    let doc = build("<p>&amp;&lt;&#65;&nbsp;x</p>");
    check(&doc);
    let p = doc.find_element("p").expect("p exists");
    assert_eq!(first_text(&doc, p).as_deref(), Some("&<A\u{00A0}x"));
}

#[test]
fn entities_decode_in_attribute_values() {
    let doc = build(r#"<a href="?a=1&amp;b=2&amp;amp;">x</a>"#);
    check(&doc);
    let a = doc.find_element("a").expect("a exists");
    assert_eq!(element(&doc, a).attr("href"), Some("?a=1&b=2&amp;"));
}

#[test]
fn long_attribute_values_are_clamped_at_a_char_boundary() {
    let value = "é".repeat(500); // 1000 bytes
    let src = format!("<p title=\"{value}\">x</p>");
    let doc = build(&src);
    check(&doc);
    let p = doc.find_element("p").expect("p exists");
    let stored = element(&doc, p).attr("title").expect("title stored");
    assert!(stored.len() <= ATTR_VALUE_CAP, "clamped to the cap");
    assert_eq!(
        stored.chars().count(),
        ATTR_VALUE_CAP / 2,
        "clamped on a char boundary: 128 whole é"
    );
}

#[test]
fn attribute_chaos_first_wins_and_decodes() {
    let doc =
        build(r#"<p id=one ID="two" class='c' empty flag unquoted=hello title="a&amp;b">x</p>"#);
    check(&doc);
    let p = doc.find_element("p").expect("p exists");
    let e = element(&doc, p);
    assert_eq!(e.attr("id"), Some("one"), "duplicate keeps the first");
    assert_eq!(e.attr("class"), Some("c"), "single quotes");
    assert_eq!(e.attr("empty"), Some(""), "boolean attribute");
    assert_eq!(e.attr("flag"), Some(""), "bare attribute");
    assert_eq!(e.attr("unquoted"), Some("hello"), "unquoted value");
    assert_eq!(e.attr("title"), Some("a&b"), "decoded value");
    assert_eq!(e.attr("missing"), None);
}

#[test]
fn attribute_storage_is_capped_per_element() {
    let mut src = String::from("<p");
    for i in 0..35 {
        src.push_str(&format!(" a{i}={i}"));
    }
    src.push('>');
    let doc = build(&src);
    check(&doc);
    let p = doc.find_element("p").expect("p exists");
    let e = element(&doc, p);
    assert_eq!(e.attrs.len(), ATTRS_PER_ELEMENT, "stored-attribute cap");
    assert_eq!(e.attr("a0"), Some("0"));
    assert_eq!(e.attr("a7"), Some("7"));
    assert_eq!(e.attr("a8"), None, "ninth attribute dropped");
    assert_eq!(e.attr("a34"), None);
}

// --- encoding --------------------------------------------------------------

#[test]
fn invalid_utf8_becomes_question_marks() {
    let doc = dom::build(b"<p>ok \xFF\xFE bad</p>").expect("bytes build");
    check(&doc);
    let p = doc.find_element("p").expect("p exists");
    assert_eq!(first_text(&doc, p).as_deref(), Some("ok ?? bad"));
}

#[test]
fn partial_utf8_tail_is_one_question_mark() {
    let doc = dom::build(b"<p>\xE2\x82</p>").expect("bytes build");
    check(&doc);
    let p = doc.find_element("p").expect("p exists");
    assert_eq!(first_text(&doc, p).as_deref(), Some("?"));
}

#[test]
fn valid_multibyte_utf8_passes_through() {
    let doc = dom::build("<p>café ☕</p>".as_bytes()).expect("build");
    check(&doc);
    let p = doc.find_element("p").expect("p exists");
    assert_eq!(first_text(&doc, p).as_deref(), Some("café ☕"));
}

#[test]
fn nul_bytes_survive_in_text() {
    let doc = dom::build(b"<p>a\x00b</p>").expect("build");
    check(&doc);
    let p = doc.find_element("p").expect("p exists");
    assert_eq!(first_text(&doc, p).as_deref(), Some("a\u{0}b"));
}

// --- tag-shape rules -------------------------------------------------------

#[test]
fn self_closing_flag_on_non_void_is_ignored() {
    // HTML5: `<div/>` is a parse error — the div stays open.
    let doc = build("<div/>inside");
    check(&doc);
    let div = doc.find_element("div").expect("div exists");
    assert_eq!(first_text(&doc, div).as_deref(), Some("inside"));
}

#[test]
fn void_elements_are_never_pushed() {
    let doc = build("<img src=x><p>after</p><br/>tail");
    check(&doc);
    let img = doc.find_element("img").expect("img exists");
    assert_eq!(child_ids(&doc, img).len(), 0, "img swallowed nothing");
    let p = doc.find_element("p").expect("p exists");
    assert_eq!(
        doc.node(p).and_then(|n| n.parent),
        Some(doc.root()),
        "p is a root sibling of img"
    );
    let tail = doc
        .children(doc.root())
        .find(|(_, n)| matches!(&n.kind, NodeKind::Text(t) if t == "tail"))
        .expect("tail text at root");
    assert_eq!(tail.1.parent, Some(doc.root()), "br did not open");
}

#[test]
fn end_tags_match_case_insensitively() {
    let doc = build("<DIV>x</DIV><div>y</DiV>");
    check(&doc);
    assert_eq!(
        common::element_names(&doc),
        vec!["div".to_string(), "div".to_string()]
    );
    let divs = child_ids(&doc, doc.root());
    assert_eq!(first_text(&doc, divs[0]).as_deref(), Some("x"));
    assert_eq!(first_text(&doc, divs[1]).as_deref(), Some("y"));
}

// --- degenerate documents --------------------------------------------------

#[test]
fn empty_document_is_a_bare_root() {
    let doc = dom::build(b"").expect("empty input builds");
    check(&doc);
    assert_eq!(doc.node_count(), 1);
    assert_eq!(child_ids(&doc, doc.root()).len(), 0);
}

#[test]
fn text_only_document_is_one_text_child() {
    let doc = build("hello world");
    check(&doc);
    let kids = child_ids(&doc, doc.root());
    assert_eq!(kids.len(), 1);
    assert!(
        matches!(&doc.node(kids[0]).expect("child exists").kind, NodeKind::Text(t) if t == "hello world"),
        "the single text node sits directly at the root"
    );
}

#[test]
fn comments_and_doctypes_are_dropped_and_adjacent_text_merges() {
    let doc = build("<!DOCTYPE html><!-- note --><p>x<!-- tail -->y</p>");
    check(&doc);
    assert_eq!(
        common::element_names(&doc),
        vec!["p".to_string()],
        "no comment/doctype nodes anywhere"
    );
    let p = doc.find_element("p").expect("p exists");
    assert_eq!(
        texts(&doc, p),
        vec!["xy".to_string()],
        "text coalesces across the dropped comment"
    );
}
