//! Realistic-page fixtures for the `dom` builder (B2): the actual
//! example.com response body (fetched 2026-11-22, 577 bytes) and an
//! old-school HTML-1.0-style document of the kind `info.cern.ch`
//! still serves (uppercase tags, unclosed `<P>`, newline-split
//! attributes).

mod common;

use common::check;
use dom::{Document, NodeKind};

fn element(doc: &Document, id: usize) -> &dom::Element {
    match &doc.node(id).expect("node must exist").kind {
        NodeKind::Element(e) => e,
        other => panic!("expected an element, got {other:?}"),
    }
}

fn first_text(doc: &Document, id: usize) -> Option<String> {
    doc.children(id).find_map(|(_, n)| match &n.kind {
        NodeKind::Text(t) => Some(t.clone()),
        _ => None,
    })
}

/// The response body of `http://example.com` as B2's smoke fetches it
/// (verbatim — IANA's public example page).
const EXAMPLE_COM: &str = "<!doctype html><html lang=en><head><meta charset=utf-8><link rel=icon href=data:,><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Example Domain</title><style>html{color-scheme:light dark;background:light-dark(#eee,#222)}body{font:16px/1.6 system-ui,sans-serif;max-width:26em;margin:auto;padding:25vh 2em 2em;text-align:center}</style></head><body><p>This domain is for use in documentation examples without needing permission. This is not a service; avoid relying on it for testing and monitoring purposes.</p><script src=/s.js></script></body></html>";

#[test]
fn example_com_builds_the_expected_skeleton() {
    let doc = dom::build(EXAMPLE_COM.as_bytes()).expect("example.com must build");
    check(&doc);

    // Head: title extracted, style raw text stored verbatim.
    assert_eq!(doc.title().as_deref(), Some("Example Domain"));
    let style = doc.find_element("style").expect("style element");
    let style_text = first_text(&doc, style).expect("style content");
    assert!(
        style_text.contains("color-scheme"),
        "raw text: CSS stored as-is"
    );

    // Body: the paragraph carries the fragment B2's viewport readback
    // asserts on.
    let body = doc.find_element("body").expect("body element");
    let paragraphs = doc
        .children(body)
        .filter(|(_, n)| matches!(&n.kind, NodeKind::Element(e) if e.name == "p"))
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    assert_eq!(paragraphs.len(), 1);
    let p_text = first_text(&doc, paragraphs[0]).expect("paragraph text");
    assert!(p_text.contains("documentation examples"));
    assert!(p_text.contains("monitoring purposes"));

    // The script keeps its `src` attribute and empty body.
    let script = doc.find_element("script").expect("script element");
    assert_eq!(element(&doc, script).attr("src"), Some("/s.js"));
    assert_eq!(doc.children(script).count(), 0, "self-closed empty script");

    // Void/head plumbing never leaks into the flow as open elements.
    let head = doc.find_element("head").expect("head element");
    assert!(doc.children(head).any(|(_, n)| matches!(
        &n.kind,
        NodeKind::Element(e) if e.name == "title"
    )));
    assert_eq!(
        doc.find_element("link")
            .map(|id| element(&doc, id).attr("href")),
        Some(Some("data:,"))
    );
}

#[test]
fn old_school_uppercase_dialect_builds() {
    // The HTML-1.0 shape info.cern.ch serves: uppercase tags, implied
    // closes, a `<P>` with no end tag, and an `<A>` tag split across
    // a newline with unquoted attributes.
    let src = "<HEADER>\n<TITLE>The World Wide Web project</TITLE>\n</HEADER>\n<H1>World Wide Web</H1>The WorldWideWeb (W3) is a wide-area<A\nNAME=0 HREF=\"WhatIs.html\">\nhypermedia</A> information retrieval initiative.<P>\nEverything there is online.";
    let doc = dom::build(src.as_bytes()).expect("old dialect must build");
    check(&doc);

    assert_eq!(doc.title().as_deref(), Some("The World Wide Web project"));

    // Lowercased elements, document order.
    assert_eq!(
        common::element_names(&doc),
        vec![
            "header".to_string(),
            "title".to_string(),
            "h1".to_string(),
            "a".to_string(),
            "p".to_string()
        ]
    );

    // The split `<A …>` tag parsed with both attributes.
    let a = doc.find_element("a").expect("a element");
    assert_eq!(element(&doc, a).attr("name"), Some("0"));
    assert_eq!(element(&doc, a).attr("href"), Some("WhatIs.html"));

    // The unclosed `<P>` became a sibling block holding the tail text.
    let p = doc.find_element("p").expect("implied p");
    assert_eq!(
        first_text(&doc, p).as_deref(),
        Some("\nEverything there is online.")
    );
}
