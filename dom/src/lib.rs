//! # dom — HTML tree construction over the `html` tokenizer (browser B2)
//!
//! [`build`] turns a byte slice of HTML into an **arena of nodes**
//! ([`Document`]): element/text nodes linked by parent / first-child /
//! next-sibling indices, no boxing, **no recursion** — a hostile page
//! with 100 000 nested tags cannot blow the kernel's 16 KiB stack,
//! because construction is an explicit-heap state machine bounded by
//! [`DEPTH_CAP`] (64 open elements) and [`NODE_CAP`] (4096 nodes).
//! Both caps are *refused fail-closed* ([`BuildError`]), never
//! silently truncated mid-structure.
//!
//! This crate is dependency-policy **exception (a)** from
//! `docs/browser.md` §4: there is no maintained `no_std` HTML tree
//! builder (html5ever/markup5ever are std, html5gum cannot build
//! `no_std` — in-tree evidence in `html/src/lib.rs`), so tree
//! construction is from scratch over our own tokenizer. It is
//! host-tested adversarially (`tests/hostile.rs`, `tests/realistic.rs`)
//! and cross-built for the kernel through `cargo xtask check`.
//!
//! # Adoption-agency-lite — documented divergences from the spec
//!
//! The WHATWG tree-construction spec (RFC §13.2) is a state machine
//! with an active-formatting-elements list, marker reconstruction and
//! foster parenting. We implement the rendering-relevant subset:
//!
//! 1. **Close-on-mismatch**: an end tag pops every open element above
//!    the matching one (proper nesting is restored, the mismatched
//!    inners are closed implicitly); end tags with no match on the
//!    stack are ignored. No active-formatting list, no reconstruction
//!    of reopened `<b>`-style elements, no adoption-agency loops.
//! 2. **Implied closes** for rendering-relevant structures only:
//!    `<p>` (and every block start) closes an open `<p>` up to a scope
//!    boundary; `<li>`, `<dd>`/`<dt>`, `<td>`/`<th>` and `<tr>` close
//!    the nearest matching open element up to their stop set (so a
//!    nested `<ul>` does **not** close the outer `<li>`).
//! 3. **No foster parenting**: mis-nested table content flows where it
//!    was parsed (layout renders `tr`/`td` as plain block/inline flow —
//!    no grid in B2).
//! 4. **No implied `html`/`head`/`body` insertion** — content attaches
//!    to the root; `head`/`title`/`meta`/`link`/`style`/`script`/
//!    `base`/`template` subtrees are simply skipped by layout, not by
//!    this crate (the tree stays faithful; the kernel decides what to
//!    render).
//! 5. **No `tbody`/`tr`/`td` fixups**: table structure is kept exactly
//!    as authored; only the implied *closes* of item 2 exist.
//! 6. **`self_closing` on a non-void element is ignored** (HTML5's
//!    rule: `<div/>` leaves `div` open); void elements are never
//!    pushed regardless of the flag.
//! 7. `</p>` with no open `<p>` is ignored (HTML5 would insert an
//!    empty `p`).
//!
//! # Raw text, entities, encoding
//!
//! - `script`/`style`: the tokenizer consumes their content as raw
//!   text; we store it **verbatim** (no entity decoding — browsers
//!   don't decode there either). `textarea`/`title` are ordinary
//!   elements in our tokenizer, so their text *is* decoded (HTML5
//!   treats them as RCDATA — the right behaviour).
//! - Text and attribute values run through
//!   [`html::normalize_newlines_into`] + [`html::decode_entities_into`]
//!   into bounded buffers sized from the input (decoded output can
//!   never exceed its input — every reference consumes ≥1 byte and
//!   emits ≤ its consumed bytes; the `None` fallback keeps the raw
//!   bytes rather than failing).
//! - **UTF-8 stance**: bytes that are not valid UTF-8 become `?`
//!   (one `?` per invalid run; an incomplete tail becomes one `?`).
//!   Valid multi-byte sequences pass through untouched — the screen
//!   layer maps glyphs its CP437 font lacks to `?` at draw time.
//! - Attribute storage is capped at [`ATTRS_PER_ELEMENT`] values of
//!   [`ATTR_VALUE_CAP`] bytes each (defense in depth on top of the
//!   caller's body cap; the tokenizer already first-wins-deduplicates
//!   at [`html::ATTR_CAP`] per tag).
//!
//! Comments and doctypes are **dropped** (not rendered, not stored).

#![no_std]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use html::{Token, Tokenizer, decode_entities_into, normalize_newlines_into};

/// Maximum number of nodes (root included) one document may hold.
/// Refused as [`BuildError::NodeCap`] — a hostile page cannot exhaust
/// the heap past this bound (defense in depth over the fetch's
/// `BODY_CAP`/`BODY_SAMPLE` head the kernel feeds in).
pub const NODE_CAP: usize = 4096;
/// Maximum number of **open elements** deep the builder will go.
/// Construction is iterative, but the cap also bounds layout's walk
/// and keeps every depth-proportional structure small; over it the
/// build is refused ([`BuildError::DepthCap`]) — fail-closed, never
/// a truncated tree.
pub const DEPTH_CAP: usize = 64;
/// Maximum number of attributes stored per element (first N in source
/// order; the tokenizer has already dropped duplicates first-wins).
pub const ATTRS_PER_ELEMENT: usize = 8;
/// Maximum stored length of one attribute value (bytes, truncated at a
/// `char` boundary — values are display/selector input, not code).
pub const ATTR_VALUE_CAP: usize = 256;

/// Index into [`Document`]'s node arena. `0` is always the root
/// (document) node.
pub type NodeId = usize;

/// Why a build was refused. Every variant is fail-closed: the caller
/// must treat it as "no tree", never as a partial tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// [`NODE_CAP`] would have been exceeded.
    NodeCap,
    /// [`DEPTH_CAP`] would have been exceeded (≥65 open elements).
    DepthCap,
    /// Internal invariant violation (arena index out of range). A bug,
    /// never input-driven — surfaced loudly instead of panicking.
    Internal,
}

impl BuildError {
    /// A short, allocation-free description for `FATAL:` lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NodeCap => "page exceeds the DOM node cap",
            Self::DepthCap => "page exceeds the DOM depth cap",
            Self::Internal => "internal DOM invariant violation",
        }
    }
}

/// What a node is. The root is [`NodeKind::Document`]; comments and
/// doctypes never become nodes (crate docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    /// The arena's root node (index 0): parent of the top-level flow.
    Document,
    /// An element with its (lowercased) name and stored attributes.
    Element(Element),
    /// Character data, entity-decoded and newline-normalized.
    Text(String),
}

/// One arena node: parent / first-child / next-sibling indices, no
/// boxing, no recursion anywhere in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Parent node (`None` only on the root).
    pub parent: Option<NodeId>,
    /// First child node, if any.
    pub first_child: Option<NodeId>,
    /// Next sibling node, if any.
    pub next_sibling: Option<NodeId>,
    /// What the node holds.
    pub kind: NodeKind,
}

/// An element: name is ASCII-lowercased at build time; attribute
/// names are lowercased too, values keep their case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// Lowercased tag name (`"div"`, `"h1"`, …).
    pub name: String,
    /// Stored attributes, source order, ≤ [`ATTRS_PER_ELEMENT`].
    pub attrs: Vec<Attribute>,
}

impl Element {
    /// The value of the first attribute matching `name`
    /// (ASCII-case-insensitive by construction — names are stored
    /// lowercased), or `None`.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.as_str())
    }
}

/// One stored attribute (decoded value, bounded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Lowercased attribute name.
    pub name: String,
    /// Entity-decoded value, ≤ [`ATTR_VALUE_CAP`] bytes.
    pub value: String,
}

/// A built document: `nodes[0]` is the root; everything else is
/// reachable through child/sibling links (checked by the test
/// invariant walker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    nodes: Vec<Node>,
}

/// Iterator over a node's children (document order).
#[derive(Debug, Clone)]
pub struct Children<'a> {
    doc: &'a Document,
    next: Option<NodeId>,
}

impl<'a> Iterator for Children<'a> {
    type Item = (NodeId, &'a Node);

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.next?;
        let node = self.doc.nodes.get(id)?;
        self.next = node.next_sibling;
        Some((id, node))
    }
}

impl Document {
    /// The root node id (always `0`).
    pub fn root(&self) -> NodeId {
        0
    }

    /// The node at `id`, or `None` when out of range.
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Number of nodes in the arena (≤ [`NODE_CAP`]).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The children of `id`, in document order.
    pub fn children(&self, id: NodeId) -> Children<'_> {
        Children {
            doc: self,
            next: self.nodes.get(id).and_then(|n| n.first_child),
        }
    }

    /// The text of the first `<title>` element (document order,
    /// concatenated text descendants), or `None`. Titles are display
    /// input for the browser's title bar — the value is still wire
    /// data; sanitize before showing it.
    pub fn title(&self) -> Option<String> {
        let title_id = self.find_element("title")?;
        let mut out = String::new();
        let mut work: Vec<NodeId> = vec![title_id];
        // Iterative preorder, children pushed reversed → text in
        // document order. Depth ≤ DEPTH_CAP and nodes ≤ NODE_CAP, so
        // this work stack stays bounded.
        while let Some(id) = work.pop() {
            let Some(node) = self.nodes.get(id) else {
                break; // invariant violation: fail with what we have
            };
            match &node.kind {
                NodeKind::Text(t) => out.push_str(t),
                _ => {
                    let mut cur = node.first_child;
                    let mut kids = Vec::new();
                    while let Some(cid) = cur {
                        kids.push(cid);
                        cur = self.nodes.get(cid).and_then(|n| n.next_sibling);
                    }
                    for kid in kids.into_iter().rev() {
                        work.push(kid);
                    }
                }
            }
        }
        Some(out)
    }

    /// First element (document order) whose lowercased name is
    /// `name`, or `None`. Iterative — never recurses.
    pub fn find_element(&self, name: &str) -> Option<NodeId> {
        let mut work: Vec<NodeId> = vec![0];
        while let Some(id) = work.pop() {
            let node = self.nodes.get(id)?;
            if let NodeKind::Element(e) = &node.kind
                && e.name == name
            {
                return Some(id);
            }
            let mut cur = node.first_child;
            let mut kids = Vec::new();
            while let Some(cid) = cur {
                kids.push(cid);
                cur = self.nodes.get(cid).and_then(|n| n.next_sibling);
            }
            for kid in kids.into_iter().rev() {
                work.push(kid);
            }
        }
        None
    }
}

/// Build a document from `input`. Fail-closed on both caps; comments
/// and doctypes are dropped; an unterminated tag at EOF is dropped by
/// the tokenizer (its own documented rule).
///
/// ```
/// let doc = dom::build(b"<p class=hi>hello &amp; bye").unwrap();
/// assert_eq!(doc.title(), None);
/// ```
pub fn build(input: &[u8]) -> Result<Document, BuildError> {
    let mut builder = Builder::new();
    for token in Tokenizer::new(input) {
        builder.token(token)?;
    }
    Ok(builder.doc)
}

// ---------------------------------------------------------------------------
// The builder — one iterative pass, explicit open-element stack
// ---------------------------------------------------------------------------

/// Element names whose start tag closes an open `<p>` (walk stops at
/// the scope set below). Rendering-relevant subset of HTML5's "special"
/// category — see the crate docs for the divergence.
const BLOCK_STARTS: [&str; 30] = [
    "p",
    "div",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ul",
    "ol",
    "dl",
    "dt",
    "dd",
    "blockquote",
    "pre",
    "hr",
    "form",
    "table",
    "section",
    "article",
    "aside",
    "header",
    "footer",
    "nav",
    "main",
    "figure",
    "figcaption",
    "address",
    "center",
    "fieldset",
];

/// Where the `<p>`-closing walk stops without closing anything
/// (approximation of HTML5's button scope — documented divergence).
const P_SCOPE: [&str; 15] = [
    "html", "body", "table", "caption", "td", "th", "li", "ul", "ol", "dl", "dt", "dd", "template",
    "button", "form",
];

/// HTML5 void elements: never pushed onto the open stack.
const VOID: [&str; 16] = [
    "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "img", "input",
    "keygen", "link", "meta", "param", "source",
];

struct Builder {
    doc: Document,
    /// Open elements, root first. Iterative construction: this stack
    /// is heap-allocated and depth-capped, never the call stack.
    stack: Vec<NodeId>,
    /// `last_child[i]` = arena's last child ever appended to node `i`
    /// (O(1) sibling linking — no per-append child walks).
    last_child: Vec<Option<NodeId>>,
}

impl Builder {
    fn new() -> Self {
        Builder {
            doc: Document {
                nodes: vec![Node {
                    parent: None,
                    first_child: None,
                    next_sibling: None,
                    kind: NodeKind::Document,
                }],
            },
            stack: alloc::vec![0],
            last_child: vec![None],
        }
    }

    fn token(&mut self, token: Token<'_>) -> Result<(), BuildError> {
        match token {
            // Dropped by design (crate docs): never rendered, never
            // stored.
            Token::Doctype(_) | Token::Comment(_) => Ok(()),
            Token::Text(bytes) => self.text(bytes),
            Token::StartTag {
                name,
                attributes,
                // HTML5: the `/` of a non-void start tag is a parse
                // error and the element stays open (divergence 6).
                self_closing: _,
            } => self.start(name, &attributes),
            Token::EndTag { name } => {
                self.end(name);
                Ok(())
            }
        }
    }

    fn start(&mut self, name: &[u8], attributes: &html::Attributes<'_>) -> Result<(), BuildError> {
        let name = lower_name(name);
        // Implied closes first: popping can only *lower* the depth,
        // so the cap check below sees the real post-close depth.
        self.implied_closes(&name);
        // Element depth = stack.len() - 1 (root at 0); pushing makes
        // it stack.len(). Refuse before the push: depth stays ≤
        // DEPTH_CAP for every node in the tree.
        if self.stack.len().saturating_sub(1) >= DEPTH_CAP {
            return Err(BuildError::DepthCap);
        }
        let parent = *self.stack.last().ok_or(BuildError::Internal)?;

        let mut attrs = Vec::new();
        for a in attributes.iter().take(ATTRS_PER_ELEMENT) {
            let aname = lower_name(a.name);
            let mut avalue = decode_text(a.value);
            clamp_char_boundary(&mut avalue, ATTR_VALUE_CAP);
            attrs.push(Attribute {
                name: aname,
                value: avalue,
            });
        }
        let void = VOID.contains(&name.as_str());
        let id = self.push(parent, NodeKind::Element(Element { name, attrs }))?;
        if !void {
            self.stack.push(id);
        }
        Ok(())
    }

    fn end(&mut self, name: &[u8]) {
        let name = lower_name(name);
        // Close-on-mismatch: pop everything down to the match; no
        // match → the end tag is ignored (divergence 1).
        let mut pos = self.stack.len();
        while pos > 1 {
            pos -= 1;
            let Some(&id) = self.stack.get(pos) else {
                break;
            };
            let Some(nm) = name_of(&self.doc, id) else {
                break;
            };
            if nm == name {
                self.stack.truncate(pos);
                return;
            }
        }
    }

    fn text(&mut self, raw: &[u8]) -> Result<(), BuildError> {
        if raw.is_empty() {
            return Ok(());
        }
        let parent = *self.stack.last().ok_or(BuildError::Internal)?;
        // script/style content is stored verbatim (crate docs): no
        // entity decoding, no newline rewriting — it is raw text.
        let raw_text = match self.doc.nodes.get(parent) {
            Some(Node {
                kind: NodeKind::Element(e),
                ..
            }) => e.name == "script" || e.name == "style",
            _ => false,
        };
        let text = if raw_text {
            to_string_lossy(raw)
        } else {
            decode_text(raw)
        };
        if text.is_empty() {
            return Ok(());
        }
        // Coalesce adjacent text (the tokenizer can split one run
        // around a dropped `</>`): merge into the last child when it
        // is text.
        let prev = self.last_child.get(parent).copied().flatten();
        if let Some(prev) = prev
            && let Some(Node {
                kind: NodeKind::Text(existing),
                ..
            }) = self.doc.nodes.get_mut(prev)
        {
            existing.push_str(&text);
            return Ok(());
        }
        self.push(parent, NodeKind::Text(text))?;
        Ok(())
    }

    /// Append one node under `parent`, linking it as the parent's
    /// last child. Refuses at [`NODE_CAP`].
    fn push(&mut self, parent: NodeId, kind: NodeKind) -> Result<NodeId, BuildError> {
        if self.doc.nodes.len() >= NODE_CAP {
            return Err(BuildError::NodeCap);
        }
        let id = self.doc.nodes.len();
        self.doc.nodes.push(Node {
            parent: Some(parent),
            first_child: None,
            next_sibling: None,
            kind,
        });
        self.last_child.push(None);
        // Structural indices only: `parent` came from the open stack
        // and `id` was just created, both < len by construction (the
        // `get_mut` form keeps even a future invariant slip fail-closed
        // rather than indexing).
        match self.last_child.get(parent).copied().flatten() {
            Some(prev) => {
                self.doc
                    .nodes
                    .get_mut(prev)
                    .ok_or(BuildError::Internal)?
                    .next_sibling = Some(id);
            }
            None => {
                self.doc
                    .nodes
                    .get_mut(parent)
                    .ok_or(BuildError::Internal)?
                    .first_child = Some(id);
            }
        }
        *self
            .last_child
            .get_mut(parent)
            .ok_or(BuildError::Internal)? = Some(id);
        Ok(id)
    }

    /// Implied end tags for a start tag (crate docs, divergence 2).
    fn implied_closes(&mut self, name: &str) {
        match name {
            "li" => {
                self.close_p();
                self.close_through(&["li"], &["ul", "ol", "html", "body", "table", "template"]);
            }
            "dd" | "dt" => {
                self.close_p();
                self.close_through(
                    &["dd", "dt"],
                    &["dl", "html", "body", "table", "ul", "ol", "template"],
                );
            }
            "td" | "th" => {
                self.close_p();
                self.close_through(&["td", "th"], &["table", "html", "body", "template"]);
            }
            "tr" => {
                self.close_p();
                self.close_tr();
            }
            n if BLOCK_STARTS.contains(&n) => self.close_p(),
            _ => {}
        }
    }

    /// Close an open `<p>` if the walk from the top of the stack
    /// reaches one before a scope boundary. Pops through the `p`
    /// (everything above it closes too — HTML5's behaviour).
    fn close_p(&mut self) {
        let mut pos = self.stack.len();
        while pos > 1 {
            pos -= 1;
            let Some(&id) = self.stack.get(pos) else {
                break;
            };
            let Some(nm) = name_of(&self.doc, id) else {
                break;
            };
            if nm == "p" {
                self.stack.truncate(pos);
                return;
            }
            if P_SCOPE.contains(&nm) {
                return;
            }
        }
    }

    /// Pop through the nearest element whose name is in `match_names`,
    /// stopping the walk (without closing) at `stop`.
    fn close_through(&mut self, match_names: &[&str], stop: &[&str]) {
        let mut pos = self.stack.len();
        while pos > 1 {
            pos -= 1;
            let Some(&id) = self.stack.get(pos) else {
                break;
            };
            let Some(nm) = name_of(&self.doc, id) else {
                break;
            };
            if match_names.contains(&nm) {
                self.stack.truncate(pos);
                return;
            }
            if stop.contains(&nm) {
                return;
            }
        }
    }

    /// A new `<tr>` closes open cells and the previous row (walking
    /// down), stopping at the table/`html`/`body` boundary.
    fn close_tr(&mut self) {
        loop {
            let decision = {
                let Some(&id) = self.stack.last() else {
                    return;
                };
                match name_of(&self.doc, id) {
                    Some("tr") => Decision::PopAndStop,
                    Some("table") | Some("html") | Some("body") | Some("template") => {
                        Decision::Stop
                    }
                    Some(_) => Decision::Pop,
                    None => Decision::Stop,
                }
            };
            match decision {
                Decision::Pop => {
                    self.stack.pop();
                }
                Decision::PopAndStop => {
                    self.stack.pop();
                    return;
                }
                Decision::Stop => return,
            }
        }
    }
}

enum Decision {
    Pop,
    PopAndStop,
    Stop,
}

/// The element name at `id`, or `None` for non-elements (only the
/// root can be one, and the root never sits above position 0).
fn name_of(doc: &Document, id: NodeId) -> Option<&str> {
    match &doc.nodes.get(id)?.kind {
        NodeKind::Element(e) => Some(e.name.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Byte → text helpers (bounded, fail-closed, no panics on wire data)
// ---------------------------------------------------------------------------

/// ASCII-lowercase a name into a `String` (UTF-8-invalid bytes → `?`).
fn lower_name(raw: &[u8]) -> String {
    let lowered: Vec<u8> = raw.iter().map(|&b| b.to_ascii_lowercase()).collect();
    to_string_lossy(&lowered)
}

/// Newline-normalize + entity-decode `raw` into buffers sized exactly
/// from the input (both outputs are ≤ their input — see crate docs),
/// then validate UTF-8 lossily. Never panics; a decoder refusal falls
/// back to the normalized-but-undecoded bytes.
fn decode_text(raw: &[u8]) -> String {
    if !raw.contains(&b'\r') && !raw.contains(&b'&') {
        return to_string_lossy(raw);
    }
    let mut normalized = alloc::vec![0u8; raw.len()];
    let n = normalize_newlines_into(raw, &mut normalized).unwrap_or(raw.len());
    normalized.truncate(n);
    if !normalized.contains(&b'&') {
        return to_string_lossy(&normalized);
    }
    let mut decoded = alloc::vec![0u8; normalized.len()];
    match decode_entities_into(&normalized, &mut decoded) {
        Some(n) => {
            decoded.truncate(n);
            to_string_lossy(&decoded)
        }
        // Unreachable for input-sized buffers (decode output ≤ input);
        // fail-closed to the undecoded bytes rather than dropping text.
        None => to_string_lossy(&normalized),
    }
}

/// Bytes → `String`: valid UTF-8 passes through, each invalid run
/// becomes one `?`, an incomplete tail becomes one `?` (crate docs).
fn to_string_lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match core::str::from_utf8(&bytes[i..]) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(e) => {
                let good = e.valid_up_to();
                if good > 0
                    && let Ok(valid) = core::str::from_utf8(&bytes[i..i + good])
                {
                    out.push_str(valid);
                }
                i += good;
                out.push('?');
                match e.error_len() {
                    Some(len) => i += len,
                    None => break, // truncated tail: one `?` total
                }
            }
        }
    }
    out
}

/// Truncate to at most `cap` bytes, never splitting a UTF-8 scalar
/// (`String::truncate` would panic — wire data must not).
fn clamp_char_boundary(s: &mut String, cap: usize) {
    if s.len() <= cap {
        return;
    }
    let mut n = cap;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s.truncate(n);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_walks_nested_text() {
        let doc = build(b"<html><head><title>A &amp; B</title></head></html>").unwrap();
        assert_eq!(doc.title().as_deref(), Some("A & B"));
    }

    #[test]
    fn no_title_is_none() {
        let doc = build(b"<p>hi</p>").unwrap();
        assert_eq!(doc.title(), None);
    }

    #[test]
    fn clamp_never_splits_a_scalar() {
        let mut s = String::from("ééé"); // 6 bytes, boundaries at 0,2,4,6
        clamp_char_boundary(&mut s, 5);
        assert_eq!(s, "éé"); // 4 bytes: boundary ≤ 5
    }
}
