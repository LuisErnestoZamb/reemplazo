//! # csscore — the deterministic CSS subset of the text-mode browser (B3)
//!
//! Parses a stylesheet into rules (`selector-list { declarations }`),
//! matches selectors against an arena tree through the [`Tree`] trait,
//! and resolves the cascade with real specificity (`id` > `class` >
//! `type`) plus source order — docs/browser.md §5: "Specificity +
//! source order implemented properly (it is ~30 lines and prevents a
//! class of wrong renders)".
//!
//! This crate is dependency-policy **exception (a)** from
//! docs/browser.md §5: the usable standalone servo pieces are
//! std-leaning internals (`cssparser` tokenizes only; the cascade and
//! the style tree live in `style`, which is not a standalone std-free
//! dependency), and the v1 property set is a few hundred lines. It is
//! `#![no_std]` + `alloc`, **zero dependencies**, `forbid(unsafe_code)`
//! and adversarially host-tested (`tests/`).
//!
//! # Supported selectors (B3)
//!
//! - type (`p`), class (`.note`), id (`#lead`), universal (`*`),
//!   compound (`div.note#lead`), descendant (`a b`, any depth up to
//!   [`COMPOUNDS_PER_SELECTOR`]), comma lists (`h1, h2`).
//! - **Dropped, not fatal**: child (`>`), sibling (`+`, `~`), attribute
//!   (`[href]`) and pseudo (`:hover`, `::before`) selectors. A dropped
//!   selector never kills its rule list: the other selectors of the
//!   comma list still match (fail-soft, per paragraph).
//! - Classes and ids are **case-sensitive** (CSS); tag names and
//!   property names/values are ASCII-case-insensitive.
//!
//! # Supported properties (B3)
//!
//! `display` (`none`/`block`/`inline`; `inline-block` → inline),
//! `color`, `background-color`, `font-weight` (`normal`/`bold`/100–900),
//! `font-style` (`normal`/`italic`/`oblique`), `text-decoration`
//! (`none`/`underline`), `list-style-type` (`disc`/`circle`/`square`,
//! `dash`, `none`), `width`/`height`, `margin`/`padding` (+ the four
//! longhands each, 1–4 value shorthand).
//!
//! Lengths are **integers**: `px` (converted to cells at
//! [`PX_PER_CELL`]; 8 px = 1 cell, rounded up), bare numbers (cells)
//! and `%` (accepted for `width` only, resolved by the caller at
//! layout time through [`Length::to_cells`]). Floats, `em`, `vh`, … are
//! unsupported: the declaration is **ignored**, the rule survives
//! (fail-soft per property — a hostile page can never poison a rule).
//!
//! # Colors → VGA attributes
//!
//! CSS colors (names, `#rgb`, `#rrggbb`, `rgb(r,g,b)`) map to one of the
//! 16 VGA text attribute indices by **nearest RGB distance** over
//! [`PALETTE`] — the same ANSI-style index table the tree already uses
//! (`apps/tui.rs`): 1 = red, 2 = green, 3 = yellow/olive, 4 = blue,
//! 6 = cyan, 7 = grey, 9–15 the bright half. Notes, documented honestly:
//!
//! - Ties resolve to the **brighter** candidate (the higher index), so
//!   `#ff00ff` maps to 13 (light magenta), not 5.
//! - `yellow` (#ffff00) maps to 11 (light yellow) because the dark
//!   yellow slot (3) is olive-brown in that table; `red` → 1,
//!   `green` → 2, `cyan` → 14, `white` → 15 (asserted in the tests and
//!   used by the kernel's `BROWSER_CSS_OK` fixture).
//! - `transparent` has no alpha in a VGA cell: the declaration is
//!   ignored (no background painted).
//! - **Italic → dim, underline → no-op**: text mode has no italic or
//!   per-cell underline (`apps/tui.rs` drops those modifiers). The
//!   kernel maps `font-style: italic` to the dark half of the palette
//!   (`fg & 0x07`, or index 8 when no color is set) and parses
//!   `text-decoration: underline` without drawing it.
//! - **`background-color` inherits down the subtree** (a divergence
//!   from CSS): the layout paints no block box, only the glyph cells it
//!   already emits, so inheritance is what makes `.note { background:
//!   … }` visibly fill the note's text.
//!
//! # What is out of scope (documented divergences)
//!
//! - No `@media` queries, no external stylesheets (`<link
//!   rel=stylesheet>` fetching is not B3), no fonts: at-rules are
//!   **skipped whole** (prelude + block, brace-matched), so a hostile
//!   `@import` cannot derail the rules after it.
//! - No `background`/`font`/`border`/`flex`/`grid` shorthands, no
//!   `!important`-adjacent `@layer`/`@supports` cascade layers.
//! - `!important` **is** implemented: the cascade key is
//!   `(important, inline, id, class, type, rule order, declaration
//!   index)`, so sheet-important beats inline-normal and
//!   inline-important beats everything.
//! - Comments are stripped naively (`/* … */` → one space, no string
//!   awareness — no supported value contains `/*`); an unterminated
//!   comment drops the rest of the sheet.
//! - Only the first [`INPUT_CAP`] bytes are parsed; at most
//!   [`RULE_CAP`] rules, [`SELECTORS_PER_RULE`] selectors per rule,
//!   [`COMPOUNDS_PER_SELECTOR`] compounds per selector,
//!   [`CLASSES_PER_COMPOUND`] classes per compound,
//!   [`DECLS_PER_RULE`] declarations per rule. Excess is dropped
//!   deterministically — never a panic, never a truncated mid-UTF-8
//!   slice.
//! - A rule truncated at end-of-input keeps the declarations parsed up
//!   to that point (fail-soft, tested).
//!
//! # Tree access
//!
//! The crate knows nothing about `dom` (zero dependencies): callers
//! implement [`Tree`] — [`Tree::parent_element`] and
//! [`Tree::element`] — and [`compute`] returns a [`Computed`] style for
//! one element node. The kernel's adapter lives in
//! `kernel/src/apps/browser.rs`; the host tests use a tiny arena.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Bytes of a stylesheet this crate will parse (the kernel already
/// bounds the `<style>` text it collects; this is defense in depth).
pub const INPUT_CAP: usize = 64 * 1024;
/// Maximum rules kept per stylesheet.
pub const RULE_CAP: usize = 256;
/// Maximum selectors in one rule's comma list.
pub const SELECTORS_PER_RULE: usize = 8;
/// Maximum compounds (descendant steps) in one complex selector.
pub const COMPOUNDS_PER_SELECTOR: usize = 8;
/// Maximum class tokens on one compound selector.
pub const CLASSES_PER_COMPOUND: usize = 8;
/// Maximum declarations kept per rule (shorthands expand to four).
pub const DECLS_PER_RULE: usize = 64;
/// Maximum selector-name length (tag, class or id), in bytes.
pub const NAME_CAP: usize = 32;
/// Maximum declaration value length, in bytes. Longer values drop the
/// declaration (never the rule).
pub const VALUE_CAP: usize = 64;
/// Length of one 80-column text cell in CSS pixels (640 px / 80 cols).
pub const PX_PER_CELL: usize = 8;

/// The ANSI-style 16-color table the rest of the tree encodes
/// (`kernel/src/apps/tui.rs`): the RGB values behind attribute indices
/// 0..16. Duplicated here because `csscore` has zero dependencies and
/// is host-tested; the kernel fixture readback (`BROWSER_CSS_OK`)
/// cross-checks the end-to-end mapping.
pub const PALETTE: [(u8, u8, u8); 16] = [
    (0x00, 0x00, 0x00),
    (0xAA, 0x00, 0x00),
    (0x00, 0xAA, 0x00),
    (0xAA, 0x55, 0x00),
    (0x00, 0x00, 0xAA),
    (0xAA, 0x00, 0xAA),
    (0x00, 0xAA, 0xAA),
    (0xAA, 0xAA, 0xAA),
    (0x55, 0x55, 0x55),
    (0xFF, 0x55, 0x55),
    (0x55, 0xFF, 0x55),
    (0xFF, 0xFF, 0x55),
    (0x55, 0x55, 0xFF),
    (0xFF, 0x55, 0xFF),
    (0x55, 0xFF, 0xFF),
    (0xFF, 0xFF, 0xFF),
];

/// `display` values of the subset (`inline-block` folds to inline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Display {
    /// Forces a block boundary.
    Block,
    /// Flows with the surrounding text.
    Inline,
    /// No box, no subtree: layout must skip the element entirely.
    None,
}

/// `font-weight` of the subset (numeric weights fold to two buckets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontWeight {
    /// `normal` / 100–500 / unsupported keywords.
    Normal,
    /// `bold` / 600–900.
    Bold,
}

/// `font-style` of the subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontStyle {
    /// Upright.
    Normal,
    /// `italic` / `oblique` (rendered dim — VGA has no italics).
    Italic,
}

/// `text-decoration` of the subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoration {
    /// Explicitly none.
    None,
    /// Parsed but not drawn: VGA text cells have no underline bit
    /// (documented no-op; the kernel keeps it for a future GUI).
    Underline,
}

/// `list-style-type` of the subset: the marker the layout draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListStyle {
    /// `* ` (also `circle`/`square`, the only glyphs text mode has).
    Disc,
    /// `- `.
    Dash,
    /// No marker at all.
    None,
}

/// A resolved length: cells directly or a percentage of a basis the
/// layout hands in (only `width` accepts `%`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Length {
    /// Whole text cells.
    Cells(u16),
    /// Percent of the basis (saturating, integer math).
    Percent(u16),
}

impl Length {
    /// Resolve to cells against `basis` (the layout's content width).
    /// Percent is integer math with saturating multiplies — wire data
    /// cannot overflow the renderer.
    pub fn to_cells(self, basis: usize) -> usize {
        match self {
            Self::Cells(cells) => usize::from(cells),
            Self::Percent(pct) => basis.saturating_mul(usize::from(pct)) / 100,
        }
    }
}

/// The four box edges, in text cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Edges {
    /// Top offset, in cells (rendered as blank lines).
    pub top: u16,
    /// Right offset, in cells (parsed; not applied by the B3 flow).
    pub right: u16,
    /// Bottom offset, in cells (parsed; not applied by the B3 flow).
    pub bottom: u16,
    /// Left offset, in cells (adds to the block indent).
    pub left: u16,
}

/// The computed style of one element — `None` fields mean "not
/// specified" (the kernel's walk then inherits or falls back to the
/// HTML default; `csscore` itself never inherits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Computed {
    /// `display` when specified.
    pub display: Option<Display>,
    /// Foreground VGA attribute index (0..16).
    pub color: Option<u8>,
    /// Background VGA attribute index (0..16).
    pub background: Option<u8>,
    /// `font-weight` when specified.
    pub font_weight: Option<FontWeight>,
    /// `font-style` when specified.
    pub font_style: Option<FontStyle>,
    /// `text-decoration` when specified.
    pub decoration: Option<Decoration>,
    /// `list-style-type` when specified.
    pub list_style: Option<ListStyle>,
    /// `width` when specified.
    pub width: Option<Length>,
    /// `height` when specified (parsed; the B3 flow lays text out, so
    /// it is not applied — documented).
    pub height: Option<Length>,
    /// Resolved `margin`.
    pub margin: Edges,
    /// Resolved `padding`.
    pub padding: Edges,
}

impl Computed {
    /// True when nothing was specified (the unstyled fast path — the
    /// kernel keeps B2's byte-identical rendering when this holds for
    /// every element).
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// One longhand property of the subset. Shorthands are expanded into
/// these at parse time, so a [`Declaration`] always names one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Property {
    /// `display`.
    Display,
    /// `color`.
    Color,
    /// `background-color`.
    BackgroundColor,
    /// `font-weight`.
    FontWeight,
    /// `font-style`.
    FontStyle,
    /// `text-decoration` / `text-decoration-line`.
    TextDecoration,
    /// `list-style-type`.
    ListStyleType,
    /// `width`.
    Width,
    /// `height`.
    Height,
    /// `margin-top`.
    MarginTop,
    /// `margin-right`.
    MarginRight,
    /// `margin-bottom`.
    MarginBottom,
    /// `margin-left`.
    MarginLeft,
    /// `padding-top`.
    PaddingTop,
    /// `padding-right`.
    PaddingRight,
    /// `padding-bottom`.
    PaddingBottom,
    /// `padding-left`.
    PaddingLeft,
}

impl Property {
    /// The CSS name of the longhand (used by tests and diagnostics).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Display => "display",
            Self::Color => "color",
            Self::BackgroundColor => "background-color",
            Self::FontWeight => "font-weight",
            Self::FontStyle => "font-style",
            Self::TextDecoration => "text-decoration",
            Self::ListStyleType => "list-style-type",
            Self::Width => "width",
            Self::Height => "height",
            Self::MarginTop => "margin-top",
            Self::MarginRight => "margin-right",
            Self::MarginBottom => "margin-bottom",
            Self::MarginLeft => "margin-left",
            Self::PaddingTop => "padding-top",
            Self::PaddingRight => "padding-right",
            Self::PaddingBottom => "padding-bottom",
            Self::PaddingLeft => "padding-left",
        }
    }

    /// Cascade slot index (one winner per longhand).
    fn slot(self) -> usize {
        self as usize
    }
}

/// Every longhand, in slot order — the cascade's assembly walk.
const ALL_PROPERTIES: [Property; 17] = [
    Property::Display,
    Property::Color,
    Property::BackgroundColor,
    Property::FontWeight,
    Property::FontStyle,
    Property::TextDecoration,
    Property::ListStyleType,
    Property::Width,
    Property::Height,
    Property::MarginTop,
    Property::MarginRight,
    Property::MarginBottom,
    Property::MarginLeft,
    Property::PaddingTop,
    Property::PaddingRight,
    Property::PaddingBottom,
    Property::PaddingLeft,
];

/// Cascade slots: one per longhand (the enum's discriminants).
const SLOTS: usize = ALL_PROPERTIES.len();

/// A typed declaration value (the property says how to read it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// `display`.
    Display(Display),
    /// `color` / `background-color` (VGA index).
    Color(u8),
    /// `font-weight`.
    FontWeight(FontWeight),
    /// `font-style`.
    FontStyle(FontStyle),
    /// `text-decoration`.
    Decoration(Decoration),
    /// `list-style-type`.
    ListStyle(ListStyle),
    /// `width` / `height` / the four sides of `margin`/`padding`.
    Length(Length),
}

/// One parsed declaration (`!important` included in the cascade key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declaration {
    /// Which longhand.
    pub property: Property,
    /// Its parsed value.
    pub value: Value,
    /// Whether it carried `!important`.
    pub important: bool,
}

/// One compound selector (`div.note#lead`); all its parts must match
/// the same element.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Compound {
    tag: Option<String>,
    id: Option<String>,
    classes: Vec<String>,
}

impl Compound {
    fn new() -> Self {
        Compound {
            tag: None,
            id: None,
            classes: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.tag.is_none() && self.id.is_none() && self.classes.is_empty()
    }

    fn matches(&self, el: &ElementRef<'_>) -> bool {
        if let Some(tag) = &self.tag
            && !tag.eq_ignore_ascii_case(el.name)
        {
            return false;
        }
        if let Some(id) = &self.id
            && el.id != Some(id.as_str())
        {
            return false;
        }
        for class in &self.classes {
            if !class_list_contains(el.class, class) {
                return false;
            }
        }
        true
    }
}

/// A complex selector: compounds joined by the descendant combinator,
/// **ancestor first** (`.outer span` = [`outer`, `span`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    compounds: Vec<Compound>,
}

impl Selector {
    /// Specificity as `(id, class, type)` counts, summed over every
    /// compound (asterisks contribute nothing).
    pub fn specificity(&self) -> (u16, u16, u16) {
        let mut ids = 0u16;
        let mut classes = 0u16;
        let mut types = 0u16;
        for compound in &self.compounds {
            if compound.id.is_some() {
                ids = ids.saturating_add(1);
            }
            classes = classes.saturating_add(compound.classes.len() as u16);
            if compound.tag.is_some() {
                types = types.saturating_add(1);
            }
        }
        (ids, classes, types)
    }

    /// Number of compounds (descendant steps), 1 for a simple selector.
    pub fn depth(&self) -> usize {
        self.compounds.len()
    }

    /// Does this selector match the element at `node`?
    pub fn matches(&self, tree: &impl Tree, node: usize) -> bool {
        let Some(last) = self.compounds.last() else {
            return false;
        };
        let Some(el) = tree.element(node) else {
            return false;
        };
        if !last.matches(&el) {
            return false;
        }
        // Walk ancestors for each remaining compound, right to left
        // (descendant combinator: any ancestor that matches counts).
        let mut cur = tree.parent_element(node);
        for compound in self.compounds.iter().rev().skip(1) {
            let mut found = false;
            while let Some(ancestor) = cur {
                let next = tree.parent_element(ancestor);
                if let Some(el) = tree.element(ancestor)
                    && compound.matches(&el)
                {
                    found = true;
                    break;
                }
                cur = next;
            }
            if !found {
                return false;
            }
        }
        true
    }
}

/// One rule: a selector list plus its declarations, in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    selectors: Vec<Selector>,
    declarations: Vec<Declaration>,
    order: u32,
}

impl Rule {
    /// The rule's selector list (empty selectors already dropped).
    pub fn selectors(&self) -> &[Selector] {
        &self.selectors
    }

    /// The rule's declarations (unknown properties already dropped).
    pub fn declarations(&self) -> &[Declaration] {
        &self.declarations
    }

    /// Source order among the stylesheet's kept rules (0-based).
    pub fn order(&self) -> u32 {
        self.order
    }

    /// The highest specificity among this rule's selectors that match
    /// `node`, or `None` when the rule does not apply.
    fn matching_specificity(&self, tree: &impl Tree, node: usize) -> Option<(u16, u16, u16)> {
        let mut best: Option<(u16, u16, u16)> = None;
        for selector in &self.selectors {
            if selector.matches(tree, node) {
                let spec = selector.specificity();
                if best.is_none_or(|b| spec > b) {
                    best = Some(spec);
                }
            }
        }
        best
    }
}

/// A parsed stylesheet: the rules plus nothing else (no media queries,
/// no external sheets — crate docs).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Stylesheet {
    rules: Vec<Rule>,
}

impl Stylesheet {
    /// Parse `input` (truncated to [`INPUT_CAP`] at a char boundary;
    /// comments stripped; at-rules skipped whole). Never panics.
    pub fn parse(input: &str) -> Self {
        let clamped = clamp_str(input, INPUT_CAP);
        let stripped = strip_comments(clamped.as_bytes());
        let mut parser = Parser {
            s: &stripped,
            i: 0,
            rules: Vec::new(),
            order: 0,
        };
        parser.run();
        Stylesheet {
            rules: parser.rules,
        }
    }

    /// The kept rules, in source order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Number of kept rules (a rule with zero *applicable* declarations
    /// is still kept: it proves the sheet parsed — see the B3 proof).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// True when the sheet has no rules at all.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Element view handed to the cascade: only what selectors need.
#[derive(Debug, Clone, Copy)]
pub struct ElementRef<'a> {
    /// Lowercased tag name.
    pub name: &'a str,
    /// `id` attribute, if present.
    pub id: Option<&'a str>,
    /// `class` attribute (whitespace-separated tokens), if present.
    pub class: Option<&'a str>,
    /// `style` attribute (inline declarations), if present.
    pub style: Option<&'a str>,
}

/// The tree the cascade walks — implemented by the kernel over `dom`,
/// and by the host tests over a tiny arena. `node` is an opaque index
/// chosen by the caller; `compute` only passes it back.
pub trait Tree {
    /// The parent **element** of `node` (text/document nodes are
    /// skipped by the implementation), or `None` at the root.
    fn parent_element(&self, node: usize) -> Option<usize>;
    /// The element at `node`, or `None` for non-elements.
    fn element(&self, node: usize) -> Option<ElementRef<'_>>;
}

/// Compute the cascade winner for every property on `node`: sheet rules
/// (specificity, source order) plus the inline `style` attribute.
pub fn compute(tree: &impl Tree, node: usize, sheet: &Stylesheet) -> Computed {
    let Some(el) = tree.element(node) else {
        return Computed::default();
    };
    let mut winners: [Option<(Rank, Value)>; SLOTS] = [None; SLOTS];
    for rule in &sheet.rules {
        let Some(spec) = rule.matching_specificity(tree, node) else {
            continue;
        };
        for (index, declaration) in rule.declarations.iter().enumerate() {
            let rank = Rank {
                important: declaration.important,
                inline: false,
                ids: spec.0,
                classes: spec.1,
                types: spec.2,
                order: rule.order,
                declaration: saturate_u16(index),
            };
            apply(&mut winners, *declaration, rank);
        }
    }
    if let Some(style) = el.style {
        for (index, declaration) in parse_declarations(style).iter().enumerate() {
            let rank = Rank {
                important: declaration.important,
                inline: true,
                ids: 0,
                classes: 0,
                types: 0,
                order: u32::MAX,
                declaration: saturate_u16(index),
            };
            apply(&mut winners, *declaration, rank);
        }
    }
    assemble(&winners)
}

/// The cascade key, most-significant first. Deriving `Ord` over the
/// field order *is* the CSS precedence rule: importance, then inline,
/// then specificity (id, class, type), then source order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    important: bool,
    inline: bool,
    ids: u16,
    classes: u16,
    types: u16,
    order: u32,
    declaration: u16,
}

/// Keep the value whose rank is highest for its property's slot.
fn apply(winners: &mut [Option<(Rank, Value)>; SLOTS], declaration: Declaration, rank: Rank) {
    let Some(slot) = winners.get_mut(declaration.property.slot()) else {
        return;
    };
    match slot {
        Some((current, _)) if *current >= rank => {}
        _ => *slot = Some((rank, declaration.value)),
    }
}

/// Turn the per-slot winners into a [`Computed`]. Slot/value pairs are
/// produced by the parser and are always consistent; a mismatch (a bug)
/// is ignored rather than panicking.
fn assemble(winners: &[Option<(Rank, Value)>; SLOTS]) -> Computed {
    let mut computed = Computed::default();
    for property in ALL_PROPERTIES {
        let Some(Some((_, value))) = winners.get(property.slot()) else {
            continue;
        };
        match (property, value) {
            (Property::Display, Value::Display(v)) => computed.display = Some(*v),
            (Property::Color, Value::Color(v)) => computed.color = Some(*v),
            (Property::BackgroundColor, Value::Color(v)) => computed.background = Some(*v),
            (Property::FontWeight, Value::FontWeight(v)) => computed.font_weight = Some(*v),
            (Property::FontStyle, Value::FontStyle(v)) => computed.font_style = Some(*v),
            (Property::TextDecoration, Value::Decoration(v)) => computed.decoration = Some(*v),
            (Property::ListStyleType, Value::ListStyle(v)) => computed.list_style = Some(*v),
            (Property::Width, Value::Length(v)) => computed.width = Some(*v),
            (Property::Height, Value::Length(v)) => computed.height = Some(*v),
            (Property::MarginTop, Value::Length(Length::Cells(c))) => computed.margin.top = *c,
            (Property::MarginRight, Value::Length(Length::Cells(c))) => computed.margin.right = *c,
            (Property::MarginBottom, Value::Length(Length::Cells(c))) => {
                computed.margin.bottom = *c
            }
            (Property::MarginLeft, Value::Length(Length::Cells(c))) => computed.margin.left = *c,
            (Property::PaddingTop, Value::Length(Length::Cells(c))) => computed.padding.top = *c,
            (Property::PaddingRight, Value::Length(Length::Cells(c))) => {
                computed.padding.right = *c
            }
            (Property::PaddingBottom, Value::Length(Length::Cells(c))) => {
                computed.padding.bottom = *c
            }
            (Property::PaddingLeft, Value::Length(Length::Cells(c))) => computed.padding.left = *c,
            _ => {}
        }
    }
    computed
}

/// Parse a standalone declaration list (an inline `style=""` value).
/// Same grammar and caps as a rule body, without the braces: unknown
/// properties are dropped, malformed declarations are skipped.
pub fn parse_declarations(input: &str) -> Vec<Declaration> {
    let clamped = clamp_str(input, INPUT_CAP);
    let stripped = strip_comments(clamped.as_bytes());
    let mut out = Vec::new();
    for raw in split_declarations(&stripped) {
        parse_declaration(raw, &mut out);
        if out.len() >= DECLS_PER_RULE {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    rules: Vec<Rule>,
    order: u32,
}

impl Parser<'_> {
    fn run(&mut self) {
        loop {
            self.skip_trivia();
            let Some(&b) = self.s.get(self.i) else {
                break;
            };
            match b {
                b'@' => self.skip_at_rule(),
                // Stray close brace / semicolon at top level: junk
                // between rules, skip one byte and keep going.
                b'}' | b';' => self.i += 1,
                _ => {
                    let Some(selectors) = self.parse_selector_list() else {
                        break; // no `{` before EOF
                    };
                    // `parse_selector_list` leaves `i` on `{` (or EOF).
                    let Some(&b'{') = self.s.get(self.i) else {
                        break;
                    };
                    self.i += 1;
                    let declarations = self.parse_block();
                    if selectors.is_empty() {
                        continue; // unusable selector list: drop the rule
                    }
                    if self.rules.len() >= RULE_CAP {
                        continue;
                    }
                    self.rules.push(Rule {
                        selectors,
                        declarations,
                        order: self.order,
                    });
                    self.order = self.order.saturating_add(1);
                }
            }
        }
    }

    /// Skip whitespace (comments were stripped up front).
    fn skip_trivia(&mut self) {
        while let Some(&b) = self.s.get(self.i) {
            if b.is_ascii_whitespace() {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    /// Skip an at-rule: `@ident` + prelude up to `;` (statement form) or
    /// a brace-matched block (group form). Unterminated → rest of sheet.
    fn skip_at_rule(&mut self) {
        let mut depth = 0usize;
        while let Some(&b) = self.s.get(self.i) {
            self.i += 1;
            match b {
                b'{' => depth = depth.saturating_add(1),
                b'}' => {
                    if depth == 0 {
                        return; // stray close ends the at-rule
                    }
                    depth -= 1;
                    if depth == 0 {
                        return; // block form finished
                    }
                }
                b';' if depth == 0 => return,
                _ => {}
            }
        }
    }

    /// Scan the selector list up to its `{`, split on commas and parse
    /// each part. `None` when EOF arrives before any `{`.
    fn parse_selector_list(&mut self) -> Option<Vec<Selector>> {
        let start = self.i;
        let mut end = None;
        let mut parens = 0usize;
        let mut j = self.i;
        while let Some(&b) = self.s.get(j) {
            match b {
                b'(' => parens = parens.saturating_add(1),
                b')' => parens = parens.saturating_sub(1),
                b'{' if parens == 0 => {
                    end = Some(j);
                    break;
                }
                // A close brace or semicolon before any `{` means the
                // "selector" was junk (e.g. a lost declaration): drop it
                // without consuming a rule body.
                b'}' | b';' if parens == 0 => {
                    self.i = j.saturating_add(1);
                    return Some(Vec::new());
                }
                _ => {}
            }
            j += 1;
        }
        let end = end?;
        let text = self.s.get(start..end)?;
        self.i = end;
        let mut selectors = Vec::new();
        for part in split_top_level_commas(text) {
            if selectors.len() >= SELECTORS_PER_RULE {
                break;
            }
            if let Some(selector) = parse_selector(part) {
                selectors.push(selector);
            }
        }
        Some(selectors)
    }

    /// Parse a rule body starting after `{`, up to its matching `}` (or
    /// EOF). Nested blocks are skipped whole (documented).
    fn parse_block(&mut self) -> Vec<Declaration> {
        let mut out = Vec::new();
        let mut buf = Vec::new();
        let mut overflow = false;
        let mut depth = 0usize;
        while let Some(&b) = self.s.get(self.i) {
            self.i += 1;
            match b {
                b'{' => {
                    depth = depth.saturating_add(1);
                    if depth == 1 {
                        // A nested block inside a declaration: ignore
                        // it and whatever it contained.
                        buf.clear();
                        overflow = false;
                    }
                }
                b'}' => {
                    if depth == 0 {
                        break; // end of the rule
                    }
                    depth -= 1;
                }
                b';' if depth == 0 => {
                    if !overflow {
                        parse_declaration(&buf, &mut out);
                        if out.len() >= DECLS_PER_RULE {
                            // Keep scanning to the closing brace so the
                            // sheet's structure stays intact.
                            buf.clear();
                            overflow = true;
                            continue;
                        }
                    }
                    buf.clear();
                    overflow = false;
                }
                _ if depth == 0 => {
                    if buf.len() < VALUE_CAP * 4 {
                        buf.push(b);
                    } else {
                        // Too long for any supported value: drop this
                        // declaration only.
                        overflow = true;
                    }
                }
                _ => {}
            }
        }
        if depth == 0 && !overflow {
            parse_declaration(&buf, &mut out);
        }
        out
    }
}

/// Split a declaration block on top-level `;` (parentheses group, so
/// `rgb(1,2,3)` never splits). Last fragment may lack a `;`.
fn split_declarations(input: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut parens = 0usize;
    for (i, &b) in input.iter().enumerate() {
        match b {
            b'(' => parens = parens.saturating_add(1),
            b')' => parens = parens.saturating_sub(1),
            b';' if parens == 0 => {
                if let Some(part) = input.get(start..i) {
                    out.push(part);
                }
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    if let Some(part) = input.get(start..) {
        out.push(part);
    }
    out
}

/// Split a selector list on commas that are not inside parentheses.
fn split_top_level_commas(input: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut parens = 0usize;
    for (i, &b) in input.iter().enumerate() {
        match b {
            b'(' => parens = parens.saturating_add(1),
            b')' => parens = parens.saturating_sub(1),
            b',' if parens == 0 => {
                if let Some(part) = input.get(start..i) {
                    out.push(part);
                }
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    if let Some(part) = input.get(start..) {
        out.push(part);
    }
    out
}

/// Parse one complex selector. Unsupported syntax (combinators other
/// than descendant, pseudo-classes, attribute selectors, non-ASCII
/// names, empty compounds) refuses the whole selector — never the sheet.
fn parse_selector(input: &[u8]) -> Option<Selector> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Tag,
        Class,
        Id,
    }

    let mut compounds: Vec<Compound> = Vec::new();
    let mut compound = Compound::new();
    let mut mode = Mode::Tag;
    let mut name = String::new();
    // A bare `*` produces an empty compound that still matches every
    // element, so it needs its own flag (`Compound::is_empty` is true).
    let mut universal = false;

    // Flush the pending simple selector into `compound`.
    let flush = |mode: Mode, name: &mut String, compound: &mut Compound| -> Option<()> {
        if name.is_empty() {
            return Some(());
        }
        if name.len() > NAME_CAP {
            return None;
        }
        match mode {
            Mode::Tag => compound.tag = Some(core::mem::take(name)),
            Mode::Class => {
                if compound.classes.len() >= CLASSES_PER_COMPOUND {
                    return None;
                }
                compound.classes.push(core::mem::take(name));
            }
            Mode::Id => {
                if compound.id.is_some() {
                    return None; // two ids on one compound: not supported
                }
                compound.id = Some(core::mem::take(name));
            }
        }
        Some(())
    };

    for &b in input {
        match b {
            b' ' | b'\t' | b'\n' | b'\r' => {
                flush(mode, &mut name, &mut compound)?;
                if universal || !compound.is_empty() {
                    compounds.push(core::mem::take(&mut compound));
                }
                compound = Compound::new();
                universal = false;
                mode = Mode::Tag;
            }
            b'.' => {
                flush(mode, &mut name, &mut compound)?;
                mode = Mode::Class;
            }
            b'#' => {
                flush(mode, &mut name, &mut compound)?;
                mode = Mode::Id;
            }
            b'*' => {
                // Universal: matches anything, contributes no name.
                if !name.is_empty() || mode != Mode::Tag {
                    return None;
                }
                universal = true;
            }
            // Unsupported combinators / pseudo / attribute selectors.
            b'>' | b'+' | b'~' | b':' | b'[' | b']' | b'(' | b')' | b',' => return None,
            b if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' => {
                if name.len() >= NAME_CAP {
                    return None;
                }
                // Tag names are ASCII-case-insensitive (folded here);
                // classes and ids stay case-sensitive (CSS).
                let ch = if mode == Mode::Tag {
                    char::from(b.to_ascii_lowercase())
                } else {
                    char::from(b)
                };
                name.push(ch);
            }
            _ => return None, // non-ASCII and other junk
        }
    }
    flush(mode, &mut name, &mut compound)?;
    if universal || !compound.is_empty() {
        compounds.push(compound);
    }
    if compounds.is_empty() {
        return None; // empty selector part (`,,`, `.`, whitespace)
    }
    if compounds.len() > COMPOUNDS_PER_SELECTOR {
        return None;
    }
    Some(Selector { compounds })
}

/// Property-name dispatch: longhands, and the two shorthands this
/// subset expands at parse time.
enum Name {
    Long(Property),
    Margin,
    Padding,
}

fn property_from_name(name: &[u8]) -> Option<Name> {
    let name = name.to_ascii_lowercase();
    let name = core::str::from_utf8(&name).ok()?;
    Some(match name {
        "display" => Name::Long(Property::Display),
        "color" => Name::Long(Property::Color),
        "background-color" => Name::Long(Property::BackgroundColor),
        "font-weight" => Name::Long(Property::FontWeight),
        "font-style" => Name::Long(Property::FontStyle),
        "text-decoration" | "text-decoration-line" => Name::Long(Property::TextDecoration),
        "list-style-type" => Name::Long(Property::ListStyleType),
        "width" => Name::Long(Property::Width),
        "height" => Name::Long(Property::Height),
        "margin-top" => Name::Long(Property::MarginTop),
        "margin-right" => Name::Long(Property::MarginRight),
        "margin-bottom" => Name::Long(Property::MarginBottom),
        "margin-left" => Name::Long(Property::MarginLeft),
        "padding-top" => Name::Long(Property::PaddingTop),
        "padding-right" => Name::Long(Property::PaddingRight),
        "padding-bottom" => Name::Long(Property::PaddingBottom),
        "padding-left" => Name::Long(Property::PaddingLeft),
        "margin" => Name::Margin,
        "padding" => Name::Padding,
        _ => return None,
    })
}

/// Parse one `property: value` fragment (no trailing `;`) into `out`.
fn parse_declaration(raw: &[u8], out: &mut Vec<Declaration>) {
    if out.len() >= DECLS_PER_RULE {
        return;
    }
    let text = trim(raw);
    if text.is_empty() || text.len() > VALUE_CAP * 3 {
        return;
    }
    let Some(colon) = text.iter().position(|&b| b == b':') else {
        return;
    };
    let name = trim(text.get(..colon).unwrap_or(&[]));
    let mut value = trim(text.get(colon.saturating_add(1)..).unwrap_or(&[]));
    if value.len() > VALUE_CAP {
        return; // over-long value: drop the declaration, keep the rule
    }
    let mut important = false;
    if let Some(bang) = value.iter().rposition(|&b| b == b'!') {
        let tail = trim(value.get(bang.saturating_add(1)..).unwrap_or(&[]));
        if tail.eq_ignore_ascii_case(b"important") {
            important = true;
            value = trim(value.get(..bang).unwrap_or(&[]));
        }
    }
    let Some(name) = property_from_name(name) else {
        return;
    };
    match name {
        Name::Long(property) => {
            if let Some(value) = parse_value(property, value) {
                push_declaration(out, property, value, important);
            }
        }
        Name::Margin | Name::Padding => {
            let margin = matches!(name, Name::Margin);
            let Some(edges) = parse_edges(value) else {
                return;
            };
            let sides = if margin {
                [
                    (Property::MarginTop, edges.top),
                    (Property::MarginRight, edges.right),
                    (Property::MarginBottom, edges.bottom),
                    (Property::MarginLeft, edges.left),
                ]
            } else {
                [
                    (Property::PaddingTop, edges.top),
                    (Property::PaddingRight, edges.right),
                    (Property::PaddingBottom, edges.bottom),
                    (Property::PaddingLeft, edges.left),
                ]
            };
            for (property, cells) in sides {
                push_declaration(
                    out,
                    property,
                    Value::Length(Length::Cells(cells)),
                    important,
                );
                if out.len() >= DECLS_PER_RULE {
                    return;
                }
            }
        }
    }
}

fn push_declaration(out: &mut Vec<Declaration>, property: Property, value: Value, important: bool) {
    if out.len() >= DECLS_PER_RULE {
        return;
    }
    out.push(Declaration {
        property,
        value,
        important,
    });
}

/// Parse a value for one longhand; `None` = unsupported value, which
/// drops only this declaration.
fn parse_value(property: Property, raw: &[u8]) -> Option<Value> {
    let raw = trim(raw);
    if raw.is_empty() {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    match property {
        Property::Display => Some(Value::Display(match lower.as_slice() {
            b"none" => Display::None,
            b"block" => Display::Block,
            b"inline" | b"inline-block" => Display::Inline,
            _ => return None,
        })),
        Property::Color | Property::BackgroundColor => Some(Value::Color(parse_color(raw)?)),
        Property::FontWeight => Some(Value::FontWeight(match lower.as_slice() {
            b"normal" | b"400" => FontWeight::Normal,
            b"bold" | b"700" => FontWeight::Bold,
            _ => {
                let weight = parse_number(&lower)?;
                if weight >= 600 {
                    FontWeight::Bold
                } else {
                    FontWeight::Normal
                }
            }
        })),
        Property::FontStyle => Some(Value::FontStyle(match lower.as_slice() {
            b"normal" => FontStyle::Normal,
            b"italic" | b"oblique" => FontStyle::Italic,
            _ => return None,
        })),
        Property::TextDecoration => Some(Value::Decoration(match lower.as_slice() {
            b"none" => Decoration::None,
            b"underline" => Decoration::Underline,
            _ => return None,
        })),
        Property::ListStyleType => Some(Value::ListStyle(match lower.as_slice() {
            b"disc" | b"circle" | b"square" => ListStyle::Disc,
            b"dash" => ListStyle::Dash,
            b"none" => ListStyle::None,
            _ => return None,
        })),
        Property::Width => Some(Value::Length(parse_length(raw, true)?)),
        Property::Height => Some(Value::Length(parse_length(raw, false)?)),
        Property::MarginTop
        | Property::MarginRight
        | Property::MarginBottom
        | Property::MarginLeft
        | Property::PaddingTop
        | Property::PaddingRight
        | Property::PaddingBottom
        | Property::PaddingLeft => Some(Value::Length(Length::Cells(parse_cells(raw)?))),
    }
}

/// Parse 1–4 lengths into CSS's shorthand box (`top right bottom left`).
fn parse_edges(raw: &[u8]) -> Option<Edges> {
    let mut values = [0u16; 4];
    let mut count = 0usize;
    for part in raw.split(u8::is_ascii_whitespace) {
        let part = trim(part);
        if part.is_empty() {
            continue;
        }
        if count >= values.len() {
            return None; // more than four values: unsupported shorthand
        }
        let slot = values.get_mut(count)?;
        *slot = parse_cells(part)?;
        count += 1;
    }
    match count {
        0 => None,
        1 => {
            let v = *values.first()?;
            Some(Edges {
                top: v,
                right: v,
                bottom: v,
                left: v,
            })
        }
        2 => Some(Edges {
            top: *values.first()?,
            right: *values.get(1)?,
            bottom: *values.first()?,
            left: *values.get(1)?,
        }),
        3 => Some(Edges {
            top: *values.first()?,
            right: *values.get(1)?,
            bottom: *values.get(2)?,
            left: *values.get(1)?,
        }),
        _ => Some(Edges {
            top: *values.first()?,
            right: *values.get(1)?,
            bottom: *values.get(2)?,
            left: *values.get(3)?,
        }),
    }
}

/// Parse an integer: digits only (no sign, no float). Values saturate
/// at [`u16::MAX`] — wire data never overflows anything downstream.
fn parse_number(raw: &[u8]) -> Option<u16> {
    let raw = trim(raw);
    if raw.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for &b in raw {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value
            .saturating_mul(10)
            .saturating_add(u32::from(b.saturating_sub(b'0')));
        if value > u32::from(u16::MAX) {
            value = u32::from(u16::MAX);
        }
    }
    Some(value as u16)
}

/// Parse a length in **cells**: bare integers are cells, `Npx` converts
/// at [`PX_PER_CELL`] rounding up. Percent is refused (only `width`
/// accepts it) — the declaration is then dropped.
fn parse_cells(raw: &[u8]) -> Option<u16> {
    let raw = trim(raw);
    let lower = raw.to_ascii_lowercase();
    let (digits, is_px) = match lower.strip_suffix(b"px") {
        Some(digits) => (digits, true),
        None => (lower.as_slice(), false),
    };
    let number = parse_number(digits)?;
    if !is_px {
        return Some(number);
    }
    let cells = usize::from(number).div_ceil(PX_PER_CELL);
    Some(u16::try_from(cells).unwrap_or(u16::MAX))
}

/// Parse a length for `width`/`height`: bare cells, `px`, and (width
/// only, enforced by the caller) `%`.
fn parse_length(raw: &[u8], allow_percent: bool) -> Option<Length> {
    let raw = trim(raw);
    let lower = raw.to_ascii_lowercase();
    if let Some(digits) = lower.strip_suffix(b"%") {
        if !allow_percent {
            return None;
        }
        return Some(Length::Percent(parse_number(digits)?));
    }
    if lower.ends_with(b"px") {
        return Some(Length::Cells(parse_cells(&lower)?));
    }
    // Unsupported units (`em`, `vh`, `pt`, …) and floats are refused
    // by `parse_number` (digits only).
    Some(Length::Cells(parse_number(&lower)?))
}

/// Parse a color: `#rgb`, `#rrggbb`, `rgb(r,g,b)`, or a CSS named
/// color — all resolved to a VGA index by nearest RGB distance.
fn parse_color(raw: &[u8]) -> Option<u8> {
    let raw = trim(raw);
    if let Some(hex) = raw.strip_prefix(b"#") {
        return parse_hex(hex);
    }
    let lower = raw.to_ascii_lowercase();
    if let Some(inner) = lower
        .strip_prefix(b"rgb(")
        .and_then(|rest| rest.strip_suffix(b")"))
    {
        let mut parts = [0u8; 3];
        let mut count = 0usize;
        for part in inner.split(|&b| b == b',') {
            if count >= parts.len() {
                return None;
            }
            let slot = parts.get_mut(count)?;
            *slot = u8::try_from(parse_number(part)?).ok()?;
            count += 1;
        }
        if count != 3 {
            return None;
        }
        return Some(nearest_vga(*parts.first()?, *parts.get(1)?, *parts.get(2)?));
    }
    let name = core::str::from_utf8(&lower).ok()?;
    let (r, g, b) = named_color(name)?;
    Some(nearest_vga(r, g, b))
}

/// `#f00` / `#ff0000` → VGA index.
fn parse_hex(hex: &[u8]) -> Option<u8> {
    let (r, g, b) = match hex.len() {
        3 => (
            hex_digit(*hex.first()?)? * 0x11,
            hex_digit(*hex.get(1)?)? * 0x11,
            hex_digit(*hex.get(2)?)? * 0x11,
        ),
        6 => (
            hex_digit(*hex.first()?)? * 0x10 + hex_digit(*hex.get(1)?)?,
            hex_digit(*hex.get(2)?)? * 0x10 + hex_digit(*hex.get(3)?)?,
            hex_digit(*hex.get(4)?)? * 0x10 + hex_digit(*hex.get(5)?)?,
        ),
        _ => return None,
    };
    Some(nearest_vga(r, g, b))
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The CSS basic color keywords (CSS Color 4 §6.1), with the RGB
/// values browsers compute. `transparent` is intentionally absent: VGA
/// cells have no alpha, so the declaration is ignored (crate docs).
fn named_color(name: &str) -> Option<(u8, u8, u8)> {
    const NAMED: [(&str, u8, u8, u8); 19] = [
        ("black", 0x00, 0x00, 0x00),
        ("silver", 0xC0, 0xC0, 0xC0),
        ("gray", 0x80, 0x80, 0x80),
        ("grey", 0x80, 0x80, 0x80),
        ("white", 0xFF, 0xFF, 0xFF),
        ("maroon", 0x80, 0x00, 0x00),
        ("red", 0xFF, 0x00, 0x00),
        ("purple", 0x80, 0x00, 0x80),
        ("fuchsia", 0xFF, 0x00, 0xFF),
        ("magenta", 0xFF, 0x00, 0xFF),
        ("green", 0x00, 0x80, 0x00),
        ("lime", 0x00, 0xFF, 0x00),
        ("olive", 0x80, 0x80, 0x00),
        ("yellow", 0xFF, 0xFF, 0x00),
        ("navy", 0x00, 0x00, 0x80),
        ("blue", 0x00, 0x00, 0xFF),
        ("teal", 0x00, 0x80, 0x80),
        ("aqua", 0x00, 0xFF, 0xFF),
        ("cyan", 0x00, 0xFF, 0xFF),
    ];
    let mut found = None;
    for (candidate, r, g, b) in NAMED {
        if candidate == name {
            found = Some((r, g, b));
            break;
        }
    }
    found
}

/// Nearest [`PALETTE`] entry to an RGB triplet by squared Euclidean
/// distance. Ties resolve to the **brighter** (higher-index) candidate
/// (crate docs): `#ff00ff` → 13, not 5.
pub fn nearest_vga(r: u8, g: u8, b: u8) -> u8 {
    let mut best = 0u8;
    let mut best_distance = u32::MAX;
    for (index, &(pr, pg, pb)) in PALETTE.iter().enumerate() {
        let dr = i32::from(r) - i32::from(pr);
        let dg = i32::from(g) - i32::from(pg);
        let db = i32::from(b) - i32::from(pb);
        let distance = (dr * dr + dg * dg + db * db) as u32;
        if distance <= best_distance {
            best_distance = distance;
            best = u8::try_from(index).unwrap_or(0);
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Byte helpers (wire data must never panic)
// ---------------------------------------------------------------------------

/// Truncate a `&str` to at most `cap` bytes on a char boundary.
fn clamp_str(s: &str, cap: usize) -> &str {
    if s.len() <= cap {
        return s;
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or("")
}

/// Replace every `/* … */` with one space (no string awareness — no
/// supported value contains `/*`; crate docs). An unterminated comment
/// swallows the rest of the sheet.
fn strip_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        if b == b'/' && input.get(i.saturating_add(1)) == Some(&b'*') {
            i = i.saturating_add(2);
            while let Some(&c) = input.get(i) {
                if c == b'*' && input.get(i.saturating_add(1)) == Some(&b'/') {
                    i = i.saturating_add(2);
                    break;
                }
                i = i.saturating_add(1);
            }
            out.push(b' ');
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    out
}

/// ASCII-whitespace trim.
fn trim(mut raw: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = raw.split_first() {
        if b.is_ascii_whitespace() {
            raw = rest;
        } else {
            break;
        }
    }
    while let Some((&b, rest)) = raw.split_last() {
        if b.is_ascii_whitespace() {
            raw = rest;
        } else {
            break;
        }
    }
    raw
}

/// Does the whitespace-separated `class` attribute contain `wanted`?
fn class_list_contains(list: Option<&str>, wanted: &str) -> bool {
    let Some(list) = list else {
        return false;
    };
    list.split_ascii_whitespace().any(|token| token == wanted)
}

fn saturate_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}
