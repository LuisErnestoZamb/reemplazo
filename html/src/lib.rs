//! Zero-copy HTML5 tokenizer over a byte slice: no allocator, no `unsafe`,
//! no panics on untrusted input.
//!
//! [`Tokenizer::new`] wraps a `&[u8]` and yields borrowed [`Token`]s — every
//! `Text`, tag name, attribute and comment payload is a subslice of the input,
//! so tokenizing costs zero allocation and zero copying. Character references
//! and newline normalization are *not* applied to tokens (that would require
//! rewriting bytes); they are opt-in via [`decode_entities_into`] /
//! [`normalize_newlines_into`], which write into a caller-provided buffer.
//!
//! ```
//! use html::{Token, Tokenizer};
//!
//! let input = b"<p class=hi>hello &amp; bye";
//! let tokens: std::vec::Vec<Token> = Tokenizer::new(input).collect();
//! assert!(matches!(tokens[0], Token::StartTag { .. }));
//! assert_eq!(tokens[1], Token::Text(b"hello &amp; bye"));
//! ```
//!
//! # Spike: why this is from scratch (2026-11-21, timeboxed)
//!
//! A scratch `#![no_std]` crate depending on `html5gum 0.9.2` (the recommended
//! port candidate, `docs/dependencies.md` §3) was cross-built with
//! `cargo build --target x86_64-unknown-none`. **It fails**:
//!
//! - Root cause: `error[E0463]: can't find crate for std` — rustc's note says
//!   *"`std` is required by `html5gum` because it does not declare
//!   `#![no_std]`"*. Two direct E0463 errors (crate level and
//!   `use std::collections::VecDeque`).
//! - Cascade: **2,046 errors across 18 source files** — 1,228× E0425 (missing
//!   prelude items `Option`/`Result`/`Some`/`None`/`Ok`/`Err`), 370× E0531,
//!   93× E0405 (missing prelude traits `Sized`/`Clone`/`Iterator`/…), 17×
//!   E0433 (`Vec`/`String`/`Box`/thread-local `OUTPUT`) — concentrated in
//!   `machine.rs` (1,277), `machine_helper.rs` (799), `entities.rs` (422).
//! - html5gum has **no `no_std` feature** to flip (`[features]` =
//!   `afl-ijon`, `jetscii`, `tree-builder`) and **24 `use std::` imports**,
//!   including `std::io`/`std::fs::File` in its public reader API.
//!
//! A port is therefore a fork-level change (add `#![no_std]` + `alloc`,
//! swap `std::collections`→`alloc::collections`, gate the io/fs readers
//! behind a feature, add a `&[u8]` reader) — not quickly viable inside the
//! timebox. Verdict: **greenfield tokenizer today**; the port-spike is
//! revisited at the browser milestone (which needs the heap anyway for the
//! DOM). Edge semantics below were transcribed from the WHATWG state machine
//! as implemented by html5gum (MIT) and cross-checked against the html5lib
//! tokenizer suite — the reference implementations `docs/dependencies.md`
//! recommends.
//!
//! # Design decisions and documented deviations
//!
//! - **Raw bytes, ASCII-case-insensitive comparison.** Tag and attribute names
//!   are emitted with their original case (zero-copy; html5gum lowercases by
//!   copying, which needs an allocator). Compare with
//!   [`eq_ignore_ascii_case`] or [`Attributes::find`].
//! - **Attribute storage: fixed inline capacity [`ATTR_CAP`] = 32.**
//!   Duplicates (ASCII-case-insensitive) keep the **first** occurrence — the
//!   WHATWG "create an element" rule and html5gum's default emitter. Beyond
//!   `ATTR_CAP` attributes are **silently dropped** (the tokenizer never
//!   errors or panics; tags with >32 unique attributes are a red flag).
//!   [`Attributes::find`] returns the first match, mirroring first-wins.
//! - **Entities stay raw in tokens.** Run [`decode_entities_into`] on text or
//!   attribute values yourself. Only the six named references `&amp; &lt;
//!   &gt; &quot; &apos; &nbsp;` plus decimal/hex numeric references are
//!   decoded; other named references (e.g. `&copy;`) stay literal. Numeric:
//!   `&#0;`/surrogates/`>U+10FFFF` → U+FFFD, `&#13;` → LF (HTML5 rule);
//!   the Windows-1252 remap for `&#128;`–`&#159;` is **not** implemented
//!   (those emit U+0080–U+009F). Named references are matched
//!   case-sensitively (lowercase forms only) and decoded with or without a
//!   trailing `;` — the HTML5 *in-text* rule; in attribute context HTML5
//!   additionally refuses a name followed by `=` or an alphanumeric, which we
//!   do not special-case (documented deviation).
//! - **Newlines.** Tag-boundary decisions treat `\r` and `\r\n` exactly like
//!   `\n` (HTML5 pre-processes input before tokenizing), so
//!   `"<a b=x\r\ny>"` tokenizes like the LF version. Emitted *payloads*
//!   (text, comment bodies, quoted attribute values) keep the original
//!   `\r`/`\r\n` bytes — zero-copy forbids rewriting them; run
//!   [`normalize_newlines_into`] for spec-exact content.
//! - **NUL bytes.** Kept verbatim in text, names and values (HTML5 would
//!   substitute U+FFFD inside tags; substitution needs a copy). In text,
//!   html5lib/html5gum also keep NUL verbatim, so text matches.
//! - **EOF handling — browsers never panic.** A tag left open at EOF
//!   (start *or* end, any position: name, `=`, quoted value…) is **dropped**
//!   (parse error, no token) — html5lib `tokenizer/test4.test`: `"<a a ='a'"`
//!   → `[]`. Unterminated comments/doctypes *are* emitted. `</>` emits
//!   nothing; `</` at EOF is text; `<` at EOF is text; `<` not followed by
//!   an ASCII letter is text (`<>`, `<0`, `<<`).
//! - **`<?…>`** (processing instructions) and `<!…>` (bogus comments,
//!   `<![CDATA[…]]>`) are tokenized as comments terminated by the next `>`
//!   (or EOF); `<?…>` bodies include the leading `?` like html5gum's PI
//!   comment data, but html5gum drops `<?`/`<?a` at EOF while we emit
//!   `Comment("?")`/`Comment("?a")` — documented deviation.
//! - **Raw text elements `script` and `style`**: content is consumed
//!   verbatim until `</script`/`</style` followed by whitespace, `/` or `>`
//!   (ASCII-case-insensitive); at EOF the content is emitted as text with no
//!   end tag. `title`, `textarea`, `xmp`, `iframe`, `plaintext` etc. are
//!   treated as ordinary elements (future work for the tree builder). The
//!   WHATWG "script data escaped/double escaped" states (`<!--<script>…`)
//!   are not implemented: close-tag scanning inside raw text is context-free.
//!   A consumer that decodes entities in `Text` must skip the content of
//!   `script`/`style` (it knows from the start tag it just saw) — browsers
//!   do not decode entities there.
//! - **Doctype token** carries the raw bytes between the `doctype` keyword
//!   and `>`, ASCII-trimmed (`<!DOCTYPE html>` → `html`), keeping original
//!   case; `>` inside quoted identifiers does not terminate it. Consumers
//!   parse that slice themselves.
//! - **Text runs separated by a dropped `</>`** are separate [`Token::Text`]
//!   tokens (their bytes are not contiguous in the input); concatenate when
//!   consuming.
//! - The tokenizer never indexes, unwraps or does unchecked arithmetic on
//!   input; all slicing goes through bounds-checked `part`. It cannot panic —
//!   the adversarial tests below tokenize every byte value and every prefix
//!   of a hostile corpus.

#![no_std]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// Maximum number of attributes stored per start tag; see the crate docs.
/// Overflow attributes are silently dropped (first [`ATTR_CAP`] kept).
pub const ATTR_CAP: usize = 32;

/// One token produced by [`Tokenizer`].
///
/// All payloads are subslices of the input; entity references and newline
/// normalization are intentionally *not* applied (see crate docs).
// `StartTag` carries the fixed inline attribute array (~1 KB), which makes
// this enum large; boxing would need an allocator this crate does not have.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token<'a> {
    /// A run of character data, entity references and NULs verbatim.
    Text(&'a [u8]),
    /// `<name …>`; `name` keeps its original case.
    StartTag {
        /// Raw tag name bytes (original case; compare with
        /// [`eq_ignore_ascii_case`]).
        name: &'a [u8],
        /// Attributes in source order, deduplicated first-wins, capped at
        /// [`ATTR_CAP`].
        attributes: Attributes<'a>,
        /// `true` for `/>`. Reported for non-void elements too — deciding
        /// what to do with it is the tree builder's job.
        self_closing: bool,
    },
    /// `</name>`; attributes on end tags are parsed and discarded.
    EndTag {
        /// Raw tag name bytes (original case).
        name: &'a [u8],
    },
    /// Comment body between `<!--` and `-->` (unterminated at EOF: the rest
    /// of the input). Bogus comments (`<!x>`, `</ x>`, `<?x>`) carry the
    /// bytes up to `>`.
    Comment(&'a [u8]),
    /// Raw bytes after the `doctype` keyword and before `>`, ASCII-trimmed
    /// (`<!DOCTYPE html>` → `html`), original case kept.
    Doctype(&'a [u8]),
}

/// One `name=value` pair of a start tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute<'a> {
    /// Raw attribute name (original case).
    pub name: &'a [u8],
    /// Raw attribute value: bytes between the quotes, or the unquoted run.
    /// Empty for boolean attributes (`<input disabled>`) — same as
    /// `<input disabled="">` in HTML5. Entity references stay raw.
    pub value: &'a [u8],
}

/// Inline, fixed-capacity attribute list of a [`Token::StartTag`].
///
/// No allocator: storage is `[Attribute; ATTR_CAP]` inside the token.
/// Overflow (more than [`ATTR_CAP`] unique names) silently drops the excess;
/// duplicates keep the first occurrence (WHATWG first-wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attributes<'a> {
    items: [Attribute<'a>; ATTR_CAP],
    len: usize,
}

impl<'a> Attributes<'a> {
    const EMPTY: Self = Attributes {
        items: [Attribute {
            name: b"",
            value: b"",
        }; ATTR_CAP],
        len: 0,
    };

    /// Append `name=value`, dropping the attribute when `name` duplicates an
    /// already-stored one (ASCII-case-insensitive) or when the list is full.
    fn push(&mut self, name: &'a [u8], value: &'a [u8]) {
        for existing in self.as_slice() {
            if eq_ignore_ascii_case(existing.name, name) {
                return; // WHATWG: first occurrence wins
            }
        }
        if let Some(slot) = self.items.get_mut(self.len) {
            *slot = Attribute { name, value };
            self.len += 1;
        }
        // else: overflow at ATTR_CAP — silently dropped, documented.
    }

    /// Number of stored attributes (≤ [`ATTR_CAP`]).
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when the tag has no attributes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The attribute at `index`, or `None` when out of range.
    pub fn get(&self, index: usize) -> Option<&Attribute<'a>> {
        if index < self.len {
            self.items.get(index)
        } else {
            None
        }
    }

    /// All stored attributes in source order.
    pub fn as_slice(&self) -> &[Attribute<'a>] {
        self.items.get(..self.len).unwrap_or(&[])
    }

    /// Iterate stored attributes in source order.
    pub fn iter(&self) -> core::slice::Iter<'_, Attribute<'a>> {
        self.as_slice().iter()
    }

    /// First attribute whose name matches `name` ASCII-case-insensitively —
    /// the value a DOM lookup would see (first-wins).
    pub fn find(&self, name: &[u8]) -> Option<&Attribute<'a>> {
        self.iter().find(|a| eq_ignore_ascii_case(a.name, name))
    }
}

/// Pull tokenizer over a byte slice. Yields [`Token`]s until input is
/// exhausted; never panics, never allocates, `O(input)` total work.
#[derive(Debug, Clone)]
pub struct Tokenizer<'a> {
    input: &'a [u8],
    pos: usize,
    /// A start tag parsed while text preceded it: returned before any
    /// further work so `Text` stays contiguous across dropped constructs.
    pending: Option<Token<'a>>,
    /// Element name (`script`/`style`, raw bytes) whose end tag we still
    /// owe: while set, input is consumed as raw text.
    raw_text: Option<&'a [u8]>,
}

impl<'a> Tokenizer<'a> {
    /// Start tokenizing `input` from the beginning.
    pub fn new(input: &'a [u8]) -> Self {
        Tokenizer {
            input,
            pos: 0,
            pending: None,
            raw_text: None,
        }
    }

    /// Main data-state loop: coalesce text up to a real construct, then let
    /// [`parse_construct`](Self::parse_construct) produce the next token.
    fn next_data(&mut self) -> Option<Token<'a>> {
        let mut text_start = self.pos;
        loop {
            let lt = match self
                .input
                .get(self.pos..)
                .and_then(|rest| rest.iter().position(|&b| b == b'<'))
            {
                Some(rel) => self.pos + rel,
                // No `<` left: emit the trailing run (possibly empty).
                None => {
                    self.pos = self.input.len();
                    return self.finish_text(text_start, self.input.len());
                }
            };
            match self.parse_construct(lt) {
                // `<` not followed by a name construct: it is text.
                Step::NotTag => self.pos = lt + 1,
                Step::Dropped => {
                    // `</>` yields nothing; its bytes vanish. Text before it
                    // ends here, text after it starts fresh (they are not
                    // contiguous, so zero-copy forces two Text tokens).
                    if text_start < lt {
                        return Some(Token::Text(part(self.input, text_start, lt)));
                    }
                    text_start = self.pos;
                }
                // Tag started, input ended mid-tag: the tag is dropped
                // (html5lib: `"<a a ='a'"` → []), earlier text still counts.
                Step::EofInTag => return self.finish_text(text_start, lt),
                Step::Token(tok) => {
                    if text_start < lt {
                        // Text precedes the construct: yield it now, the
                        // token on the next call.
                        self.pending = Some(tok);
                        return Some(Token::Text(part(self.input, text_start, lt)));
                    }
                    return Some(tok);
                }
            }
        }
    }

    /// Consume raw-text (`script`/`style`) content until the matching end
    /// tag, EOF, or a pending token.
    fn next_raw_text(&mut self) -> Option<Token<'a>> {
        let Some(name) = self.raw_text else {
            return self.next_data();
        };
        match self.find_raw_close(name) {
            Some(i) if i > self.pos => {
                let text = Token::Text(part(self.input, self.pos, i));
                self.pos = i; // end tag is parsed on the next call
                Some(text)
            }
            Some(_) => {
                // End tag is right at `pos`: parse it as a normal construct.
                self.raw_text = None;
                self.next_data()
            }
            None => {
                // EOF without a close tag: remaining bytes are text only.
                self.raw_text = None;
                let start = self.pos;
                self.pos = self.input.len();
                self.finish_text(start, self.input.len())
            }
        }
    }

    /// First index ≥ `pos` of `</name` followed by whitespace, `/` or `>`.
    /// EOF right after the name does **not** count (html5gum: the bytes stay
    /// text), and the match is ASCII-case-insensitive.
    fn find_raw_close(&self, name: &[u8]) -> Option<usize> {
        let mut i = self.pos;
        while i < self.input.len() {
            if self.input.get(i) != Some(&b'<') {
                i += 1;
                continue;
            }
            let after = i + 2;
            let end = after + name.len();
            if let Some(chunk) = self.input.get(after..end)
                && eq_ignore_ascii_case(chunk, name)
            {
                match self.input.get(end) {
                    Some(&b) if is_html_whitespace(b) || b == b'>' || b == b'/' => {
                        return Some(i);
                    }
                    _ => {} // EOF or wrong boundary: not a close tag
                }
            }
            i += 1;
        }
        None
    }

    /// Emit the text run `text_start..end` if non-empty.
    fn finish_text(&mut self, text_start: usize, end: usize) -> Option<Token<'a>> {
        if text_start < end {
            Some(Token::Text(part(self.input, text_start, end)))
        } else {
            None
        }
    }

    /// Classify the construct starting at `<` (`lt`).
    fn parse_construct(&mut self, lt: usize) -> Step<'a> {
        match self.input.get(lt + 1).copied() {
            None => Step::NotTag, // `<` at EOF is text
            Some(b'!') => self.parse_declaration(lt + 2),
            Some(b'/') => self.parse_after_slash(lt + 2),
            // `<?…>`: treated as a bogus comment whose body starts at the
            // `?` (documented deviation — see crate docs).
            Some(b'?') => self.bogus_comment(lt + 1),
            Some(c) if c.is_ascii_alphabetic() => self.parse_tag(lt, false),
            Some(_) => Step::NotTag, // `<0`, `<<`, `< `… → text
        }
    }

    /// After `</`: end tag, dropped `</>`, bogus comment, or text.
    fn parse_after_slash(&mut self, i: usize) -> Step<'a> {
        match self.input.get(i).copied() {
            None => Step::NotTag, // `</` at EOF is text
            Some(b'>') => {
                // `</>`: parse error, nothing emitted (html5lib).
                self.pos = i + 1;
                Step::Dropped
            }
            Some(c) if c.is_ascii_alphabetic() => self.parse_tag(i - 2, true),
            Some(_) => self.bogus_comment(i), // `</ x>` etc.
        }
    }

    /// After `<!`: comment, doctype, or bogus comment (`<!x>`, `<![CDATA[…]]>`).
    fn parse_declaration(&mut self, i: usize) -> Step<'a> {
        if self.input.get(i..i + 2) == Some(b"--".as_slice()) {
            self.comment(i + 2)
        } else if self
            .input
            .get(i..i + 7)
            .is_some_and(|kw| eq_ignore_ascii_case(kw, b"doctype"))
        {
            self.doctype(i + 7)
        } else {
            self.bogus_comment(i)
        }
    }

    /// Bogus comment: everything from `i` up to the next `>` (or EOF).
    fn bogus_comment(&mut self, i: usize) -> Step<'a> {
        let mut end = i;
        while let Some(&c) = self.input.get(end) {
            if c == b'>' {
                break;
            }
            end += 1;
        }
        let data = part(self.input, i, end);
        self.pos = if end < self.input.len() {
            end + 1
        } else {
            self.input.len()
        };
        Step::Token(Token::Comment(data))
    }

    /// The WHATWG comment state machine (transcribed from html5gum), running
    /// over `input[s..]` where `s` is just past `<!--`. `end` tracks the
    /// comment-data boundary; the data is always the contiguous run
    /// `input[s..end]` (dropped dashes are re-added by later pushes in FIFO
    /// order over pending input bytes, so the slice stays zero-copy).
    /// Every `end` update is clamped to `pos`, which keeps
    /// `s ≤ end ≤ len` by construction — no path can panic.
    fn comment(&mut self, s: usize) -> Step<'a> {
        #[derive(Clone, Copy)]
        enum St {
            Start,
            StartDash,
            Main,
            Lt,
            LtBang,
            LtBangDash,
            LtBangDashDash,
            End,
            EndDash,
            EndBang,
        }
        let mut st = St::Start;
        let mut pos = s;
        let mut end = s; // exclusive end of comment data in `input`
        loop {
            let c = self.input.get(pos).copied();
            match st {
                St::Start => match c {
                    Some(b'-') => {
                        pos += 1;
                        st = St::StartDash;
                    }
                    Some(b'>') => {
                        // `<!-->`: abrupt close, empty comment.
                        pos += 1;
                        return self.emit_comment(s, end, pos);
                    }
                    Some(_) => st = St::Main, // reconsume
                    None => return self.emit_comment(s, end, pos),
                },
                St::StartDash => match c {
                    Some(b'-') => {
                        pos += 1;
                        st = St::End;
                    }
                    Some(b'>') => {
                        // `<!--->`: abrupt close, empty comment.
                        pos += 1;
                        return self.emit_comment(s, end, pos);
                    }
                    Some(_) => {
                        end = (end + 1).min(pos); // re-add the dash
                        st = St::Main; // reconsume c
                    }
                    None => return self.emit_comment(s, end, pos),
                },
                St::Main => match c {
                    Some(b'<') => {
                        end = pos + 1;
                        pos += 1;
                        st = St::Lt;
                    }
                    Some(b'-') => {
                        pos += 1;
                        st = St::EndDash;
                    }
                    Some(_) => {
                        end = pos + 1;
                        pos += 1;
                    }
                    None => return self.emit_comment(s, end, pos),
                },
                St::Lt => match c {
                    Some(b'!') => {
                        end = pos + 1;
                        pos += 1;
                        st = St::LtBang;
                    }
                    Some(b'<') => {
                        end = pos + 1;
                        pos += 1;
                    }
                    Some(_) => st = St::Main, // reconsume
                    None => return self.emit_comment(s, end, pos),
                },
                St::LtBang => match c {
                    Some(b'-') => {
                        pos += 1;
                        st = St::LtBangDash;
                    }
                    Some(_) => st = St::Main, // reconsume
                    None => return self.emit_comment(s, end, pos),
                },
                St::LtBangDash => match c {
                    Some(b'-') => {
                        pos += 1;
                        st = St::LtBangDashDash;
                    }
                    Some(_) => st = St::EndDash, // reconsume
                    None => st = St::EndDash,    // reconsume → EOF emits
                },
                // `<!--<!--x` and friends: nested-comment parse error.
                St::LtBangDashDash => st = St::End, // reconsume everything
                St::End => match c {
                    Some(b'>') => {
                        pos += 1;
                        return self.emit_comment(s, end, pos);
                    }
                    Some(b'!') => {
                        pos += 1;
                        st = St::EndBang;
                    }
                    Some(b'-') => {
                        end = (end + 1).min(pos); // push one pending dash
                        pos += 1;
                    }
                    Some(_) => {
                        end = (end + 2).min(pos); // push "--"
                        st = St::Main; // reconsume c
                    }
                    None => return self.emit_comment(s, end, pos),
                },
                St::EndDash => match c {
                    Some(b'-') => {
                        pos += 1;
                        st = St::End;
                    }
                    Some(_) => {
                        end = (end + 1).min(pos); // push "-"
                        st = St::Main; // reconsume c
                    }
                    None => return self.emit_comment(s, end, pos),
                },
                St::EndBang => match c {
                    Some(b'-') => {
                        // `--!-`: push "--!" over the pending run; the dash
                        // itself stays pending for the next push.
                        end = (end + 3).min(pos);
                        pos += 1;
                        st = St::EndDash;
                    }
                    Some(b'>') => {
                        // `--!>`: incorrectly closed, still ends the comment.
                        pos += 1;
                        return self.emit_comment(s, end, pos);
                    }
                    Some(_) => {
                        end = (end + 3).min(pos); // push "--!"
                        st = St::Main; // reconsume c
                    }
                    None => return self.emit_comment(s, end, pos),
                },
            }
        }
    }

    fn emit_comment(&mut self, s: usize, end: usize, pos: usize) -> Step<'a> {
        self.pos = pos;
        Step::Token(Token::Comment(part(self.input, s, end)))
    }

    /// After `<!doctype` (case-insensitive): raw inner slice up to `>`,
    /// with `>` inside quoted identifiers ignored. Emitted at EOF too.
    fn doctype(&mut self, s: usize) -> Step<'a> {
        let mut pos = s;
        let mut quote = 0u8;
        while let Some(&c) = self.input.get(pos) {
            if quote != 0 {
                if c == quote {
                    quote = 0;
                }
            } else if c == b'>' {
                break;
            } else if c == b'"' || c == b'\'' {
                quote = c;
            }
            pos += 1;
        }
        let content = trim_html_whitespace(part(self.input, s, pos));
        self.pos = if pos < self.input.len() {
            pos + 1
        } else {
            self.input.len()
        };
        Step::Token(Token::Doctype(content))
    }

    /// Full start/end tag parse: name, attributes, `/>`, `>`. Reaching EOF
    /// anywhere inside drops the whole tag (html5lib test4 semantics).
    fn parse_tag(&mut self, lt: usize, is_end: bool) -> Step<'a> {
        // `lt` points at `<`; an end tag's name starts after `</`.
        let name_start = lt + 1 + usize::from(is_end);
        let mut i = name_start; // first name byte is ASCII alpha (caller checked)
        while let Some(&c) = self.input.get(i) {
            if is_html_whitespace(c) || c == b'/' || c == b'>' {
                break;
            }
            i += 1;
        }
        if i >= self.input.len() {
            return self.eof_in_tag();
        }
        let name = part(self.input, name_start, i);
        let mut attrs = Attributes::EMPTY;
        let mut self_closing = false;

        // Before-attribute-name loop; every path either continues here or
        // returns a token / EOF-drop, so no attribute state is skipped.
        loop {
            while self.input.get(i).is_some_and(|&c| is_html_whitespace(c)) {
                i += 1;
            }
            let Some(&terminator) = self.input.get(i) else {
                return self.eof_in_tag();
            };
            match terminator {
                b'>' => {
                    self.pos = i + 1;
                    if !is_end
                        && (eq_ignore_ascii_case(name, b"script")
                            || eq_ignore_ascii_case(name, b"style"))
                    {
                        self.raw_text = Some(name);
                    }
                    return Step::Token(if is_end {
                        Token::EndTag { name }
                    } else {
                        Token::StartTag {
                            name,
                            attributes: attrs,
                            self_closing,
                        }
                    });
                }
                b'/' => {
                    // `/>` sets the flag only when `>` follows immediately;
                    // otherwise the `/` is a separator (html5gum).
                    i += 1;
                    if self.input.get(i) == Some(&b'>') {
                        self_closing = true;
                    }
                }
                _ => {
                    // Attribute name; a leading `=` becomes part of the name
                    // (html5gum: `<a =b>` → attribute `=b`).
                    let name_start = if terminator == b'=' {
                        let start = i;
                        i += 1;
                        start
                    } else {
                        i
                    };
                    while let Some(&c) = self.input.get(i) {
                        if is_html_whitespace(c) || c == b'=' || c == b'/' || c == b'>' {
                            break;
                        }
                        i += 1;
                    }
                    if i >= self.input.len() {
                        return self.eof_in_tag();
                    }
                    let attr_name = part(self.input, name_start, i);

                    let mut value: &[u8] = b"";
                    if self.input.get(i) == Some(&b'=') {
                        i += 1;
                        while self.input.get(i).is_some_and(|&c| is_html_whitespace(c)) {
                            i += 1;
                        }
                        let Some(&quote) = self.input.get(i) else {
                            return self.eof_in_tag();
                        };
                        match quote {
                            q @ (b'"' | b'\'') => {
                                i += 1;
                                let value_start = i;
                                while let Some(&c) = self.input.get(i) {
                                    if c == q {
                                        break;
                                    }
                                    i += 1;
                                }
                                if i >= self.input.len() {
                                    return self.eof_in_tag(); // unterminated quote
                                }
                                value = part(self.input, value_start, i);
                                i += 1; // past the closing quote
                            }
                            b'>' => {} // `b=>`: missing value, stays empty
                            _ => {
                                // Unquoted: ends at whitespace or `>`.
                                let value_start = i;
                                while let Some(&c) = self.input.get(i) {
                                    if is_html_whitespace(c) || c == b'>' {
                                        break;
                                    }
                                    i += 1;
                                }
                                if i >= self.input.len() {
                                    return self.eof_in_tag();
                                }
                                value = part(self.input, value_start, i);
                            }
                        }
                    }
                    // Boolean attributes keep an empty value; the terminator
                    // (`>`, `/`, whitespace) is handled on the next pass.
                    attrs.push(attr_name, value);
                }
            }
        }
    }

    fn eof_in_tag(&mut self) -> Step<'a> {
        self.pos = self.input.len();
        Step::EofInTag
    }
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        if let Some(tok) = self.pending.take() {
            return Some(tok);
        }
        if self.raw_text.is_some() {
            return self.next_raw_text();
        }
        self.next_data()
    }
}

/// Outcome of parsing at a `<`; see [`Tokenizer::next_data`].
// Carries a full `Token` (~1 KB inline attributes) — same trade-off as
// `Token` itself: no allocator to box into.
#[allow(clippy::large_enum_variant)]
enum Step<'a> {
    /// `<` is not a construct — caller absorbs it as text.
    NotTag,
    /// Construct consumed, no token emitted (`</>`).
    Dropped,
    /// Tag started but input ended — tag dropped, text up to `<` stands.
    EofInTag,
    /// A token is ready; `self.pos` is past it.
    Token(Token<'a>),
}

/// ASCII-case-insensitive byte-slice comparison — how this crate compares
/// tag and attribute names without copying or lowercasing them.
///
/// ```
/// assert!(html::eq_ignore_ascii_case(b"DIV", b"div"));
/// assert!(!html::eq_ignore_ascii_case(b"div", b"dif"));
/// ```
pub fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// HTML5 whitespace: space, tab, LF, FF (`0x0C`) and CR (CR and CRLF count
/// as LF after input pre-processing, so CR is included for tag boundaries).
pub fn is_html_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0C | b'\r')
}

/// Bounds-checked subslice: `input[start..end]`, or empty when the range is
/// invalid. Every slice in this crate goes through here — the tokenizer
/// cannot panic on any input.
fn part(input: &[u8], start: usize, end: usize) -> &[u8] {
    if start <= end {
        input.get(start..end).unwrap_or(&[])
    } else {
        &[]
    }
}

fn trim_html_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if !is_html_whitespace(*first) {
            break;
        }
        bytes = rest;
    }
    while let Some((last, rest)) = bytes.split_last() {
        if !is_html_whitespace(*last) {
            break;
        }
        bytes = rest;
    }
    bytes
}

/// Named character references this crate knows (HTML5 subset).
const NAMED_REFERENCES: [(&[u8], &[u8]); 6] = [
    (b"nbsp", b"\xC2\xA0"), // U+00A0 NO-BREAK SPACE (C2 A0)
    (b"quot", b"\""),
    (b"apos", b"'"),
    (b"amp", b"&"),
    (b"lt", b"<"),
    (b"gt", b">"),
];

/// Decode **all** character references in `raw` into `out`, returning the
/// number of bytes written (`Some(0)` for empty input), or `None` when `out`
/// is too small — in which case `out` holds a partial, unspecified prefix.
///
/// Covers `&amp; &lt; &gt; &quot; &apos; &nbsp;`, decimal `&#NN;` and hex
/// `&#xHH;`. Per HTML5, invalid or incomplete sequences stay **literal**:
/// `&am`, `&`, `&#x;`, `&#;` are copied through unchanged. Numeric values
/// `0`, surrogates and anything above U+10FFFF become U+FFFD (`EF BF BD`),
/// `&#13;` becomes LF. Named references are matched case-sensitively
/// (lowercase) and decode with or without `;` (in-text rule); other names
/// (`&copy;`) stay literal. See the crate docs for the full deviation list.
///
/// ```
/// let mut buf = [0u8; 16];
/// let n = html::decode_entities_into(b"a &amp; b", &mut buf).unwrap();
/// assert_eq!(&buf[..n], b"a & b");
/// assert_eq!(html::decode_entities_into(b"&am", &mut buf), Some(3));
/// assert_eq!(&buf[..3], b"&am");
/// ```
pub fn decode_entities_into(raw: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut i = 0;
    let mut o = 0;
    while i < raw.len() {
        if raw.get(i) != Some(&b'&') {
            *out.get_mut(o)? = raw.get(i).copied()?;
            i += 1;
            o += 1;
            continue;
        }

        // Numeric: &#NN; or &#xHH; (semicolon optional, digits required).
        if raw.get(i + 1) == Some(&b'#') {
            let mut j = i + 2;
            let hex = matches!(raw.get(j), Some(&b'x') | Some(&b'X'));
            if hex {
                j += 1;
            }
            let base = if hex { 16u32 } else { 10u32 };
            let digits_start = j;
            let mut value: u32 = 0;
            let mut overflow = false;
            while let Some(d) = raw.get(j).and_then(|&c| digit_value(c, hex)) {
                j += 1;
                if !overflow {
                    match value.checked_mul(base).and_then(|v| v.checked_add(d)) {
                        Some(v) => value = v,
                        None => overflow = true, // absurdly long number → FFFD
                    }
                }
            }
            if j == digits_start {
                // No digits (`&#`, `&#x;`): literal `&`, rescan the rest.
                *out.get_mut(o)? = b'&';
                i += 1;
                o += 1;
                continue;
            }
            if raw.get(j) == Some(&b';') {
                j += 1;
            }
            let cp = if overflow {
                0xFFFD
            } else {
                match value {
                    0 | 0xD800..=0xDFFF => 0xFFFD,
                    13 => 10, // &#13; is LF after pre-processing
                    v if v > 0x10FFFF => 0xFFFD,
                    v => v,
                }
            };
            o = write_utf8(out, o, cp)?;
            i = j;
            continue;
        }

        // Named: longest match from the known table, `;` optional.
        let mut best: Option<(&[u8], &[u8])> = None;
        for (name, replacement) in NAMED_REFERENCES {
            if let Some(chunk) = raw.get(i + 1..i + 1 + name.len())
                && chunk == name
                && best.is_none_or(|(best_name, _)| name.len() > best_name.len())
            {
                best = Some((name, replacement));
            }
        }
        if let Some((name, replacement)) = best {
            let mut consumed = 1 + name.len();
            if raw.get(i + consumed) == Some(&b';') {
                consumed += 1;
            }
            for &b in replacement {
                *out.get_mut(o)? = b;
                o += 1;
            }
            i += consumed;
            continue;
        }

        // Not a known reference: keep the `&` literal (HTML5 behavior).
        *out.get_mut(o)? = b'&';
        i += 1;
        o += 1;
    }
    Some(o)
}

fn digit_value(byte: u8, hex: bool) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' if hex => Some(u32::from(byte - b'a' + 10)),
        b'A'..=b'F' if hex => Some(u32::from(byte - b'A' + 10)),
        _ => None,
    }
}

/// Store one byte at `out[o]`; `None` when it does not fit.
fn put(out: &mut [u8], o: usize, byte: u8) -> Option<usize> {
    *out.get_mut(o)? = byte;
    Some(o + 1)
}

/// Encode `cp` as UTF-8 at `out[o..]`; `None` when it does not fit.
fn write_utf8(out: &mut [u8], o: usize, cp: u32) -> Option<usize> {
    if cp < 0x80 {
        return put(out, o, cp as u8);
    }
    if cp < 0x800 {
        let o = put(out, o, (cp >> 6) as u8 | 0xC0)?;
        return put(out, o, (cp & 0x3F) as u8 | 0x80);
    }
    if cp < 0x10000 {
        let o = put(out, o, (cp >> 12) as u8 | 0xE0)?;
        let o = put(out, o, ((cp >> 6) & 0x3F) as u8 | 0x80)?;
        return put(out, o, (cp & 0x3F) as u8 | 0x80);
    }
    let o = put(out, o, (cp >> 18) as u8 | 0xF0)?;
    let o = put(out, o, ((cp >> 12) & 0x3F) as u8 | 0x80)?;
    let o = put(out, o, ((cp >> 6) & 0x3F) as u8 | 0x80)?;
    put(out, o, (cp & 0x3F) as u8 | 0x80)
}

/// Normalize line endings into `out` per HTML5 input pre-processing:
/// `\r\n` and lone `\r` each become a single `\n`. Returns bytes written,
/// or `None` when `out` is too small (partial prefix written).
///
/// The tokenizer itself does **not** rewrite token payloads (zero-copy), so
/// run this on `Text`/comment/attribute slices when spec-exact content
/// matters.
///
/// ```
/// let mut buf = [0u8; 8];
/// let n = html::normalize_newlines_into(b"a\r\nb\rc", &mut buf).unwrap();
/// assert_eq!(&buf[..n], b"a\nb\nc");
/// ```
pub fn normalize_newlines_into(raw: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut i = 0;
    let mut o = 0;
    while i < raw.len() {
        let byte = match raw.get(i).copied()? {
            b'\r' => {
                if raw.get(i + 1) == Some(&b'\n') {
                    i += 1; // swallow the LF of a CRLF pair
                }
                b'\n'
            }
            b => b,
        };
        *out.get_mut(o)? = byte;
        i += 1;
        o += 1;
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    /// Tokenize `input` to completion.
    fn toks(input: &[u8]) -> Vec<Token<'_>> {
        Tokenizer::new(input).collect()
    }

    /// A bare attribute-less start token (all test inputs are `'static`).
    fn start(name: &'static [u8]) -> Token<'static> {
        Token::StartTag {
            name,
            attributes: Attributes::EMPTY,
            self_closing: false,
        }
    }

    /// One `(name, value)` pair as produced by [`start_tag`].
    type AttrPair<'a> = (&'a [u8], &'a [u8]);

    /// Parse a single start tag: (name, [(attr, value)…], self_closing).
    fn start_tag(input: &[u8]) -> (&[u8], Vec<AttrPair<'_>>, bool) {
        match toks(input).into_iter().next() {
            Some(Token::StartTag {
                name,
                attributes,
                self_closing,
            }) => (
                name,
                attributes
                    .iter()
                    .map(|a| (a.name, a.value))
                    .collect::<Vec<_>>(),
                self_closing,
            ),
            other => panic!("expected start tag, got {other:?}"),
        }
    }

    /// Substring search for byte slices.
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
    }

    // ---- basic structure ----------------------------------------------------

    #[test]
    fn empty_input_yields_nothing() {
        assert!(toks(b"").is_empty());
        assert!(Tokenizer::new(b"").next().is_none());
    }

    #[test]
    fn plain_text_is_one_token() {
        assert_eq!(toks(b"hello world"), vec![Token::Text(b"hello world")]);
    }

    #[test]
    fn simple_start_and_end_tag() {
        assert_eq!(
            toks(b"<h></h>"),
            vec![start(b"h"), Token::EndTag { name: b"h" }]
        );
    }

    #[test]
    fn adjacent_tags_without_text() {
        assert_eq!(toks(b"<a><b>").len(), 2);
    }

    #[test]
    fn lt_not_followed_by_name_is_text() {
        // html5lib: `<>`, `<0`, `<<`, `< ` are all character tokens.
        assert_eq!(toks(b"<>"), vec![Token::Text(b"<>")]);
        assert_eq!(toks(b"<0"), vec![Token::Text(b"<0")]);
        assert_eq!(toks(b"<<a>"), vec![Token::Text(b"<"), start(b"a")]);
        assert_eq!(toks(b"< a >"), vec![Token::Text(b"< a >")]);
        assert_eq!(toks(b"a < b"), vec![Token::Text(b"a < b")]);
    }

    #[test]
    fn lt_at_eof_is_text() {
        assert_eq!(toks(b"<"), vec![Token::Text(b"<")]);
        assert_eq!(toks(b"</"), vec![Token::Text(b"</")]);
        assert_eq!(toks(b"x</"), vec![Token::Text(b"x</")]);
    }

    #[test]
    fn empty_end_tag_is_dropped() {
        // html5lib: `a</>bc` → characters `abc`; zero-copy splits the run
        // into two Text tokens around the vanishing `</>`.
        assert_eq!(toks(b"a</>bc"), vec![Token::Text(b"a"), Token::Text(b"bc")]);
        assert!(toks(b"</>").is_empty());
    }

    #[test]
    fn bogus_end_tag_is_a_comment() {
        // html5lib: `</ ` → Comment " ", `</x>` is a real end tag.
        assert_eq!(toks(b"</ "), vec![Token::Comment(b" ")]);
        assert_eq!(toks(b"</x>"), vec![Token::EndTag { name: b"x" }]);
        assert_eq!(toks(b"</ x>"), vec![Token::Comment(b" x")]);
    }

    #[test]
    fn end_tag_with_attributes_is_end_tag() {
        assert_eq!(toks(b"</h a='b'>"), vec![Token::EndTag { name: b"h" }]);
    }

    #[test]
    fn end_tag_self_closing_ignored() {
        assert_eq!(toks(b"</a/>"), vec![Token::EndTag { name: b"a" }]);
    }

    // ---- attributes ---------------------------------------------------------

    #[test]
    fn quoted_and_unquoted_attribute_values() {
        let (name, attrs, sc) = start_tag(b"<a x=\"1\" y='2' z=3>");
        assert_eq!(name, b"a");
        assert_eq!(
            attrs,
            vec![
                (b"x".as_slice(), b"1".as_slice()),
                (b"y", b"2"),
                (b"z", b"3")
            ]
        );
        assert!(!sc);
    }

    #[test]
    fn gt_inside_quoted_value_does_not_end_tag() {
        // The adversarial classic: `<a b=">">`.
        let (name, attrs, _) = start_tag(b"<a b=\">\">");
        assert_eq!(name, b"a");
        assert_eq!(attrs, vec![(b"b".as_slice(), b">".as_slice())]);
    }

    #[test]
    fn unquoted_values_end_at_whitespace_or_gt() {
        assert_eq!(
            start_tag(b"<a href=/x/y c=d>").1,
            vec![(b"href".as_slice(), b"/x/y".as_slice()), (b"c", b"d")]
        );
        // html5lib: `title=hello world` → two attributes.
        assert_eq!(
            start_tag(b"<a title=hello world>").1,
            vec![(b"title".as_slice(), b"hello".as_slice()), (b"world", b"")]
        );
        // `<a b=>`: missing value → empty.
        assert_eq!(
            start_tag(b"<a b=>").1,
            vec![(b"b".as_slice(), b"".as_slice())]
        );
    }

    #[test]
    fn boolean_attributes_have_empty_values() {
        assert_eq!(
            start_tag(b"<input disabled checked>").1,
            vec![(b"disabled".as_slice(), b"".as_slice()), (b"checked", b"")]
        );
    }

    #[test]
    fn duplicate_attributes_keep_first_wins() {
        // WHATWG: `<h a='b' a='d'>` → one `a='b'` (first wins, ci names).
        let (name, attrs, _) = start_tag(b"<h a='b' a='d'>");
        assert_eq!(name, b"h");
        assert_eq!(attrs, vec![(b"a".as_slice(), b"b".as_slice())]);
        let (_, attrs, _) = start_tag(b"<div id=x ID=y id=z>");
        assert_eq!(attrs, vec![(b"id".as_slice(), b"x".as_slice())]);
    }

    #[test]
    fn self_closing_flag() {
        assert!(start_tag(b"<br/>").2);
        assert!(start_tag(b"<div/>").2, "non-void self-closing is reported");
        assert!(!start_tag(b"<a / >").2, "space breaks `/>`");
        assert!(start_tag(b"<a/>").2);
    }

    #[test]
    fn mixed_case_names_stay_raw_but_compare_ci() {
        let (name, attrs, _) = start_tag(b"<DiV ClAsS=X>");
        assert_eq!(name, b"DiV");
        assert!(eq_ignore_ascii_case(name, b"div"));
        assert!(!eq_ignore_ascii_case(name, b"dif"));
        assert_eq!(attrs, vec![(b"ClAsS".as_slice(), b"X".as_slice())]);
        assert_eq!(toks(b"</DiV>"), vec![Token::EndTag { name: b"DiV" }]);
    }

    #[test]
    fn leading_equals_becomes_part_of_attr_name() {
        // html5gum: `<a =b>` → attribute named `=b`.
        assert_eq!(
            start_tag(b"<a =b>").1,
            vec![(b"=b".as_slice(), b"".as_slice())]
        );
    }

    #[test]
    fn attributes_accessors() {
        let tokens = toks(b"<div a=1 b=2>");
        let Some(Token::StartTag { attributes, .. }) = tokens.first() else {
            panic!("expected start tag");
        };
        assert_eq!(attributes.len(), 2);
        assert!(!attributes.is_empty());
        assert_eq!(attributes.get(0).map(|a| a.name), Some(b"a".as_slice()));
        assert_eq!(attributes.get(9), None);
        assert_eq!(attributes.as_slice().len(), 2);
        assert_eq!(attributes.iter().count(), 2);
        assert_eq!(
            attributes.find(b"B").map(|a| a.value),
            Some(b"2".as_slice())
        );
        assert!(attributes.find(b"zz").is_none());
        let empty = Attributes::EMPTY;
        assert!(empty.is_empty());
        assert!(empty.find(b"a").is_none());
    }

    #[test]
    fn attribute_overflow_at_documented_cap_is_silent() {
        let mut html = String::from("<div");
        for n in 0..40 {
            html.push_str(&format!(" a{n}={n}"));
        }
        html.push('>');
        let tokens = toks(html.as_bytes());
        let Some(Token::StartTag { attributes, .. }) = tokens.first() else {
            panic!("expected start tag");
        };
        assert_eq!(attributes.len(), ATTR_CAP);
        assert_eq!(attributes.get(0).map(|a| a.name), Some(b"a0".as_slice()));
        assert_eq!(
            attributes.get(ATTR_CAP - 1).map(|a| a.name),
            Some(b"a31".as_slice())
        );
        assert!(attributes.find(b"a32").is_none());
        assert!(attributes.find(b"a39").is_none());
        // Tokenizer keeps working after the overflow.
        assert_eq!(tokens.len(), 1);
    }

    // ---- EOF handling (browsers never panic) --------------------------------

    #[test]
    fn unclosed_tags_at_eof_are_dropped() {
        // html5lib tokenizer/test4.test: every one of these → [].
        let cases: [&[u8]; 11] = [
            b"<a",
            b"<a ",
            b"<a a",
            b"<a a ",
            b"<a a =",
            b"<a a =\"a",
            b"<a a ='a",
            b"<a a ='a'",
            b"<a a =a",
            b"<z/",
            b"</a",
        ];
        for input in cases {
            assert!(toks(input).is_empty(), "{input:?} must yield no tokens");
        }
    }

    #[test]
    fn text_before_dropped_tag_survives() {
        assert_eq!(toks(b"<p>hi<a"), vec![start(b"p"), Token::Text(b"hi")]);
        assert_eq!(toks(b"x<a"), vec![Token::Text(b"x")]);
    }

    #[test]
    fn unterminated_comment_at_eof_is_emitted() {
        assert_eq!(toks(b"<!--comment"), vec![Token::Comment(b"comment")]);
        assert_eq!(toks(b"<!-- <!--"), vec![Token::Comment(b" <!")]);
        assert_eq!(toks(b"<!"), vec![Token::Comment(b"")]);
        assert_eq!(toks(b"<!-"), vec![Token::Comment(b"-")]);
        assert_eq!(toks(b"<!--"), vec![Token::Comment(b"")]);
    }

    #[test]
    fn unterminated_doctype_at_eof_is_emitted() {
        assert_eq!(toks(b"<!DOCTYPE HtMl"), vec![Token::Doctype(b"HtMl")]);
        assert_eq!(toks(b"<!DOCTYPE html "), vec![Token::Doctype(b"html")]);
    }

    // ---- doctype ------------------------------------------------------------

    #[test]
    fn doctype_basic_and_ci_keyword() {
        assert_eq!(toks(b"<!DOCTYPE html>"), vec![Token::Doctype(b"html")]);
        assert_eq!(toks(b"<!doctype html>"), vec![Token::Doctype(b"html")]);
        assert_eq!(toks(b"<!DocType HtMl>"), vec![Token::Doctype(b"HtMl")]);
        assert_eq!(toks(b"<!DOCTYPE>"), vec![Token::Doctype(b"")]);
        assert_eq!(
            toks(b"<!DOCTYPE html PUBLIC \"x>y\">"),
            vec![Token::Doctype(b"html PUBLIC \"x>y\"")],
            "quoted `>` must not end the doctype"
        );
    }

    #[test]
    fn truncated_doctype_keyword_is_bogus_comment() {
        // html5lib: `<!DOC>` → Comment "DOC".
        assert_eq!(toks(b"<!DOC>"), vec![Token::Comment(b"DOC")]);
        assert_eq!(toks(b"<!doc\x00"), vec![Token::Comment(b"doc\x00")]);
    }

    #[test]
    fn doctype_mid_key_eof_still_emits() {
        // html5lib test4: `<!DOCTYPE html PUBLI` → DOCTYPE.
        assert_eq!(
            toks(b"<!DOCTYPE html PUBLI"),
            vec![Token::Doctype(b"html PUBLI")]
        );
    }

    // ---- comments -----------------------------------------------------------

    #[test]
    fn comment_variants() {
        assert_eq!(toks(b"<!--x-->"), vec![Token::Comment(b"x")]);
        assert_eq!(toks(b"<!-- -->"), vec![Token::Comment(b" ")]);
        // html5lib abrupt-close forms.
        assert_eq!(toks(b"<!-->"), vec![Token::Comment(b"")]);
        assert_eq!(toks(b"<!--->"), vec![Token::Comment(b"")]);
        assert_eq!(toks(b"<!---->"), vec![Token::Comment(b"")]);
        assert_eq!(toks(b"<!----->"), vec![Token::Comment(b"-")]);
        // `--!>` closes a comment (comment-end-bang).
        assert_eq!(toks(b"<!--a--!>"), vec![Token::Comment(b"a")]);
        // Nested-comment parse error: html5lib expects 9 bytes ` <!--test`.
        assert_eq!(
            toks(b"<!-- <!--test-->"),
            vec![Token::Comment(b" <!--test")]
        );
        // The first `-->` wins; the rest is text.
        assert_eq!(
            toks(b"<!-- a -->b-->"),
            vec![Token::Comment(b" a "), Token::Text(b"b-->")]
        );
        assert_eq!(
            toks(b"a<!--c-->b"),
            vec![Token::Text(b"a"), Token::Comment(b"c"), Token::Text(b"b")]
        );
    }

    #[test]
    fn bogus_declaration_forms_are_comments() {
        assert_eq!(toks(b"<!x>"), vec![Token::Comment(b"x")]);
        assert_eq!(toks(b"<!>"), vec![Token::Comment(b"")]);
        assert_eq!(
            toks(b"<![CDATA[x]]>"),
            vec![Token::Comment(b"[CDATA[x]]")],
            "CDATA in HTML content is a bogus comment"
        );
        assert_eq!(toks(b"<?xml?>"), vec![Token::Comment(b"?xml?")]);
        assert_eq!(toks(b"<?"), vec![Token::Comment(b"?")]);
    }

    // ---- raw text (script/style) -------------------------------------------

    #[test]
    fn script_raw_text_with_lt_inside() {
        // The adversarial classic: `if (a<b)` must not open a tag.
        assert_eq!(
            toks(b"<script>if (a<b) {}</script>"),
            vec![
                start(b"script"),
                Token::Text(b"if (a<b) {}"),
                Token::EndTag { name: b"script" },
            ]
        );
    }

    #[test]
    fn raw_text_close_is_case_insensitive_with_boundary() {
        assert_eq!(
            toks(b"<SCRIPT>x</SCRIPT>"),
            vec![
                start(b"SCRIPT"),
                Token::Text(b"x"),
                Token::EndTag { name: b"SCRIPT" },
            ]
        );
        // `</scriptx>` is not a close: it stays text until the real one.
        assert_eq!(
            toks(b"<script>a</scriptx>y</script>"),
            vec![
                start(b"script"),
                Token::Text(b"a</scriptx>y"),
                Token::EndTag { name: b"script" },
            ]
        );
        // `</script` at EOF (no boundary byte) is text, no end tag.
        assert_eq!(
            toks(b"<script>a</script"),
            vec![start(b"script"), Token::Text(b"a</script")]
        );
    }

    #[test]
    fn raw_text_unterminated_at_eof() {
        assert_eq!(
            toks(b"<script>alert(1)"),
            vec![start(b"script"), Token::Text(b"alert(1)")]
        );
        assert_eq!(
            toks(b"<script>"),
            vec![start(b"script")],
            "empty raw text emits no empty Text token"
        );
    }

    #[test]
    fn script_content_keeps_entities_raw_and_nested_tags_as_text() {
        let tokens = toks(b"<script>var a = \"&amp;\"; if (x < y) {}<b></b></script>");
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[1], Token::Text(t) if contains_bytes(t, b"&amp;")));
        assert!(matches!(tokens[1], Token::Text(t) if contains_bytes(t, b"<b>")));
    }

    #[test]
    fn style_is_raw_text_too() {
        assert_eq!(
            toks(b"<style>a<b{}</style>"),
            vec![
                start(b"style"),
                Token::Text(b"a<b{}"),
                Token::EndTag { name: b"style" },
            ]
        );
    }

    #[test]
    fn self_closing_script_still_enters_raw_text() {
        assert_eq!(
            toks(b"<script/>x</script>"),
            vec![
                Token::StartTag {
                    name: b"script",
                    attributes: Attributes::EMPTY,
                    self_closing: true,
                },
                Token::Text(b"x"),
                Token::EndTag { name: b"script" },
            ]
        );
    }

    #[test]
    fn non_raw_elements_are_not_raw() {
        // `title`/`textarea` are RCDATA (future work): today they are
        // ordinary elements — documented limitation, asserted here.
        assert_eq!(toks(b"<title><b>x</title>").len(), 4);
    }

    // ---- NUL, case, long input ----------------------------------------------

    #[test]
    fn nul_bytes_are_text_and_stay_verbatim() {
        assert_eq!(toks(b"a\x00b"), vec![Token::Text(b"a\x00b")]);
        // NUL inside a tag name stays raw (documented: HTML5 would use FFFD).
        let (name, ..) = start_tag(b"<a\x00b>");
        assert_eq!(name, b"a\x00b");
    }

    #[test]
    fn long_text_single_token() {
        let mut input = "x".repeat(10_000).into_bytes();
        input.extend_from_slice(b"<b>");
        let tokens = toks(&input);
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], Token::Text(t) if t.len() == 10_000));
        assert!(matches!(tokens[1], Token::StartTag { .. }));
    }

    // ---- newline handling ----------------------------------------------------

    #[test]
    fn cr_in_tags_behaves_like_lf() {
        // Pre-processing equivalence: CR/CRLF must not change token bounds.
        let cr = start_tag(b"<a b=c\r\rd>");
        let lf = start_tag(b"<a b=c\n\nd>");
        assert_eq!(cr, lf);
        assert_eq!(cr.1, vec![(b"b".as_slice(), b"c".as_slice()), (b"d", b"")]);
    }

    #[test]
    fn text_keeps_raw_newlines_and_helper_normalizes() {
        // Zero-copy: payloads keep CR; normalization is opt-in.
        assert_eq!(toks(b"a\r\nb"), vec![Token::Text(b"a\r\nb")]);
        let mut buf = [0u8; 16];
        let n = normalize_newlines_into(b"a\r\nb\rc", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"a\nb\nc");
        let n = normalize_newlines_into(b"no change", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"no change");
        assert_eq!(
            normalize_newlines_into(b"12345678901234567", &mut buf),
            None
        ); // >16
        assert_eq!(normalize_newlines_into(b"", &mut buf), Some(0));
    }

    // ---- character references ------------------------------------------------

    #[test]
    fn decode_named_references() {
        let mut buf = [0u8; 32];
        let cases: [(&[u8], &[u8]); 5] = [
            (b"&amp;", b"&"),
            (b"&lt;", b"<"),
            (b"&gt;", b">"),
            (b"&quot;", b"\""),
            (b"&apos;", b"'"),
        ];
        for (input, expected) in cases {
            let n = decode_entities_into(input, &mut buf).unwrap();
            assert_eq!(&buf[..n], expected, "{input:?}");
        }
        let n = decode_entities_into(b"&nbsp;", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"\xC2\xA0"); // C2 A0
        // Several in a row, with literal text around them.
        let n = decode_entities_into(b"a &amp; &lt; b", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"a & < b");
        // Unknown names stay literal.
        let n = decode_entities_into(b"&copy; &am", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"&copy; &am");
        // Single pass: `&amp;amp;` → `&amp;`.
        let n = decode_entities_into(b"&amp;amp;", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"&amp;");
    }

    #[test]
    fn decode_numeric_references() {
        let mut buf = [0u8; 32];
        let cases: [(&[u8], &[u8]); 6] = [
            (b"&#65;", b"A"),
            (b"&#x41;", b"A"),
            (b"&#0036;", b"$"),
            (b"&#x3f;", b"?"),
            (b"&#65", b"A"), // missing semicolon still decodes (HTML5)
            (b"&#13;", b"\n"),
        ];
        for (input, expected) in cases {
            let n = decode_entities_into(input, &mut buf).unwrap();
            assert_eq!(&buf[..n], expected, "{input:?}");
        }
        let n = decode_entities_into(b"&#00000065;", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"A", "leading zeros are fine");
    }

    #[test]
    fn decode_entity_edge_cases_stay_literal_or_become_fffd() {
        let mut buf = [0u8; 32];
        let ffffd = b"\xEF\xBF\xBD"; // UTF-8 U+FFFD
        let literal: [&[u8]; 7] = [b"&#x;", b"&#;", b"&#x", b"&#", b"&", b"&am", b"&x"];
        for input in literal {
            let n = decode_entities_into(input, &mut buf).unwrap();
            assert_eq!(&buf[..n], input, "{input:?} must stay literal");
        }
        // `&#0;`, surrogates and out-of-range values → U+FFFD (HTML5).
        let fffd_cases: [&[u8]; 4] = [b"&#0;", b"&#xD800;", b"&#1114112;", b"&#x110000;"];
        for input in fffd_cases {
            let n = decode_entities_into(input, &mut buf).unwrap();
            assert_eq!(&buf[..n], ffffd, "{input:?} must decode to U+FFFD");
        }
        // Absurdly long digit runs saturate to FFFD instead of overflowing.
        let n = decode_entities_into(b"&#99999999999999999999999;", &mut buf).unwrap();
        assert_eq!(&buf[..n], ffffd);
        // `&amp` at EOF decodes (in-text rule); `&ampx` is `&x` here.
        let n = decode_entities_into(b"&amp", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"&");
        let n = decode_entities_into(b"&ampx", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"&x");
        // `&` followed by non-name text.
        let n = decode_entities_into(b"a & b", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"a & b");
    }

    #[test]
    fn decode_reports_when_output_buffer_is_too_small() {
        let mut buf = [0u8; 1];
        assert_eq!(decode_entities_into(b"&nbsp;", &mut buf), None); // 2 bytes
        assert_eq!(decode_entities_into(b"a b", &mut buf), None);
        assert_eq!(decode_entities_into(b"&x", &mut buf), None);
        assert_eq!(decode_entities_into(b"x", &mut buf), Some(1));
        let mut buf = [0u8; 0];
        assert_eq!(decode_entities_into(b"", &mut buf), Some(0));
        assert_eq!(decode_entities_into(b"&", &mut buf), None);
    }

    #[test]
    fn tokenizer_keeps_entities_raw_in_text_and_attributes() {
        assert_eq!(toks(b"a &amp; b"), vec![Token::Text(b"a &amp; b")]);
        assert_eq!(
            start_tag(b"<a href=\"&amp;?x=1\">").1,
            vec![(b"href".as_slice(), b"&amp;?x=1".as_slice())]
        );
    }

    // ---- adversarial sweep ---------------------------------------------------

    #[test]
    fn adversarial_corpus_never_panics_and_slices_stay_in_bounds() {
        fn in_bounds(haystack: &[u8], needle: &[u8]) -> bool {
            if needle.is_empty() {
                return true; // empty values are static `b""`
            }
            let lo = haystack.as_ptr() as usize;
            let hi = lo + haystack.len();
            let p = needle.as_ptr() as usize;
            p >= lo && p + needle.len() <= hi
        }

        fn check(haystack: &[u8]) {
            for tok in Tokenizer::new(haystack) {
                match tok {
                    Token::Text(t) | Token::Comment(t) | Token::Doctype(t) => {
                        assert!(in_bounds(haystack, t), "{haystack:?}")
                    }
                    Token::EndTag { name } => {
                        assert!(in_bounds(haystack, name), "{haystack:?}")
                    }
                    Token::StartTag {
                        name, attributes, ..
                    } => {
                        assert!(in_bounds(haystack, name), "{haystack:?}");
                        for attr in attributes.iter() {
                            assert!(in_bounds(haystack, attr.name), "{haystack:?}");
                            assert!(in_bounds(haystack, attr.value), "{haystack:?}");
                        }
                    }
                }
            }
        }

        // Every single byte, every pair with `<`, `&`, quotes and CR.
        for b in 0u8..=255 {
            check(&[b]);
            check(&[b'<', b]);
            check(&[b'<', b, b'>']);
            check(&[b'&', b]);
            check(&[b'"', b, b'"']);
            check(&[b'<', b'a', b'=', b'"', b, b'>']);
            check(&[b'\r', b]);
        }
        // Hostile fragments, each in isolation and at every prefix.
        let fragments: [&[u8]; 28] = [
            b"<",
            b">",
            b"</",
            b"<!",
            b"<!-",
            b"<!--",
            b"<!---",
            b"<!DOCTYPE",
            b"<?",
            b"<?xml",
            b"<a",
            b"<a ",
            b"<a b=",
            b"<a b=\"",
            b"<a b='",
            b"</a",
            b"<script",
            b"<script>",
            b"<script><",
            b"&",
            b"&#",
            b"&#x",
            b"a<b",
            b"<<>>",
            b"<\x00>",
            b"<a\x00b>",
            b"<a b=c\x00d>",
            b"a\r\nb<c\r\nd>",
        ];
        for frag in fragments {
            check(frag);
            for cut in 0..=frag.len() {
                check(&frag[..cut]);
            }
        }
        // Every prefix of an all-byte-values blob (hits every state with
        // whatever came before it).
        let all: Vec<u8> = (0u8..=255).collect();
        for cut in 0..=all.len() {
            check(&all[..cut]);
        }
        // Repeated hostile patterns (state-machine loops).
        let repeat = "<a b=\"x</script><!----!>&#x;".repeat(20);
        check(repeat.as_bytes());
        for cut in [0, 1, 2, 3, 5, 8, 13, 21] {
            check(&repeat.as_bytes()[..cut]);
        }
    }

    #[test]
    fn tokenizer_terminates_on_unbalanced_constructs() {
        let openers: [String; 5] = [
            "<".repeat(500),
            "<!".repeat(300),
            "<a ".repeat(300),
            "<script>".repeat(100),
            "</".repeat(300),
        ];
        for input in openers {
            let count = Tokenizer::new(input.as_bytes()).count();
            assert!(count <= input.len(), "must terminate: {count} tokens");
        }
    }
}
