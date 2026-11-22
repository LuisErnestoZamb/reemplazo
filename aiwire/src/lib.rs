//! Chat API wire types for the AI client (milestone A3 of
//! docs/ai-client.md §2, §6): an OpenAI-compatible `POST
//! /v1/chat/completions` request builder, the non-streaming response
//! parse, the streaming chunk parse and a from-scratch SSE line parser.
//!
//! # Why this crate exists (dependency policy)
//!
//! Everything with wire input lives in a pure, host-tested crate — the
//! same split as `git-pktline`/`ssh-wire`/`editorbuf`. JSON itself is
//! **not** hand-rolled: `serde_json` + `serde` are the reviewed
//! adoptation of docs/ai-client.md §2 (official `no_std` + `alloc`,
//! de-facto standard, RustSec-clean, MIT/Apache-2.0), pinned in
//! `Cargo.lock`. The **SSE parser**, by contrast, is from-scratch under
//! dependency-policy exception (a): every known SSE crate
//! (`eventsource-stream`, `reqwest-eventsource`) needs `futures`/`std`,
//! while the format is ~40 lines of line framing (§3 of the doc); the
//! adversarial suite below is the bar that justifies it.
//!
//! # Failure model
//!
//! All input is untrusted: malformed/truncated/oversized data returns
//! `Err` — never panics, never indexes out of range, never "best
//! effort" parses. This crate is `#![forbid(unsafe_code)]`.
//!
//! # Scope of A3
//!
//! The boot proof exercises request serialization and response parsing
//! end-to-end against xtask's mock. The SSE parser ships (host-tested
//! here) for the A4 streaming milestone; no kernel path feeds it yet.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// One chat message: role (`system`/`user`/`assistant`) plus text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

impl Message {
    /// A message with an explicit role string (the OpenAI dialect
    /// treats roles as free-form strings; unknown roles are the
    /// server's problem to reject, not ours to fabricate).
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Message {
            role: role.into(),
            content: content.into(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self::new("system", content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::new("user", content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new("assistant", content)
    }
}

/// A complete `POST /v1/chat/completions` request body.
///
/// Field order is the serialized order (serde preserves declaration
/// order), pinned byte-exactly by the host suite.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub stream: bool,
    pub temperature: f32,
}

impl ChatRequest {
    /// A new request for `model` with no messages, non-streaming,
    /// temperature 0.0 — grow it with [`Self::system`]/[`Self::user`]/
    /// [`Self::assistant`] and [`Self::stream`]/[`Self::temperature`].
    pub fn new(model: impl Into<String>) -> Self {
        ChatRequest {
            model: model.into(),
            messages: Vec::new(),
            stream: false,
            temperature: 0.0,
        }
    }

    /// Append a message (builder style).
    pub fn message(mut self, message: Message) -> Self {
        self.messages.push(message);
        self
    }

    pub fn system(self, content: impl Into<String>) -> Self {
        self.message(Message::system(content))
    }

    pub fn user(self, content: impl Into<String>) -> Self {
        self.message(Message::user(content))
    }

    pub fn assistant(self, content: impl Into<String>) -> Self {
        self.message(Message::assistant(content))
    }

    /// Request server-side streaming (`text/event-stream` reply).
    pub fn stream(mut self, on: bool) -> Self {
        self.stream = on;
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature;
        self
    }

    /// Serialize to the exact JSON body sent on the wire.
    ///
    /// Fail-closed on a non-finite temperature: serde_json would emit
    /// `null` for NaN/Infinity, which silently changes the request the
    /// server sees — refuse instead.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        if !self.temperature.is_finite() {
            return Err(serde::ser::Error::custom(
                "temperature must be a finite number",
            ));
        }
        serde_json::to_vec(self)
    }
}

/// One `choices[]` entry of a non-streaming completion.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Choice {
    pub message: ChatMessage,
}

/// The assistant message inside a `choices[]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChatMessage {
    pub content: String,
}

/// A complete non-streaming chat completion. Unknown fields (`id`,
/// `object`, `created`, `usage`, `finish_reason`, …) are ignored — a
/// real server always sends more than we read, and serde does that
/// without weakening validation of the fields we *do* read.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChatResponse {
    pub choices: Vec<Choice>,
}

impl ChatResponse {
    /// Parse a response body. Truncated/malformed JSON, wrong types
    /// and missing fields are all `Err`.
    pub fn from_slice(body: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(body)
    }

    /// The first choice's message content, or `None` when the server
    /// sent an empty `choices` array (an error the caller decides
    /// about — fail-closed by never inventing a reply).
    pub fn reply(&self) -> Option<&str> {
        self.choices
            .first()
            .map(|choice| choice.message.content.as_str())
    }
}

/// One `choices[]` entry of a streaming chunk.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChunkChoice {
    pub delta: Delta,
}

/// The incremental `delta` of a streaming chunk — `content` is absent
/// on role-only and `[DONE]`-adjacent chunks, hence `Option`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Delta {
    pub content: Option<String>,
}

/// One streaming chunk (`stream: true` replies). Parsed from the JSON
/// payload of one SSE `data:` event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StreamChunk {
    pub choices: Vec<ChunkChoice>,
}

impl StreamChunk {
    pub fn from_slice(body: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(body)
    }

    /// The first choice's delta text, `None` when the chunk carries no
    /// content (role announcement, empty delta).
    pub fn delta_text(&self) -> Option<&str> {
        self.choices
            .first()
            .and_then(|choice| choice.delta.content.as_deref())
    }
}

// ---------------------------------------------------------------------------
// SSE (text/event-stream) line parser — from-scratch, exception (a)
// ---------------------------------------------------------------------------

/// Longest single SSE line buffered (the `data:` line or any other
/// field/comment). Past this the stream is refused, never truncated.
pub const SSE_LINE_CAP: usize = 8 * 1024;
/// Longest accumulated event payload (multi-line `data:` joined with
/// `\n`). Refused, never truncated.
pub const SSE_DATA_CAP: usize = 16 * 1024;
/// Longest streamed reply text kept (A4): `delta.content` fragments are
/// appended here for display, and bytes past this bound are **counted
/// and dropped** (the stream itself is separately bounded by the
/// caller's total-bytes cap). 4 KiB is far more than a text-mode pane
/// can show and keeps a hostile stream from growing the heap.
pub const STREAM_TEXT_CAP: usize = 4 * 1024;

/// What consuming one SSE event did to a [`StreamText`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFlow {
    /// More events may follow.
    Continue,
    /// `data: [DONE]` was seen: the stream is over (later events are
    /// ignored by [`Sse`] itself).
    Done,
}

/// Why a streamed event was refused. Fail-closed: the caller stops the
/// exchange, it never renders a half-understood payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// A `data:` payload that was not a chunk object we can read.
    BadPayload,
}

/// Accumulates the `delta.content` fragments of an SSE completion in
/// arrival order — the A4 counterpart of [`ChatResponse`] for the
/// streaming path.
///
/// This type is deliberately pure: it consumes already-dispatched
/// [`SseEvent`]s (so the SSE framing stays in [`Sse`]) and never
/// touches a socket, a screen or a clock. The kernel drives it from the
/// transport loop and renders [`StreamText::text`] as it grows; that is
/// exactly what the host tests below exercise.
#[derive(Debug, Default)]
pub struct StreamText {
    /// Accumulated, bounded reply text (fragments appended verbatim —
    /// sanitizing for display is the caller's job).
    text: String,
    /// Content-bearing fragments seen.
    deltas: usize,
    /// At least one fragment did not fit [`STREAM_TEXT_CAP`].
    truncated: bool,
    /// `[DONE]` was dispatched.
    done: bool,
}

impl StreamText {
    pub fn new() -> Self {
        Self::default()
    }

    /// The reply text accumulated so far.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// How many `delta.content` fragments were appended (fragments
    /// past the cap still count — the count is a wire observation).
    pub fn deltas(&self) -> usize {
        self.deltas
    }

    /// Did any fragment exceed the text bound?
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Has `data: [DONE]` arrived?
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Consume one dispatched event.
    ///
    /// - [`SseEvent::Done`] marks the stream complete and returns
    ///   [`StreamFlow::Done`] (idempotent: a second `Done` is the same).
    /// - [`SseEvent::Data`] must hold exactly one streamed chunk (one
    ///   JSON object); the delta's `content` (when present) is appended
    ///   in arrival order, bounded by [`STREAM_TEXT_CAP`]. A payload
    ///   that does not parse as a [`StreamChunk`] is
    ///   [`StreamError::BadPayload`] — never a silent skip.
    pub fn push(&mut self, event: &SseEvent) -> Result<StreamFlow, StreamError> {
        match event {
            SseEvent::Done => {
                self.done = true;
                Ok(StreamFlow::Done)
            }
            SseEvent::Data(payload) => {
                let chunk = StreamChunk::from_slice(payload.as_bytes())
                    .map_err(|_| StreamError::BadPayload)?;
                if let Some(delta) = chunk.delta_text() {
                    self.deltas = self.deltas.saturating_add(1);
                    let room = STREAM_TEXT_CAP.saturating_sub(self.text.len());
                    let prefix = prefix_at_most(delta, room);
                    self.text.push_str(prefix);
                    if prefix.len() < delta.len() {
                        self.truncated = true;
                    }
                }
                Ok(StreamFlow::Continue)
            }
        }
    }
}

/// The longest UTF-8 prefix of `s` that is at most `max` bytes long —
/// never splits a code point (a split would make the accumulated text
/// invalid, and the caller's sanitizer works on `str`).
fn prefix_at_most(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = 0usize;
    for (index, _) in s.char_indices() {
        if index > max {
            break;
        }
        end = index;
    }
    // `char_indices` may stop before the first char when max < 1:
    // then only the empty prefix fits.
    s.get(..end).unwrap_or("")
}

/// One dispatched SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseEvent {
    /// A complete event's `data` payload (multi-line data joined per
    /// spec with `\n`).
    Data(String),
    /// The `data: [DONE]` stream terminator.
    Done,
}

/// Why the SSE parser refused the stream. Every variant is
/// fail-closed: stop, discard, never "parse what we can".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseError {
    /// A line grew past [`SSE_LINE_CAP`] without its newline.
    LineTooLarge,
    /// Accumulated event data grew past [`SSE_DATA_CAP`].
    DataTooLarge,
    /// A `data:` payload that is not valid UTF-8.
    BadUtf8,
}

/// Incremental SSE line parser: feed bytes in, get events out.
///
/// Framing (WHATWG event stream): lines end with LF or CRLF; a blank
/// line dispatches the accumulated `data:` lines as one event; `data:`
/// values keep exactly one leading space stripped (`data:x` and
/// `data: x` both mean `x`); lines starting with `:` are comments;
/// fields other than `data` (`event:`, `id:`, `retry:`) are accepted
/// and ignored (A4 only needs payloads); `data: [DONE]` dispatches
/// [`SseEvent::Done`] and the parser then ignores the rest of the
/// stream. An event with no `data:` field dispatches nothing.
///
/// Per spec, EOF ([`Sse::finish`]) **discards** a pending unterminated
/// line and an undispatched event — a stream that ends without a blank
/// line does not produce a half event.
#[derive(Debug, Default)]
pub struct Sse {
    /// Current line being accumulated (without its terminator).
    line: Vec<u8>,
    /// Accumulated `data:` payload of the current event.
    data: Vec<u8>,
    /// At least one `data:` field seen for the current event.
    has_data: bool,
    /// `[DONE]` seen: the stream is over, further input is ignored.
    done: bool,
}

impl Sse {
    pub fn new() -> Self {
        Self::default()
    }

    /// True once `data: [DONE]` has been dispatched.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Feed a chunk of the event stream, appending any completed events
    /// to `out`. Splits are safe at **any** byte (the suite feeds one
    /// byte at a time).
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<SseEvent>) -> Result<(), SseError> {
        for &byte in input {
            if self.done {
                return Ok(()); // stream over: ignore trailing bytes
            }
            match byte {
                b'\n' => {
                    let line = core::mem::take(&mut self.line);
                    self.process_line(&line, out)?;
                }
                _ => {
                    if self.line.len() >= SSE_LINE_CAP {
                        return Err(SseError::LineTooLarge);
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(())
    }

    /// End of stream: discard the pending (unterminated) line and any
    /// undispatched event, per the WHATWG event-stream spec — an EOF
    /// never produces a half event. Subsequent feeds still work only
    /// if no terminator was pending; this mainly resets line state.
    pub fn finish(&mut self) {
        self.line.clear();
        self.data.clear();
        self.has_data = false;
    }

    /// Process one complete line (terminator already stripped).
    fn process_line(&mut self, line: &[u8], out: &mut Vec<SseEvent>) -> Result<(), SseError> {
        // Tolerate CRLF as well as LF: the CR of a CRLF pair is the
        // last byte of the line buffer.
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        if line.is_empty() {
            // Blank line: dispatch the accumulated event.
            if self.has_data {
                self.has_data = false;
                if self.data == b"[DONE]" {
                    self.data.clear();
                    self.done = true;
                    out.push(SseEvent::Done);
                } else {
                    let text = core::str::from_utf8(&self.data)
                        .map_err(|_| SseError::BadUtf8)?
                        .to_string();
                    self.data.clear();
                    out.push(SseEvent::Data(text));
                }
            }
            return Ok(());
        }

        if line.starts_with(b":") {
            return Ok(()); // comment line
        }

        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Ok(()); // field without a colon is ignored (spec)
        };
        let name = &line[..colon];
        if name != b"data" {
            return Ok(()); // event:/id:/retry: — accepted, ignored (A3/A4)
        }
        // `data: value` strips exactly one leading space; `data:value`
        // keeps its first byte as-is.
        let value = match line.get(colon + 1) {
            Some(b' ') => &line[colon + 2..],
            _ => &line[colon + 1..],
        };
        if self.has_data && self.data.len() + 1 + value.len() > SSE_DATA_CAP {
            return Err(SseError::DataTooLarge);
        }
        if self.has_data {
            self.data.push(b'\n'); // multi-line data joins with LF (spec)
        }
        self.data.extend_from_slice(value);
        self.has_data = true;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Adversarial host tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    /// A realistic canned OpenAI-style reply — the exact shape a real
    /// endpoint returns (extra fields everywhere we don't read).
    const REALISTIC: &[u8] = br#"{
        "id": "chatcmpl-9xAbCdEfGhIjKlMnOpQrStUvWxYz",
        "object": "chat.completion",
        "created": 1763712000,
        "model": "gpt-4o-mini-2024-07-18",
        "system_fingerprint": "fp_0f03d4ac1e",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "reemplazo: mock reply ok",
                    "refusal": null
                },
                "logprobs": null,
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": 8,
            "total_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 0},
            "completion_tokens_details": {"reasoning_tokens": 0, "audio_tokens": 0}
        }
    }"#;

    // -- request serialization ------------------------------------------------

    #[test]
    fn request_serializes_byte_exactly() {
        let request = ChatRequest::new("reemplazo-mock")
            .system("You are reemplazo's assistant.")
            .user("hello from reemplazo")
            .temperature(0.7);
        let json = request.to_json().expect("serialize");
        let expected = concat!(
            r#"{"model":"reemplazo-mock","messages":["#,
            r#"{"role":"system","content":"You are reemplazo's assistant."},"#,
            r#"{"role":"user","content":"hello from reemplazo"}],"#,
            r#""stream":false,"temperature":0.7}"#
        );
        assert_eq!(core::str::from_utf8(&json).expect("utf8"), expected);
    }

    #[test]
    fn request_default_flags_serialize() {
        let json = ChatRequest::new("m").to_json().expect("serialize");
        assert_eq!(
            core::str::from_utf8(&json).expect("utf8"),
            r#"{"model":"m","messages":[],"stream":false,"temperature":0.0}"#
        );
        let streaming = ChatRequest::new("m").stream(true).to_json().expect("s");
        assert!(
            core::str::from_utf8(&streaming)
                .expect("utf8")
                .contains(r#""stream":true"#)
        );
    }

    #[test]
    fn request_round_trips_messages_in_order() {
        let request = ChatRequest::new("m").system("s").user("u").assistant("a");
        let json = request.to_json().expect("serialize");
        // serde can read back what we wrote (same crate both sides).
        let value: serde_json::Value = serde_json::from_slice(&json).expect("self-parse");
        let messages = value["messages"].as_array().expect("array");
        let roles: Vec<&str> = messages
            .iter()
            .map(|m| m["role"].as_str().expect("role"))
            .collect();
        assert_eq!(roles, ["system", "user", "assistant"]);
    }

    #[test]
    fn request_refuses_non_finite_temperature() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let request = ChatRequest::new("m").temperature(bad);
            assert!(request.to_json().is_err(), "accepted temperature {bad:?}");
        }
    }

    #[test]
    fn request_serializes_control_characters_as_json_escapes() {
        let request = ChatRequest::new("m").user("a\"b\nc\\d");
        let json = request.to_json().expect("serialize");
        let text = core::str::from_utf8(&json).expect("utf8");
        assert!(text.contains(r#"a\"b\nc\\d"#), "unescaped in {text:?}");
    }

    // -- response parsing -----------------------------------------------------

    #[test]
    fn response_parses_realistic_reply() {
        let response = ChatResponse::from_slice(REALISTIC).expect("parse");
        assert_eq!(response.reply(), Some("reemplazo: mock reply ok"));
        assert_eq!(response.choices.len(), 1);
        assert_eq!(
            response.choices[0].message.content,
            "reemplazo: mock reply ok"
        );
    }

    #[test]
    fn response_missing_choices_is_an_error() {
        for bad in [
            &br#"{"id":"x"}"#[..],
            &br#"{"choices":null}"#[..],
            &br#"{"object":"chat.completion"}"#[..],
        ] {
            assert!(ChatResponse::from_slice(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn response_empty_choices_yields_no_reply() {
        let response = ChatResponse::from_slice(br#"{"choices":[]}"#).expect("parse");
        assert_eq!(response.reply(), None);
    }

    #[test]
    fn response_wrong_types_are_refused() {
        for bad in [
            &br#"{"choices":"nope"}"#[..],
            &br#"{"choices":[{}]}"#[..],
            &br#"{"choices":[{"message":{}}]}"#[..],
            &br#"{"choices":[{"message":{"content":42}}]}"#[..],
            &br#"{"choices":[{"message":{"content":null}}]}"#[..],
            &br#"{"choices":[{"message":{"content":["a"]}}]}"#[..],
        ] {
            assert!(ChatResponse::from_slice(bad).is_err(), "accepted {bad:?}");
        }
        // Unknown field *beside* a valid `content` must NOT break the
        // parse (real servers pad their payloads).
        assert!(
            ChatResponse::from_slice(br#"{"choices":[{"message":{"content":"ok","extra":1}}]}"#)
                .is_ok()
        );
    }

    #[test]
    fn response_unknown_fields_are_ignored() {
        // `extra` beside `content` must not break the parse.
        let response = ChatResponse::from_slice(
            br#"{"choices":[{"message":{"content":"hi","extra":1}}],"usage":{}}"#,
        )
        .expect("parse");
        assert_eq!(response.reply(), Some("hi"));
    }

    #[test]
    fn response_truncated_json_is_an_error() {
        let full = REALISTIC;
        // Feed every truncation length of a realistic body: none may
        // parse (the shortest prefixes are not JSON either).
        for cut in [1usize, 10, 40, full.len() / 2, full.len() - 2] {
            let partial = &full[..cut];
            let result = ChatResponse::from_slice(partial);
            // A cut that happens to land after the closing brace would
            // be a different test; `REALISTIC` only ends at len().
            assert!(result.is_err(), "parsed at cut {cut}");
        }
        assert!(ChatResponse::from_slice(&full[..full.len() - 1]).is_err());
    }

    #[test]
    fn response_malformed_and_non_utf8_bodies_are_errors() {
        for bad in [
            &b"not json at all"[..],
            &b"{}"[..],
            &b"[1,2,3]"[..],
            &b"\"just a string\""[..],
            &[0xFF, 0xFE, b'{', b'}'][..],
            &b"{\"choices\":[{\"message\":{\"content\":\"\xff\xfe\"}}]}"[..],
            &b"\xef\xbb\xbf{\"choices\":[]}"[..], // BOM: refused, not skipped
        ] {
            assert!(ChatResponse::from_slice(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn response_huge_numbers_are_never_materialized() {
        // Unknown fields are skipped lexically (serde_json's
        // `ignore_value` is an iterative scanner — verified in source,
        // no recursion, no number conversion), so absurd magnitudes in
        // fields we do not read are accepted *and never stored*: the
        // kernel additionally caps the whole body at 64 KiB.
        for body in [
            &br#"{"choices":[],"usage":{"total_tokens":99999999999999999999999}}"#[..],
            &br#"{"choices":[],"n":1e400}"#[..],
            &br#"{"choices":[],"n":-99999999999999999999999999}"#[..],
        ] {
            assert!(ChatResponse::from_slice(body).is_ok(), "refused {body:?}");
        }
        // Materializing that same out-of-range number fails closed
        // (serde_json refuses it as a typed/Value number) — so a future
        // typed field can never silently hold Infinity…
        assert!(serde_json::from_slice::<serde_json::Value>(br#"{"n":1e400}"#).is_err());
        // …and a number where a *string* is expected is an error today.
        assert!(
            ChatResponse::from_slice(br#"{"choices":[{"message":{"content":1e400}}]}"#).is_err()
        );
    }

    #[test]
    fn response_deep_nesting_fails_closed_where_typed() {
        // Deep nesting inside unknown fields: skipped by serde_json's
        // *iterative* ignore path (no recursion, no stack growth —
        // verified against serde_json's `ignore_value` source), so a
        // hostile body cannot blow the kernel stack here. Accepted.
        let mut deep = String::from("{\"choices\":[],\"x\":");
        for _ in 0..1000 {
            deep.push('[');
        }
        for _ in 0..1000 {
            deep.push(']');
        }
        deep.push('}');
        assert!(ChatResponse::from_slice(deep.as_bytes()).is_ok());
        // Where we *read* structure, the depth is bounded: >128 levels
        // of typed array is refused by serde_json's recursion limit.
        let mut typed = String::from("{\"choices\":");
        for _ in 0..200 {
            typed.push('[');
        }
        typed.push(']');
        typed.push('}');
        assert!(ChatResponse::from_slice(typed.as_bytes()).is_err());
        // And a Value materialization is depth-limited too.
        let mut value = String::from("{\"x\":");
        for _ in 0..200 {
            value.push('[');
        }
        for _ in 0..200 {
            value.push(']');
        }
        value.push('}');
        assert!(serde_json::from_slice::<serde_json::Value>(value.as_bytes()).is_err());
    }

    // -- streaming chunks -----------------------------------------------------

    #[test]
    fn chunk_parses_delta_content() {
        let chunk =
            StreamChunk::from_slice(br#"{"choices":[{"index":0,"delta":{"content":"hel"}}]}"#)
                .expect("parse");
        assert_eq!(chunk.delta_text(), Some("hel"));
    }

    #[test]
    fn chunk_without_content_is_none_not_error() {
        // First chunk of a real stream: role announcement, no content
        // key at all (`Option` field absent → None, not an error).
        let chunk = StreamChunk::from_slice(
            br#"{"choices":[{"delta":{"role":"assistant"}}],"object":"x"}"#,
        )
        .expect("parse");
        assert_eq!(chunk.delta_text(), None);
        // Empty delta object likewise (content absent).
        let chunk = StreamChunk::from_slice(br#"{"choices":[{"delta":{}}]}"#).expect("parse");
        assert_eq!(chunk.delta_text(), None);
        // Empty choices array likewise.
        let chunk = StreamChunk::from_slice(br#"{"choices":[]}"#).expect("parse");
        assert_eq!(chunk.delta_text(), None);
        // Wrong shape still fails closed: missing delta, missing choices.
        assert!(StreamChunk::from_slice(br#"{"choices":[{}]}"#).is_err());
        assert!(StreamChunk::from_slice(br#"{"choices":[{"delta":null}]}"#).is_err());
        assert!(StreamChunk::from_slice(br#"{}"#).is_err());
    }

    // -- SSE parsing ----------------------------------------------------------

    fn feed_whole(input: &str) -> Result<Vec<SseEvent>, SseError> {
        let mut sse = Sse::new();
        let mut out = Vec::new();
        sse.feed(input.as_bytes(), &mut out)?;
        sse.finish();
        Ok(out)
    }

    #[test]
    fn sse_parses_simple_events_lf_and_crlf() {
        let lf = feed_whole("data: one\n\ndata: two\n\n").expect("lf");
        assert_eq!(
            lf,
            vec![SseEvent::Data("one".into()), SseEvent::Data("two".into())]
        );
        let crlf = feed_whole("data: one\r\n\r\ndata: two\r\n\r\n").expect("crlf");
        assert_eq!(crlf, lf, "CRLF must mean exactly what LF means");
    }

    #[test]
    fn sse_byte_at_a_time_split_is_safe() {
        let input = "data: hel\r\n\ndata: lo world\n\ndata: [DONE]\n\n";
        let mut sse = Sse::new();
        let mut out = Vec::new();
        for byte in input.bytes() {
            sse.feed(&[byte], &mut out).expect("feed");
        }
        assert_eq!(
            out,
            vec![
                SseEvent::Data("hel".into()),
                SseEvent::Data("lo world".into()),
                SseEvent::Done
            ]
        );
        assert!(sse.is_done());
    }

    #[test]
    fn sse_data_without_space_keeps_value_intact() {
        // `data:x` (no space) and `data: x` both mean `x`; `data:  x`
        // means ` x` (only ONE space is stripped — spec).
        assert_eq!(
            feed_whole("data:hello\n\n").expect("nospace"),
            vec![SseEvent::Data("hello".into())]
        );
        assert_eq!(
            feed_whole("data: hello\n\n").expect("space"),
            vec![SseEvent::Data("hello".into())]
        );
        assert_eq!(
            feed_whole("data:  hello\n\n").expect("twospace"),
            vec![SseEvent::Data(" hello".into())]
        );
        // Empty value still dispatches an event.
        assert_eq!(
            feed_whole("data:\n\n").expect("empty"),
            vec![SseEvent::Data(String::new())]
        );
    }

    #[test]
    fn sse_multiline_data_joins_with_newline() {
        assert_eq!(
            feed_whole("data: line1\ndata: line2\ndata: line3\n\n").expect("multi"),
            vec![SseEvent::Data("line1\nline2\nline3".into())]
        );
    }

    #[test]
    fn sse_done_terminator_and_stream_tail_are_absorbed() {
        let events = feed_whole("data: {\"a\":1}\n\ndata: [DONE]\n\ndata: {\"b\":2}\n\nmore\n\n")
            .expect("done");
        assert_eq!(
            events,
            vec![SseEvent::Data("{\"a\":1}".into()), SseEvent::Done]
        );
    }

    #[test]
    fn sse_event_without_data_dispatches_nothing() {
        // An `event:`-only block with a blank line: no data → nothing.
        assert_eq!(
            feed_whole("event: ping\nid: 5\nretry: 100\n\n").expect("nodata"),
            Vec::new()
        );
        // A comment-only block likewise.
        assert_eq!(feed_whole(": keep-alive\n\n").expect("comment"), Vec::new());
        // But data after that still works.
        assert_eq!(
            feed_whole("event: ping\n\ndata: after\n\n").expect("after"),
            vec![SseEvent::Data("after".into())]
        );
    }

    #[test]
    fn sse_field_without_colon_and_unknown_fields_are_ignored() {
        assert_eq!(
            feed_whole("garbage\nevent: x\ndata: kept\n\n").expect("mixed"),
            vec![SseEvent::Data("kept".into())]
        );
    }

    #[test]
    fn sse_finish_discards_pending_event() {
        // Spec: EOF discards undispatched data — a stream that just
        // ends does not fabricate a half event.
        let mut sse = Sse::new();
        let mut out = Vec::new();
        sse.feed(b"data: pending\n", &mut out).expect("feed");
        assert!(out.is_empty(), "undispatched data must not emit early");
        sse.finish();
        assert!(out.is_empty(), "EOF must discard, not dispatch");
        // A complete line *without* the blank line: same discard.
        sse.feed(b"data: done-line", &mut out).expect("feed");
        sse.finish();
        assert!(out.is_empty());
    }

    #[test]
    fn sse_oversized_line_is_refused_not_truncated() {
        let mut sse = Sse::new();
        let mut out = Vec::new();
        let mut result = Ok(());
        let mut fed = 0usize;
        let long = vec![b'a'; SSE_LINE_CAP + 64];
        for byte in long {
            result = sse.feed(&[byte], &mut out);
            fed += 1;
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(SseError::LineTooLarge));
        // Refused at the cap — not one buffer's worth of silent loss.
        assert!(fed <= SSE_LINE_CAP + 1, "refused only after {fed} bytes");
    }

    #[test]
    fn sse_oversized_event_data_is_refused() {
        // Many short data lines accumulating past SSE_DATA_CAP.
        let mut sse = Sse::new();
        let mut out = Vec::new();
        let line = format!("data: {}\n", "x".repeat(1024));
        let mut result = Ok(());
        for _ in 0..32 {
            result = sse.feed(line.as_bytes(), &mut out);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(SseError::DataTooLarge));
        assert!(out.is_empty(), "a refused event must not half-dispatch");
    }

    #[test]
    fn sse_non_utf8_data_is_refused() {
        // Refused at dispatch (the blank line), not silently lossy:
        let mut sse = Sse::new();
        let mut out = Vec::new();
        assert_eq!(
            sse.feed(b"data: \xff\xfe\n\n", &mut out),
            Err(SseError::BadUtf8)
        );
        assert!(out.is_empty(), "a refused payload must not dispatch");
        // Same refusal when the newline arrives in a later chunk.
        let mut sse = Sse::new();
        let mut out = Vec::new();
        assert_eq!(sse.feed(b"data: \xff\n", &mut out), Ok(()));
        assert_eq!(sse.feed(b"\n", &mut out), Err(SseError::BadUtf8));
        assert!(out.is_empty());
    }

    #[test]
    fn sse_json_payload_parses_as_chunk_after_dispatch() {
        // The A4 path: SSE event → JSON → StreamChunk.
        let events = feed_whole(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n",
        )
        .expect("feed");
        let first = events.first().expect("event");
        let payload = match first {
            SseEvent::Data(text) => text.as_bytes(),
            other => panic!("unexpected event {other:?}"),
        };
        let chunk = StreamChunk::from_slice(payload).expect("chunk");
        assert_eq!(chunk.delta_text(), Some("hi"));
    }

    // -- streamed text accumulation (A4) --------------------------------------

    fn stream_feed(stream: &mut StreamText, payloads: &[&str]) -> Vec<StreamFlow> {
        let mut flows = Vec::new();
        for payload in payloads {
            let event = SseEvent::Data(String::from(*payload));
            flows.push(stream.push(&event).expect("valid chunk"));
        }
        flows
    }

    #[test]
    fn stream_text_accumulates_deltas_in_arrival_order() {
        let mut stream = StreamText::new();
        let flows = stream_feed(
            &mut stream,
            &[
                r#"{"choices":[{"index":0,"delta":{"role":"assistant"}}]}"#,
                r#"{"choices":[{"index":0,"delta":{"content":"reem"}}]}"#,
                r#"{"choices":[{"index":0,"delta":{"content":"plazo: "}}]}"#,
                r#"{"choices":[{"index":0,"delta":{"content":"ok"}}]}"#,
            ],
        );
        assert_eq!(flows, vec![StreamFlow::Continue; 4]);
        assert_eq!(stream.text(), "reemplazo: ok");
        // The role-only chunk is not a content fragment.
        assert_eq!(stream.deltas(), 3);
        assert!(!stream.truncated());
        assert!(!stream.is_done());
        stream.push(&SseEvent::Done).expect("done");
        assert!(stream.is_done());
        // Idempotent: a second terminator changes nothing.
        assert_eq!(stream.push(&SseEvent::Done), Ok(StreamFlow::Done));
        assert_eq!(stream.text(), "reemplazo: ok");
    }

    #[test]
    fn stream_text_done_ends_the_flow_not_the_text() {
        let mut stream = StreamText::new();
        stream_feed(&mut stream, &[r#"{"choices":[{"delta":{"content":"a"}}]}"#]);
        assert_eq!(stream.push(&SseEvent::Done), Ok(StreamFlow::Done));
        assert_eq!(stream.text(), "a");
    }

    #[test]
    fn stream_text_refuses_non_chunk_payloads() {
        for bad in [
            "",
            "not json",
            "[DONE] trailing",
            r#"{"choices":"nope"}"#,
            r#"{"choices":[{"delta":null}]}"#,
            r#"{"id":"x"}"#,
            "{\"choices\":[{\"delta\":{\"content\":1}}]}",
        ] {
            let mut stream = StreamText::new();
            assert_eq!(
                stream.push(&SseEvent::Data(String::from(bad))),
                Err(StreamError::BadPayload),
                "accepted {bad:?}"
            );
            assert_eq!(stream.text(), "", "a refused payload left text behind");
            assert_eq!(stream.deltas(), 0);
        }
    }

    #[test]
    fn stream_text_delta_without_content_counts_nothing() {
        let mut stream = StreamText::new();
        stream_feed(
            &mut stream,
            &[
                r#"{"choices":[]}"#,
                r#"{"choices":[{"delta":{}}]}"#,
                r#"{"choices":[{"delta":{"content":null}}]}"#,
            ],
        );
        assert_eq!(stream.text(), "");
        assert_eq!(stream.deltas(), 0);
        assert!(!stream.truncated());
    }

    #[test]
    fn stream_text_is_bounded_and_counts_dropped_bytes() {
        let fragment = "x".repeat(1024);
        let payload = format!(r#"{{"choices":[{{"delta":{{"content":"{fragment}"}}}}]}}"#);
        let mut stream = StreamText::new();
        for _ in 0..8 {
            stream
                .push(&SseEvent::Data(payload.clone()))
                .expect("chunk");
        }
        assert_eq!(stream.text().len(), STREAM_TEXT_CAP);
        assert!(stream.text().bytes().all(|b| b == b'x'));
        assert!(stream.truncated(), "the cap must be recorded, not hidden");
        // Every fragment was observed on the wire even past the cap.
        assert_eq!(stream.deltas(), 8);
    }

    #[test]
    fn stream_text_never_splits_a_code_point() {
        let mut stream = StreamText::new();
        // Fill to one byte below the cap, then offer a two-byte `é`.
        let filler = "y".repeat(STREAM_TEXT_CAP - 1);
        let payload = format!(r#"{{"choices":[{{"delta":{{"content":"{filler}"}}}}]}}"#);
        stream.push(&SseEvent::Data(payload)).expect("filler");
        assert_eq!(stream.text().len(), STREAM_TEXT_CAP - 1);
        stream
            .push(&SseEvent::Data(String::from(
                r#"{"choices":[{"delta":{"content":"é"}}]}"#,
            )))
            .expect("accented");
        assert_eq!(stream.text().len(), STREAM_TEXT_CAP - 1);
        assert!(stream.truncated());
        // The accumulated text is still valid UTF-8 by construction.
        assert!(core::str::from_utf8(stream.text().as_bytes()).is_ok());
        // A fragment that fits exactly is appended whole.
        let mut exact = StreamText::new();
        let filler = "z".repeat(STREAM_TEXT_CAP);
        let payload = format!(r#"{{"choices":[{{"delta":{{"content":"{filler}"}}}}]}}"#);
        exact.push(&SseEvent::Data(payload)).expect("exact");
        assert_eq!(exact.text().len(), STREAM_TEXT_CAP);
        assert!(!exact.truncated());
    }

    #[test]
    fn stream_end_to_end_sse_events_to_text() {
        // The whole A4 path on one buffer: raw SSE → Sse → StreamText,
        // split at every byte boundary of the stream.
        let stream_bytes = b"data: {\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n\
              data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n\
              data: [DONE]\n\n";
        for split in 0..=stream_bytes.len() {
            let mut sse = Sse::new();
            let mut text = StreamText::new();
            let mut out = Vec::new();
            for part in [&stream_bytes[..split], &stream_bytes[split..]] {
                sse.feed(part, &mut out).expect("feed");
                for event in out.drain(..) {
                    let _ = text.push(&event).expect("event");
                }
            }
            assert_eq!(text.text(), "hello", "split at {split}");
            assert_eq!(text.deltas(), 2);
            assert!(text.is_done());
        }
    }

    #[test]
    fn sse_split_across_arbitrary_chunk_boundaries() {
        // Feed the same stream in two halves at *every* split point.
        let input = b"data: abc\r\n\r\ndata: [DONE]\n\n";
        for split in 0..=input.len() {
            let mut sse = Sse::new();
            let mut out = Vec::new();
            sse.feed(&input[..split], &mut out).expect("first half");
            sse.feed(&input[split..], &mut out).expect("second half");
            assert_eq!(
                out,
                vec![SseEvent::Data("abc".into()), SseEvent::Done],
                "split at {split}"
            );
        }
    }
}
