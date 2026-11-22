//! In-memory editor buffer for milestone A2 (docs/ai-client.md §5, §7):
//! a **gap buffer over `Vec<u8>`** with a line index and a bounded
//! undo/redo history. Zero dependencies, `forbid(unsafe_code)`.
//!
//! # Why from scratch — dependency-policy exceptions (a) and (b)
//!
//! Recorded in docs/ai-client.md §5: no known maintained `no_std` rope
//! exists — `ropey` is std-only (verified in its published source),
//! `crop` is std-ecosystem, the `sp-ropey` fork is abandoned — which is
//! exception (a); and for our actual workload (source files bounded to
//! [`MAX_BYTES`] on a 2.9 GB / 5400 rpm machine) a flat buffer uses less
//! memory than a rope tree, is trivially `#![forbid(unsafe_code)]`, and
//! is far easier to drive adversarially against a plain-`Vec` oracle,
//! which is exception (b). The commit for this milestone cites both.
//!
//! # Design decisions (and their tradeoffs)
//!
//! - **Gap buffer**: `data: Vec<u8>` holds `front ++ gap ++ back`; the
//!   logical offset → physical index mapping skips the gap. Every edit
//!   first [`Buffer::move_gap`]s the gap to the edit point, so edits at
//!   the same place are O(edit) amortized; [`Buffer::compact`] (also
//!   called out explicitly by the tests) normalizes the layout by moving
//!   the gap to the end and dropping the dead bytes. All offset
//!   arithmetic is checked (`checked_add`/range guards) — no public path
//!   can overflow, and the internal raw operations fail soft on an
//!   impossible invariant rather than panic (the kernel never panics on
//!   user input).
//! - **Line index**: line-start offsets are **recomputed from scratch
//!   after every accepted edit** (O(len) scan). Documented tradeoff:
//!   incremental maintenance is O(lines) but doubles the invariants to
//!   prove; at our bounds (≤ 1 MiB, Core2 2.16 GHz) a full re-scan per
//!   keystroke is sub-millisecond, and the simple implementation is the
//!   one the oracle test can check exhaustively. Files are bounded —
//!   this is honest complexity, not a hidden `O(n)` bomb.
//! - **Undo/redo**: **inverse-edit records**, not snapshots. Each record
//!   keeps the exact bytes the edit removed *and* inserted, so undo and
//!   redo are byte-exact LIFO replays (no ambiguity about which kind of
//!   edit it was). Snapshots would cost O(len) *per entry* — 64 snapshots
//!   of a 1 MiB buffer is 64 MiB, far too much for our 16 MiB heap;
//!   records cost O(edit size). The stack is bounded twice over: at most
//!   [`HISTORY_MAX`] entries and at most [`HISTORY_BYTES`] of payload
//!   (oldest evicted first), so history memory is capped at
//!   `max(HISTORY_BYTES, largest single edit)` — a single edit can never
//!   exceed [`MAX_BYTES`], and undoing an edit *larger* than the byte cap
//!   is still possible while it is the only entry (see
//!   `oversized_single_edit_stays_undoable`).
//! - **UTF-8**: every edit validates that both offsets are char
//!   boundaries of the (always valid) buffer and that inserted text is
//!   valid UTF-8 (`&str` by construction). Mid-scalar offsets are
//!   refused with [`EditError::NotCharBoundary`] — never a panic, never
//!   a split scalar.
//!
//! The kernel-side viewport/cursor glue lives in `kernel/src/apps/editor.rs`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Hard cap on buffer contents: 1 MiB per buffer. The kernel heap is
/// 16 MiB (`kernel/src/heap.rs`) and hosts two ratatui frame buffers
/// plus the network chain, so an editor buffer gets an explicit bound
/// (docs/ai-client.md §8 "Bounded memory").
pub const MAX_BYTES: usize = 1 << 20;

/// Undo stack cap in entries (the "last N operations" bound).
pub const HISTORY_MAX: usize = 64;

/// Undo/redo payload cap in bytes (removed + inserted bytes across both
/// stacks). Oldest entries are evicted first when either cap is hit.
pub const HISTORY_BYTES: usize = 256 * 1024;

/// Why an edit was refused. Fail-closed: an `Err` leaves the buffer
/// byte-identical to before the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditError {
    /// Offset beyond the logical end, or a range that runs past it.
    OutOfBounds,
    /// An offset lands inside a multi-byte UTF-8 scalar.
    NotCharBoundary,
    /// The insert would push the buffer past [`MAX_BYTES`].
    TooLarge,
}

impl core::fmt::Display for EditError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::OutOfBounds => "offset out of bounds",
            Self::NotCharBoundary => "offset lands inside a multi-byte character",
            Self::TooLarge => "buffer would exceed its byte cap",
        })
    }
}

impl core::error::Error for EditError {}

/// One history entry: the bytes the edit removed from, and inserted
/// into, the buffer at `at`. Undo = remove `inserted` then insert
/// `removed`; redo = the other way round. Exactly one of the two payloads
/// is empty for a pure insert or a pure delete, so the entry costs the
/// size of the edit, not the size of the buffer.
#[derive(Debug, Clone)]
struct Edit {
    at: usize,
    removed: Vec<u8>,
    inserted: Vec<u8>,
}

impl Edit {
    fn payload(&self) -> usize {
        self.removed.len() + self.inserted.len()
    }
}

/// The text buffer: gap buffer + line index + bounded undo/redo.
#[derive(Debug)]
pub struct Buffer {
    /// `front [0, gap_start) ++ gap [gap_start, gap_end) ++ back
    /// [gap_end, data.len())`; logical length is `data.len() - gap`.
    data: Vec<u8>,
    gap_start: usize,
    gap_end: usize,
    /// Logical byte offset of the start of every line; `lines[0] == 0`
    /// always, and a trailing `\n` therefore yields an empty last line.
    lines: Vec<usize>,
    undo: VecDeque<Edit>,
    redo: VecDeque<Edit>,
    /// Payload bytes currently held by `undo` + `redo` (see
    /// [`HISTORY_BYTES`]).
    history_bytes: usize,
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Buffer {
    /// An empty buffer: one empty line, no history.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            gap_start: 0,
            gap_end: 0,
            lines: Vec::from([0usize]),
            undo: VecDeque::new(),
            redo: VecDeque::new(),
            history_bytes: 0,
        }
    }

    /// A buffer pre-filled with `text` (already valid UTF-8 by
    /// construction), contiguous with the gap at the end.
    /// [`EditError::TooLarge`] when `text` exceeds [`MAX_BYTES`].
    pub fn from_text(text: &str) -> Result<Self, EditError> {
        if text.len() > MAX_BYTES {
            return Err(EditError::TooLarge);
        }
        let mut buffer = Self::new();
        buffer.data.extend_from_slice(text.as_bytes());
        buffer.gap_start = text.len();
        buffer.gap_end = text.len();
        buffer.reindex();
        Ok(buffer)
    }

    /// Logical length in bytes (gap excluded).
    pub fn len(&self) -> usize {
        self.data.len() - (self.gap_end - self.gap_start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert `text` at the char boundary `pos`. Refuses mid-scalar
    /// offsets ([`EditError::NotCharBoundary`]), offsets past the end
    /// ([`EditError::OutOfBounds`]) and inserts past [`MAX_BYTES`]
    /// ([`EditError::TooLarge`]); an empty insert is a no-op that does
    /// not touch the history.
    pub fn insert(&mut self, pos: usize, text: &str) -> Result<(), EditError> {
        let total = self.len();
        if pos > total {
            return Err(EditError::OutOfBounds);
        }
        if !self.is_boundary(pos) {
            return Err(EditError::NotCharBoundary);
        }
        if text.is_empty() {
            return Ok(());
        }
        let new_len = total.checked_add(text.len()).ok_or(EditError::TooLarge)?;
        if new_len > MAX_BYTES {
            return Err(EditError::TooLarge);
        }
        let bytes = text.as_bytes();
        self.raw_insert(pos, bytes);
        self.reindex();
        self.push_history(Edit {
            at: pos,
            removed: Vec::new(),
            inserted: bytes.to_vec(),
        });
        Ok(())
    }

    /// Remove `len` bytes starting at `pos`. Both `pos` and `pos + len`
    /// must be char boundaries, so a scalar is never split (the byte
    /// after a removed range is either the end of the buffer or the
    /// start of a scalar). A zero-length remove at a valid offset is a
    /// no-op that does not touch the history.
    pub fn remove(&mut self, pos: usize, len: usize) -> Result<(), EditError> {
        let total = self.len();
        if pos > total {
            return Err(EditError::OutOfBounds);
        }
        let end = pos.checked_add(len).ok_or(EditError::OutOfBounds)?;
        if end > total {
            return Err(EditError::OutOfBounds);
        }
        if !self.is_boundary(pos) || !self.is_boundary(end) {
            return Err(EditError::NotCharBoundary);
        }
        if len == 0 {
            return Ok(());
        }
        let removed = self.raw_take(pos, len);
        self.reindex();
        self.push_history(Edit {
            at: pos,
            removed,
            inserted: Vec::new(),
        });
        Ok(())
    }

    /// Undo the most recent edit. `false` when the stack is empty
    /// (undoing past the beginning is a no-op, never an error).
    pub fn undo(&mut self) -> bool {
        let Some(edit) = self.undo.pop_back() else {
            return false;
        };
        // Inverse of the recorded edit: drop what it inserted, put back
        // what it removed. Both raw ops are invariant-guarded; by LIFO
        // construction `at` and the payload lengths are valid here.
        self.raw_drop(edit.at, edit.inserted.len());
        self.raw_insert(edit.at, &edit.removed);
        self.reindex();
        self.redo.push_back(edit);
        true
    }

    /// Redo the most recently undone edit. `false` when nothing is
    /// pending (redoing past the end is a no-op).
    pub fn redo(&mut self) -> bool {
        let Some(edit) = self.redo.pop_back() else {
            return false;
        };
        self.raw_drop(edit.at, edit.removed.len());
        self.raw_insert(edit.at, &edit.inserted);
        self.reindex();
        self.undo.push_back(edit);
        true
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    /// Whether any edit exists in either history stack — the status
    /// bar's "modified" flag. Documented semantics: we do not snapshot
    /// the initial text to compare against, so undoing all the way back
    /// to the opening text still reads as modified (the redo stack holds
    /// a pending change).
    pub fn modified(&self) -> bool {
        !self.undo.is_empty() || !self.redo.is_empty()
    }

    /// Number of lines (≥ 1 always: an empty buffer is one empty line).
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// The raw line-start offsets (logical byte offsets, ascending,
    /// first is always 0) — exposed for the oracle tests and for the
    /// editor's gutter math.
    pub fn line_starts(&self) -> &[usize] {
        &self.lines
    }

    /// Byte offset where line `line` starts, or `None` if out of range.
    pub fn line_start(&self, line: usize) -> Option<usize> {
        self.lines.get(line).copied()
    }

    /// Byte offset where line `line`'s text ends — the position of its
    /// trailing `\n`, or the buffer end for the last line (so the empty
    /// last line after a trailing `\n` has `start == end`). `None` if
    /// out of range.
    pub fn line_end(&self, line: usize) -> Option<usize> {
        self.lines.get(line)?;
        match self.lines.get(line.checked_add(1)?) {
            Some(&next) => next.checked_sub(1),
            None => Some(self.len()),
        }
    }

    /// The line containing byte offset `pos` (the `\n` itself belongs to
    /// the line it terminates). `None` when `pos > len`.
    pub fn line_of(&self, pos: usize) -> Option<usize> {
        if pos > self.len() {
            return None;
        }
        let idx = self.lines.partition_point(|&start| start <= pos);
        Some(idx.saturating_sub(1))
    }

    /// Copy line `line`'s text (without the trailing `\n`) into `out`
    /// (replaced). `false` — leaving `out` cleared — when the line does
    /// not exist.
    pub fn line_bytes(&self, line: usize, out: &mut Vec<u8>) -> bool {
        out.clear();
        let (Some(start), Some(end)) = (self.line_start(line), self.line_end(line)) else {
            return false;
        };
        // start ≤ end by construction (line_end is the next start minus
        // the newline, or the buffer end).
        self.copy_out(start, end - start, out).is_ok()
    }

    /// Copy the logical byte range `[pos, pos + len)` into `out`
    /// (replaced). Bounds and char boundaries are validated first, so
    /// `out` is only ever touched by a successful copy.
    pub fn copy_out(&self, pos: usize, len: usize, out: &mut Vec<u8>) -> Result<(), EditError> {
        let total = self.len();
        if pos > total {
            return Err(EditError::OutOfBounds);
        }
        let end = pos.checked_add(len).ok_or(EditError::OutOfBounds)?;
        if end > total {
            return Err(EditError::OutOfBounds);
        }
        if !self.is_boundary(pos) || !self.is_boundary(end) {
            return Err(EditError::NotCharBoundary);
        }
        out.clear();
        let gap = self.gap_end - self.gap_start;
        if end <= self.gap_start {
            // Entirely in the front region.
            let slice = self.data.get(pos..end).ok_or(EditError::OutOfBounds)?;
            out.extend_from_slice(slice);
        } else if pos >= self.gap_start {
            // Entirely in the back region: logical → physical adds the gap.
            let slice = self
                .data
                .get(pos + gap..end + gap)
                .ok_or(EditError::OutOfBounds)?;
            out.extend_from_slice(slice);
        } else {
            // Straddles the gap: front part + back part.
            let front = self
                .data
                .get(pos..self.gap_start)
                .ok_or(EditError::OutOfBounds)?;
            let back_len = end - self.gap_start;
            let back = self
                .data
                .get(self.gap_end..self.gap_end + back_len)
                .ok_or(EditError::OutOfBounds)?;
            out.extend_from_slice(front);
            out.extend_from_slice(back);
        }
        Ok(())
    }

    /// The whole buffer as a fresh `Vec<u8>` (gap bypassed, no
    /// compaction required). The tests' primary oracle comparison.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        // 0 and len are char boundaries of a valid buffer, so this
        // cannot fail; the belt-and-braces clear keeps an impossible
        // failure visible as "empty output" rather than stale bytes.
        if self.copy_out(0, self.len(), &mut out).is_err() {
            out.clear();
        }
        out
    }

    /// Is `pos` a char boundary (or the buffer end)? An offset past the
    /// end is not a boundary; the check is the UTF-8 continuation-byte
    /// test, which is exact for a buffer that is valid UTF-8 — and this
    /// buffer always is (every insert takes `&str`, every range edit
    /// refuses non-boundaries).
    pub fn is_boundary(&self, pos: usize) -> bool {
        if pos > self.len() {
            return false;
        }
        if pos == self.len() {
            return true;
        }
        self.byte_at(pos).is_some_and(|byte| byte & 0xC0 != 0x80)
    }

    /// Start offset of the scalar before `pos` (snaps back over
    /// continuation bytes); `None` at offset 0 or past the end. This is
    /// the editor's char-aware Backspace primitive.
    pub fn prev_boundary(&self, pos: usize) -> Option<usize> {
        if pos == 0 || pos > self.len() {
            return None;
        }
        let mut start = pos - 1;
        while start > 0 && self.byte_at(start).is_some_and(|b| b & 0xC0 == 0x80) {
            start -= 1;
        }
        Some(start)
    }

    /// End offset of the scalar starting at the boundary `pos` (i.e.
    /// the next boundary); `None` at the buffer end, past the end, or
    /// when `pos` is not a boundary. This is the editor's Right-arrow
    /// primitive.
    pub fn next_boundary(&self, pos: usize) -> Option<usize> {
        let total = self.len();
        if pos >= total {
            return None;
        }
        let byte = self.byte_at(pos)?;
        let width = match byte {
            0x00..=0x7F => 1,
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            // Continuation byte: `pos` is not a boundary.
            _ => return None,
        };
        let end = pos.checked_add(width)?;
        if end > total {
            return None; // truncated scalar — impossible in a valid buffer
        }
        Some(end)
    }

    /// How many characters precede `pos` within its line (the editor's
    /// column, 0-based). `None` when `pos` is not a char boundary or is
    /// past the end.
    pub fn char_index(&self, pos: usize) -> Option<usize> {
        if pos > self.len() || !self.is_boundary(pos) {
            return None;
        }
        let line = self.line_of(pos)?;
        let mut at = self.lines.get(line).copied()?;
        let mut count = 0usize;
        while at < pos {
            at = self.next_boundary(at)?;
            count += 1;
        }
        Some(count)
    }

    /// Byte offset of the `char_idx`-th character of `line`, clamped to
    /// the line's end when `char_idx` asks past it (how the editor keeps
    /// the column when moving Up/Down to a shorter line).
    pub fn line_offset_for_char(&self, line: usize, char_idx: usize) -> Option<usize> {
        let mut at = self.line_start(line)?;
        let end = self.line_end(line)?;
        let mut count = 0usize;
        while at < end && count < char_idx {
            match self.next_boundary(at) {
                Some(next) => at = next,
                None => break,
            }
            count += 1;
        }
        Some(at)
    }

    /// Normalize the layout: move the gap to the end of the buffer and
    /// drop the dead bytes (capacity is kept). Content and line index
    /// are unchanged — the compaction test asserts exactly that.
    pub fn compact(&mut self) {
        let total = self.len();
        self.move_gap(total);
        // move_gap(total) leaves the gap at `[total, data.len())`;
        // truncate drops those dead bytes, so both gap markers must
        // land on the new end (leaving gap_end at the old data length
        // would corrupt `len()` on the next call).
        self.data.truncate(total);
        self.gap_start = total;
        self.gap_end = total;
    }

    // ------------------------------------------------------------------
    // Gap mechanics
    // ------------------------------------------------------------------

    /// Gap size in bytes.
    fn gap(&self) -> usize {
        self.gap_end - self.gap_start
    }

    /// Physical index of logical offset `pos` (valid for `pos < len`;
    /// callers check first).
    fn phys(&self, pos: usize) -> usize {
        if pos < self.gap_start {
            pos
        } else {
            // pos ≤ len = data.len() - gap ⇒ pos + gap ≤ data.len().
            pos + self.gap()
        }
    }

    /// The byte at logical `pos`, or `None` at/past the end.
    fn byte_at(&self, pos: usize) -> Option<u8> {
        if pos >= self.len() {
            return None;
        }
        self.data.get(self.phys(pos)).copied()
    }

    /// Slide the gap so it starts at logical `pos` (`pos ≤ len`).
    /// Fail-soft guard: a `pos` beyond the end (unreachable from public
    /// ops and from LIFO-valid history records) is ignored rather than
    /// panicking — the kernel must never panic on a logic bug.
    fn move_gap(&mut self, pos: usize) {
        debug_assert!(pos <= self.len(), "gap target beyond the logical end");
        if pos > self.len() {
            return;
        }
        if pos < self.gap_start {
            // Shift the front tail right, into the gap's far end.
            let n = self.gap_start - pos;
            // gap_end ≥ gap_start ≥ n, so `gap_end - n` cannot underflow
            // and `[gap_end - n, gap_end)` is inside `data`.
            let dest = self.gap_end - n;
            self.data.copy_within(pos..self.gap_start, dest);
            self.gap_start = pos;
            self.gap_end = dest;
        } else if pos > self.gap_start {
            // Shift the back head left, over the gap.
            let n = pos - self.gap_start;
            // pos ≤ len ⇒ gap_end + n ≤ data.len(), and gap_start + n =
            // pos ≤ len ≤ data.len() (both copy ranges in bounds;
            // copy_within handles the overlap).
            self.data
                .copy_within(self.gap_end..self.gap_end + n, self.gap_start);
            self.gap_start += n;
            self.gap_end += n;
        }
    }

    /// Insert bytes with the gap already (or subsequently) at `pos` —
    /// no validation, no history. Invariant guards fail soft (see
    /// [`Buffer::move_gap`]); unreachable from valid callers.
    fn raw_insert(&mut self, pos: usize, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if pos > self.len() {
            return; // invariant guard: unreachable
        }
        self.move_gap(pos);
        let old_len = self.data.len();
        let Some(new_len) = old_len.checked_add(bytes.len()) else {
            return; // invariant guard: unreachable (capped by MAX_BYTES)
        };
        // Grow the vec, slide the back region right by bytes.len(), then
        // write the new bytes into the (now larger) gap's front edge.
        self.data.resize(new_len, 0);
        self.data
            .copy_within(self.gap_end..old_len, self.gap_end + bytes.len());
        // gap_start ≤ old_len and gap_start + bytes.len() ≤ new_len, so
        // this slot exists; it is dead gap space, safe to overwrite.
        let Some(slot) = self
            .data
            .get_mut(self.gap_start..self.gap_start + bytes.len())
        else {
            return; // invariant guard: unreachable
        };
        slot.copy_from_slice(bytes);
        self.gap_start += bytes.len();
        self.gap_end += bytes.len();
    }

    /// Remove `n` bytes at `pos` without keeping them (undo of an
    /// insert). Invariant-guarded like [`Buffer::raw_insert`].
    fn raw_drop(&mut self, pos: usize, n: usize) {
        let total = self.len();
        if pos > total || n > total - pos {
            return; // invariant guard: unreachable
        }
        if n == 0 {
            return;
        }
        self.move_gap(pos);
        // After move_gap(pos) the back region holds total - pos bytes,
        // so gap_end + n ≤ data.len() (n ≤ total - pos was checked).
        self.gap_end += n;
    }

    /// Remove `n` bytes at `pos` and hand them back (the delete path).
    /// Same guards as [`Buffer::raw_drop`]; an impossible call yields an
    /// empty `Vec` instead of a panic.
    fn raw_take(&mut self, pos: usize, n: usize) -> Vec<u8> {
        let total = self.len();
        if pos > total || n > total - pos {
            return Vec::new(); // invariant guard: unreachable
        }
        self.move_gap(pos);
        let removed = self
            .data
            .get(self.gap_end..self.gap_end + n)
            .map(|slice| slice.to_vec())
            .unwrap_or_default();
        self.gap_end += n;
        removed
    }

    /// Rebuild the line index from scratch (the documented tradeoff —
    /// see the module docs). Walks the physical layout once, skipping
    /// the gap, and records `logical + 1` after every `\n`.
    fn reindex(&mut self) {
        self.lines.clear();
        self.lines.push(0);
        let (mut phys, mut logical) = (0usize, 0usize);
        while phys < self.data.len() {
            if phys == self.gap_start {
                phys = self.gap_end;
                if phys >= self.data.len() {
                    break;
                }
            }
            if self.data.get(phys) == Some(&b'\n') {
                // The `\n` is at logical `logical` < total, so +1 is in
                // range and cannot overflow.
                self.lines.push(logical + 1);
            }
            phys += 1;
            logical += 1;
        }
    }

    // ------------------------------------------------------------------
    // History
    // ------------------------------------------------------------------

    /// Record a fresh edit: the redo stack is invalidated (a new edit
    /// branches history), then the entry is pushed and both caps are
    /// enforced by evicting the oldest entries first. A single entry
    /// larger than [`HISTORY_BYTES`] is kept when it is alone — refusing
    /// to record it would make the edit permanently un-undoable (see the
    /// module docs' memory bound).
    fn push_history(&mut self, edit: Edit) {
        while let Some(old) = self.redo.pop_back() {
            self.history_bytes = self.history_bytes.saturating_sub(old.payload());
        }
        self.history_bytes = self.history_bytes.saturating_add(edit.payload());
        self.undo.push_back(edit);
        while self.undo.len() > 1
            && (self.undo.len() > HISTORY_MAX || self.history_bytes > HISTORY_BYTES)
        {
            if let Some(old) = self.undo.pop_front() {
                self.history_bytes = self.history_bytes.saturating_sub(old.payload());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — adversarial, host-run (`cargo test -p editorbuf`).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    /// Deterministic xorshift64* — no `rand` dependency (dependency
    /// policy: zero new crates), fixed seed so every run is identical.
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Self(if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            })
        }

        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            if n == 0 {
                0
            } else {
                (self.next() % n as u64) as usize
            }
        }
    }

    /// Oracle: line-start offsets of a plain byte string.
    fn oracle_lines(text: &[u8]) -> Vec<usize> {
        let mut starts = vec![0usize];
        for (i, &byte) in text.iter().enumerate() {
            if byte == b'\n' {
                starts.push(i + 1);
            }
        }
        starts
    }

    /// Every char boundary of a valid-UTF-8 byte string, ascending,
    /// including 0 and len.
    fn boundaries(text: &[u8]) -> Vec<usize> {
        let mut out = vec![0usize];
        let mut i = 0usize;
        while i < text.len() {
            let width = match text[i] {
                0x00..=0x7F => 1,
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                _ => 4,
            };
            i += width;
            out.push(i);
        }
        out
    }

    /// The full consistency bar: bytes, length, line index — all against
    /// the plain-`Vec` oracle — plus every line start being a char
    /// boundary of the real buffer.
    fn assert_consistent(buf: &Buffer, oracle: &[u8]) {
        assert_eq!(buf.len(), oracle.len(), "length drifted at {oracle:?}");
        assert_eq!(buf.to_vec().as_slice(), oracle, "content drifted");
        assert_eq!(
            buf.line_starts(),
            oracle_lines(oracle).as_slice(),
            "line index drifted at {oracle:?}"
        );
        for &start in buf.line_starts() {
            assert!(
                buf.is_boundary(start),
                "line start {start} is not a char boundary"
            );
        }
    }

    // -- empty / basic edges ---------------------------------------------

    #[test]
    fn empty_buffer_basics() {
        let buf = Buffer::new();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.line_count(), 1);
        assert_eq!(buf.line_starts(), &[0]);
        assert_eq!(buf.to_vec().as_slice(), b"");
        assert!(buf.is_boundary(0));
        assert!(!buf.is_boundary(1));
        assert_eq!(buf.line_of(0), Some(0));
        assert_eq!(buf.line_of(1), None);
        assert_eq!(buf.prev_boundary(0), None);
        assert_eq!(buf.next_boundary(0), None);
        assert!(!buf.can_undo());
        assert!(!buf.can_redo());
        assert!(!buf.modified());

        let mut buf = buf;
        buf.insert(0, "x").expect("insert into empty at 0");
        assert_eq!(buf.to_vec(), b"x");
        assert!(buf.undo());
        assert_eq!(buf.to_vec().as_slice(), b"");
    }

    #[test]
    fn insert_at_front_and_append_at_end() {
        let mut buf = Buffer::from_text("ell").expect("fits");
        buf.insert(0, "h").expect("insert at 0");
        assert_eq!(buf.to_vec(), b"hell");
        buf.insert(buf.len(), "o").expect("append at end");
        assert_eq!(buf.to_vec(), b"hello");
        assert_consistent(&buf, b"hello");

        // Append onto a gap that has moved around first.
        buf.insert(2, "\n").expect("mid insert");
        buf.compact();
        buf.insert(buf.len(), "!").expect("append after compact");
        assert_eq!(buf.to_vec(), b"he\nllo!");
        assert_consistent(&buf, b"he\nllo!");
    }

    // -- UTF-8 boundary refusal ------------------------------------------

    #[test]
    fn edits_refused_inside_multibyte_scalars() {
        //2-, 3- and 4-byte scalars mixed with ASCII.
        let text = "a\u{e9}\u{65e5}\u{1d11e}b\n\u{e9}\u{65e5}";
        let mut buf = Buffer::from_text(text).expect("fits");
        let before = buf.to_vec();
        assert_eq!(before, text.as_bytes());

        let mut refused = 0usize;
        for off in 0..text.len() {
            if buf.is_boundary(off) {
                continue;
            }
            refused += 1;
            assert_eq!(
                buf.insert(off, "x"),
                Err(EditError::NotCharBoundary),
                "insert at interior offset {off} must be refused"
            );
            assert_eq!(
                buf.remove(off, 1),
                Err(EditError::NotCharBoundary),
                "remove starting at interior offset {off} must be refused"
            );
            assert_eq!(
                buf.copy_out(off, 1, &mut Vec::new()),
                Err(EditError::NotCharBoundary),
                "copy starting at interior offset {off} must be refused"
            );
            assert_eq!(buf.to_vec(), before, "refused edit touched the buffer");
        }
        // The four scalars above contribute 1 + 2 + 3 + 3 interior offsets.
        assert!(refused >= 9, "expected ≥9 interior offsets, saw {refused}");

        // A range *ending* mid-scalar is refused even from a boundary.
        assert_eq!(buf.remove(1, 1), Err(EditError::NotCharBoundary)); // 'a' + half of é
        assert_eq!(buf.remove(0, 2), Err(EditError::NotCharBoundary)); // ends inside é
        assert_eq!(buf.to_vec(), before);
    }

    #[test]
    fn utf8_stays_valid_under_boundary_edits() {
        let mut buf = Buffer::from_text("start: ").expect("fits");
        let pieces = ["\u{e9}", "\u{65e5}\u{672c}", "\u{1d11e}", "ascii", "\n"];
        for (i, piece) in pieces.iter().enumerate() {
            // Walk back up to two char boundaries — a raw `len - k`
            // could land inside a multi-byte scalar.
            let mut at = buf.len();
            for _ in 0..(i % 3) {
                at = buf.prev_boundary(at).unwrap_or(0);
            }
            buf.insert(at, piece).expect("boundary insert");
        }
        let bytes = buf.to_vec();
        let text = std::str::from_utf8(&bytes).expect("buffer must stay valid UTF-8");
        assert!(text.contains('\u{1d11e}'));
        assert!(text.starts_with("start"));
        assert_consistent(&buf, &bytes);
    }

    #[test]
    fn remove_refused_on_half_char_ranges() {
        let mut buf = Buffer::from_text("a\u{e9}b").expect("fits"); // a=0, é=1..3, b=3
        let before = buf.to_vec();
        assert_eq!(buf.remove(1, 1), Err(EditError::NotCharBoundary));
        assert_eq!(buf.remove(2, 1), Err(EditError::NotCharBoundary));
        assert_eq!(buf.remove(0, 2), Err(EditError::NotCharBoundary));
        assert_eq!(buf.to_vec(), before);
        // Whole scalar: fine.
        buf.remove(1, 2).expect("remove é");
        assert_eq!(buf.to_vec(), b"ab");
    }

    // -- gap compaction ---------------------------------------------------

    #[test]
    fn gap_compaction_preserves_content_and_lines() {
        let mut buf = Buffer::from_text("one\ntwo\nthree\n").expect("fits");
        let script: [(usize, &str); 6] = [
            (0, "X"),         // front
            (4, "Y"),         // mid
            (buf.len(), "Z"), // end (len evaluated now:15)
            (2, "\n\n"),      // front-ish
            (0, "start\n"),   // front
            (7, "mid"),       // middle — forces a gap slide
        ];
        for (i, (at, text)) in script.into_iter().enumerate() {
            buf.insert(at, text)
                .unwrap_or_else(|e| panic!("step {i}: {e}"));
            let before = buf.to_vec();
            let lines_before = buf.line_starts().to_vec();
            buf.compact();
            assert_eq!(
                buf.to_vec(),
                before,
                "compaction changed content at step {i}"
            );
            assert_eq!(
                buf.line_starts(),
                lines_before.as_slice(),
                "compaction changed the line index at step {i}"
            );
            assert_consistent(&buf, &before);
        }
        // And compacting an already-normalized buffer is idempotent.
        let snapshot = buf.to_vec();
        buf.compact();
        assert_eq!(buf.to_vec(), snapshot);
        assert_consistent(&buf, &snapshot);

        // Removes are what grow the gap — compaction after a delete is
        // the case with actual dead bytes to drop (this is the case
        // that caught the gap-marker bug: truncate must reset both
        // markers, not just shrink the vec).
        for round in 0..3 {
            let end = buf.len();
            let start = buf.prev_boundary(end).expect("non-empty");
            buf.remove(start, end - start).expect("trim last scalar");
            let before = buf.to_vec();
            let lines_before = buf.line_starts().to_vec();
            buf.compact();
            assert_eq!(buf.to_vec(), before, "content moved at round {round}");
            assert_eq!(
                buf.line_starts(),
                lines_before.as_slice(),
                "line index moved at round {round}"
            );
            assert_consistent(&buf, &before);

            let first_end = buf.next_boundary(0).expect("non-empty");
            buf.remove(0, first_end).expect("trim first scalar");
            let before = buf.to_vec();
            buf.compact();
            assert_eq!(buf.to_vec(), before, "content moved at round {round}b");
            assert_consistent(&buf, &before);
        }
        assert!(!buf.is_empty());
    }

    // -- line index vs oracle --------------------------------------------

    #[test]
    fn line_index_matches_vec_oracle() {
        fn apply(buf: &mut Buffer, oracle: &mut Vec<u8>, at: usize, text: &str) {
            buf.insert(at, text).expect("valid insert");
            oracle.splice(at..at, text.bytes());
            assert_consistent(buf, oracle);
        }

        let mut buf = Buffer::new();
        let mut oracle: Vec<u8> = Vec::new();

        apply(&mut buf, &mut oracle, 0, "alpha\nbeta");
        let append_at = oracle.len();
        apply(&mut buf, &mut oracle, append_at, "\ngamma\ndelta\n");
        apply(&mut buf, &mut oracle, 6, "\n"); // split a line
        apply(&mut buf, &mut oracle, 0, "\n\n"); // leading blank lines

        // Delete a range crossing several lines.
        let start = 5;
        let end = 14;
        buf.remove(start, end - start).expect("cross-line delete");
        let removed: Vec<u8> = oracle.drain(start..end).collect();
        assert!(!removed.is_empty());
        assert_consistent(&buf, &oracle);

        // Delete to the very end, then back to empty.
        buf.remove(buf.len(), 0).expect("zero-length at end");
        assert_consistent(&buf, &oracle);
        let len = buf.len();
        buf.remove(0, len).expect("clear everything");
        oracle.clear();
        assert_consistent(&buf, &oracle);
        assert_eq!(buf.line_count(), 1);
    }

    #[test]
    fn delete_range_across_lines_updates_index() {
        let mut buf = Buffer::from_text("one\ntwo\nthree").expect("fits");
        assert_eq!(buf.line_count(), 3);
        buf.remove(4, 4).expect("remove \"two\\n\"");
        assert_eq!(buf.to_vec(), b"one\nthree");
        assert_eq!(buf.line_starts(), &[0, 4]);
        assert_eq!(buf.line_count(), 2);
        assert_eq!(buf.line_of(5), Some(1));
        // The trailing line without a newline.
        assert_eq!(buf.line_end(1), Some(9));
    }

    // -- undo / redo -------------------------------------------------------

    #[test]
    fn undo_redo_roundtrip_restores_bytes() {
        let original = "fn main() {\n    let x = 1;\n}\n";
        let mut buf = Buffer::from_text(original).expect("fits");
        let mut states = vec![buf.to_vec()]; // states[i] = after i edits

        buf.insert(12, "let y = 2;\n    ").expect("edit 1");
        states.push(buf.to_vec());
        let cut_start = buf.to_vec().iter().position(|&b| b == b'y').unwrap_or(0);
        buf.remove(cut_start, 6).expect("edit 2");
        states.push(buf.to_vec());
        buf.insert(0, "// header\n").expect("edit 3");
        states.push(buf.to_vec());
        let final_state = buf.to_vec();

        // Undo all the way back, one state at a time.
        for expected in states.iter().rev().skip(1) {
            assert!(buf.undo());
            assert_eq!(&buf.to_vec(), expected);
        }
        assert!(!buf.undo(), "undo past the beginning must be a no-op");
        assert_eq!(buf.to_vec().as_slice(), original.as_bytes());
        assert!(!buf.can_undo());
        assert!(buf.can_redo());

        // Redo all the way forward.
        for expected in states.iter().skip(1) {
            assert!(buf.redo());
            assert_eq!(&buf.to_vec(), expected);
        }
        assert!(!buf.redo(), "redo past the end must be a no-op");
        assert_eq!(buf.to_vec(), final_state);
        assert_consistent(&buf, &final_state);
    }

    #[test]
    fn undo_past_beginning_redo_past_end_are_noops() {
        let mut buf = Buffer::from_text("seed").expect("fits");
        assert!(!buf.undo());
        assert!(!buf.redo());
        buf.insert(4, "!").expect("edit");
        assert!(buf.undo());
        assert!(!buf.undo());
        assert!(!buf.undo());
        assert!(buf.redo());
        assert!(!buf.redo());
        assert_eq!(buf.to_vec(), b"seed!");
    }

    #[test]
    fn new_edit_clears_redo() {
        let mut buf = Buffer::new();
        buf.insert(0, "ab").expect("edit 1");
        buf.insert(2, "c").expect("edit 2");
        assert!(buf.undo()); // back to "ab"
        assert!(buf.can_redo());
        buf.insert(2, "z").expect("branching edit");
        assert!(!buf.can_redo(), "a new edit must invalidate redo");
        assert!(!buf.redo());
        assert_eq!(buf.to_vec(), b"abz");
        assert!(buf.undo());
        assert_eq!(buf.to_vec(), b"ab");
        // The edit from before the branch ("ab") is still on the stack —
        // only the *redo* branch was discarded by the new edit.
        assert!(buf.undo());
        assert_eq!(buf.to_vec().as_slice(), b"");
        assert!(!buf.undo(), "the first edit is the last one left");
    }

    #[test]
    fn modified_flag_tracks_history() {
        let mut buf = Buffer::from_text("fresh").expect("fits");
        assert!(!buf.modified());
        buf.insert(5, "!").expect("edit");
        assert!(buf.modified());
        assert!(buf.undo());
        assert!(
            buf.modified(),
            "documented: undoing back to the opening text still reads modified \
             (the redo stack holds a pending change)"
        );
        assert!(buf.redo());
        assert!(buf.modified());
    }

    #[test]
    fn zero_length_edits_are_noops_without_history() {
        let mut buf = Buffer::from_text("abc").expect("fits");
        buf.insert(1, "").expect("empty insert");
        buf.insert(3, "").expect("empty append");
        buf.remove(1, 0).expect("empty remove");
        assert!(!buf.can_undo(), "no-ops must not enter the history");
        assert_eq!(buf.to_vec(), b"abc");
        assert_consistent(&buf, b"abc");
    }

    // -- bounds / checked arithmetic --------------------------------------

    #[test]
    fn out_of_bounds_offsets_refused_checked_arithmetic() {
        let mut buf = Buffer::from_text("abc").expect("fits");
        let before = buf.to_vec();

        assert_eq!(buf.insert(4, "x"), Err(EditError::OutOfBounds));
        assert_eq!(buf.insert(usize::MAX, "x"), Err(EditError::OutOfBounds));
        assert_eq!(buf.remove(4, 1), Err(EditError::OutOfBounds));
        assert_eq!(buf.remove(usize::MAX, 1), Err(EditError::OutOfBounds));
        // pos + len must overflow-check, not wrap.
        assert_eq!(buf.remove(2, usize::MAX), Err(EditError::OutOfBounds));
        assert_eq!(
            buf.copy_out(usize::MAX, 2, &mut Vec::new()),
            Err(EditError::OutOfBounds)
        );
        assert_eq!(
            buf.copy_out(1, usize::MAX, &mut Vec::new()),
            Err(EditError::OutOfBounds)
        );
        assert_eq!(buf.line_of(usize::MAX), None);
        assert_eq!(buf.line_start(4), None);
        assert_eq!(buf.line_end(4), None);
        assert_eq!(buf.prev_boundary(usize::MAX), None);
        assert_eq!(buf.next_boundary(usize::MAX), None);
        assert_eq!(buf.to_vec(), before, "refused ops touched the buffer");
        assert!(!buf.can_undo());
    }

    #[test]
    fn buffer_byte_cap_refused() {
        let big = String::from("a").repeat(MAX_BYTES + 1);
        assert!(
            matches!(Buffer::from_text(&big), Err(EditError::TooLarge)),
            "from_text must refuse a buffer over the cap"
        );

        let mut buf = Buffer::from_text(&big[..MAX_BYTES - 4]).expect("under cap");
        let before = buf.to_vec();
        assert_eq!(buf.insert(buf.len(), "12345"), Err(EditError::TooLarge));
        assert_eq!(buf.to_vec(), before, "refused insert touched the buffer");
        assert!(!buf.can_undo(), "the refused insert must not enter history");
        buf.insert(buf.len(), "1234").expect("exactly at the cap");
        assert_eq!(buf.len(), MAX_BYTES);
        assert!(buf.can_undo(), "the accepted insert is recorded");
    }

    #[test]
    fn huge_single_line_is_one_line() {
        let text = String::from("x").repeat(20_000);
        let mut buf = Buffer::from_text(&text).expect("fits");
        assert_eq!(buf.line_count(), 1);
        assert_eq!(buf.line_start(0), Some(0));
        assert_eq!(buf.line_end(0), Some(20_000));
        assert_eq!(buf.line_of(19_999), Some(0));
        assert_eq!(buf.line_of(20_000), Some(0));
        assert_eq!(buf.char_index(20_000), Some(20_000));
        // Column past the end clamps to the line end.
        assert_eq!(buf.line_offset_for_char(0, 99_999), Some(20_000));
        assert_eq!(buf.line_offset_for_char(0, 5), Some(5));
        // Editing deep inside the huge line.
        buf.insert(10_000, "\n").expect("split");
        assert_eq!(buf.line_count(), 2);
        buf.remove(10_000, 1).expect("rejoin");
        assert_eq!(buf.line_count(), 1);
        assert_consistent(&buf, text.as_bytes());
    }

    #[test]
    fn trailing_newline_yields_empty_last_line() {
        let buf = Buffer::from_text("a\n").expect("fits");
        assert_eq!(buf.line_starts(), &[0, 2]);
        assert_eq!(buf.line_count(), 2);
        assert_eq!(buf.line_end(0), Some(1));
        assert_eq!(buf.line_end(1), Some(2));
        let mut out = Vec::new();
        assert!(buf.line_bytes(1, &mut out));
        assert!(out.is_empty());
        assert_eq!(buf.line_of(1), Some(0)); // the \n belongs to line 0
        assert_eq!(buf.line_of(2), Some(1));
        assert_eq!(buf.char_index(2), Some(0));
    }

    #[test]
    fn boundary_navigation_and_char_index() {
        // a(1) é(2) 日(3) 𝄞(4) \n b  → boundaries 0 1 3 6 10 11 12
        let text = "a\u{e9}\u{65e5}\u{1d11e}\nb";
        let buf = Buffer::from_text(text).expect("fits");
        assert_eq!(buf.to_vec().len(), 12);
        assert_eq!(buf.line_starts(), &[0, 11]);

        let mut walked = 0usize;
        while let Some(next) = buf.next_boundary(walked) {
            assert!(buf.is_boundary(next));
            walked = next;
        }
        assert_eq!(walked, 12, "forward walk must reach the end");

        let mut back = 12usize;
        let mut seen = vec![12usize];
        while let Some(prev) = buf.prev_boundary(back) {
            back = prev;
            seen.push(prev);
        }
        assert_eq!(back, 0, "backward walk must reach the start");
        assert_eq!(seen, vec![12, 11, 10, 6, 3, 1, 0]);

        assert_eq!(buf.char_index(0), Some(0));
        assert_eq!(buf.char_index(6), Some(3));
        assert_eq!(buf.char_index(10), Some(4));
        assert_eq!(buf.char_index(11), Some(0)); // line 1 starts fresh
        assert_eq!(buf.char_index(2), None); // mid-é
        assert_eq!(buf.line_offset_for_char(0, 2), Some(3)); // start of 日
        assert_eq!(buf.line_offset_for_char(0, 4), Some(10)); // line end
        assert_eq!(buf.line_offset_for_char(1, 0), Some(11));
    }

    #[test]
    fn backspace_semantics_remove_whole_scalar() {
        // The editor's Backspace: prev_boundary + remove the scalar.
        let mut buf = Buffer::from_text("a\u{e9}\u{65e5}").expect("fits");
        let mut cursor = buf.len(); // after 日
        for expected_remaining in [3usize, 1, 0] {
            let prev = buf.prev_boundary(cursor).expect("not at start");
            buf.remove(prev, cursor - prev).expect("backspace");
            cursor = prev;
            assert_eq!(buf.len(), expected_remaining);
            std::str::from_utf8(&buf.to_vec()).expect("still valid UTF-8");
        }
        assert_eq!(buf.prev_boundary(cursor), None, "backspace at start");
        assert_eq!(buf.to_vec().as_slice(), b"");
    }

    // -- history bounds ---------------------------------------------------

    #[test]
    fn history_entry_cap_evicts_oldest() {
        let mut buf = Buffer::new();
        for _ in 0..100 {
            buf.insert(buf.len(), "a").expect("fits");
        }
        assert_eq!(buf.len(), 100);
        let mut undos = 0;
        while buf.undo() {
            undos += 1;
        }
        assert_eq!(
            undos, HISTORY_MAX,
            "exactly HISTORY_MAX edits must stay undoable"
        );
        assert_eq!(buf.len(), 100 - HISTORY_MAX, "oldest edits were evicted");
    }

    #[test]
    fn history_byte_cap_evicts_oldest() {
        let mut buf = Buffer::new();
        let chunk = String::from("x").repeat(64 * 1024); // 8 × 64 KiB = 512 KiB
        for _ in 0..8 {
            buf.insert(buf.len(), &chunk).expect("fits");
        }
        assert_eq!(buf.len(), 8 * 64 * 1024);
        let mut undos = 0;
        while buf.undo() {
            undos += 1;
        }
        // 4 × 64 KiB = exactly HISTORY_BYTES survives; the older half
        // was evicted to keep the cap.
        assert_eq!(undos, HISTORY_BYTES / (64 * 1024));
        assert_eq!(buf.len(), 4 * 64 * 1024);
    }

    #[test]
    fn oversized_single_edit_stays_undoable() {
        // One edit larger than HISTORY_BYTES: it alone is kept (the
        // documented memory bound), and is undoable while alone.
        let mut buf = Buffer::new();
        let big = String::from("y").repeat(HISTORY_BYTES + 1);
        buf.insert(0, &big).expect("fits");
        assert_eq!(buf.len(), HISTORY_BYTES + 1);
        buf.insert(buf.len(), "z").expect("second edit");
        // Pushing a second edit over the byte cap evicts the oldest
        // (the big one) — history stays within the cap.
        assert!(buf.undo(), "the newest edit is undoable");
        assert!(!buf.undo(), "the oversized oldest edit was evicted");
        assert_eq!(buf.len(), HISTORY_BYTES + 1, "content restored by the undo");
    }

    // -- the big one: random edits vs the plain-Vec oracle -----------------

    /// A mirror of the buffer's history records for the oracle side.
    #[derive(Clone)]
    struct TestOp {
        at: usize,
        removed: Vec<u8>,
        inserted: Vec<u8>,
    }

    impl TestOp {
        fn undo_on(&self, oracle: &mut Vec<u8>) {
            oracle.drain(self.at..self.at + self.inserted.len());
            oracle.splice(self.at..self.at, self.removed.iter().copied());
        }

        fn redo_on(&self, oracle: &mut Vec<u8>) {
            oracle.drain(self.at..self.at + self.removed.len());
            oracle.splice(self.at..self.at, self.inserted.iter().copied());
        }
    }

    #[test]
    fn random_edit_undo_redo_matches_oracle() {
        const STEPS: usize = 4_000;
        // Keep the undo stack below HISTORY_MAX by construction (drain
        // before it could reach the cap) and cap every payload far below
        // HISTORY_BYTES — then eviction never fires and the oracle needs
        // no copy of the trim logic; the two dedicated cap tests above
        // cover eviction on its own.
        const DRAIN_AT: usize = 56;

        let mut rng = Rng::new(0x00C0_FFEE_1234_5678);
        let seed_text = "line one\nline two\n\u{e9}\u{65e5}\nend";
        let mut buf = Buffer::from_text(seed_text).expect("fits");
        let mut oracle = seed_text.as_bytes().to_vec();
        let mut hist: Vec<TestOp> = Vec::new();
        let mut redo: Vec<TestOp> = Vec::new();
        let pieces = [
            "a",
            "bc",
            "\u{e9}",
            "\u{65e5}\u{672c}",
            "\n",
            "\nline\n",
            "Z",
        ];

        for step in 0..STEPS {
            match rng.below(100) {
                // --- fresh edit (drains the undo stack first so the
                // entry cap can never fire in this test) ---
                0..=59 => {
                    while hist.len() >= DRAIN_AT {
                        let op = hist.pop().expect("hist non-empty");
                        assert!(buf.undo(), "step {step}: undo must be available");
                        op.undo_on(&mut oracle);
                        redo.push(op);
                    }
                    let bounds = boundaries(&oracle);
                    let at = bounds[rng.below(bounds.len())];
                    let text = pieces[rng.below(pieces.len())];
                    buf.insert(at, text)
                        .unwrap_or_else(|e| panic!("step {step}: {e}"));
                    oracle.splice(at..at, text.bytes());
                    hist.push(TestOp {
                        at,
                        removed: Vec::new(),
                        inserted: text.as_bytes().to_vec(),
                    });
                    redo.clear();
                }
                // --- delete a bounded range between random boundaries ---
                60..=79 => {
                    // Drain first: undoing mutates `oracle`, so the
                    // range must be picked from the post-drain content.
                    while hist.len() >= DRAIN_AT {
                        let op = hist.pop().expect("hist non-empty");
                        assert!(buf.undo(), "step {step}: undo must be available");
                        op.undo_on(&mut oracle);
                        redo.push(op);
                    }
                    let bounds = boundaries(&oracle);
                    let start_idx = rng.below(bounds.len());
                    // At most 8 scalars (≤ 32 bytes) per delete: keeps
                    // every payload far under HISTORY_BYTES.
                    let max_idx = (start_idx + 8).min(bounds.len() - 1);
                    if max_idx > start_idx {
                        let end_idx = start_idx + 1 + rng.below(max_idx - start_idx);
                        let start = bounds[start_idx];
                        let end = bounds[end_idx];
                        buf.remove(start, end - start)
                            .unwrap_or_else(|e| panic!("step {step}: {e}"));
                        let removed: Vec<u8> = oracle.drain(start..end).collect();
                        hist.push(TestOp {
                            at: start,
                            removed,
                            inserted: Vec::new(),
                        });
                        redo.clear();
                    }
                }
                // --- undo ---
                80..=89 => match hist.pop() {
                    Some(op) => {
                        assert!(buf.undo(), "step {step}: undo must succeed");
                        op.undo_on(&mut oracle);
                        redo.push(op);
                    }
                    None => assert!(!buf.undo(), "step {step}: undo past the beginning"),
                },
                // --- redo ---
                _ => match redo.pop() {
                    Some(op) => {
                        assert!(buf.redo(), "step {step}: redo must succeed");
                        op.redo_on(&mut oracle);
                        hist.push(op);
                    }
                    None => assert!(!buf.redo(), "step {step}: redo past the end"),
                },
            }

            assert_consistent(&buf, &oracle);
            assert_eq!(buf.can_undo(), !hist.is_empty(), "step {step}");
            assert_eq!(buf.can_redo(), !redo.is_empty(), "step {step}");
            assert!(hist.len() + redo.len() <= DRAIN_AT, "step {step}");

            // Exercise compaction mid-stream too: content must not move.
            if step % 256 == 255 {
                let before = buf.to_vec();
                buf.compact();
                assert_eq!(buf.to_vec(), before, "step {step}: compact moved bytes");
                assert_consistent(&buf, &oracle);
            }
        }

        // The run ends in a non-trivial state (edits really happened).
        assert!(hist.len() + redo.len() > 0);
        assert_ne!(buf.to_vec(), seed_text.as_bytes());
    }
}
