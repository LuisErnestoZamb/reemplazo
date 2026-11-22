//! Kernel side of the userland loader: take the captured `hello` module,
//! run [`super::elf::parse`], build a private address space and prove every
//! mapping. Prints `ELF_OK` only after the whole proof succeeds.
//!
//! Hito 1 is *cooperative*: the returned [`LoadedProcess`] carries the entry
//! and both stacks for the privilege/scheduler milestones to switch to ring 3
//! with `Yield`/`Exit`. This file never loads CR3, touches the GDT or arms a
//! tick — those are owned by `m-privilege` / `m-scheduler`.

use super::elf::{self, ElfError, ElfImage, PF_W, Segment};
use super::module;
use crate::memory::{self, Frame, USER_END, USER_STACK_SIZE, UserMapError, UserPageTable};

/// Why loading failed. Fatal in the boot proof; returned to the future
/// `spawn` syscall once one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadError {
    BadElf(ElfError),
    Map(UserMapError),
    NoFrames,
    Overflow,
    MissingMapping(u64),
    /// A `PT_LOAD` range would overlap the reserved user stack.
    StackOverlap,
}

/// A validated, mapped user process. Frames stay allocated until
/// [`LoadedProcess::destroy`] (or a future scheduler takes ownership).
#[derive(Debug)]
pub(crate) struct LoadedProcess {
    pub space: UserPageTable,
    /// `e_entry` inside the user region.
    pub entry: u64,
    /// Top of the 16 KiB user stack (initial RSP for ring 3).
    pub user_stack_top: u64,
    /// Identity-mapped 4 KiB kernel stack (RSP0 for the privilege switch).
    pub kernel_stack_top: u64,
    kernel_stack: Frame,
}

impl LoadedProcess {
    /// Return every frame this process owns. Never call while its PML4 is
    /// loaded in CR3; switch back to the kernel map first.
    pub(crate) fn destroy(self) {
        memory::free_user_page_table(&self.space);
        memory::free(self.kernel_stack);
    }
}

/// Copy the file-backed part of one segment into a freshly zeroed page.
/// The parser proved `offset + filesz <= module.len()`, so the source range
/// is inside the captured static; the destination is the exclusive frame.
fn copy_file_part(
    image: &ElfImage<'_>,
    seg: &Segment,
    page: u64,
    frame: Frame,
) -> Result<(), LoadError> {
    let seg_file_end = seg.vaddr.saturating_add(seg.filesz);
    let page_end = page.saturating_add(memory::FRAME_SIZE);
    let start = seg.vaddr.max(page);
    let end = seg_file_end.min(page_end);
    if start >= end {
        return Ok(());
    }
    let src_in_file = seg
        .offset
        .checked_add(start - seg.vaddr)
        .ok_or(LoadError::Overflow)?;
    let count = (end - start) as usize;
    // SAFETY: `start..end` is the intersection of the validated file range
    // with this page, so `src_in_file..src_in_file+count` lies inside
    // `image.bytes()`; the destination lies inside `frame` (4 KiB, owned,
    // identity-mapped), and the two regions cannot alias.
    unsafe {
        core::ptr::copy_nonoverlapping(
            image.bytes().as_ptr().add(src_in_file as usize),
            (frame.start_phys() + (start - page)) as *mut u8,
            count,
        )
    };
    Ok(())
}

/// Map one segment's pages. `memsz > filesz` pages stay zeroed (`.bss`).
fn map_segment(
    space: &mut UserPageTable,
    image: &ElfImage<'_>,
    seg: &Segment,
) -> Result<(), LoadError> {
    let seg_end = seg
        .vaddr
        .checked_add(seg.memsz)
        .ok_or(LoadError::Overflow)?;
    if seg_end > USER_END.saturating_sub(USER_STACK_SIZE) {
        return Err(LoadError::StackOverlap);
    }
    let first = seg.vaddr - (seg.vaddr % memory::FRAME_SIZE);
    let last = seg_end.div_ceil(memory::FRAME_SIZE) * memory::FRAME_SIZE;
    let writable = seg.flags & PF_W != 0;
    let mut page = first;
    while page < last {
        let frame = memory::alloc_zeroed().ok_or(LoadError::NoFrames)?;
        if let Err(e) = copy_file_part(image, seg, page, frame) {
            memory::free(frame);
            return Err(e);
        }
        if let Err(e) = memory::map_user_page(space, page, frame, writable) {
            memory::free(frame);
            return Err(LoadError::Map(e));
        }
        // Read the entry back through the page tables (not through the
        // virtual address — CR3 is still the kernel's). Every level must
        // carry U/S, exactly as x86-64 requires for ring 3 access.
        let mapped = memory::user_page_frame(space, page).ok_or(LoadError::MissingMapping(page))?;
        if mapped.0 != frame || mapped.1 & 0b100 == 0 {
            return Err(LoadError::MissingMapping(page));
        }
        page = page
            .checked_add(memory::FRAME_SIZE)
            .ok_or(LoadError::Overflow)?;
    }
    Ok(())
}

/// Map the user stack (top-down, `USER_STACK_SIZE` bytes of zeroed RW pages)
/// and the separate kernel stack frame.
fn map_stacks(space: &mut UserPageTable) -> Result<(u64, Frame), LoadError> {
    let top = USER_END;
    let bottom = top
        .checked_sub(USER_STACK_SIZE)
        .ok_or(LoadError::Overflow)?;
    let mut page = bottom;
    while page < top {
        let frame = memory::alloc_zeroed().ok_or(LoadError::NoFrames)?;
        if let Err(e) = memory::map_user_page(space, page, frame, true) {
            memory::free(frame);
            return Err(LoadError::Map(e));
        }
        if memory::user_page_frame(space, page)
            .ok_or(LoadError::MissingMapping(page))?
            .0
            != frame
        {
            return Err(LoadError::MissingMapping(page));
        }
        page = page
            .checked_add(memory::FRAME_SIZE)
            .ok_or(LoadError::Overflow)?;
    }
    // Supervisor-only by construction: the identity map in PML4[0] has no
    // U/S bit, which the new PML4 copied from CR3.
    let kernel_stack = memory::alloc_zeroed().ok_or(LoadError::NoFrames)?;
    Ok((top, kernel_stack))
}

/// Parse + map the captured `hello` ELF. The returned process owns its
/// frames; nothing here changes CR3 or enables interrupts.
pub(crate) fn load(raw: &[u8]) -> Result<LoadedProcess, LoadError> {
    let image = elf::parse(raw).map_err(LoadError::BadElf)?;
    let mut space = memory::create_user_page_table().ok_or(LoadError::NoFrames)?;
    for seg in image.segments() {
        if let Err(e) = map_segment(&mut space, &image, seg) {
            memory::free_user_page_table(&space);
            return Err(e);
        }
    }
    let (user_stack_top, kernel_stack) = match map_stacks(&mut space) {
        Ok(v) => v,
        Err(e) => {
            memory::free_user_page_table(&space);
            return Err(e);
        }
    };
    let kernel_stack_top = match kernel_stack.start_phys().checked_add(memory::FRAME_SIZE) {
        Some(top) => top,
        None => {
            memory::free_user_page_table(&space);
            memory::free(kernel_stack);
            return Err(LoadError::Overflow);
        }
    };
    Ok(LoadedProcess {
        space,
        entry: image.entry,
        user_stack_top,
        kernel_stack_top,
        kernel_stack,
    })
}

/// Boot proof: silent without a `hello` module (diskless/installed boots
/// keep their marker chains), prints `ELF_OK` only when the image parsed,
/// every page mapped user-accessible and the two stacks were allocated.
/// `FATAL: elf:` + halt for a present but malformed module.
pub(crate) fn boot_proof() {
    let Some(raw) = module::hello_bytes() else {
        return;
    };
    match load(raw) {
        Ok(process) => {
            serial_println!(
                "elf: entry={:#x} user_stack={:#x} kernel_stack={:#x} bytes={}",
                process.entry,
                process.user_stack_top,
                process.kernel_stack_top,
                raw.len()
            );
            serial_println!("ELF_OK"); // machine-checked by `cargo xtask smoke`
            process.destroy();
        }
        Err(e) => {
            serial_println!("FATAL: elf: {:?}", e);
            crate::halt();
        }
    }
}
