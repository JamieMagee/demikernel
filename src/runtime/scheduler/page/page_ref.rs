// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    expect_ok,
    runtime::scheduler::{
        page::{WakerPage, WAKER_PAGE_SIZE},
        waker64::WAKER_BIT_LENGTH,
    },
};
use ::std::{
    alloc::{Allocator, Global, Layout},
    mem,
    ops::Deref,
    ptr::{self, NonNull},
};

//======================================================================================================================
// Structures
//======================================================================================================================

/// The [crate::Scheduler] relies on this custom reference type to drive the
/// state of futures.
pub struct WakerPageRef(NonNull<WakerPage>);

//======================================================================================================================
// Associate Functions
//======================================================================================================================

/// Associate Functions for Waker Page References
impl WakerPageRef {
    pub fn new(page: NonNull<WakerPage>) -> Self {
        Self(page)
    }

    /// Casts the target [WakerPageRef] into a [NonNull<u8>].
    ///
    /// The reference itself is not intended for reading/writing to
    /// member-fields of a [WakerPage], once it does not point to meaningful
    /// information on this structure. Indeed, the reference is carefully
    /// constructed so that: if points to the base address location of the
    /// structure plus an  offset (in bytes) that identifies some particular
    /// future in the underlying [WakerPage]. The scheduler relies on this hack
    /// to cast back the reference to a [WakerPage] and access the futures
    /// within it correctly.
    ///
    /// This hack only works because: (i) the number of bits in
    /// [crate::waker64::Waker64]s match the number of bytes in [WakerPage]s;
    /// and (ii) [WakerPage]s are aligned to their on memory addresses multiple
    /// of their own size (ie: aligned to N*sizeof([WakerPage])).
    ///
    /// If you don't understand the above explanation, take some time to
    /// carefully review the pointer arithmetic interaction between
    /// [crate::page::WakerPage], [crate::page::WakerPageRef],
    /// [crate::page::WakerRef] and [crate::Scheduler].
    pub fn as_raw_waker_ref(&self, ix: usize) -> NonNull<u8> {
        debug_assert!(ix < WAKER_BIT_LENGTH);

        // Bump the refcount of the underlying waker page.
        let self_ = self.clone();
        mem::forget(self_);

        unsafe {
            let base_ptr: *mut u8 = self.0.as_ptr().cast();
            NonNull::new_unchecked(base_ptr.add(ix))
        }
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Clone for WakerPageRef {
    fn clone(&self) -> Self {
        let old_refount = unsafe { self.0.as_ref().refcount_inc() };
        debug_assert!(old_refount < u64::MAX);
        Self(self.0)
    }
}

impl Drop for WakerPageRef {
    fn drop(&mut self) {
        match unsafe { self.0.as_ref().refcount_dec() } {
            Some(1) => unsafe {
                ptr::drop_in_place(self.0.as_mut());
                Global.deallocate(self.0.cast(), Layout::for_value(self.0.as_ref()));
            },
            Some(_) => {},
            None => panic!("double free on waker page {:?}", self.0),
        }
    }
}

impl Deref for WakerPageRef {
    type Target = WakerPage;

    fn deref(&self) -> &WakerPage {
        unsafe { self.0.as_ref() }
    }
}

impl Default for WakerPageRef {
    fn default() -> Self {
        let layout = Layout::new::<WakerPage>();
        assert_eq!(layout.align(), WAKER_PAGE_SIZE);
        let mut ptr = expect_ok!(Global.allocate(layout), "Failed to allocate WakerPage").cast();
        unsafe {
            let page: &mut WakerPage = ptr.as_mut();
            page.reset();
        }
        Self(ptr)
    }
}

//======================================================================================================================
// Unit Tests
//======================================================================================================================

#[cfg(test)]
mod tests {
    use crate::runtime::scheduler::page::WakerPageRef;
    use ::anyhow::Result;

    #[test]
    fn test_clone() -> Result<()> {
        let page = WakerPageRef::default();
        crate::ensure_eq!(page.refcount(), 1);

        // Clone page
        let page_clone = page.clone();
        crate::ensure_eq!(page_clone.refcount(), 2);
        crate::ensure_eq!(page.refcount(), 2);

        // Clone page_clone
        let page_clone_clone = page_clone.clone();
        crate::ensure_eq!(page_clone_clone.refcount(), 3);
        crate::ensure_eq!(page_clone.refcount(), 3);
        crate::ensure_eq!(page.refcount(), 3);

        // Drop page_clone_clone
        drop(page_clone_clone);
        crate::ensure_eq!(page_clone.refcount(), 2);
        crate::ensure_eq!(page.refcount(), 2);

        // Drop page_clone
        drop(page_clone);
        crate::ensure_eq!(page.refcount(), 1);

        // Clone page
        let page_clone = page.clone();
        crate::ensure_eq!(page_clone.refcount(), 2);
        crate::ensure_eq!(page.refcount(), 2);

        // Clone page again
        let page_clone_clone = page.clone();
        crate::ensure_eq!(page_clone_clone.refcount(), 3);
        crate::ensure_eq!(page_clone.refcount(), 3);
        crate::ensure_eq!(page.refcount(), 3);

        // Drop page
        drop(page);
        crate::ensure_eq!(page_clone_clone.refcount(), 2);
        crate::ensure_eq!(page_clone.refcount(), 2);

        // Drop page_clone_clone
        drop(page_clone_clone);
        crate::ensure_eq!(page_clone.refcount(), 1);

        Ok(())
    }

    #[test]
    fn test_into() -> Result<()> {
        let page = WakerPageRef::default();
        crate::ensure_eq!(page.refcount(), 1);

        let _ = page.as_raw_waker_ref(0);
        crate::ensure_eq!(page.refcount(), 2);

        let _ = page.as_raw_waker_ref(31);
        crate::ensure_eq!(page.refcount(), 3);

        let _ = page.as_raw_waker_ref(63);
        crate::ensure_eq!(page.refcount(), 4);

        Ok(())
    }
}
