// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::pal::Socklen;
use ::std::mem;
use libc::sockaddr;

//======================================================================================================================
// Structures
//======================================================================================================================

#[derive(Clone, Copy)]
pub struct RawSocketAddr(libc::sockaddr_ll);

//======================================================================================================================
// Associate Functions
//======================================================================================================================

impl RawSocketAddr {
    pub fn new(ifidx: i32, mac: &[u8; 6]) -> Self {
        // Pad MAC address to 8 bytes
        let mut addr = [0u8; 8];
        addr[..6].copy_from_slice(mac);

        RawSocketAddr(libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifidx,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: libc::ETH_ALEN as u8,
            sll_addr: addr,
        })
    }

    pub fn as_sockaddr_ptr(&self) -> (*const sockaddr, Socklen) {
        let ptr = unsafe { mem::transmute::<*const libc::sockaddr_ll, *const sockaddr>(&self.0) };
        let len = mem::size_of::<libc::sockaddr_ll>() as u32;
        (ptr, len)
    }

    pub fn as_sockaddr_ptr_mut(&mut self) -> (*mut sockaddr, Socklen) {
        let ptr = unsafe { mem::transmute::<*mut libc::sockaddr_ll, *mut sockaddr>(&mut self.0) };
        let len = mem::size_of::<libc::sockaddr_ll>() as u32;
        (ptr, len)
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Default for RawSocketAddr {
    fn default() -> Self {
        Self(unsafe { mem::zeroed() })
    }
}
