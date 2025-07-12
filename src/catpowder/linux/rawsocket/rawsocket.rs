// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    catpowder::linux::RawSocketAddr,
    pal::{SockAddrIn, Socklen},
    runtime::fail::Fail,
};
use ::std::{mem, mem::MaybeUninit};

//======================================================================================================================
// Structures
//======================================================================================================================

pub struct RawSocket(libc::c_int);

//======================================================================================================================
// Associate Functions
//======================================================================================================================

impl RawSocket {
    pub fn new() -> Result<Self, Fail> {
        let domain = libc::AF_PACKET; // raw packet socket, no header parsing
        let ty = libc::SOCK_RAW | libc::SOCK_NONBLOCK; // raw, non-blocking socket
        let protocol = libc::ETH_P_ALL; // all protocols

        let fd = unsafe { libc::socket(domain, ty, protocol) };
        if fd == -1 {
            return Err(Fail::new(libc::EAGAIN, "failed to create raw socket"));
        }

        trace!("created raw socket with fd={:?}", fd);
        Ok(RawSocket(fd))
    }

    // Binds the socket to a raw address.
    pub fn bind(&self, addr: &RawSocketAddr) -> Result<(), Fail> {
        let (ptr, len) = addr.as_sockaddr_ptr();

        let ret = unsafe { libc::bind(self.0, ptr, len) };
        if ret == -1 {
            return Err(Fail::new(libc::EAGAIN, "failed to bind raw socket"));
        }

        Ok(())
    }

    /// Sends data through a raw socket.
    pub fn sendto(&self, data: &[u8], rawaddr: &RawSocketAddr) -> Result<usize, Fail> {
        let (addr_ptr, addr_len) = rawaddr.as_sockaddr_ptr();
        let ret = unsafe {
            libc::sendto(
                self.0,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                libc::MSG_DONTWAIT,
                addr_ptr,
                addr_len,
            )
        };

        if ret == -1 {
            return Err(Fail::new(libc::EAGAIN, "failed to send data through raw socket"));
        }

        Ok(ret as usize)
    }

    /// Receive data from a raw socket.
    pub fn recvfrom(&self, recv_buffer: &[MaybeUninit<u8>]) -> Result<(usize, RawSocketAddr), Fail> {
        let ptr = recv_buffer.as_ptr() as *mut libc::c_void;
        let mut addrlen = mem::size_of::<SockAddrIn>() as u32;
        let mut rawaddr = RawSocketAddr::default();
        let (addr_ptr, _) = rawaddr.as_sockaddr_ptr_mut();
        let addrlen_ptr = &mut addrlen as *mut Socklen;

        let ret = unsafe {
            libc::recvfrom(
                self.0,
                ptr,
                recv_buffer.len(),
                libc::MSG_DONTWAIT,
                addr_ptr,
                addrlen_ptr as *mut u32,
            ) as i32
        };

        if ret == -1 {
            return Err(Fail::new(libc::EAGAIN, "failed to receive data from raw socket"));
        }

        Ok((ret as usize, rawaddr))
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Drop for RawSocket {
    fn drop(&mut self) {
        let ret = unsafe { libc::close(self.0) };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            warn!("failed to close raw socket (fd={}): {}", self.0, errno);
        } else {
            trace!("closed raw socket fd={}", self.0)
        }
    }
}
