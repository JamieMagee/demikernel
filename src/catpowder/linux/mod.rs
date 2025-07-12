// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod rawsocket;

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    catpowder::linux::rawsocket::{RawSocket, RawSocketAddr},
    demikernel::config::Config,
    expect_ok,
    inetstack::consts::{MAX_BATCH_SIZE_NUM_PACKETS, MAX_HEADER_SIZE},
    inetstack::protocols::{layer1::PhysicalLayer, layer2::Ethernet2Header},
    runtime::{
        fail::Fail,
        limits,
        memory::{DemiBuffer, DemiMemoryAllocator},
        Runtime, SharedObject,
    },
};
use ::arrayvec::ArrayVec;
use ::std::{
    fs,
    mem::{self, MaybeUninit},
    num::ParseIntError,
};

//======================================================================================================================
// Structures
//======================================================================================================================

#[derive(Clone)]
pub struct LinuxRuntime {
    ifindex: i32,
    socket: SharedObject<RawSocket>,
    max_body_size: usize,
}

//======================================================================================================================
// Associate Functions
//======================================================================================================================

impl LinuxRuntime {
    pub fn new(config: &Config) -> Result<Self, Fail> {
        let mac_addr = [0; 6];

        let ifindex = Self::ifindex_for(&config.local_interface_name()?)
            .map_err(|_| Fail::new(libc::EINVAL, "could not parse ifindex"))?;

        let socket = RawSocket::new()?;
        let bind_addr = RawSocketAddr::new(ifindex, &mac_addr);
        socket.bind(&bind_addr)?;

        let max_body_size = config.mtu()? as usize - MAX_HEADER_SIZE;

        Ok(Self {
            ifindex,
            socket: SharedObject::<RawSocket>::new(socket),
            max_body_size,
        })
    }

    fn ifindex_for(ifname: &str) -> Result<i32, ParseIntError> {
        let path = format!("/sys/class/net/{}/ifindex", ifname);
        expect_ok!(fs::read_to_string(path), "could not read ifname")
            .trim()
            .parse()
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl DemiMemoryAllocator for LinuxRuntime {
    fn max_buffer_size_bytes(&self) -> usize {
        self.max_body_size
    }

    fn allocate_demi_buffer(&self, size: usize) -> Result<DemiBuffer, Fail> {
        Ok(DemiBuffer::new_with_headroom(size as u16, MAX_HEADER_SIZE as u16))
    }
}

impl Runtime for LinuxRuntime {}

impl PhysicalLayer for LinuxRuntime {
    fn transmit(&mut self, packets: ArrayVec<DemiBuffer, MAX_BATCH_SIZE_NUM_PACKETS>) -> Result<(), Fail> {
        for packet in packets {
            // Parse header but keep original packet untouched for sending by cloning it.
            let header = Ethernet2Header::parse_and_strip(&mut packet.clone()).unwrap();
            let dst_mac = header.dst_addr().to_array();
            let addr = RawSocketAddr::new(self.ifindex, &dst_mac);

            match self.socket.sendto(&packet, &addr) {
                Ok(n) if n == packet.len() => (),
                Ok(n) => {
                    let cause = format!("transmit: partial send: packet_size={:?} sent={:?}", packet.len(), n);
                    warn!("{}", cause);
                    return Err(Fail::new(libc::EAGAIN, &cause));
                },
                Err(e) => {
                    warn!("transmit(): send failed: {:?}", e);
                    return Err(Fail::new(libc::EIO, "send failed"));
                },
            }
        }
        Ok(())
    }

    // Only receives one packet for now.
    // TODO: Support receiving multiple packets in a single call.
    // TODO: Remove extra copy of the packet.
    // TODO: Change to use `DemiBuffer` directly instead of `MaybeUninit<u8>`.
    fn receive(&mut self) -> Result<ArrayVec<DemiBuffer, MAX_BATCH_SIZE_NUM_PACKETS>, Fail> {
        let mut recv_buffer = [unsafe { MaybeUninit::uninit().assume_init() }; limits::RECVBUF_SIZE_MAX];

        let (nbytes, _src) = match self.socket.recvfrom(&mut recv_buffer) {
            Ok(res) => res,
            Err(_) => return Ok(ArrayVec::new()),
        };

        let bytes = unsafe {
            mem::transmute::<[MaybeUninit<u8>; limits::RECVBUF_SIZE_MAX], [u8; limits::RECVBUF_SIZE_MAX]>(recv_buffer)
        };

        let mut packet = DemiBuffer::from_slice(&bytes)?;
        packet.trim(limits::RECVBUF_SIZE_MAX - nbytes)?;

        let mut packets = ArrayVec::new();
        packets.push(packet);
        Ok(packets)
    }
}
