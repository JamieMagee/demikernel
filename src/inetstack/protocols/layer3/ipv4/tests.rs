// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    inetstack::{
        protocols::layer3::{ip::IpProtocol, ipv4::Ipv4Header},
        test_helpers::{ALICE_IPV4, BOB_IPV4},
    },
    runtime::memory::DemiBuffer,
};
use ::anyhow::Result;

//======================================================================================================================
// Helper Functions
//======================================================================================================================

fn build_ipv4_header(
    buf: &mut [u8],
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    id: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    src_addr: &[u8],
    dest_addr: &[u8],
    mut checksum: Option<u16>,
) {
    // Version + IHL.
    buf[0] = ((version & 0xf) << 4) | (ihl & 0xf);

    // DSCP + ECN.
    buf[1] = ((dscp & 0x3f) << 2) | (ecn & 0x3);

    // Total Length.
    buf[2..4].copy_from_slice(&total_length.to_be_bytes());

    // ID.
    buf[4..6].copy_from_slice(&id.to_be_bytes());

    // Flags + Offset.
    let field = ((flags as u16 & 7) << 13) | (fragment_offset & 0x1fff);
    buf[6..8].copy_from_slice(&field.to_be_bytes());

    // Time to live.
    buf[8] = ttl;

    // Protocol.
    buf[9] = protocol;

    // Source address.
    buf[12..16].copy_from_slice(src_addr);

    // Destination address.
    buf[16..20].copy_from_slice(dest_addr);

    // Header checksum.
    if checksum.is_none() {
        let header_size = (ihl as usize) << 2;
        checksum = Some(Ipv4Header::compute_checksum(&buf[..header_size]));
    }
    buf[10..12].copy_from_slice(&checksum.unwrap().to_be_bytes());
}

//======================================================================================================================
// Unit-Tests for Happy Path
//======================================================================================================================

#[test]
fn test_ipv4_header_parse_good() -> Result<()> {
    const HEADER_MAX_SIZE: usize = (5 + 10) << 2;
    const PAYLOAD_SIZE: usize = 8;
    const DATAGRAM_SIZE: usize = HEADER_MAX_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    let data = [1, 2, 3, 4, 5, 6, 7, 8];

    let data_bytes = DemiBuffer::from_slice(&data).expect("'data' should fit in a DemiBuffer");
    let ihl_values = 5..16;

    for ihl in ihl_values {
        let header_size = (ihl as usize) << 2;
        let datagram_size = header_size + PAYLOAD_SIZE;

        build_ipv4_header(
            &mut raw_bytes[..header_size],
            4,
            ihl,
            0,
            0,
            datagram_size as u16,
            0,
            0x2,
            0,
            1,
            IpProtocol::UDP as u8,
            &ALICE_IPV4.octets(),
            &BOB_IPV4.octets(),
            None,
        );

        // Payload
        raw_bytes[header_size..datagram_size].copy_from_slice(&data);

        let mut buffer = match DemiBuffer::from_slice(&raw_bytes[..datagram_size]) {
            Ok(b) => b,
            Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
        };

        match Ipv4Header::parse_and_strip(&mut buffer) {
            Ok(ipv4_hdr) => {
                assert_eq!(ipv4_hdr.src_addr(), ALICE_IPV4);
                assert_eq!(ipv4_hdr.dst_addr(), BOB_IPV4);
                assert_eq!(ipv4_hdr.protocol(), IpProtocol::UDP);
                assert_eq!(buffer.len(), PAYLOAD_SIZE);
                assert_eq!(buffer[..], data_bytes[..]);
            },
            Err(e) => anyhow::bail!("{:?}", e),
        }
    }

    Ok(())
}

//======================================================================================================================
// Unit-Tests for Invalid Path
//======================================================================================================================

#[test]
fn test_ipv4_header_parse_invalid_version() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    let invalid_versions = [0, 1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    for version in invalid_versions {
        build_ipv4_header(
            &mut raw_bytes,
            version,
            5,
            0,
            0,
            DATAGRAM_SIZE as u16,
            0,
            0x2,
            0,
            1,
            IpProtocol::UDP as u8,
            &ALICE_IPV4.octets(),
            &BOB_IPV4.octets(),
            None,
        );

        let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
            Ok(b) => b,
            Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
        };

        if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
            anyhow::bail!("parsed ipv4_header with invalid version: {:?}", version);
        }
    }

    Ok(())
}

/// IHL is Internet Header Length
#[test]
fn test_ipv4_header_parse_invalid_ihl() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    let invalid_ihl_values = [0, 1, 2, 3, 4];

    for ihl in invalid_ihl_values {
        build_ipv4_header(
            &mut raw_bytes,
            4,
            ihl,
            0,
            0,
            DATAGRAM_SIZE as u16,
            0,
            0x2,
            0,
            1,
            IpProtocol::UDP as u8,
            &ALICE_IPV4.octets(),
            &BOB_IPV4.octets(),
            None,
        );

        let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
            Ok(buf) => buf,
            Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
        };

        if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
            anyhow::bail!("parsed ipv4 header with invalid IHL: {:?}", ihl)
        };
    }

    Ok(())
}

#[test]
fn test_ipv4_header_parse_invalid_total_length() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    let invalid_total_lengths = 0..20;

    for total_length in invalid_total_lengths {
        build_ipv4_header(
            &mut raw_bytes,
            4,
            5,
            0,
            0,
            total_length,
            0,
            0x2,
            0,
            1,
            IpProtocol::UDP as u8,
            &ALICE_IPV4.octets(),
            &BOB_IPV4.octets(),
            None,
        );

        let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
            Ok(b) => b,
            Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
        };

        if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
            anyhow::bail!("parsed ipv4 header with invalid total_length: {:?}", total_length)
        };
    }

    Ok(())
}

#[test]
fn test_ipv4_header_parse_invalid_flags() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    // Flags field must have bit 3 zeroed as it is marked Reserved.
    let flags = 0x4;

    build_ipv4_header(
        &mut raw_bytes,
        4,
        5,
        0,
        0,
        DATAGRAM_SIZE as u16,
        0x1d,
        flags,
        0,
        1,
        IpProtocol::UDP as u8,
        &ALICE_IPV4.octets(),
        &BOB_IPV4.octets(),
        None,
    );

    let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
        Ok(b) => b,
        Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
    };

    if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
        anyhow::bail!("parsed ipv4 header with invalid flags: {:?}", flags)
    }

    Ok(())
}

/// TTL is Time To Live
#[test]
fn test_ipv4_header_parse_invalid_ttl() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    // Datagrams with zeroed TTL values must me dropped.
    let ttl = 0x0;

    build_ipv4_header(
        &mut raw_bytes,
        4,
        5,
        0,
        0,
        DATAGRAM_SIZE as u16,
        0,
        0x2,
        0,
        ttl,
        IpProtocol::UDP as u8,
        &ALICE_IPV4.octets(),
        &BOB_IPV4.octets(),
        None,
    );

    let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
        Ok(b) => b,
        Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
    };

    if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
        anyhow::bail!("parsed ipv4 header with invalid ttl: {:?}", ttl);
    }

    Ok(())
}

#[test]
fn test_ipv4_header_parse_invalid_protocol() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    let invalid_protocol_values = 144..252;

    for protocol in invalid_protocol_values {
        build_ipv4_header(
            &mut raw_bytes,
            4,
            5,
            0,
            0,
            DATAGRAM_SIZE as u16,
            0,
            0x2,
            0,
            1,
            protocol,
            &ALICE_IPV4.octets(),
            &BOB_IPV4.octets(),
            None,
        );

        let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
            Ok(b) => b,
            Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
        };

        if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
            anyhow::ensure!(false, "parsed ipv4 header with invalid protocol: {:?}", protocol)
        };
    }

    Ok(())
}

#[test]
fn test_ipv4_header_parse_invalid_header_checksum() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    // Datagrams with invalid header checksum must me dropped.
    let hdr_checksum = 0x1;

    build_ipv4_header(
        &mut raw_bytes,
        4,
        5,
        0,
        0,
        DATAGRAM_SIZE as u16,
        0,
        0x2,
        0,
        1,
        IpProtocol::UDP as u8,
        &ALICE_IPV4.octets(),
        &BOB_IPV4.octets(),
        Some(hdr_checksum),
    );

    let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
        Ok(b) => b,
        Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
    };

    if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
        anyhow::bail!("parsed ipv4 header with invalid header checksum: {:?}", hdr_checksum);
    }

    Ok(())
}

//======================================================================================================================
// Unit-Tests for Unsupported Paths
//======================================================================================================================

#[test]
fn test_ipv4_header_parse_unsupported_dscp() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    let unsupported_dscp_values = 1..63;

    for dscp in unsupported_dscp_values {
        build_ipv4_header(
            &mut raw_bytes,
            4,
            5,
            dscp,
            0,
            DATAGRAM_SIZE as u16,
            0,
            0x2,
            0,
            1,
            IpProtocol::UDP as u8,
            &ALICE_IPV4.octets(),
            &BOB_IPV4.octets(),
            None,
        );

        let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
            Ok(b) => b,
            Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
        };

        if Ipv4Header::parse_and_strip(&mut buffer).is_err() {
            anyhow::bail!("dscp field should be ignored (dscp: {:?})", dscp);
        }
    }

    Ok(())
}

#[test]
fn test_ipv4_header_parse_unsupported_ecn() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    let unsupported_ecn_values = 1..3;

    for ecn in unsupported_ecn_values {
        build_ipv4_header(
            &mut raw_bytes,
            4,
            5,
            0,
            ecn,
            DATAGRAM_SIZE as u16,
            0,
            0x2,
            0,
            1,
            IpProtocol::UDP as u8,
            &ALICE_IPV4.octets(),
            &BOB_IPV4.octets(),
            None,
        );

        let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
            Ok(b) => b,
            Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
        };

        if Ipv4Header::parse_and_strip(&mut buffer).is_err() {
            anyhow::bail!("ecn field should be ignored (ecn: {:?})", ecn);
        };
    }

    Ok(())
}

/// TODO: Drop this test once we support fragmentation.
#[test]
fn test_ipv4_header_parse_unsupported_fragmentation() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

    let mut raw_bytes = [0; DATAGRAM_SIZE];
    // Fragmented packets are unsupported.
    // Fragments are detected by having either the MF bit set in Flags or a non-zero Fragment Offset field.
    let flags = 0x1; // Set MF bit.
                     //
    build_ipv4_header(
        &mut raw_bytes,
        4,
        5,
        0,
        0,
        DATAGRAM_SIZE as u16,
        0x1d,
        flags,
        0,
        1,
        IpProtocol::UDP as u8,
        &ALICE_IPV4.octets(),
        &BOB_IPV4.octets(),
        None,
    );

    let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
        Ok(b) => b,
        Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
    };

    if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
        anyhow::bail!("parsed ipv4 header with Flags: {:?}. Do we support it now?", flags);
    };

    // Fragmented packets are unsupported.
    // Fragments are detected by having either the MF bit set in Flags or a non-zero Fragment Offset field.
    let fragment_offset = 1;

    build_ipv4_header(
        &mut buffer,
        4,
        5,
        0,
        0,
        DATAGRAM_SIZE as u16,
        0x1d,
        0x2,
        fragment_offset,
        1,
        IpProtocol::UDP as u8,
        &ALICE_IPV4.octets(),
        &BOB_IPV4.octets(),
        None,
    );

    let mut buffer = match DemiBuffer::from_slice(&buffer) {
        Ok(b) => b,
        Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
    };

    if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
        anyhow::bail!(
            "parsed ipv4 header with fragment_offset: {:?}. Do we support it now?",
            fragment_offset,
        );
    }

    Ok(())
}

/// TODO: Drop this test once we support them.
#[test]
fn test_ipv4_header_parse_unsupported_protocol() -> Result<()> {
    const HEADER_SIZE: usize = 20;
    const PAYLOAD_SIZE: usize = 0;
    const DATAGRAM_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;
    let mut raw_bytes = [0; DATAGRAM_SIZE];

    // Iterate over unsupported values for fragment flags.
    for protocol in 0..143 {
        match protocol {
            // Skip supported protocols.
            1 | 6 | 17 => continue,
            _ => {
                build_ipv4_header(
                    &mut raw_bytes,
                    4,
                    5,
                    0,
                    0,
                    DATAGRAM_SIZE as u16,
                    0,
                    0x2,
                    0,
                    1,
                    protocol,
                    &ALICE_IPV4.octets(),
                    &BOB_IPV4.octets(),
                    None,
                );

                let mut buffer = match DemiBuffer::from_slice(&raw_bytes) {
                    Ok(buf) => buf,
                    Err(e) => anyhow::bail!("failed to create buffer: {:?}", e),
                };

                if Ipv4Header::parse_and_strip(&mut buffer).is_ok() {
                    anyhow::bail!("parsed ipv4 header with protocol: {:?}. Now supported?", protocol);
                };
            },
        };
    }

    Ok(())
}
