// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    inetstack::{
        protocols::{
            layer2::{EtherType2, Ethernet2Header},
            layer3::arp::header::{ArpHeader, ArpOperation},
        },
        test_helpers::{self, SharedEngine, SharedTestPhysicalLayer},
        types::MacAddress,
    },
    runtime::memory::DemiBuffer,
};
use ::anyhow::Result;
use ::futures::FutureExt;
use ::std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

//======================================================================================================================
// Constants
//======================================================================================================================

const ARP_RETRY_COUNT: usize = 2;
const ARP_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

//======================================================================================================================
// Tests
//======================================================================================================================

/// Tests immediate reply for an ARP request.
#[test]
fn arp_immediate_reply() -> Result<()> {
    let mut now = Instant::now();
    let local_mac = test_helpers::ALICE_MAC;
    let local_ipv4 = test_helpers::ALICE_IPV4;
    let remote_mac = test_helpers::BOB_MAC;
    let remote_ipv4 = test_helpers::BOB_IPV4;
    let mut engine = new_engine(now, test_helpers::ALICE_CONFIG_PATH)?;

    // Create an ARP query request to the local IP address.
    let buffer = build_arp_query(&remote_mac, &remote_ipv4, &local_ipv4);

    engine.push_frame(buffer);

    // Move clock forward and poll the engine.
    now += Duration::from_micros(1);
    engine.advance_clock(now);
    engine.runtime().poll_background_tasks();

    // Check if the ARP cache outputs a reply message.
    let mut buffers = engine.pop_expected_frames(1);
    crate::ensure_eq!(buffers.len(), 1);
    let mut pkt = buffers.pop_front().unwrap();

    // Sanity check Ethernet header.
    let eth2_header = Ethernet2Header::parse_and_strip(&mut pkt)?;
    crate::ensure_eq!(eth2_header.dst_addr(), remote_mac);
    crate::ensure_eq!(eth2_header.src_addr(), local_mac);
    crate::ensure_eq!(eth2_header.ether_type(), EtherType2::Arp);

    // Sanity check ARP header.
    let arp_header = ArpHeader::parse_and_consume(pkt)?;
    crate::ensure_eq!(arp_header.operation(), ArpOperation::Reply);
    crate::ensure_eq!(arp_header.sender_hardware_addr(), local_mac);
    crate::ensure_eq!(arp_header.sender_protocol_addr(), local_ipv4);
    crate::ensure_eq!(arp_header.target_protocol_addr(), remote_ipv4);

    Ok(())
}

/// Tests no reply for an ARP request.
#[test]
fn arp_no_reply() -> Result<()> {
    let mut now: Instant = Instant::now();
    let remote_mac = test_helpers::BOB_MAC;
    let remote_ipv4 = test_helpers::BOB_IPV4;
    let other_remote_ipv4 = test_helpers::CARRIE_IPV4;
    let mut engine = new_engine(now, test_helpers::ALICE_CONFIG_PATH)?;

    // Create an ARP query request to a different IP address.
    let buffer = build_arp_query(&remote_mac, &remote_ipv4, &other_remote_ipv4);

    // Feed it to engine.
    engine.push_frame(buffer);

    // Move clock forward and poll the engine.
    now += Duration::from_micros(1);
    engine.advance_clock(now);

    // Ensure that no reply message is output.
    let buffers = engine.pop_expected_frames(0);
    crate::ensure_eq!(buffers.len(), 0);

    Ok(())
}

/// Tests updates on the ARP cache.
#[test]
fn arp_cache_update() -> Result<()> {
    let mut now = Instant::now();
    let local_mac = test_helpers::BOB_MAC;
    let local_ipv4 = test_helpers::BOB_IPV4;
    let other_remote_mac = test_helpers::CARRIE_MAC;
    let other_remote_ipv4 = test_helpers::CARRIE_IPV4;
    let mut engine = new_engine(now, test_helpers::BOB_CONFIG_PATH)?;

    // Create an ARP query request to the local IP address.
    let buffer = build_arp_query(&other_remote_mac, &other_remote_ipv4, &local_ipv4);

    // Feed it to engine.
    engine.push_frame(buffer);

    // Move clock forward and poll the engine.
    now += Duration::from_micros(1);
    engine.advance_clock(now);
    engine.runtime().poll_background_tasks();

    // Check if the ARP cache has been updated.
    let cache = engine.transport().export_arp_cache();
    crate::ensure_eq!(cache.get(&other_remote_ipv4), Some(&other_remote_mac));

    // Check if the ARP cache outputs a reply message.
    let mut buffers = engine.pop_expected_frames(1);
    crate::ensure_eq!(buffers.len(), 1);
    let mut first_pkt = buffers.pop_front().unwrap();

    // Sanity check Ethernet header.
    let eth2_header = Ethernet2Header::parse_and_strip(&mut first_pkt)?;
    crate::ensure_eq!(eth2_header.dst_addr(), other_remote_mac);
    crate::ensure_eq!(eth2_header.src_addr(), local_mac);
    crate::ensure_eq!(eth2_header.ether_type(), EtherType2::Arp);

    // Sanity check ARP header.
    let arp_header = ArpHeader::parse_and_consume(first_pkt)?;
    crate::ensure_eq!(arp_header.operation(), ArpOperation::Reply);
    crate::ensure_eq!(arp_header.sender_hardware_addr(), local_mac);
    crate::ensure_eq!(arp_header.sender_protocol_addr(), local_ipv4);
    crate::ensure_eq!(arp_header.target_protocol_addr(), other_remote_ipv4);

    Ok(())
}

#[test]
fn arp_cache_timeout() -> Result<()> {
    let mut now = Instant::now();
    let other_remote_ipv4 = test_helpers::CARRIE_IPV4;
    let mut engine = new_engine(now, test_helpers::ALICE_CONFIG_PATH)?;
    let mut inetstack = engine.transport();
    let coroutine = Box::pin(async move { inetstack.arp_query(other_remote_ipv4).await }.fuse());
    let _qt = engine
        .runtime()
        .clone()
        .insert_nonpolling_coroutine("arp query", coroutine)?;

    for _ in 0..(ARP_RETRY_COUNT + 1) {
        engine.runtime().poll_foreground_tasks();
        // Check if the ARP cache outputs a reply message.
        let buffers = engine.pop_expected_frames(1);
        crate::ensure_eq!(buffers.len(), 1);

        // Move clock forward and poll the engine.
        now += ARP_REQUEST_TIMEOUT;
        engine.advance_clock(now);
    }

    // Check if the ARP cache outputs a reply message.
    let buffers = engine.pop_expected_frames(0);
    crate::ensure_eq!(buffers.len(), 0);

    // Ensure that the ARP query has failed with ETIMEDOUT.
    // TODO: Put this final test back but the ARP query does not conform to our standard set of foreground tasks.
    // match engine.wait(qt, Duration::from_secs(0)) {
    //     Err(err) => crate::ensure_eq!(err.errno, libc::ETIMEDOUT),
    //     Ok(_) => unreachable!("arp query must fail with ETIMEDOUT"),
    // }

    Ok(())
}

//======================================================================================================================
// Test Helpers
//======================================================================================================================

fn build_arp_query(local_mac: &MacAddress, local_ipv4: &Ipv4Addr, remote_ipv4: &Ipv4Addr) -> DemiBuffer {
    let body = ArpHeader::new(
        ArpOperation::Request,
        *local_mac,
        *local_ipv4,
        MacAddress::broadcast(),
        *remote_ipv4,
    );
    let mut pkt = body.create_and_serialize();
    let header = Ethernet2Header::new(MacAddress::broadcast(), *local_mac, EtherType2::Arp);
    header.serialize_and_attach(&mut pkt);
    pkt
}

fn new_engine(now: Instant, config_path: &str) -> Result<SharedEngine> {
    let layer1_endpoint = SharedTestPhysicalLayer::new(now);
    Ok(SharedEngine::new(config_path, layer1_endpoint, now)?)
}
