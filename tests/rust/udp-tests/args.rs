// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::Result;
use clap::{Arg, Command};
use std::{
    net::{SocketAddr, SocketAddrV4},
    str::FromStr,
};

#[derive(Debug)]
pub struct ProgramArguments {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl ProgramArguments {
    pub fn new() -> Result<Self> {
        let matches = Command::new("udp-tests")
            .arg(
                Arg::new("local")
                    .long("local-address")
                    .value_parser(clap::value_parser!(String))
                    .required(true)
                    .value_name("ADDRESS:PORT")
                    .help("Sets the address of local socket"),
            )
            .arg(
                Arg::new("remote")
                    .long("remote-address")
                    .value_parser(clap::value_parser!(String))
                    .required(true)
                    .value_name("ADDRESS:PORT")
                    .help("Sets the address of remote socket"),
            )
            .get_matches();

        let local_addr = SocketAddr::V4({
            let addr = matches.get_one::<String>("local").expect("missing address");
            SocketAddrV4::from_str(addr)?
        });

        let remote_addr = SocketAddr::V4({
            let addr = matches.get_one::<String>("remote").expect("missing address");
            SocketAddrV4::from_str(addr)?
        });

        Ok(Self {
            local_addr,
            remote_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    // ToDo: Remove this `unused` annotation after remote_addr is used (when new tests are added to this file).
    #[allow(unused)]
    pub fn get_remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}
