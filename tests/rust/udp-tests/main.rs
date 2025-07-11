// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![deny(clippy::all)]

mod args;
mod bind;
mod close;

use anyhow::Result;
use args::ProgramArguments;
use demikernel::{LibOS, LibOSName};

/// Runs a test and prints the result to standard output.
#[macro_export]
macro_rules! test {
    ($fn_name:ident($($arg:expr),*)) => {{
        match $fn_name($($arg),*) {
            Ok(ok) =>
                vec![(stringify!($fn_name).to_string(), "passed".to_string(), Ok(ok))],
            Err(err) =>
                vec![(stringify!($fn_name).to_string(), "failed".to_string(), Err(err))],
        }
    }};
}

/// Appends the test result to the vector.
#[macro_export]
macro_rules! append_test_result {
    ($vec:ident, $expr:expr) => {
        $vec.append(&mut $expr);
    };
}

fn main() -> Result<()> {
    let args = ProgramArguments::new()?;
    let mut libos = LibOS::new(LibOSName::from_env()?.into(), None)?;
    let mut num_failed = 0;
    let mut results = Vec::new();

    append_test_result!(results, bind::run_tests(&mut libos, &args.local_addr().ip()));
    append_test_result!(results, close::run_tests(&mut libos, &args.local_addr().ip()));

    for (name, status, test_result) in results {
        println!("[{}] {}", status, name);
        if let Err(e) = test_result {
            num_failed += 1;
            println!("    {}", e);
        }
    }

    if num_failed > 0 {
        anyhow::bail!("{} tests failed", num_failed);
    }

    println!("all tests passed");
    Ok(())
}
