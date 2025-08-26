// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use paranoid_system::env::{Params, ParamsIntegrityRt};
use std::sync::Arc;

fn main() -> Result<()> {
    let _env = Arc::new(ParamsIntegrityRt::new()?);
    unimplemented!("Work in progress");

    //Ok(())
}
