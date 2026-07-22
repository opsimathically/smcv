#![forbid(unsafe_code)]

use std::io::{self, Write as _};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &smcv_server::openapi_document())?;
    writeln!(output)?;
    Ok(())
}
