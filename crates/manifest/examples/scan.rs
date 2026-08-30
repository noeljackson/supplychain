//! Scans the tracked fixture corpus and dumps each hit as JSON, for the
//! `manifest` parity probe.

use supplychain_core::json_compat;
use supplychain_ioc::{BLOCKED_PACKAGE_NAMES, DataDirFirst, load_list, load_packages};
use supplychain_manifest::{Indicators, scan_repo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = DataDirFirst::new("iocs");
    let indicators = Indicators::new(
        &load_packages(&source)?,
        &load_list(&source, BLOCKED_PACKAGE_NAMES)?,
    );

    let hits = scan_repo("parity/fixtures/manifests", &indicators)?;

    // Sorted on the whole record: Go map iteration is randomised, and the
    // scanner's own ordering is only by (File, Name), which leaves ties among
    // sections and indicator versions unordered. Comparing sets is the honest
    // gate here.
    let mut lines: Vec<String> = hits
        .iter()
        .map(json_compat::to_string)
        .collect::<Result<_, _>>()?;
    lines.sort();
    for line in lines {
        println!("{line}");
    }
    Ok(())
}
