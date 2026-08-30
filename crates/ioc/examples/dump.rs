//! Dumps parsed IOC data in a stable tab-separated form.
//!
//! Used by the parity harness to diff this loader against the Go one.

use supplychain_ioc::{
    BLOCKED_PACKAGE_NAMES, C2_DOMAINS, DEAD_DROP_SIGNATURES, DataDirFirst, PAYLOAD_FILENAMES,
    PERSISTENCE_PATHS, load_list, load_packages,
};

fn main() -> std::io::Result<()> {
    let source = DataDirFirst::new("iocs");
    for package in load_packages(&source)? {
        let parsed = package
            .parsed
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!("PKG\t{}\t{}\t{}", package.name, package.version, parsed);
    }
    for name in [
        BLOCKED_PACKAGE_NAMES,
        C2_DOMAINS,
        PERSISTENCE_PATHS,
        DEAD_DROP_SIGNATURES,
        PAYLOAD_FILENAMES,
    ] {
        for value in load_list(&source, name)? {
            println!("LIST\t{name}\t{value}");
        }
    }
    Ok(())
}
