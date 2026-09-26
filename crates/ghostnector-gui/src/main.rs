//! The `ghostnector-gui` binary.
//!
//! Usage: `ghostnector-gui [--socket <PATH>]`
//!
//! The window is the whole product surface. The binary holds no privilege, parses no policy, and
//! makes no security decision: it renders what `ghostnector-core` reports.

#[cfg(all(unix, feature = "gtk"))]
fn main() -> gtk4::glib::ExitCode {
    let mut socket = std::path::PathBuf::from("/run/ghostnector/core.sock");
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => match arguments.next() {
                Some(path) => socket = std::path::PathBuf::from(path),
                None => {
                    eprintln!("ghostnector-gui: --socket needs a path");
                    std::process::exit(2);
                }
            },
            "-V" | "--version" => {
                println!("ghostnector-gui {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!("ghostnector-gui [--socket <PATH>]\n\nRenders the Ghostnector control plane's state and asks it to change. It decides nothing itself.");
                std::process::exit(0);
            }
            other => {
                eprintln!("ghostnector-gui: unknown argument '{other}'");
                std::process::exit(2);
            }
        }
    }
    ghostnector_gui::app::run(socket)
}

#[cfg(not(all(unix, feature = "gtk")))]
fn main() {
    eprintln!(
        "ghostnector-gui was built without the 'gtk' feature; build it with \
         `cargo build -p ghostnector-gui --features gtk` on Linux"
    );
    std::process::exit(2);
}
