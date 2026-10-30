# Main Identify
> A ida plugin for locating the `main` entry point in C, Go, and Rust programs.

Identify the user-defined `main` function in stripped Rust, Go, and C/C++ binaries. The current version supports **Rust (with std), Go, and C/C++**, targeting **x86/x64** architectures and **PE/ELF** formats.

## Installation

Copy the entire directory into your IDA user plugins directory:

- **macOS:** `~/.idapro/plugins/main-identify/`
- **Windows:** `%APPDATA%\Hex-Rays\IDA Pro\plugins\main-identify\`

## Usage

1. Press **Ctrl+Shift+M**, or navigate to **Edit → Plugins → Main Identify**.
2. The results window displays the address, entry type, score, startup caller, detection method, existing name, and complete startup call chain. Entry types include **Rust main / Go main.main / C ABI main / C/C++ main**. User-defined entry points are ranked above C ABI entry points. Press **Enter** or double-click a row to jump to the selected address.
3. Right-click a result row and select **Edit** to rename the function based on its type (`rust_main`, `go_main`, `c_main`, or `native_main`) and append a one-line summary comment containing the entry type, detection method, score, and wrapper address.