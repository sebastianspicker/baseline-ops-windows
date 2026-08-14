#![no_main]

use baselineops_windows::{NativeEncoding, decode_native_output};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_native_output(data, NativeEncoding::Utf8);
    let _ = decode_native_output(data, NativeEncoding::Utf16Le);
});
