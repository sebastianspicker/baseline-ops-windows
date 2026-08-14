#![no_main]

use baselineops_windows::PathPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data)
        && let Ok(policy) = PathPolicy::new(".")
    {
        let _ = policy.output_file(value);
    }
});
