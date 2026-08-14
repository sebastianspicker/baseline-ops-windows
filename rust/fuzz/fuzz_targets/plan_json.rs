#![no_main]

use baselineops_domain::{JsonLoadLimits, load_plan_json};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = load_plan_json(data, JsonLoadLimits::default());
});
