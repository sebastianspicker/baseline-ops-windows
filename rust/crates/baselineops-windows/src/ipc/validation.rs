pub(super) fn valid_sid_text(value: &str) -> bool {
    value.len() >= 5
        && value.len() <= 1024
        && value.starts_with("S-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
}
