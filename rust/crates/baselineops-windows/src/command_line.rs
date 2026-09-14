//! Pure Windows argument-token encoding shared by trusted process launchers.

pub(crate) fn quote_argument(argument: &str) -> String {
    let mut output = String::from("\"");
    let mut backslashes = 0_usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '\"' {
            output.push_str(&"\\".repeat(backslashes.saturating_mul(2).saturating_add(1)));
            output.push(character);
            backslashes = 0;
        } else {
            output.push_str(&"\\".repeat(backslashes));
            output.push(character);
            backslashes = 0;
        }
    }
    output.push_str(&"\\".repeat(backslashes.saturating_mul(2)));
    output.push('\"');
    output
}

#[cfg(test)]
mod tests {
    use super::quote_argument;

    #[test]
    fn preserves_empty_tokens_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote_argument(""), "\"\"");
        assert_eq!(quote_argument("plain"), "\"plain\"");
        assert_eq!(quote_argument("two words"), "\"two words\"");
        assert_eq!(
            quote_argument(r"C:\Program Files\"),
            r#""C:\Program Files\\""#
        );
        assert_eq!(quote_argument(r#"say \"hi\""#), r#""say \\\"hi\\\"""#);
    }
}
