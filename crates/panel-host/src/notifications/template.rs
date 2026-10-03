const KEYS: [&str; 5] = ["title", "server", "message", "time", "event"];

pub fn valid(template: &str) -> bool {
    if template.trim().is_empty()
        || template.encode_utf16().count() > 4000
        || template
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return false;
    }
    let mut rest = template;
    while let Some((before, after)) = rest.split_once("{{") {
        if before.contains("}}") {
            return false;
        }
        let Some((key, tail)) = after.split_once("}}") else {
            return false;
        };
        if !KEYS.contains(&key) {
            return false;
        }
        rest = tail;
    }
    !rest.contains("}}")
}

pub(super) fn render(template: &str, values: [&str; 5]) -> String {
    let mut output = String::new();
    let mut rest = template;
    while let Some((before, after)) = rest.split_once("{{") {
        output.push_str(before);
        let Some((key, tail)) = after.split_once("}}") else {
            break;
        };
        if let Some(index) = KEYS.iter().position(|known| *known == key) {
            output.push_str(values[index]);
        }
        rest = tail;
    }
    output.push_str(rest);
    // Bound the rendered payload too; replacements can exceed the template's own limit.
    let mut units = 0;
    let output: String = output
        .chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= 4095
        })
        .collect();
    if units > 4095 {
        format!("{output}…")
    } else {
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn substitutions_are_literal_and_rendered_messages_are_bounded() {
        assert!(valid("{{title}}\n{{message}}"));
        for template in ["", "{{unknown}}", "{{title", "title}}", "\0"] {
            assert!(!valid(template));
        }
        assert_eq!(
            render(
                "{{server}} / {{message}}",
                ["", "{{message}}", "literal", "", ""]
            ),
            "{{message}} / literal"
        );
        let message = "😀".repeat(5000);
        assert!(
            render("{{message}}", ["", "", &message, "", ""])
                .encode_utf16()
                .count()
                <= 4096
        );
    }
}
