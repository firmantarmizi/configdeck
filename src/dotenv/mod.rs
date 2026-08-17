use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_ENTRIES: usize = 500;
pub const MAX_VALUE_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseIssue {
    pub line: usize,
    pub message: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParseReport {
    pub entries: Vec<Entry>,
    pub issues: Vec<ParseIssue>,
}

pub fn parse(input: &str) -> ParseReport {
    if input.len() > MAX_INPUT_BYTES {
        return ParseReport {
            issues: vec![ParseIssue {
                line: 0,
                message: "input exceeds the 256 KiB limit",
            }],
            ..ParseReport::default()
        };
    }
    if input.contains('\0') {
        return ParseReport {
            issues: vec![ParseIssue {
                line: 0,
                message: "NUL bytes are not allowed",
            }],
            ..ParseReport::default()
        };
    }

    let mut report = ParseReport::default();
    let mut keys = HashSet::new();
    for (index, physical_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = if index == 0 {
            physical_line
                .strip_prefix('\u{feff}')
                .unwrap_or(physical_line)
        } else {
            physical_line
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if report.entries.len() >= MAX_ENTRIES {
            report.issues.push(ParseIssue {
                line: line_number,
                message: "import exceeds the 500-variable limit",
            });
            break;
        }
        match parse_assignment(trimmed) {
            Ok(entry) => {
                if keys.insert(entry.key.clone()) {
                    report.entries.push(entry);
                } else {
                    report.issues.push(ParseIssue {
                        line: line_number,
                        message: "duplicate key",
                    });
                }
            }
            Err(message) => report.issues.push(ParseIssue {
                line: line_number,
                message,
            }),
        }
    }
    if report.entries.is_empty() && report.issues.is_empty() {
        report.issues.push(ParseIssue {
            line: 0,
            message: "no variable assignments found",
        });
    }
    report
}

fn parse_assignment(line: &str) -> Result<Entry, &'static str> {
    let assignment = line.strip_prefix("export ").unwrap_or(line);
    let (key, raw_value) = assignment
        .split_once('=')
        .ok_or("expected KEY=VALUE assignment")?;
    let key = key.trim();
    if !valid_key(key) {
        return Err("invalid variable key");
    }
    let value = parse_value(raw_value.trim())?;
    if value.len() > MAX_VALUE_BYTES {
        return Err("value exceeds the 32 KiB limit");
    }
    Ok(Entry {
        key: key.to_owned(),
        value,
    })
}

fn parse_value(value: &str) -> Result<String, &'static str> {
    if let Some(quoted) = value.strip_prefix('"') {
        return parse_double_quoted(quoted);
    }
    if let Some(quoted) = value.strip_prefix('\'') {
        return parse_single_quoted(quoted);
    }
    Ok(value.to_owned())
}

fn parse_double_quoted(value: &str) -> Result<String, &'static str> {
    let mut result = String::new();
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            result.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\\' => '\\',
                '"' => '"',
                _ => return Err("unknown escape in double-quoted value"),
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            if value[index + character.len_utf8()..].trim().is_empty() {
                return Ok(result);
            }
            return Err("unexpected characters after quoted value");
        } else {
            result.push(character);
        }
    }
    Err("unterminated double-quoted value")
}

fn parse_single_quoted(value: &str) -> Result<String, &'static str> {
    let Some(end) = value.find('\'') else {
        return Err("unterminated single-quoted value");
    };
    if !value[end + 1..].trim().is_empty() {
        return Err("unexpected characters after quoted value");
    }
    Ok(value[..end].to_owned())
}

pub fn render(entries: &[Entry]) -> String {
    let mut output = String::new();
    for entry in entries {
        output.push_str(&entry.key);
        output.push('=');
        output.push_str(&render_value(&entry.value));
        output.push('\n');
    }
    output
}

fn render_value(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let safe = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'%' | b'+')
    });
    if safe {
        return value.to_owned();
    }
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(character),
        }
    }
    result.push('"');
    result
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 255
        && key.bytes().enumerate().all(|(index, byte)| {
            byte == b'_'
                || byte.is_ascii_alphanumeric() && (index > 0 || byte.is_ascii_alphabetic())
        })
}

#[cfg(test)]
mod tests {
    use super::{Entry, MAX_ENTRIES, parse, render};

    #[test]
    fn parses_data_without_shell_interpolation() {
        let report = parse(
            "# comment\nexport API_URL=https://example.test/a=b\nTOKEN=$HOME-$(whoami)\nEMPTY=\n",
        );
        assert!(report.issues.is_empty());
        assert_eq!(report.entries[0].value, "https://example.test/a=b");
        assert_eq!(report.entries[1].value, "$HOME-$(whoami)");
        assert_eq!(report.entries[2].value, "");
    }

    #[test]
    fn canonical_round_trip_covers_required_edge_cases() {
        let entries = vec![
            Entry {
                key: "SPACE".into(),
                value: " two words ".into(),
            },
            Entry {
                key: "QUOTE".into(),
                value: "say \"hello\"".into(),
            },
            Entry {
                key: "HASH".into(),
                value: "a#b".into(),
            },
            Entry {
                key: "NEWLINE".into(),
                value: "first\nsecond".into(),
            },
            Entry {
                key: "EQUALS".into(),
                value: "a=b=c".into(),
            },
            Entry {
                key: "UNICODE".into(),
                value: "halo dunia 🌏".into(),
            },
            Entry {
                key: "EMPTY".into(),
                value: String::new(),
            },
            Entry {
                key: "SLASH".into(),
                value: r"C:\path\value".into(),
            },
        ];
        let rendered = render(&entries);
        let reparsed = parse(&rendered);
        assert!(reparsed.issues.is_empty(), "{:?}", reparsed.issues);
        assert_eq!(reparsed.entries, entries);
    }

    #[test]
    fn reports_duplicates_invalid_keys_and_ambiguous_quotes() {
        let report = parse("A=one\nA=two\n9BAD=value\nBROKEN=\"value\" trailing\n");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.issues.len(), 3);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.message == "duplicate key")
        );
    }

    #[test]
    fn enforces_entry_limit() {
        let input = (0..=MAX_ENTRIES)
            .map(|index| format!("K{index}=value"))
            .collect::<Vec<_>>()
            .join("\n");
        let report = parse(&input);
        assert_eq!(report.entries.len(), MAX_ENTRIES);
        assert_eq!(report.issues.len(), 1);
    }
}
