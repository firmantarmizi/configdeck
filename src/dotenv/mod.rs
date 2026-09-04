use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_ENTRIES: usize = 500;
pub const MAX_VALUE_BYTES: usize = 32 * 1024;
const MAX_DESCRIPTION_CHARS: usize = 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub position: i64,
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
    if let Some(issue) = validate_input(input) {
        return ParseReport {
            issues: vec![issue],
            ..ParseReport::default()
        };
    }

    let mut report = ParseReport::default();
    let lines = input.lines().collect::<Vec<_>>();
    let mut keys = HashSet::new();
    let mut current_group = None;
    let mut pending_comments = Vec::new();
    let mut section_boundary = true;
    for (index, physical_line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let line = if index == 0 {
            physical_line
                .strip_prefix('\u{feff}')
                .unwrap_or(physical_line)
        } else {
            physical_line
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            pending_comments.clear();
            section_boundary = true;
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix('#') {
            let comment = comment.trim();
            if let Some(group) = parse_group_heading(comment).or_else(|| {
                section_boundary
                    .then(|| infer_plain_group(&lines, index, comment))
                    .flatten()
            }) {
                current_group = Some(group);
                pending_comments.clear();
                section_boundary = false;
            } else if !comment.is_empty() {
                pending_comments.push(comment.to_owned());
            }
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
            Ok(mut entry) => {
                let description =
                    (!pending_comments.is_empty()).then(|| pending_comments.join(" "));
                if description
                    .as_ref()
                    .is_some_and(|value| value.chars().count() > MAX_DESCRIPTION_CHARS)
                {
                    report.issues.push(ParseIssue {
                        line: line_number,
                        message: "description exceeds the 1,000-character limit",
                    });
                    pending_comments.clear();
                    continue;
                }
                if keys.insert(entry.key.clone()) {
                    entry.group.clone_from(&current_group);
                    entry.description = description;
                    entry.position = i64::try_from(report.entries.len()).unwrap_or(i64::MAX);
                    report.entries.push(entry);
                    pending_comments.clear();
                    section_boundary = false;
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

fn validate_input(input: &str) -> Option<ParseIssue> {
    if input.len() > MAX_INPUT_BYTES {
        Some(ParseIssue {
            line: 0,
            message: "input exceeds the 256 KiB limit",
        })
    } else if input.contains('\0') {
        Some(ParseIssue {
            line: 0,
            message: "NUL bytes are not allowed",
        })
    } else {
        None
    }
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
        group: None,
        description: None,
        position: 0,
    })
}

fn parse_group_heading(comment: &str) -> Option<String> {
    let bracketed = comment.strip_prefix('[')?.strip_suffix(']')?;
    normalize_group_name(bracketed)
}

fn infer_plain_group(lines: &[&str], index: usize, comment: &str) -> Option<String> {
    let candidate = normalize_group_name(comment)?;
    if candidate.ends_with(['.', ':', ';']) || candidate.contains('=') {
        return None;
    }
    let mut following = lines[index + 1..]
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty());
    let next = following.next()?;
    let decorated = comment.starts_with(['=', '-', '*']) || comment.ends_with(['=', '-', '*']);
    let followed_by_description = next.starts_with('#')
        && following
            .find(|line| !line.starts_with('#'))
            .is_some_and(|line| parse_assignment(line).is_ok());
    (decorated || followed_by_description).then_some(candidate)
}

fn normalize_group_name(value: &str) -> Option<String> {
    let trimmed = value
        .trim()
        .trim_matches(|character| matches!(character, '=' | '-' | '*' | ' '))
        .trim();
    (!trimmed.is_empty() && trimmed.chars().count() <= 80).then(|| trimmed.to_owned())
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
    let group_order = entries
        .iter()
        .filter_map(|entry| {
            entry
                .group
                .as_ref()
                .map(|group| (group.as_str(), entry.position))
        })
        .fold(
            BTreeMap::<&str, i64>::new(),
            |mut order, (group, position)| {
                order
                    .entry(group)
                    .and_modify(|current| *current = (*current).min(position))
                    .or_insert(position);
                order
            },
        );
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| match (&left.group, &right.group) {
        (None, None) => left
            .position
            .cmp(&right.position)
            .then_with(|| left.key.cmp(&right.key)),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(left_group), Some(right_group)) => group_order
            .get(left_group.as_str())
            .cmp(&group_order.get(right_group.as_str()))
            .then_with(|| left_group.cmp(right_group))
            .then_with(|| left.position.cmp(&right.position))
            .then_with(|| left.key.cmp(&right.key)),
    });

    let mut output = String::new();
    let mut previous_group: Option<&str> = None;
    for entry in ordered {
        let group = entry.group.as_deref();
        if group != previous_group {
            if !output.is_empty() {
                output.push('\n');
            }
            if let Some(group) = group {
                output.push_str("# [");
                output.push_str(group);
                output.push_str("]\n");
            }
            previous_group = group;
        }
        if let Some(description) = entry.description.as_deref() {
            for line in description
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                output.push_str("# ");
                output.push_str(line);
                output.push('\n');
            }
        }
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
                group: None,
                description: None,
                position: 0,
            },
            Entry {
                key: "QUOTE".into(),
                value: "say \"hello\"".into(),
                group: None,
                description: None,
                position: 1,
            },
            Entry {
                key: "HASH".into(),
                value: "a#b".into(),
                group: None,
                description: None,
                position: 2,
            },
            Entry {
                key: "NEWLINE".into(),
                value: "first\nsecond".into(),
                group: None,
                description: None,
                position: 3,
            },
            Entry {
                key: "EQUALS".into(),
                value: "a=b=c".into(),
                group: None,
                description: None,
                position: 4,
            },
            Entry {
                key: "UNICODE".into(),
                value: "halo dunia 🌏".into(),
                group: None,
                description: None,
                position: 5,
            },
            Entry {
                key: "EMPTY".into(),
                value: String::new(),
                group: None,
                description: None,
                position: 6,
            },
            Entry {
                key: "SLASH".into(),
                value: r"C:\path\value".into(),
                group: None,
                description: None,
                position: 7,
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

    #[test]
    fn detects_groups_and_key_descriptions_without_exposing_values() {
        let report = parse(
            "# [Database]\n# Primary database host\nDB_HOST=db.internal\nDB_PORT=5432\n\n# Cache\n# Shared cache endpoint\nREDIS_URL=redis://cache\n",
        );
        assert!(report.issues.is_empty(), "{:?}", report.issues);
        assert_eq!(report.entries[0].group.as_deref(), Some("Database"));
        assert_eq!(
            report.entries[0].description.as_deref(),
            Some("Primary database host")
        );
        assert_eq!(report.entries[1].group.as_deref(), Some("Database"));
        assert_eq!(report.entries[2].group.as_deref(), Some("Cache"));

        let rendered = render(&report.entries);
        assert!(rendered.contains("# [Database]"));
        assert!(rendered.contains("# Primary database host"));
        assert_eq!(parse(&rendered).entries, report.entries);
    }

    #[test]
    fn canonical_render_places_ungrouped_entries_before_grouped_sections() {
        let entries = vec![
            Entry {
                key: "DB_HOST".into(),
                value: "database".into(),
                group: Some("Database".into()),
                description: None,
                position: 0,
            },
            Entry {
                key: "APP_NAME".into(),
                value: "ConfigDeck".into(),
                group: None,
                description: Some("Application display name".into()),
                position: 1,
            },
        ];

        let rendered = render(&entries);
        assert!(rendered.starts_with("# Application display name\nAPP_NAME=ConfigDeck\n"));
        let reparsed = parse(&rendered);
        assert!(reparsed.issues.is_empty(), "{:?}", reparsed.issues);
        assert_eq!(reparsed.entries[0].group, None);
        assert_eq!(reparsed.entries[1].group.as_deref(), Some("Database"));
    }
}
