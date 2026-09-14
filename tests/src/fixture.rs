use std::{collections::HashMap, path::PathBuf};

pub(crate) fn fixture(file: &str) -> HashMap<String, Vec<u8>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("x86_64/crypto").join(file)).unwrap();
    let mut out: HashMap<String, Vec<u8>> = HashMap::new();
    let mut label = String::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let (name, body) = match line.find(':') {
            Some(i) if !line[..i].contains(char::is_whitespace) => {
                (Some(line[..i].trim()), line[i + 1..].trim())
            }
            _ => (None, line),
        };
        if let Some(n) = name {
            label = n.to_owned();
            out.entry(label.clone()).or_default();
        }
        if label.is_empty() {
            continue;
        }
        let mut p = body.splitn(2, char::is_whitespace);
        let op = p.next().unwrap();
        let args = p.next().unwrap_or("").trim();
        let v = out.get_mut(&label).unwrap();
        match op {
            ".byte" => {
                for x in args.split(',') {
                    v.push(num(x));
                }
            }
            ".quad" => {
                for x in args.split(',') {
                    v.extend_from_slice(&num64(x).to_le_bytes());
                }
            }
            ".zero" | ".space" => v.resize(v.len() + num64(args) as usize, 0),
            ".fill" => {
                let mut x = args.split(',');
                let n = num64(x.next().unwrap()) as usize;
                let value = num(x.nth(1).unwrap_or("0"));
                v.extend(std::iter::repeat_n(value, n));
            }
            ".ascii" | ".asciz" => {
                let s = args.trim_matches('"').as_bytes();
                v.extend_from_slice(s);
                if op == ".asciz" {
                    v.push(0);
                }
            }
            _ => {}
        }
    }
    out
}

fn num(s: &str) -> u8 {
    let s = s.trim();
    if s == "-1" {
        255
    } else if let Some(x) = s.strip_prefix("0x") {
        u64::from_str_radix(x, 16).unwrap() as u8
    } else {
        s.parse::<u64>().unwrap() as u8
    }
}

fn num64(s: &str) -> u64 {
    let s = s.trim();
    if s == "-1" {
        u64::MAX
    } else if let Some(x) = s.strip_prefix("0x") {
        u64::from_str_radix(x, 16).unwrap()
    } else {
        s.parse().unwrap()
    }
}
