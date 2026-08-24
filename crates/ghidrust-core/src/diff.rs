//! Program-vs-program diff (changed bytes + unmatched sections/functions).
//!
//! Reference: Ghidra Version Tracking / radiff2 block comparison — not a count-only dialog.

use crate::program::Program;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProgramDiff {
    pub left_name: String,
    pub right_name: String,
    pub unmatched_sections_left: Vec<String>,
    pub unmatched_sections_right: Vec<String>,
    pub unmatched_functions_left: Vec<String>,
    pub unmatched_functions_right: Vec<String>,
    pub byte_diffs: Vec<ByteDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteDiff {
    pub va: u64,
    pub left: u8,
    pub right: u8,
}

impl ProgramDiff {
    pub fn is_count_only(&self) -> bool {
        self.byte_diffs.is_empty()
            && self.unmatched_sections_left.is_empty()
            && self.unmatched_sections_right.is_empty()
            && self.unmatched_functions_left.is_empty()
            && self.unmatched_functions_right.is_empty()
    }

    pub fn render(&self) -> String {
        let mut s = format!(
            "diff {} vs {}\n",
            self.left_name, self.right_name
        );
        if self.is_count_only() {
            s.push_str("no section/function/byte differences\n");
            return s;
        }
        for n in &self.unmatched_sections_left {
            s.push_str(&format!("- section {n}\n"));
        }
        for n in &self.unmatched_sections_right {
            s.push_str(&format!("+ section {n}\n"));
        }
        for n in &self.unmatched_functions_left {
            s.push_str(&format!("- function {n}\n"));
        }
        for n in &self.unmatched_functions_right {
            s.push_str(&format!("+ function {n}\n"));
        }
        for d in self.byte_diffs.iter().take(64) {
            s.push_str(&format!("  {:#x}: {:02x} -> {:02x}\n", d.va, d.left, d.right));
        }
        if self.byte_diffs.len() > 64 {
            s.push_str(&format!("  … {} more byte diffs\n", self.byte_diffs.len() - 64));
        }
        s
    }
}

pub fn diff_programs(left: &Program, right: &Program) -> ProgramDiff {
    let mut d = ProgramDiff {
        left_name: left.name.clone(),
        right_name: right.name.clone(),
        ..Default::default()
    };
    let lsec: Vec<_> = left.sections.iter().map(|s| s.name.clone()).collect();
    let rsec: Vec<_> = right.sections.iter().map(|s| s.name.clone()).collect();
    for n in &lsec {
        if !rsec.iter().any(|x| x == n) {
            d.unmatched_sections_left.push(n.clone());
        }
    }
    for n in &rsec {
        if !lsec.iter().any(|x| x == n) {
            d.unmatched_sections_right.push(n.clone());
        }
    }
    let lfn: Vec<_> = left
        .analysis
        .functions
        .iter()
        .map(|f| format!("{}:{:#x}", f.name, f.entry))
        .collect();
    let rfn: Vec<_> = right
        .analysis
        .functions
        .iter()
        .map(|f| format!("{}:{:#x}", f.name, f.entry))
        .collect();
    for n in &lfn {
        if !rfn.iter().any(|x| x == n) {
            d.unmatched_functions_left.push(n.clone());
        }
    }
    for n in &rfn {
        if !lfn.iter().any(|x| x == n) {
            d.unmatched_functions_right.push(n.clone());
        }
    }
    for lb in &left.blocks {
        if let Some(rb) = right.blocks.iter().find(|b| b.va == lb.va) {
            let n = lb.bytes.len().min(rb.bytes.len());
            for i in 0..n {
                if lb.bytes[i] != rb.bytes[i] {
                    d.byte_diffs.push(ByteDiff {
                        va: lb.va + i as u64,
                        left: lb.bytes[i],
                        right: rb.bytes[i],
                    });
                    if d.byte_diffs.len() >= 256 {
                        return d;
                    }
                }
            }
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_function, load_bytes};

    #[test]
    fn mutated_copy_reports_byte_or_function_diff() {
        let pe = crate::fixture_path("tiny_x64.pe");
        let data = std::fs::read(&pe).expect("pe");
        let mut left = load_bytes(&data, "a").expect("left");
        let mut right = load_bytes(&data, "b").expect("right");
        let entry = left.entry.unwrap();
        let _ = create_function(&mut left, entry, None);
        if let Some(b) = right.blocks.first_mut() {
            if !b.bytes.is_empty() {
                b.bytes[0] ^= 0xff;
            }
        }
        let d = diff_programs(&left, &right);
        assert!(
            !d.is_count_only(),
            "expected real diff, got {}",
            d.render()
        );
        let text = d.render();
        assert!(
            text.contains("function") || text.contains("0x") || text.contains("section"),
            "{text}"
        );
        assert!(!text.starts_with("Sections:"), "must not be count-only");
    }
}
