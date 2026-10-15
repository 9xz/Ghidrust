//! Function Start Search — PE pdata/exports first, then entry, symbols, prologues.

use super::AnalyzerOutput;
use crate::error::Result;
use crate::pe_functions::{
    KnownFunctionSpans, RuntimeFunction, grow_function, parse_export_code_vas,
    parse_runtime_functions,
};
use crate::program::{FunctionInfo, FunctionSeedKind, Program};

pub fn run(prog: &mut Program) -> Result<AnalyzerOutput> {
    let mut seeds: Vec<(u64, FunctionSeedKind, Option<u64>, Option<String>)> = Vec::new();

    // 1) PE Exception Directory — authoritative begins/ends (mandatory PE64 pass).
    let runtime: Vec<RuntimeFunction> = parse_runtime_functions(prog);
    for rf in &runtime {
        seeds.push((rf.begin_va, FunctionSeedKind::Pdata, Some(rf.end_va), None));
    }
    // Weak seeds (symbol names, byte-pattern prologues) must never split these bodies.
    let pdata_spans = KnownFunctionSpans::from_runtime(&runtime);

    // 2) PE exports that land in executable memory.
    for (va, name) in parse_export_code_vas(prog) {
        seeds.push((va, FunctionSeedKind::Export, None, Some(name)));
    }

    // 3) Image entry.
    if let Some(e) = prog.entry {
        seeds.push((e, FunctionSeedKind::Prologue, None, None));
    }

    // 4) Symbol VAs that look like code entries.
    for s in &prog.analysis.symbols {
        if !prog.contains_va(s.va) {
            continue;
        }
        if !prog
            .blocks
            .iter()
            .any(|b| b.executable && s.va >= b.va && s.va < b.va + b.size)
        {
            continue;
        }
        let weak_name =
            s.name.starts_with("FUN_") || s.name.starts_with("Lab") || s.name.starts_with("synth_");
        if weak_name && !pdata_spans.contains_interior(s.va) {
            seeds.push((s.va, FunctionSeedKind::Prologue, None, Some(s.name.clone())));
        }
    }

    // 5) Prologue scan: push rbp; mov rbp, rsp — and standalone sub rsp, imm.
    for block in prog.exec_blocks() {
        let b = &block.bytes;
        let mut i = 0;
        while i + 4 <= b.len() {
            let at_push_rbp_mov =
                b[i] == 0x55 && b[i + 1] == 0x48 && b[i + 2] == 0x89 && b[i + 3] == 0xE5;
            if at_push_rbp_mov {
                let va = block.va + i as u64;
                if !pdata_spans.contains_interior(va) {
                    seeds.push((va, FunctionSeedKind::Prologue, None, None));
                }
                i += 4;
                continue;
            }
            if b[i] == 0x48 && b[i + 1] == 0x83 && b[i + 2] == 0xEC {
                let mid_frame = i >= 4
                    && b[i - 4] == 0x55
                    && b[i - 3] == 0x48
                    && b[i - 2] == 0x89
                    && b[i - 1] == 0xE5;
                if !mid_frame && !pdata_spans.contains_interior(block.va + i as u64) {
                    seeds.push((block.va + i as u64, FunctionSeedKind::Prologue, None, None));
                }
            }
            i += 1;
        }
    }

    // Prefer pdata / export over weaker seeds at the same VA.
    seeds.sort_by(|(a, ka, _, _), (b, kb, _, _)| {
        a.cmp(b)
            .then_with(|| seed_priority(ka).cmp(&seed_priority(kb)))
    });
    let mut merged: Vec<(u64, FunctionSeedKind, Option<u64>, Option<String>)> = Vec::new();
    for (va, kind, pdata_end, name) in seeds {
        if let Some(last) = merged.last_mut() {
            if last.0 == va {
                if seed_priority(&kind) < seed_priority(&last.1) {
                    last.1 = kind;
                }
                if last.2.is_none() {
                    last.2 = pdata_end;
                }
                if last.3.is_none() {
                    last.3 = name;
                }
                continue;
            }
        }
        merged.push((va, kind, pdata_end, name));
    }
    let seeds = merged;

    // Grow: weak seeds end at min(next_seed, first_ret, int3_run>=2, decode_bail).
    // PE Exception Directory seeds keep their full unwind span (an early `ret` inside
    // it is not the end); only a following authoritative seed can shorten them.
    let mut raw: Vec<FunctionInfo> = Vec::new();
    for (i, (entry, kind, pdata_end, name_opt)) in seeds.iter().enumerate() {
        let next_seed = seeds.get(i + 1).map(|(v, _, _, _)| *v);
        let hard = match (pdata_end, next_seed) {
            (Some(pe), Some(ns)) => Some((*pe).min(ns)),
            (Some(pe), None) => Some(*pe),
            (None, Some(ns)) => Some(ns),
            (None, None) => None,
        };
        let end = match (pdata_end, hard) {
            (Some(_), Some(limit)) => pdata_body_end(prog, *entry, limit),
            _ => None,
        }
        .unwrap_or_else(|| grow_function(prog, *entry, hard));
        let name = name_opt
            .clone()
            .or_else(|| {
                prog.analysis
                    .symbols
                    .iter()
                    .find(|s| s.va == *entry)
                    .map(|s| s.name.clone())
            })
            .unwrap_or_else(|| format!("FUN_{entry:08x}"));
        raw.push(FunctionInfo::new(*entry, end, name).with_seed_kind(*kind));
    }

    // Prefer earlier starts: discard any start strictly inside a kept function.
    // Entries are unique and sorted, so the furthest kept end is the only one to test.
    raw.sort_by_key(|f| f.entry);
    let mut functions: Vec<FunctionInfo> = Vec::with_capacity(raw.len());
    let mut kept_end = 0u64;
    for f in raw {
        if f.entry < kept_end {
            continue;
        }
        kept_end = kept_end.max(f.end);
        functions.push(f);
    }
    if functions.is_empty() {
        if let Some(e) = prog.entry {
            functions.push(
                FunctionInfo::new(e, grow_function(prog, e, None), format!("FUN_{e:08x}"))
                    .with_seed_kind(FunctionSeedKind::Prologue),
            );
        }
    }
    let n = functions.len();
    let pdata_n = functions
        .iter()
        .filter(|f| f.seed_kind == Some(FunctionSeedKind::Pdata))
        .count();
    prog.analysis.functions = functions.clone();
    Ok(AnalyzerOutput {
        name: "Function Start Search".into(),
        status: "ok".into(),
        message: format!(
            "identified {n} function start(s) ({pdata_n} from PE Exception Directory)"
        ),
        functions: Some(functions),
        ..Default::default()
    })
}

/// Authoritative end of a `.pdata`-covered body: the whole unwind span (or the next
/// authoritative seed when one lands inside it), clamped to the executable block that
/// holds `entry`. `None` when `entry` is not in executable memory.
fn pdata_body_end(prog: &Program, entry: u64, limit: u64) -> Option<u64> {
    let block = prog
        .exec_blocks()
        .find(|b| entry >= b.va && entry < b.va.saturating_add(b.size))?;
    Some(
        limit
            .min(block.va.saturating_add(block.size))
            .max(entry.saturating_add(1)),
    )
}

fn seed_priority(k: &FunctionSeedKind) -> u8 {
    match k {
        FunctionSeedKind::Pdata => 0,
        FunctionSeedKind::Export => 1,
        FunctionSeedKind::MethodPointer => 2,
        FunctionSeedKind::Prologue => 3,
        FunctionSeedKind::Manual => 4,
        FunctionSeedKind::Synthesized => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::{DisasmMode, disassemble_range_ex};
    use crate::pe_functions::split_bait as bait;
    use crate::program::SymbolInfo;
    use crate::xrefs::calls_callees;

    fn listing_mnemonics(prog: &Program, f: &FunctionInfo) -> Vec<String> {
        let r = disassemble_range_ex(prog, f.entry, 64, false, DisasmMode::Bounded, Some(f.end))
            .expect("bounded listing");
        let last = r.insns.last().expect("non-empty listing");
        assert_eq!(
            last.address + last.length as u64,
            f.end,
            "listing must tile the stored extent exactly"
        );
        r.insns.iter().map(|i| i.mnemonic.clone()).collect()
    }

    #[test]
    fn pdata_body_is_not_split_by_interior_prologue_patterns() {
        let mut prog = bait::program();
        run(&mut prog).unwrap();

        let entries: Vec<u64> = prog.analysis.functions.iter().map(|f| f.entry).collect();
        assert_eq!(
            entries,
            vec![bait::BAIT, bait::NEXT],
            "interior `sub rsp` (+3) and `push rbp; mov rbp, rsp` (+0x13) must not become starts"
        );

        // Full .pdata span, past the early `ret` at +0x12.
        let f = prog.function_at(bait::BAIT).unwrap().clone();
        assert_eq!(f.end, bait::BAIT_END);
        assert_eq!(f.seed_kind, Some(FunctionSeedKind::Pdata));

        // Preserved code: all three pushes, the sub rsp, both returns.
        let m = listing_mnemonics(&prog, &f);
        assert_eq!(&m[..4], ["push", "push", "push", "sub"]);
        assert_eq!(m.iter().filter(|s| *s == "ret").count(), 2);
        assert_eq!(m.last().map(String::as_str), Some("ret"));

        // Preserved call: the post-early-ret `call NEXT` is still an outgoing edge.
        let edges = calls_callees(&prog, bait::BAIT);
        assert!(
            edges
                .iter()
                .any(|e| e.kind == "call" && e.to == bait::NEXT && e.to_entry == Some(bait::NEXT)),
            "missing call edge to NEXT in {edges:?}"
        );
    }

    #[test]
    fn function_after_pdata_body_remains_discoverable() {
        let mut prog = bait::program();
        run(&mut prog).unwrap();

        let next = prog
            .function_at(bait::NEXT)
            .expect("NEXT must be discovered");
        assert_eq!(next.seed_kind, Some(FunctionSeedKind::Prologue));
        assert_eq!(next.end, bait::NEXT_END);
        assert_eq!(listing_mnemonics(&prog, next), ["sub", "xor", "add", "ret"]);
        // The metadata-bounded neighbour neither grows into nor is cut by NEXT.
        assert_eq!(prog.function_at(bait::BAIT).unwrap().end, bait::BAIT_END);
    }

    #[test]
    fn weak_symbol_seeds_inside_pdata_body_are_ignored() {
        let mut prog = bait::program();
        for (va, name) in [
            (bait::INTERIOR_SUB_RSP, "FUN_140001003"),
            (bait::INTERIOR_PUSH_RBP, "Lab140001013"),
        ] {
            prog.analysis.symbols.push(SymbolInfo {
                va,
                name: name.into(),
                demangled: None,
            });
        }
        run(&mut prog).unwrap();
        let entries: Vec<u64> = prog.analysis.functions.iter().map(|f| f.entry).collect();
        assert_eq!(entries, vec![bait::BAIT, bait::NEXT]);
        assert_eq!(prog.function_at(bait::BAIT).unwrap().end, bait::BAIT_END);
    }
}
