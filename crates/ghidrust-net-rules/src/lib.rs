//! Ghidrust Net Rule (GNR) dialect — Suricata/ET-shaped parse, compile, ET Open install.

mod addr;
mod install;
mod parse;

pub use addr::{addr_matches, port_matches};
pub use install::{
    active_pack_path, bundled_minimal_rules, install_et_open, list_rules_json, load_active_ruleset,
    md5_hex_pub, set_active_pack, tar_gz_dir, user_rules_root, write_mini_et_tree, InstallOpts,
    InstallReport,
    DEFAULT_ET_VERSION,
};
pub use parse::{
    compile_rules, compile_rules_with, default_vars, load_rule_pack, load_vars_file, CompiledRuleset,
    ContentOpt, DetectOp, Rule, RuleError, SkippedSid, Vars,
};
