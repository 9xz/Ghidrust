//! Hand-rolled C header parser (Ghidra Parse C Source analog).
//!
//! Reference grammar (not linked): Clang `ParseDecl` / Ghidra `CParser` /
//! pycparser c_parser — structs, typedefs, enums, function prototypes.
//! No clang/libclang/tree-sitter runtime.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedType {
    pub name: String,
    pub kind: String,
    pub members: Vec<ParsedMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedMember {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ParseError {}

/// Parse a C header/source snippet into named types with members/params.
pub fn parse_c_source(src: &str) -> Result<Vec<ParsedType>, ParseError> {
    let stripped = strip_comments_and_pp(src);
    let toks = tokenize(&stripped);
    let mut p = Parser { toks, i: 0 };
    p.parse_unit()
}

fn strip_comments_and_pp(src: &str) -> String {
    let mut out = String::new();
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
            out.push(' ');
            continue;
        }
        if b[i] == b'#' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn tokenize(s: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_whitespace() {
            if !cur.is_empty() {
                toks.push(std::mem::take(&mut cur));
            }
        } else if matches!(c, '{' | '}' | '(' | ')' | ';' | ',' | '*') {
            if !cur.is_empty() {
                toks.push(std::mem::take(&mut cur));
            }
            toks.push(c.to_string());
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        toks.push(cur);
    }
    toks
}

struct Parser {
    toks: Vec<String>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.i).map(String::as_str)
    }
    fn bump(&mut self) -> Option<String> {
        if self.i < self.toks.len() {
            let t = self.toks[self.i].clone();
            self.i += 1;
            Some(t)
        } else {
            None
        }
    }
    fn eat(&mut self, s: &str) -> bool {
        if self.peek() == Some(s) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, s: &str) -> Result<(), ParseError> {
        if self.eat(s) {
            Ok(())
        } else {
            Err(ParseError {
                message: format!("expected '{s}', got {:?}", self.peek()),
            })
        }
    }

    fn parse_unit(&mut self) -> Result<Vec<ParsedType>, ParseError> {
        let mut out = Vec::new();
        while self.peek().is_some() {
            if self.peek() == Some(";") {
                self.bump();
                continue;
            }
            if let Some(t) = self.parse_item()? {
                out.push(t);
            }
        }
        if out.is_empty() {
            return Err(ParseError {
                message: "no types parsed".into(),
            });
        }
        Ok(out)
    }

    fn parse_item(&mut self) -> Result<Option<ParsedType>, ParseError> {
        match self.peek() {
            Some("struct") => self.parse_struct(),
            Some("enum") => self.parse_enum(),
            Some("typedef") => self.parse_typedef(),
            Some("union") => self.parse_union(),
            Some(_) => self.parse_prototype_or_skip(),
            None => Ok(None),
        }
    }

    fn parse_struct(&mut self) -> Result<Option<ParsedType>, ParseError> {
        self.expect("struct")?;
        let name = self
            .bump()
            .filter(|t| is_ident(t))
            .ok_or_else(|| ParseError {
                message: "struct name".into(),
            })?;
        if !self.eat("{") {
            // opaque `struct Foo;`
            let _ = self.eat(";");
            return Ok(Some(ParsedType {
                name,
                kind: "struct".into(),
                members: Vec::new(),
            }));
        }
        let members = self.parse_fields()?;
        self.expect("}")?;
        let _ = self.eat(";");
        Ok(Some(ParsedType {
            name,
            kind: "struct".into(),
            members,
        }))
    }

    fn parse_union(&mut self) -> Result<Option<ParsedType>, ParseError> {
        self.expect("union")?;
        let name = self
            .bump()
            .filter(|t| is_ident(t))
            .unwrap_or_else(|| "anon_union".into());
        if !self.eat("{") {
            let _ = self.eat(";");
            return Ok(None);
        }
        let members = self.parse_fields()?;
        self.expect("}")?;
        let _ = self.eat(";");
        Ok(Some(ParsedType {
            name,
            kind: "union".into(),
            members,
        }))
    }

    fn parse_enum(&mut self) -> Result<Option<ParsedType>, ParseError> {
        self.expect("enum")?;
        let name = self
            .bump()
            .filter(|t| is_ident(t))
            .ok_or_else(|| ParseError {
                message: "enum name".into(),
            })?;
        self.expect("{")?;
        let mut members = Vec::new();
        while let Some(t) = self.peek() {
            if t == "}" {
                break;
            }
            if t == "," {
                self.bump();
                continue;
            }
            let n = self.bump().unwrap();
            if is_ident(&n) {
                members.push(ParsedMember {
                    name: n,
                    ty: "int".into(),
                });
            }
            if self.eat("=") {
                let _ = self.bump();
            }
        }
        self.expect("}")?;
        let _ = self.eat(";");
        Ok(Some(ParsedType {
            name,
            kind: "enum".into(),
            members,
        }))
    }

    fn parse_typedef(&mut self) -> Result<Option<ParsedType>, ParseError> {
        self.expect("typedef")?;
        if self.peek() == Some("struct") {
            let mut st = self.parse_struct()?.ok_or_else(|| ParseError {
                message: "typedef struct".into(),
            })?;
            // `typedef struct Foo { } Foo_t;` — last ident before `;` already eaten
            // After struct parse we already consumed `;`. Name stays struct name.
            if let Some(alias) = self.peek().filter(|t| is_ident(t)).map(|s| s.to_string()) {
                self.bump();
                let _ = self.eat(";");
                st.kind = "typedef".into();
                st.members.insert(
                    0,
                    ParsedMember {
                        name: st.name.clone(),
                        ty: "struct".into(),
                    },
                );
                st.name = alias;
            }
            return Ok(Some(st));
        }
        let ty = self.parse_type_spec();
        let name = self
            .bump()
            .filter(|t| is_ident(t))
            .ok_or_else(|| ParseError {
                message: "typedef name".into(),
            })?;
        if self.eat("(") {
            let params = self.parse_params()?;
            self.expect(")")?;
            let _ = self.eat(";");
            return Ok(Some(ParsedType {
                name,
                kind: "prototype".into(),
                members: params,
            }));
        }
        let _ = self.eat(";");
        Ok(Some(ParsedType {
            name,
            kind: "typedef".into(),
            members: vec![ParsedMember {
                name: "_alias".into(),
                ty,
            }],
        }))
    }

    fn parse_prototype_or_skip(&mut self) -> Result<Option<ParsedType>, ParseError> {
        let ty = self.parse_type_spec();
        if ty.is_empty() {
            self.bump();
            return Ok(None);
        }
        let name = match self.peek() {
            Some(t) if is_ident(t) => self.bump().unwrap(),
            _ => {
                // skip until ; or {
                while let Some(t) = self.bump() {
                    if t == ";" || t == "}" {
                        break;
                    }
                    if t == "{" {
                        let mut depth = 1;
                        while depth > 0 {
                            match self.bump().as_deref() {
                                Some("{") => depth += 1,
                                Some("}") => depth -= 1,
                                None => break,
                                _ => {}
                            }
                        }
                        break;
                    }
                }
                return Ok(None);
            }
        };
        if self.eat("(") {
            let params = self.parse_params()?;
            self.expect(")")?;
            if self.eat("{") {
                let mut depth = 1;
                while depth > 0 {
                    match self.bump().as_deref() {
                        Some("{") => depth += 1,
                        Some("}") => depth -= 1,
                        None => break,
                        _ => {}
                    }
                }
            }
            let _ = self.eat(";");
            return Ok(Some(ParsedType {
                name,
                kind: "prototype".into(),
                members: params,
            }));
        }
        let _ = self.eat(";");
        Ok(None)
    }

    fn parse_fields(&mut self) -> Result<Vec<ParsedMember>, ParseError> {
        let mut members = Vec::new();
        while let Some(t) = self.peek() {
            if t == "}" {
                break;
            }
            let ty = self.parse_type_spec();
            let name = self
                .bump()
                .filter(|t| is_ident(t))
                .unwrap_or_else(|| "_".into());
            let _ = self.eat(";");
            if !ty.is_empty() {
                members.push(ParsedMember { name, ty });
            }
        }
        Ok(members)
    }

    fn parse_params(&mut self) -> Result<Vec<ParsedMember>, ParseError> {
        let mut params = Vec::new();
        if self.peek() == Some(")") {
            return Ok(params);
        }
        if self.peek() == Some("void") {
            let _ = self.bump();
            return Ok(params);
        }
        loop {
            let ty = self.parse_type_spec();
            let name = if self.peek().is_some_and(is_ident) && self.peek() != Some(")") {
                self.bump().unwrap()
            } else {
                format!("arg{}", params.len())
            };
            if !ty.is_empty() {
                params.push(ParsedMember { name, ty });
            }
            if self.eat(",") {
                continue;
            }
            break;
        }
        Ok(params)
    }

    fn parse_type_spec(&mut self) -> String {
        let mut parts = Vec::new();
        const KW: &[&str] = &[
            "const",
            "volatile",
            "unsigned",
            "signed",
            "struct",
            "enum",
            "union",
            "int",
            "char",
            "short",
            "long",
            "void",
            "float",
            "double",
            "size_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "int8_t",
            "int16_t",
            "int32_t",
            "int64_t",
        ];
        while let Some(t) = self.peek() {
            let continue_ident = is_ident(t)
                && (parts.is_empty()
                    || matches!(
                        parts.last().map(String::as_str),
                        Some("struct" | "enum" | "union" | "unsigned" | "signed" | "long" | "short" | "const")
                    ));
            if KW.contains(&t) || continue_ident {
                parts.push(self.bump().unwrap());
                continue;
            }
            if t == "*" {
                parts.push(self.bump().unwrap());
                continue;
            }
            break;
        }
        parts.join(" ")
    }
}

fn is_ident(s: &str) -> bool {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {
            cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    }
}

/// Pretty body stored in `ProgramEdits.user_types`.
pub fn format_type_body(t: &ParsedType) -> String {
    let mut s = format!("{} {}\n", t.kind, t.name);
    for m in &t.members {
        s.push_str(&format!("  {} {}\n", m.ty, m.name));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNIPPET: &str = r#"
        struct Widget {
            int id;
            char *name;
        };
        typedef unsigned int u32;
        enum Color { RED, GREEN, BLUE };
        int draw(struct Widget *w, int flags);
    "#;

    #[test]
    fn parses_struct_typedef_enum_prototype() {
        let types = parse_c_source(SNIPPET).expect("parse");
        assert!(!types.is_empty());
        let names: Vec<_> = types.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"Widget"), "{names:?}");
        assert!(names.contains(&"u32"), "{names:?}");
        assert!(names.contains(&"Color"), "{names:?}");
        assert!(names.contains(&"draw"), "{names:?}");
        let w = types.iter().find(|t| t.name == "Widget").unwrap();
        assert_eq!(w.kind, "struct");
        assert!(w.members.iter().any(|m| m.name == "id"));
        assert!(w.members.iter().any(|m| m.name == "name"));
        let d = types.iter().find(|t| t.name == "draw").unwrap();
        assert_eq!(d.kind, "prototype");
        assert!(d.members.iter().any(|m| m.ty.contains("Widget") || m.name.contains("w") || m.ty.contains("int")));
        let c = types.iter().find(|t| t.name == "Color").unwrap();
        assert!(c.members.iter().any(|m| m.name == "RED"));
    }

    #[test]
    fn apply_parsed_c_stores_fields_on_program() {
        let mut prog = crate::Program::new("t".into(), "PE32+");
        let types = parse_c_source(SNIPPET).unwrap();
        prog.edits.apply_parsed_c(types);
        let w = prog.edits.parsed_types.get("Widget").expect("Widget");
        assert!(w.members.iter().any(|m| m.name == "id" || m.name == "name"));
        assert!(prog.edits.user_types["Widget"].contains("id"));
    }
}
