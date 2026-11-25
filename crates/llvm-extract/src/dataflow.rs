use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct Origins {
    map: HashMap<String, Vec<u32>>,
}

impl Origins {
    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn of(&self, register: &str) -> &[u32] {
        self.map.get(register).map_or(&[], Vec::as_slice)
    }

    pub fn produced_by(&mut self, register: &str, node: u32) {
        self.map.insert(register.to_string(), vec![node]);
    }

    pub fn derived_from(&mut self, register: &str, sources: Vec<u32>) {
        if sources.is_empty() {
            self.map.remove(register);
        } else {
            let mut sources = sources;
            sources.sort_unstable();
            sources.dedup();
            self.map.insert(register.to_string(), sources);
        }
    }

    pub fn behind(&self, rhs: &str) -> Vec<u32> {
        let mut out: Vec<u32> = used_registers(rhs)
            .into_iter()
            .flat_map(|r| self.of(r).iter().copied())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

pub fn split_assignment(line: &str) -> (Option<&str>, &str) {
    if !line.starts_with('%') {
        return (None, line);
    }
    let Some(eq) = line.find(" = ") else {
        return (None, line);
    };
    let dst = line[..eq].trim();
    if dst.contains(char::is_whitespace) || dst.contains('"') {
        return (None, line);
    }
    (Some(dst), line[eq + 3..].trim_start())
}

pub fn reads_memory(rhs: &str) -> bool {
    rhs.split_whitespace()
        .find(|w| !matches!(*w, "volatile" | "atomic" | "tail" | "musttail" | "notail"))
        .is_some_and(|opcode| opcode == "load")
}

pub fn used_registers(rhs: &str) -> Vec<&str> {
    let bytes = rhs.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'"') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i + 1;
        while end < bytes.len() && is_name_byte(bytes[end]) {
            end += 1;
        }
        if end > start + 1 {
            let name = &rhs[start..end];
            if !out.contains(&name) {
                out.push(name);
            }
        }
        i = end.max(start + 1);
    }
    out
}

pub fn sret_slot(rhs: &str) -> Option<&str> {
    let at = rhs.find("sret(")?;
    let after = &rhs[at + "sret(".len()..];
    let close = after.find(')')?;
    first_register(&after[close + 1..])
}

pub fn memcpy_operands(rhs: &str) -> Option<(&str, &str)> {
    if !rhs.contains("llvm.memcpy") {
        return None;
    }
    match used_registers(rhs).as_slice() {
        [dst, src, ..] => Some((dst, src)),
        _ => None,
    }
}

pub fn load_pointer(rhs: &str) -> Option<&str> {
    reads_memory(rhs).then(|| first_register(rhs)).flatten()
}

fn first_register(s: &str) -> Option<&str> {
    used_registers(s).into_iter().next()
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'$' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_assignment_splits_into_destination_and_rhs() {
        let (dst, rhs) = split_assignment("%0 = call i32 @f(ptr %m)");
        assert_eq!(dst, Some("%0"));
        assert_eq!(rhs, "call i32 @f(ptr %m)");
    }

    #[test]
    fn an_instruction_with_no_result_has_no_destination() {
        let (dst, rhs) = split_assignment("call void @g(ptr %0)");
        assert_eq!(dst, None);
        assert_eq!(rhs, "call void @g(ptr %0)");
    }

    #[test]
    fn a_quoted_name_is_not_a_destination() {
        let (dst, _) = split_assignment("%\"core::option::Option\" = type { i8 }");
        assert_eq!(dst, None);
    }

    #[test]
    fn uses_are_read_off_the_right_hand_side() {
        assert_eq!(
            used_registers("call i32 @f(ptr %msg, i64 %len, ptr %msg)"),
            vec!["%msg", "%len"],
            "in order, deduplicated"
        );
    }

    #[test]
    fn quoted_type_names_are_not_uses() {
        assert_eq!(
            used_registers("call void @f(ptr %0, %\"core::fmt::Formatter\"* %1)"),
            vec!["%0", "%1"]
        );
    }

    #[test]
    fn an_sret_slot_is_read_off_the_argument_list() {
        assert_eq!(
            sret_slot("invoke void @f(ptr sret([344 x i8]) align 8 %_4, ptr %rng, i64 2048)"),
            Some("%_4")
        );
        assert_eq!(sret_slot("call i32 @f(ptr %0)"), None);
    }

    #[test]
    fn memcpy_gives_up_its_destination_and_source() {
        assert_eq!(
            memcpy_operands(
                "call void @llvm.memcpy.p0.p0.i64(ptr align 8 %0, ptr align 8 %key, i64 344, i1 false)"
            ),
            Some(("%0", "%key"))
        );
        assert_eq!(memcpy_operands("call void @f(ptr %0, ptr %1)"), None);
    }

    #[test]
    fn a_load_yields_the_slot_it_reads() {
        assert_eq!(load_pointer("load ptr, ptr %_4, align 8"), Some("%_4"));
        assert_eq!(
            load_pointer("getelementptr inbounds i8, ptr %0, i64 8"),
            None
        );
    }

    #[test]
    fn a_load_is_the_boundary_and_a_pure_instruction_is_not() {
        assert!(reads_memory("load ptr, ptr %p"));
        assert!(reads_memory("volatile load i32, ptr %p"));
        assert!(!reads_memory("getelementptr inbounds i8, ptr %0, i64 8"));
        assert!(!reads_memory("bitcast ptr %0 to ptr"));
        assert!(!reads_memory("add i64 %0, 1"));
        assert!(!reads_memory("call i32 @f(ptr %0)"));
    }

    #[test]
    fn origins_travel_through_pure_instructions_and_merge() {
        let mut o = Origins::default();
        o.produced_by("%0", 7);
        o.produced_by("%1", 9);
        assert_eq!(o.of("%0"), &[7]);

        o.derived_from("%2", o.behind("add i64 %0, %1"));
        assert_eq!(o.of("%2"), &[7, 9], "both sources reach the derived value");

        o.derived_from("%3", o.behind("bitcast ptr %2 to ptr"));
        assert_eq!(o.of("%3"), &[7, 9], "and travel one more hop");
    }

    #[test]
    fn a_register_with_no_traced_origin_contributes_nothing() {
        let o = Origins::default();
        assert!(o.behind("call void @f(ptr %untracked)").is_empty());
    }

    #[test]
    fn clearing_drops_the_previous_bodys_registers() {
        let mut o = Origins::default();
        o.produced_by("%0", 7);
        o.clear();
        assert!(o.of("%0").is_empty());
    }
}
