#[cfg(test)]
mod tests {
    use crate::docgen::*;

    #[test]
    fn test_extract_docs_policy_with_comment() {
        let source = "// Access control for AI systems.\npolicy access { rule allow() { permit } }";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "access");
        assert_eq!(items[0].kind, DocItemKind::Policy);
        assert_eq!(
            items[0].doc_comment,
            Some("Access control for AI systems.".to_string())
        );
    }

    #[test]
    fn test_extract_docs_function_with_comment() {
        let source = "// Compute the risk score.\nfn risk(x: Int) -> Int { x }";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "risk");
        assert_eq!(items[0].kind, DocItemKind::Function);
        assert_eq!(
            items[0].doc_comment,
            Some("Compute the risk score.".to_string())
        );
        assert!(items[0].signature.contains("fn risk("));
    }

    #[test]
    fn test_extract_docs_no_comment() {
        let source = "policy access { rule allow() { permit } }";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].doc_comment, None);
    }

    #[test]
    fn test_extract_children_rules_inside_policy() {
        let source = "policy access {\n    // Allow if low risk.\n    rule allow(risk: Int) { permit }\n    rule deny_high() { deny }\n}";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].children.len(), 2);
        assert_eq!(items[0].children[0].name, "allow");
        assert_eq!(items[0].children[0].kind, DocItemKind::Rule);
        assert_eq!(
            items[0].children[0].doc_comment,
            Some("Allow if low risk.".to_string())
        );
        assert_eq!(items[0].children[1].name, "deny_high");
    }

    #[test]
    fn test_extract_struct_fields_as_children() {
        let source = "struct Model {\n    name: String,\n    version: Int\n}";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Model");
        assert_eq!(items[0].kind, DocItemKind::Struct);
        assert_eq!(items[0].children.len(), 2);
        assert_eq!(items[0].children[0].name, "name");
        assert_eq!(items[0].children[1].name, "version");
    }

    #[test]
    fn test_render_markdown_table_of_contents() {
        let source = "// A policy.\npolicy access { rule allow() { permit } }\n\nfn helper() -> Int { 42 }";
        let items = extract_docs(source);
        let md = render_markdown(&items, "test_module");
        assert!(md.contains("# test_module"));
        assert!(md.contains("## Table of Contents"));
        assert!(md.contains("- [access]"));
        assert!(md.contains("- [helper]"));
    }

    #[test]
    fn test_render_markdown_code_blocks() {
        let source = "fn compute(x: Int) -> Int { x }";
        let items = extract_docs(source);
        let md = render_markdown(&items, "module");
        assert!(md.contains("```rune"));
        assert!(md.contains("fn compute("));
    }

    #[test]
    fn test_render_markdown_doc_comments() {
        let source = "// Does important work.\nfn work() -> Int { 1 }";
        let items = extract_docs(source);
        let md = render_markdown(&items, "module");
        assert!(md.contains("Does important work."));
    }

    #[test]
    fn test_empty_source_produces_empty_docs() {
        let items = extract_docs("");
        assert!(items.is_empty());
    }

    #[test]
    fn test_invalid_source_produces_empty_docs() {
        let items = extract_docs("fn bad( { }");
        assert!(items.is_empty());
    }

    #[test]
    fn test_multiline_doc_comment() {
        let source = "// Line one.\n// Line two.\nfn multi() -> Int { 1 }";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        let doc = items[0].doc_comment.as_ref().unwrap();
        assert!(doc.contains("Line one."));
        assert!(doc.contains("Line two."));
    }

    #[test]
    fn test_extract_enum_variants() {
        let source = "enum Color { Red, Green, Blue }";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, DocItemKind::Enum);
        assert_eq!(items[0].children.len(), 3);
        assert_eq!(items[0].children[0].name, "Red");
    }

    #[test]
    fn test_render_empty_items() {
        let md = render_markdown(&[], "empty");
        assert!(md.contains("# empty"));
        assert!(md.contains("No documented items."));
    }

    // ═════════════════════════════════════════════════════════════════
    // Module documentation
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_extract_docs_inline_module() {
        let source = "// Crypto utilities.\nmod crypto {\n    pub fn verify() -> Bool { true }\n}";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "crypto");
        assert_eq!(items[0].kind, DocItemKind::Module);
        assert_eq!(items[0].doc_comment, Some("Crypto utilities.".to_string()));
        assert!(items[0].signature.contains("mod crypto"));
    }

    #[test]
    fn test_extract_docs_module_children_are_public_only() {
        let source = "mod crypto {\n    pub fn verify() -> Bool { true }\n    fn secret() -> Bool { false }\n}";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        // Only pub fn verify should be a child.
        assert_eq!(items[0].children.len(), 1);
        assert_eq!(items[0].children[0].name, "verify");
    }

    #[test]
    fn test_extract_docs_pub_module() {
        let source = "pub mod crypto {\n    pub fn verify() -> Bool { true }\n}";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert!(items[0].signature.contains("pub mod crypto"));
    }

    #[test]
    fn test_extract_docs_file_based_module() {
        let source = "// External module.\nmod external;";
        let items = extract_docs(source);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "external");
        assert_eq!(items[0].kind, DocItemKind::Module);
        assert!(items[0].children.is_empty());
    }

    #[test]
    fn test_render_markdown_with_module() {
        let source = "// Crypto module.\nmod crypto {\n    pub fn verify() -> Bool { true }\n}";
        let items = extract_docs(source);
        let md = render_markdown(&items, "test");
        assert!(md.contains("## crypto"));
        assert!(md.contains("Module"));
        assert!(md.contains("mod crypto"));
    }
}
