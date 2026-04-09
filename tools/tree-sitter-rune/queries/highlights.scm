; ═══════════════════════════════════════════════════════════════════════
; RUNE Syntax Highlighting Queries for Tree-sitter
; ═══════════════════════════════════════════════════════════════════════

; ── Governance decisions ─────────────────────────────────────────────
(governance_decision) @keyword.return

; ── Keywords ─────────────────────────────────────────────────────────
"policy" @keyword
"rule" @keyword
"fn" @keyword
"let" @keyword
"mut" @keyword
"const" @keyword
"struct" @keyword
"enum" @keyword
"type" @keyword
"impl" @keyword
"trait" @keyword
"pub" @keyword
"extern" @keyword
"mod" @keyword
"use" @keyword
"as" @keyword
"self" @variable.builtin
"super" @variable.builtin
"if" @keyword.conditional
"else" @keyword.conditional
"match" @keyword.conditional
"while" @keyword.repeat
"for" @keyword.repeat
"in" @keyword.repeat
"return" @keyword.return
"break" @keyword.return
"continue" @keyword.return

; ── Governance modifiers ─────────────────────────────────────────────
"attest" @keyword
"audit" @keyword
"secure_zone" @keyword
"unsafe_ffi" @keyword.exception
"require" @keyword
"satisfies" @keyword
"where" @keyword
"with" @keyword
"perform" @keyword
"handle" @keyword

; ── Capability and effect keywords ───────────────────────────────────
"capability" @keyword
"effect" @keyword
"effects" @keyword
"capabilities" @keyword

; ── Declarations ─────────────────────────────────────────────────────
(policy_declaration name: (identifier) @type)
(rule_declaration name: (identifier) @function)
(function_declaration name: (identifier) @function)
(struct_declaration name: (identifier) @type)
(enum_declaration name: (identifier) @type)
(trait_declaration name: (identifier) @type)
(impl_block type: (identifier) @type)
(capability_declaration name: (identifier) @type)
(effect_declaration name: (identifier) @type)
(type_alias name: (identifier) @type.definition)
(type_constraint name: (identifier) @type.definition)
(const_declaration name: (identifier) @constant)
(extern_fn_declaration name: (identifier) @function)

; ── Type annotations ─────────────────────────────────────────────────
(type_identifier) @type
(return_type (type_identifier) @type)
(parameter type: (type_identifier) @type)
(struct_field type: (type_identifier) @type)

; ── Function calls ───────────────────────────────────────────────────
(call_expression function: (identifier) @function.call)

; ── Parameters and variables ─────────────────────────────────────────
(parameter name: (identifier) @variable.parameter)
(let_statement name: (identifier) @variable)

; ── Literals ─────────────────────────────────────────────────────────
(integer_literal) @number
(float_literal) @number.float
(string_literal) @string
(boolean_literal) @boolean

; ── Operators ────────────────────────────────────────────────────────
"+" @operator
"-" @operator
"*" @operator
"/" @operator
"%" @operator
"==" @operator
"!=" @operator
"<" @operator
">" @operator
"<=" @operator
">=" @operator
"&&" @operator
"||" @operator
"!" @operator
"not" @operator
"=" @operator
"+=" @operator
"-=" @operator
"*=" @operator
"=>" @punctuation.delimiter

; ── Punctuation ──────────────────────────────────────────────────────
"(" @punctuation.bracket
")" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
"[" @punctuation.bracket
"]" @punctuation.bracket
"," @punctuation.delimiter
":" @punctuation.delimiter
"::" @punctuation.delimiter
";" @punctuation.delimiter
"->" @punctuation.delimiter
"." @punctuation.delimiter

; ── Comments ─────────────────────────────────────────────────────────
(line_comment) @comment
(block_comment) @comment
