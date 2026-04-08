// ═══════════════════════════════════════════════════════════════════════
// Tree-sitter Grammar for the RUNE Governance-First Language
//
// Provides syntax highlighting in VS Code, Neovim, Helix, Zed, and
// GitHub via tree-sitter. Covers all RUNE constructs through M5.
// ═══════════════════════════════════════════════════════════════════════

/// @type {import('tree-sitter-cli').Grammar}
module.exports = grammar({
  name: "rune",

  extras: $ => [
    /\s/,
    $.line_comment,
    $.block_comment,
  ],

  word: $ => $.identifier,

  rules: {
    source_file: $ => repeat($._item),

    _item: $ => choice(
      $.policy_declaration,
      $.function_declaration,
      $.struct_declaration,
      $.enum_declaration,
      $.type_alias,
      $.type_constraint,
      $.capability_declaration,
      $.effect_declaration,
      $.trait_declaration,
      $.impl_block,
      $.const_declaration,
      $.mod_declaration,
      $.use_declaration,
    ),

    // ── Policy declarations ──────────────────────────────────────

    policy_declaration: $ => seq(
      optional("pub"),
      "policy",
      field("name", $.identifier),
      "{",
      repeat($.rule_declaration),
      "}",
    ),

    rule_declaration: $ => seq(
      "rule",
      field("name", $.identifier),
      $.parameter_list,
      optional($.return_type),
      $.block,
    ),

    // ── Function declarations ────────────────────────────────────

    function_declaration: $ => seq(
      optional("pub"),
      "fn",
      field("name", $.identifier),
      $.parameter_list,
      optional($.return_type),
      optional($.effect_annotation),
      optional($.capability_annotation),
      $.block,
    ),

    parameter_list: $ => seq(
      "(",
      optional(seq(
        $.parameter,
        repeat(seq(",", $.parameter)),
        optional(","),
      )),
      ")",
    ),

    parameter: $ => seq(
      field("name", $.identifier),
      ":",
      field("type", $._type_expr),
    ),

    return_type: $ => seq("->", $._type_expr),

    effect_annotation: $ => seq(
      "with", "effects", "{",
      optional(seq($.identifier, repeat(seq(",", $.identifier)), optional(","))),
      "}",
    ),

    capability_annotation: $ => seq(
      "with", "capabilities", "{",
      optional(seq($.identifier, repeat(seq(",", $.identifier)), optional(","))),
      "}",
    ),

    // ── Type declarations ────────────────────────────────────────

    struct_declaration: $ => seq(
      optional("pub"),
      "struct",
      field("name", $.identifier),
      "{",
      optional(seq(
        $.struct_field,
        repeat(seq(",", $.struct_field)),
        optional(","),
      )),
      "}",
    ),

    struct_field: $ => seq(
      field("name", $.identifier),
      ":",
      field("type", $._type_expr),
    ),

    enum_declaration: $ => seq(
      optional("pub"),
      "enum",
      field("name", $.identifier),
      "{",
      optional(seq(
        $.enum_variant,
        repeat(seq(",", $.enum_variant)),
        optional(","),
      )),
      "}",
    ),

    enum_variant: $ => seq(
      field("name", $.identifier),
      optional(seq("(", $._type_expr, repeat(seq(",", $._type_expr)), ")")),
    ),

    type_alias: $ => seq(
      optional("pub"),
      "type",
      field("name", $.identifier),
      "=",
      $._type_expr,
      ";",
    ),

    type_constraint: $ => seq(
      optional("pub"),
      "type",
      field("name", $.identifier),
      "=",
      $._type_expr,
      $.where_clause,
      ";",
    ),

    capability_declaration: $ => seq(
      "capability",
      field("name", $.identifier),
      "{",
      repeat($.identifier),
      "}",
    ),

    effect_declaration: $ => seq(
      "effect",
      field("name", $.identifier),
      "{",
      repeat($.effect_operation),
      "}",
    ),

    effect_operation: $ => seq(
      field("name", $.identifier),
      ":",
      $._type_expr,
      optional(seq("->", $._type_expr)),
    ),

    trait_declaration: $ => seq(
      optional("pub"),
      "trait",
      field("name", $.identifier),
      "{",
      repeat($.function_declaration),
      "}",
    ),

    impl_block: $ => seq(
      "impl",
      field("type", $.identifier),
      optional(seq("for", $.identifier)),
      "{",
      repeat($.function_declaration),
      "}",
    ),

    const_declaration: $ => seq(
      "const",
      field("name", $.identifier),
      ":",
      field("type", $._type_expr),
      "=",
      $._expression,
      ";",
    ),

    mod_declaration: $ => seq(
      optional("pub"),
      "mod",
      field("name", $.identifier),
      choice(
        ";",
        seq("{", repeat($._item), "}"),
      ),
    ),

    use_declaration: $ => seq(
      optional("pub"),
      "use",
      $.path,
      optional(choice(
        seq("::", "*"),
        seq("as", field("alias", $.identifier)),
      )),
      ";",
    ),

    path: $ => seq($._path_segment, repeat(seq("::", $._path_segment))),

    _path_segment: $ => choice($.identifier, "self", "super"),

    // ── Type expressions ─────────────────────────────────────────

    _type_expr: $ => choice(
      $.type_identifier,
      $.refined_type,
    ),

    type_identifier: $ => $.identifier,

    refined_type: $ => seq(
      $.identifier,
      $.where_clause,
    ),

    where_clause: $ => seq(
      "where",
      "{",
      optional(seq(
        $.refinement_predicate,
        repeat(seq(",", $.refinement_predicate)),
        optional(","),
      )),
      "}",
    ),

    refinement_predicate: $ => seq(
      field("field", $.identifier),
      field("op", choice(">", "<", ">=", "<=", "==", "!=", "in", "not_in")),
      field("value", $._literal),
    ),

    // ── Blocks and statements ────────────────────────────────────

    block: $ => seq("{", repeat($._statement), optional($._expression), "}"),

    _statement: $ => choice(
      $.let_statement,
      $.expression_statement,
      $.return_statement,
    ),

    let_statement: $ => seq(
      "let",
      optional("mut"),
      field("name", $.identifier),
      optional(seq(":", $._type_expr)),
      "=",
      $._expression,
      ";",
    ),

    expression_statement: $ => seq($._expression, ";"),

    return_statement: $ => seq("return", optional($._expression), ";"),

    // ── Expressions ──────────────────────────────────────────────

    _expression: $ => choice(
      $.governance_decision,
      $.if_expression,
      $.match_expression,
      $.while_expression,
      $.for_expression,
      $.binary_expression,
      $.unary_expression,
      $.call_expression,
      $.field_expression,
      $.block,
      $.require_expression,
      $.attest_expression,
      $.audit_expression,
      $.secure_zone_expression,
      $.unsafe_ffi_expression,
      $.perform_expression,
      $.handle_expression,
      $.assignment,
      $._primary,
    ),

    governance_decision: $ => choice("permit", "deny", "escalate", "quarantine"),

    if_expression: $ => prec.right(seq(
      "if",
      field("condition", $._expression),
      field("then", $.block),
      optional(seq("else", field("else", choice($.block, $.if_expression)))),
    )),

    match_expression: $ => seq(
      "match",
      field("subject", $._expression),
      "{",
      repeat($.match_arm),
      "}",
    ),

    match_arm: $ => seq(
      field("pattern", $._pattern),
      "=>",
      field("body", $._expression),
      optional(","),
    ),

    _pattern: $ => choice(
      $.identifier,
      $._literal,
      "_",
    ),

    while_expression: $ => seq(
      "while",
      field("condition", $._expression),
      field("body", $.block),
    ),

    for_expression: $ => seq(
      "for",
      field("variable", $.identifier),
      "in",
      field("iterable", $._expression),
      field("body", $.block),
    ),

    binary_expression: $ => {
      const table = [
        [1, choice("||")],
        [2, choice("&&")],
        [3, choice("==", "!=")],
        [4, choice("<", ">", "<=", ">=")],
        [5, choice("+", "-")],
        [6, choice("*", "/", "%")],
      ];
      return choice(
        ...table.map(([prec_level, op]) =>
          prec.left(prec_level, seq(
            field("left", $._expression),
            field("op", op),
            field("right", $._expression),
          ))
        ),
      );
    },

    unary_expression: $ => prec(7, seq(
      field("op", choice("!", "-", "not")),
      field("operand", $._expression),
    )),

    call_expression: $ => prec(8, seq(
      field("function", $.identifier),
      "(",
      optional(seq(
        $._expression,
        repeat(seq(",", $._expression)),
        optional(","),
      )),
      ")",
    )),

    field_expression: $ => prec.left(9, seq(
      field("object", $._expression),
      ".",
      field("field", $.identifier),
    )),

    assignment: $ => prec.right(0, seq(
      field("target", $.identifier),
      field("op", choice("=", "+=", "-=", "*=")),
      field("value", $._expression),
    )),

    require_expression: $ => seq(
      "require",
      $._expression,
      "satisfies",
      $.where_clause,
    ),

    attest_expression: $ => seq("attest", $._expression),

    audit_expression: $ => seq("audit", $.block),

    secure_zone_expression: $ => seq(
      "secure_zone",
      optional(seq("[", $.identifier, repeat(seq(",", $.identifier)), "]")),
      $.block,
    ),

    unsafe_ffi_expression: $ => seq("unsafe_ffi", $.block),

    perform_expression: $ => seq("perform", $.identifier, "(", optional(seq($._expression, repeat(seq(",", $._expression)))), ")"),

    handle_expression: $ => seq("handle", $.block, "with", "{", repeat($.match_arm), "}"),

    // ── Primary expressions ──────────────────────────────────────

    _primary: $ => choice(
      $._literal,
      $.identifier,
      $.parenthesized_expression,
    ),

    parenthesized_expression: $ => seq("(", $._expression, ")"),

    _literal: $ => choice(
      $.integer_literal,
      $.float_literal,
      $.string_literal,
      $.boolean_literal,
    ),

    integer_literal: $ => /0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|[0-9][0-9_]*/,

    float_literal: $ => /[0-9][0-9_]*\.[0-9][0-9_]*([eE][+-]?[0-9]+)?/,

    string_literal: $ => seq('"', repeat(choice(/[^"\\]+/, /\\./)), '"'),

    boolean_literal: $ => choice("true", "false"),

    // ── Tokens ───────────────────────────────────────────────────

    identifier: $ => /[a-zA-Z_][a-zA-Z0-9_]*/,

    line_comment: $ => token(seq("//", /.*/)),

    block_comment: $ => token(seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/")),
  },
});
