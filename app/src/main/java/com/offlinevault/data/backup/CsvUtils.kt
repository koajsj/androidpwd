package com.offlinevault.data.backup

/** Minimal RFC-4180 style CSV reader/writer — enough for Chrome exports and our own CSV. */
object CsvUtils {
    private enum class ParseState {
        FIELD_START,
        UNQUOTED,
        QUOTED,
        AFTER_QUOTE
    }

    /** Parses CSV text into rows of fields, honouring quoted fields and embedded commas/newlines. */
    fun parse(
        text: String,
        maxRows: Int = 100_000,
        maxColumns: Int = 256,
        maxFieldChars: Int = 256 * 1024
    ): List<List<String>> {
        require(maxRows > 0 && maxColumns > 0 && maxFieldChars > 0) { "Invalid CSV limits" }
        val rows = mutableListOf<List<String>>()
        var field = StringBuilder()
        var row = mutableListOf<String>()
        var state = ParseState.FIELD_START
        var i = 0

        fun finishField() {
            row.add(field.toString())
            require(row.size <= maxColumns) { "CSV has too many columns" }
            field = StringBuilder()
            state = ParseState.FIELD_START
        }

        fun finishRow() {
            finishField()
            rows.add(row)
            require(rows.size <= maxRows) { "CSV has too many rows" }
            row = mutableListOf()
        }

        while (i < text.length) {
            val raw = text[i]
            val isNewline = raw == '\n' || raw == '\r'
            when (state) {
                ParseState.QUOTED -> {
                    if (raw == '"') {
                        if (i + 1 < text.length && text[i + 1] == '"') {
                            field.append('"')
                            require(field.length <= maxFieldChars) { "CSV field is too large" }
                            i++
                        } else {
                            state = ParseState.AFTER_QUOTE
                        }
                    } else {
                        field.append(if (isNewline) '\n' else raw)
                        require(field.length <= maxFieldChars) { "CSV field is too large" }
                        if (raw == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++
                    }
                }

                ParseState.AFTER_QUOTE -> when {
                    raw == ',' -> finishField()
                    isNewline -> {
                        finishRow()
                        if (raw == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++
                    }
                    else -> throw IllegalArgumentException("CSV has characters after a closing quote")
                }

                ParseState.FIELD_START -> when {
                    raw == '"' -> state = ParseState.QUOTED
                    raw == ',' -> finishField()
                    isNewline -> {
                        finishRow()
                        if (raw == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++
                    }
                    else -> {
                        field.append(raw)
                        require(field.length <= maxFieldChars) { "CSV field is too large" }
                        state = ParseState.UNQUOTED
                    }
                }

                ParseState.UNQUOTED -> when {
                    raw == '"' -> throw IllegalArgumentException("CSV has a quote inside an unquoted field")
                    raw == ',' -> finishField()
                    isNewline -> {
                        finishRow()
                        if (raw == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++
                    }
                    else -> {
                        field.append(raw)
                        require(field.length <= maxFieldChars) { "CSV field is too large" }
                    }
                }
            }
            i++
        }
        require(state != ParseState.QUOTED) { "CSV contains an unterminated quoted field" }
        // flush trailing field/row
        if (state != ParseState.FIELD_START || field.isNotEmpty() || row.isNotEmpty()) {
            finishRow()
        }
        return rows.filter { it.any { f -> f.isNotBlank() } }
    }

    // Leading characters a spreadsheet may interpret as the start of a formula (CSV injection).
    private val FORMULA_TRIGGERS = setOf('=', '+', '-', '@')
    private val FORMULA_PREFIX_WHITESPACE = setOf(' ', '\t', '\r', '\n')

    fun escape(value: String): String {
        // Neutralise CSV/formula injection: a cell that opens with a formula trigger gets a leading
        // apostrophe so Excel / Sheets render it as literal text instead of evaluating it.
        val guarded = if (startsLikeFormula(value)) "'$value" else value
        return if (guarded.contains(',') || guarded.contains('"') ||
            guarded.contains('\n') || guarded.contains('\r')
        ) {
            "\"" + guarded.replace("\"", "\"\"") + "\""
        } else guarded
    }

    fun buildRow(fields: List<String>): String = fields.joinToString(",") { escape(it) }

    private fun startsLikeFormula(value: String): Boolean {
        val firstSignificant = value.dropWhile { it in FORMULA_PREFIX_WHITESPACE }.firstOrNull()
        return firstSignificant != null && firstSignificant in FORMULA_TRIGGERS
    }
}
