package com.offlinevault.data.backup

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CsvUtilsTest {
    @Test fun escapesFormulaCells() {
        assertEquals("'=SUM(A1:A2)", CsvUtils.escape("=SUM(A1:A2)"))
        assertEquals("'+secret", CsvUtils.escape("+secret"))
        assertEquals("'  =SUM(A1:A2)", CsvUtils.escape("  =SUM(A1:A2)"))
        assertEquals("'\t@danger", CsvUtils.escape("\t@danger"))
    }

    @Test fun rejectsUnterminatedQuotedField() {
        assertThrows(IllegalArgumentException::class.java) {
            CsvUtils.parse("name,password\n\"broken,value")
        }
    }

    @Test fun rejectsQuotesInUnquotedFieldsAndCharactersAfterClosingQuote() {
        assertThrows(IllegalArgumentException::class.java) {
            CsvUtils.parse("name,password\nbad\"value,secret")
        }
        assertThrows(IllegalArgumentException::class.java) {
            CsvUtils.parse("name,password\n\"closed\"junk,secret")
        }
    }

    @Test fun parsesQuotedMultilineFieldsEscapedQuotesAndBothLineEndings() {
        assertEquals(listOf(listOf("name", "note"), listOf("示例", "第一行\n第二行")),
            CsvUtils.parse("name,note\n\"示例\",\"第一行\n第二行\"\n"))
        val rows = CsvUtils.parse("name,note,empty\r\n\"示\"\"例\",\"a\r\nb\",\r\n")

        assertEquals(listOf("name", "note", "empty"), rows[0])
        assertEquals(listOf("示\"例", "a\nb", ""), rows[1])
    }

    @Test fun rejectsRowsColumnsAndFieldsBeyondConfiguredLimits() {
        assertThrows(IllegalArgumentException::class.java) {
            CsvUtils.parse("a\nb\nc", maxRows = 2)
        }
        assertThrows(IllegalArgumentException::class.java) {
            CsvUtils.parse("a,b,c", maxColumns = 2)
        }
        assertThrows(IllegalArgumentException::class.java) {
            CsvUtils.parse("abcdef", maxFieldChars = 5)
        }
    }
}
