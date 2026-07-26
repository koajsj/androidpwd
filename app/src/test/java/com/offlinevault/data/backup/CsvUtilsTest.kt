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

    @Test fun parsesQuotedFieldsAndNewlines() {
        val rows = CsvUtils.parse(
            "name,note\n\"示例\",\"第一行\n第二行\"\n"
        )

        assertEquals(listOf("name", "note"), rows[0])
        assertEquals(listOf("示例", "第一行\n第二行"), rows[1])
    }

    @Test fun rejectsUnterminatedQuotedField() {
        assertThrows(IllegalArgumentException::class.java) {
            CsvUtils.parse("name,password\n\"broken,value")
        }
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
