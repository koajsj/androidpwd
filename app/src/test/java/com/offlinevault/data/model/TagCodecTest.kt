package com.offlinevault.data.model

import org.junit.Assert.assertEquals
import org.junit.Test

class TagCodecTest {
    @Test fun roundTripsNormalizedTagsWithoutLosingPunctuation() {
        val tags = listOf("工作,重要", "邮箱/账号", "中文 标签")
        assertEquals(tags, TagCodec.decode(TagCodec.encode(tags)))
        assertEquals(
            listOf("Work", "个人"),
            TagCodec.decode(TagCodec.encode(listOf(" Work ", "work", "", "个人")))
        )
    }

    @Test fun readsLegacyCommaSeparatedTags() {
        assertEquals(listOf("工作", "邮箱"), TagCodec.decode(" 工作,邮箱 "))
    }

    @Test fun preservesLegacyTagThatLooksLikeMalformedVersionedValue() {
        assertEquals(listOf("tags-v1:not-json"), TagCodec.decode("tags-v1:not-json"))
    }
}
