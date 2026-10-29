package com.offlinevault.data.model

import com.google.gson.Gson
import java.util.UUID

enum class CustomFieldType { SECRET, TOTP }

/** Values are decrypted only for an unlocked editor/detail or encrypted backup operation. */
data class CustomField(
    val id: String = UUID.randomUUID().toString(),
    val label: String = "",
    val value: String = "",
    val type: CustomFieldType = CustomFieldType.SECRET
)

object CustomFieldCodec {
    const val MAX_FIELDS = 20
    const val MAX_LABEL_LENGTH = 64
    const val MAX_VALUE_LENGTH = 8192
    private val gson = Gson()

    fun validate(fields: List<CustomField>) {
        require(fields.size <= MAX_FIELDS) { "自定义字段最多 20 项" }
        require(fields.map { it.id }.distinct().size == fields.size) { "自定义字段标识重复" }
        fields.forEach {
            require(it.id.length in 1..64 && it.label.isNotBlank() && it.label.length <= MAX_LABEL_LENGTH &&
                it.value.length <= MAX_VALUE_LENGTH) { "自定义字段名称或内容无效" }
            require(it.type in CustomFieldType.entries) { "不支持的自定义字段类型" }
            if (it.type == CustomFieldType.TOTP) com.offlinevault.security.Totp.parse(it.value)
        }
    }

    fun encode(fields: List<CustomField>): String {
        validate(fields)
        return if (fields.isEmpty()) "" else gson.toJson(fields.toTypedArray(), Array<CustomField>::class.java)
    }

    fun decode(value: String): List<CustomField> {
        if (value.isEmpty()) return emptyList()
        require(value.length <= MAX_FIELDS * (MAX_VALUE_LENGTH * 6 + 1024)) { "字段数据过大" }
        // A concrete array type avoids anonymous TypeToken signatures being erased by R8 full mode.
        val fields = requireNotNull(gson.fromJson(value, Array<CustomField>::class.java)) { "字段数据无效" }.toList()
        validate(fields)
        return fields
    }
}
