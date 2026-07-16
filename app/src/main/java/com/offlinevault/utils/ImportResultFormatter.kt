package com.offlinevault.utils

import com.offlinevault.data.backup.ImportResult

/** One concise result message shared by both import entry points. */
fun ImportResult.toUserMessage(): String {
    val firstError = errors.firstOrNull()
    if (imported == 0 && updated == 0 && skippedDuplicates == 0 && failed == 0) {
        return firstError ?: "没有可导入的项目"
    }
    val summary = "导入完成：新增 $imported 项，覆盖 $updated 项，跳过 $skippedDuplicates 项，失败 $failed 项"
    return if (firstError.isNullOrBlank()) summary else "$summary。$firstError"
}
