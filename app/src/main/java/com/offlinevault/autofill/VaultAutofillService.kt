package com.offlinevault.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import com.offlinevault.MainActivity
import com.offlinevault.OfflineVaultApp
import com.offlinevault.R
import com.offlinevault.security.SessionManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger

/**
 * Offline autofill service. It NEVER touches the network — it only reads the locally decrypted
 * vault while the app is unlocked and requires a user pick before returning a fill dataset. It also
 * offers to SAVE newly typed credentials via the platform's native "save" prompt.
 *
 * When the vault is locked there is no key in memory, so no credentials can be offered for fill;
 * saving is deferred until the next unlock.
 */
class VaultAutofillService : AutofillService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    // PendingIntent identity ignores extras. A unique request code prevents concurrent forms from
    // overwriting each other's AutofillId extras through FLAG_UPDATE_CURRENT.
    private val nextAuthenticationRequestCode = AtomicInteger()

    private companion object {
        // AssistStructure belongs to the app requesting autofill. Bound traversal prevents a
        // malformed or hostile hierarchy from exhausting the service stack or main memory.
        const val MAX_STRUCTURE_NODES = 2_000
        const val MAX_STRUCTURE_DEPTH = 64
    }

    private data class ParsedFields(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?,
        val extraPasswordIds: List<AutofillId>,
        val webDomain: String?,
        val packageName: String?,
        val usernameValue: String?,
        val passwordValue: String?
    ) {
        /** Stable identifier for this target: the web origin if present, else the native app. */
        val identifier: String?
            get() = webDomain?.let(OriginMatcher::normalizeHost)
                ?: packageName?.takeIf { it.isNotBlank() }?.let(OriginMatcher::appIdentifier)

        fun fillableIds(): List<AutofillId> = listOfNotNull(usernameId, passwordId)
    }

    private data class FieldCandidate(
        val id: AutofillId,
        val value: String?,
        val order: Int,
        val score: Int = 0
    )

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.safeSuccess(null)
            return
        }

        val parsed = try {
            parseStructure(structure)
        } catch (_: Exception) {
            callback.safeSuccess(null)
            return
        }
        // Never operate on our own UI, and require at least one fillable field.
        if (parsed.packageName.isNullOrBlank() ||
            parsed.packageName == applicationContext.packageName ||
            (parsed.passwordId == null && parsed.usernameId == null)
        ) {
            callback.safeSuccess(null)
            return
        }

        val saveInfo = runCatching { buildSaveInfo(parsed) }.getOrNull()

        // While locked there is no key, so no datasets can be built — but we still register the
        // SaveInfo so the user can save credentials they type now (persisted after the next unlock).
        if (!SessionManager.isUnlocked) {
            val response = runCatching {
                saveInfo?.let { FillResponse.Builder().setSaveInfo(it).build() }
            }.getOrNull()
            callback.safeSuccess(response)
            return
        }

        serviceScope.launch {
            try {
                if (cancellationSignal.isCanceled) return@launch

                val builder = FillResponse.Builder()
                var hasContent = false
                buildManualSearchPresentation(parsed)?.let { (intentSender, presentation) ->
                    builder.setAuthentication(parsed.fillableIds().toTypedArray(), intentSender, presentation)
                    hasContent = true
                }
                if (saveInfo != null) {
                    builder.setSaveInfo(saveInfo)
                    hasContent = true
                }
                callback.safeSuccess(if (hasContent) builder.build() else null)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Never let an unexpected failure escape the launch — that would crash the autofill
                // service process. Fail gracefully by offering nothing.
                callback.safeSuccess(null)
            }
        }
    }

    /** A save offer needs at least a password field; the username is included when present. */
    private fun buildSaveInfo(parsed: ParsedFields): SaveInfo? {
        val passwordId = parsed.passwordId ?: return null
        if (parsed.identifier == null) return null
        var type = SaveInfo.SAVE_DATA_TYPE_PASSWORD
        if (parsed.usernameId != null) {
            type = type or SaveInfo.SAVE_DATA_TYPE_USERNAME
        }
        val optionalIds = (listOfNotNull(parsed.usernameId) + parsed.extraPasswordIds).distinct()
        return SaveInfo.Builder(type, arrayOf(passwordId)).apply {
            if (optionalIds.isNotEmpty()) setOptionalIds(optionalIds.toTypedArray())
            setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
        }.build()
    }

    private fun parseStructure(structure: AssistStructure): ParsedFields {
        val usernameCandidates = mutableListOf<FieldCandidate>()
        val passwordCandidates = mutableListOf<FieldCandidate>()
        var webDomain: String? = null
        val packageName = structure.activityComponent?.packageName
        var order = 0
        var visitedNodes = 0

        fun traverse(node: AssistStructure.ViewNode, depth: Int) {
            if (visitedNodes >= MAX_STRUCTURE_NODES || depth > MAX_STRUCTURE_DEPTH) return
            visitedNodes++
            if (node.webDomain?.isNotEmpty() == true && webDomain == null) {
                webDomain = node.webDomain
            }
            val autofillId = node.autofillId
            if (autofillId != null && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
                val hints = node.autofillHints?.map { it.lowercase(Locale.ROOT) } ?: emptyList()
                val inputType = node.inputType
                val value = textValueOf(node)
                val fieldOrder = order++
                val isPassword = hints.any { it.contains("password") } ||
                    isPasswordInput(inputType) ||
                    looksLikePassword(node)
                val usernameScore = usernameScore(node, hints, inputType)

                if (isPassword) {
                    passwordCandidates += FieldCandidate(autofillId, value, fieldOrder)
                } else if (usernameScore > 0) {
                    usernameCandidates += FieldCandidate(autofillId, value, fieldOrder, usernameScore)
                }
            }
            for (i in 0 until node.childCount) {
                traverse(node.getChildAt(i), depth + 1)
            }
        }

        for (i in 0 until structure.windowNodeCount) {
            if (visitedNodes >= MAX_STRUCTURE_NODES) break
            traverse(structure.getWindowNodeAt(i).rootViewNode, depth = 0)
        }

        val primaryPassword = passwordCandidates.firstOrNull()
        val firstPasswordOrder = primaryPassword?.order ?: Int.MAX_VALUE
        val primaryUsername = usernameCandidates
            .filter { it.order < firstPasswordOrder }
            .maxWithOrNull(compareBy<FieldCandidate> { it.score }.thenBy { it.order })
            ?: usernameCandidates.maxWithOrNull(compareBy<FieldCandidate> { it.score }.thenBy { -it.order })
        val usernameValue = primaryUsername?.value?.takeIf { it.isNotBlank() }
            ?: usernameCandidates.firstNotNullOfOrNull { it.value?.takeIf(String::isNotBlank) }
        val passwordValue = passwordCandidates
            .asReversed()
            .firstNotNullOfOrNull { it.value?.takeIf { value -> value.isNotEmpty() } }
            ?: primaryPassword?.value

        return ParsedFields(
            usernameId = primaryUsername?.id,
            passwordId = primaryPassword?.id,
            extraPasswordIds = passwordCandidates.drop(1).map { it.id },
            webDomain = webDomain,
            packageName = packageName,
            usernameValue = usernameValue,
            passwordValue = passwordValue
        )
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.safeSuccess()
            return
        }
        val parsed = try {
            parseStructure(structure)
        } catch (_: Exception) {
            callback.safeSuccess()
            return
        }
        val identifier = parsed.identifier
        val password = parsed.passwordValue
        if (parsed.packageName.isNullOrBlank() ||
            parsed.packageName == applicationContext.packageName ||
            identifier == null || password.isNullOrEmpty()
        ) {
            callback.safeSuccess()
            return
        }
        val capture = PendingAutofillSave.Capture(
            identifier = identifier,
            username = parsed.usernameValue.orEmpty(),
            password = password
        )

        if (SessionManager.isUnlocked) {
            val app = application as OfflineVaultApp
            serviceScope.launch {
                try {
                    val vaultId = app.container.vaultRepository.ensureDefault().id
                    app.container.passwordRepository.upsertFromAutofill(
                        vaultId, capture.identifier, capture.username, capture.password
                    )
                    callback.safeSuccess()
                } catch (e: CancellationException) {
                    callback.safeFailure("自动填充保存已取消")
                    throw e
                } catch (_: Exception) {
                    callback.safeFailure("无法保存到密码库，请打开应用后重试")
                }
            }
        } else {
            // Locked: stash the capture and bring the app forward so the user can unlock; the save
            // completes right after unlock. Stashing first means the capture survives even if the
            // activity start is suppressed by the OS background-launch limits.
            val queued = PendingAutofillSave.set(capture)
            if (!queued) {
                callback.safeFailure("无法安全暂存账号，请解锁应用后重试")
                return
            }
            val launched = runCatching {
                startActivity(
                    Intent(this, MainActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            }.isSuccess
            if (launched) callback.safeSuccess()
            else callback.safeFailure("请手动打开应用并解锁以完成保存")
        }
    }

    private fun FillCallback.safeSuccess(response: FillResponse?) {
        runCatching { onSuccess(response) }
    }

    private fun SaveCallback.safeSuccess() {
        runCatching { onSuccess() }
    }

    private fun SaveCallback.safeFailure(message: String) {
        runCatching { onFailure(message) }
    }

    // ---- Matching ----------------------------------------------------------

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    // ---- User-confirmed fill entry -----------------------------------------

    private fun buildManualSearchPresentation(parsed: ParsedFields): Pair<android.content.IntentSender, RemoteViews>? {
        if (parsed.fillableIds().isEmpty()) return null
        val normalizedDomain = parsed.webDomain?.let(OriginMatcher::normalizeHost)
        val targetLabel = OriginMatcher.targetLabel(normalizedDomain, parsed.packageName)
        val intent = AutofillSearchActivity.buildIntent(
            this,
            parsed.usernameId,
            parsed.passwordId,
            normalizedDomain,
            parsed.packageName
        )
        val pendingIntent = PendingIntent.getActivity(
            this,
            nextAuthenticationRequestCode.getAndIncrement(),
            intent,
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
        )
        val presentation = RemoteViews(packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_title, "选择账号填充")
            setTextViewText(R.id.autofill_subtitle, "当前：$targetLabel")
        }
        return pendingIntent.intentSender to presentation
    }

    // ---- Structure parsing -------------------------------------------------

    /** Reads the text the user has currently entered into a node, if any. */
    private fun textValueOf(node: AssistStructure.ViewNode): String? {
        val value = node.autofillValue
        val fromAutofill = if (value != null && value.isText) value.textValue.toString() else null
        return (fromAutofill ?: node.text?.toString())?.takeIf { it.isNotEmpty() }
    }

    private fun isPasswordInput(inputType: Int): Boolean {
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        val klass = inputType and InputType.TYPE_MASK_CLASS
        return variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
            (klass == InputType.TYPE_CLASS_NUMBER &&
                (inputType and InputType.TYPE_NUMBER_VARIATION_PASSWORD) != 0)
    }

    private fun usernameScore(
        node: AssistStructure.ViewNode,
        hints: List<String>,
        inputType: Int
    ): Int {
        var score = 0
        if (hints.any { it.contains("username") || it.contains("login") || it.contains("account") }) score += 5
        if (hints.any { it.contains("email") || it == View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase(Locale.ROOT) }) score += 5
        if (hints.any { it.contains("phone") || it.contains("tel") }) score += 4
        if (isEmailOrPhoneInput(inputType)) score += 3
        if (looksLikeUsername(node)) score += 3
        return score
    }

    private fun isEmailOrPhoneInput(inputType: Int): Boolean {
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        val klass = inputType and InputType.TYPE_MASK_CLASS
        return variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS ||
            klass == InputType.TYPE_CLASS_PHONE
    }

    private fun looksLikePassword(node: AssistStructure.ViewNode): Boolean {
        val surfaces = textSurfaces(node)
        val keywords = listOf("password", "passwd", "passcode", "pwd", "密码", "口令")
        return keywords.any { keyword -> surfaces.any { it.contains(keyword) } }
    }

    private fun looksLikeUsername(node: AssistStructure.ViewNode): Boolean {
        val surfaces = textSurfaces(node)
        val keywords = listOf(
            "username", "user_name", "userid", "user_id", "email", "e-mail", "mail",
            "login", "loginid", "login_id", "account", "acct", "phone", "mobile",
            "telephone", "tel", "账号", "帐号", "账户", "用户名", "邮箱", "手机", "电话"
        )
        return keywords.any { keyword -> surfaces.any { it.contains(keyword) } }
    }

    private fun textSurfaces(node: AssistStructure.ViewNode): List<String> {
        val direct = listOfNotNull(
            node.hint,
            node.idEntry,
            node.className,
            node.htmlInfo?.tag
        )
        val htmlAttributes = node.htmlInfo?.attributes.orEmpty().flatMap { attr ->
            listOfNotNull(attr.first, attr.second)
        }
        return (direct + htmlAttributes).map { it.lowercase(Locale.ROOT) }
    }
}
