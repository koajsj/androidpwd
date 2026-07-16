package com.offlinevault.security

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import javax.crypto.SecretKey

/**
 * Offline-only 12-word recovery phrases.
 *
 * This is intentionally "BIP39-style" rather than wallet-compatible BIP39:
 * - 12 lowercase English words from a fixed local word list.
 * - no plaintext persistence;
 * - the normalized phrase is only used to derive a recovery key for re-wrapping the DEK.
 */
class MnemonicManager {

    private val random = SecureRandom()
    private val words = WORD_LIST
    private val wordSet = words.toHashSet()

    fun generateWords(count: Int = WORD_COUNT): List<String> =
        List(count) { words[random.nextInt(words.size)] }

    fun normalize(input: String): String =
        input
            .trim()
            .lowercase(Locale.ROOT)
            .split(Regex("\\s+"))
            .filter { it.isNotBlank() }
            .joinToString(" ")

    fun splitWords(input: String): List<String> =
        normalize(input).split(' ').filter { it.isNotBlank() }

    fun isValidPhrase(input: String): Boolean {
        val phraseWords = splitWords(input)
        return phraseWords.size == WORD_COUNT && phraseWords.all { it in wordSet }
    }

    fun deriveRecoveryKey(
        normalizedPhrase: String,
        salt: ByteArray,
        kdf: KdfSpec = KdfVersions.current()
    ): SecretKey {
        val phraseChars = normalizedPhrase.toCharArray()
        return try {
            CryptoManager.deriveKey(phraseChars, salt, kdf)
        } finally {
            phraseChars.fill('\u0000')
        }
    }

    fun verifierHash(normalizedPhrase: String, salt: ByteArray, kdf: KdfSpec = KdfVersions.current()): String {
        val keyBytes = deriveRecoveryKey(normalizedPhrase, salt, kdf).encoded
        return try {
            val digest = MessageDigest.getInstance("SHA-256").digest(keyBytes)
            try {
                CryptoManager.encode(digest)
            } finally {
                digest.fill(0)
            }
        } finally {
            keyBytes.fill(0)
        }
    }

    fun verifierMatches(
        normalizedPhrase: String,
        salt: ByteArray,
        expectedHash: String,
        kdf: KdfSpec = KdfVersions.current()
    ): Boolean {
        val actual = CryptoManager.decode(verifierHash(normalizedPhrase, salt, kdf))
        val expected = CryptoManager.decode(expectedHash)
        return try {
            MessageDigest.isEqual(actual, expected)
        } finally {
            actual.fill(0)
            expected.fill(0)
        }
    }

    companion object {
        const val WORD_COUNT = 12

        private val WORD_LIST = listOf(
            "able", "about", "absent", "access", "acid", "across", "adapt", "admit",
            "adult", "advice", "aerobic", "affair", "afford", "afraid", "again", "agency",
            "agree", "ahead", "aim", "airport", "album", "alert", "alien", "alive",
            "allow", "almost", "alone", "alpha", "already", "always", "amazing", "amount",
            "anchor", "ancient", "anger", "angle", "animal", "answer", "anyone", "apart",
            "april", "arch", "arena", "argue", "arise", "armed", "around", "arrive",
            "artist", "aspect", "asset", "assist", "assume", "athlete", "atom", "attack",
            "attend", "august", "author", "auto", "autumn", "awake", "aware", "awesome",
            "axis", "bachelor", "badge", "bamboo", "basic", "battery", "become", "before",
            "begin", "behave", "behind", "believe", "below", "benefit", "best", "between",
            "beyond", "bicycle", "biology", "birthday", "blanket", "blossom", "blue", "body",
            "bonus", "border", "borrow", "bottle", "bottom", "brave", "bread", "breeze",
            "brick", "bridge", "bright", "bring", "brother", "budget", "build", "bullet",
            "bundle", "button", "camera", "canal", "canyon", "carbon", "career", "carpet",
            "carry", "casual", "catalog", "cattle", "cause", "center", "century", "chain",
            "change", "chaos", "charge", "check", "choice", "choose", "circle", "citizen",
            "civil", "claim", "clarify", "classic", "clerk", "client", "climb", "clinic",
            "clock", "close", "cloud", "coach", "coast", "coffee", "collect", "color",
            "column", "comfort", "common", "company", "concert", "confirm", "connect", "control",
            "cook", "copper", "corner", "cotton", "course", "cover", "craft", "cradle",
            "credit", "crisp", "culture", "curious", "current", "custom", "damage", "dance",
            "danger", "dealer", "debate", "decade", "december", "decide", "decline", "decorate",
            "defense", "define", "degree", "deliver", "demand", "dense", "depart", "depend",
            "deposit", "design", "desk", "detail", "develop", "device", "dialog", "digital",
            "dinner", "direct", "discover", "disease", "display", "distance", "doctor", "domain",
            "donate", "double", "dragon", "drama", "dream", "drift", "drive", "dutch",
            "dynamic", "eager", "early", "earth", "easily", "echo", "economy", "edge",
            "edit", "effort", "either", "elder", "electric", "elite", "embark", "emotion",
            "empire", "enable", "energy", "engine", "enhance", "enjoy", "enough", "ensure",
            "entry", "equal", "equip", "escape", "essay", "estate", "ethics", "even",
            "event", "evolve", "exact", "example", "exchange", "excite", "exclude", "exhibit",
            "exist", "expand", "expect", "expert", "expire", "explain", "export", "extend",
            "fabric", "faculty", "famous", "fancy", "fashion", "father", "feature", "february",
            "federal", "fellow", "female", "festival", "field", "figure", "filter", "final",
            "finance", "finger", "finish", "flavor", "flight", "flower", "focus", "follow",
            "forest", "forget", "formal", "fortune", "forward", "found", "frame", "fresh",
            "friend", "future", "galaxy", "gallery", "garden", "gather", "general", "gentle",
            "genuine", "glance", "global", "golden", "govern", "grace", "grade", "grant",
            "gravity", "green", "ground", "group", "guard", "guide", "habit", "handle",
            "harbor", "harmony", "harvest", "health", "height", "hello", "hidden", "history",
            "holiday", "honest", "honor", "hope", "hotel", "hour", "human", "humble",
            "husband", "idea", "identify", "ignore", "image", "impact", "improve", "include",
            "income", "increase", "index", "indoor", "infant", "inform", "inherit", "initial",
            "injury", "inside", "inspire", "install", "intact", "interest", "invent", "invite",
            "island", "issue", "jacket", "january", "jazz", "journey", "judge", "junior",
            "keep", "kernel", "keyboard", "kingdom", "kitchen", "ladder", "language", "laser",
            "later", "launch", "leader", "learn", "legal", "lesson", "letter", "level",
            "library", "light", "limit", "listen", "little", "logic", "loyal", "lucky",
            "machine", "magnet", "major", "manage", "manual", "margin", "market", "master",
            "matter", "maximum", "measure", "member", "memory", "message", "method", "middle",
            "mild", "minute", "mirror", "mobile", "model", "modern", "moment", "monitor",
            "month", "moral", "motion", "museum", "music", "mutual", "nation", "native",
            "nature", "nearby", "nearly", "network", "neutral", "night", "noble", "normal",
            "notice", "novel", "number", "object", "observe", "obtain", "office", "often",
            "olive", "online", "option", "orange", "orbit", "order", "origin", "output",
            "outside", "owner", "oxygen", "packet", "paddle", "page", "palace", "panel",
            "parent", "party", "pattern", "peace", "people", "perfect", "perform", "period",
            "permit", "person", "phase", "phone", "photo", "phrase", "piano", "picture",
            "pilot", "planet", "plastic", "platform", "please", "plunge", "pocket", "poem",
            "point", "policy", "popular", "portion", "position", "possible", "pottery", "poverty",
            "power", "practice", "prefer", "prepare", "present", "pretty", "prevent", "price",
            "primary", "print", "priority", "private", "problem", "process", "produce", "profile",
            "program", "project", "protect", "public", "purpose", "quality", "quarter", "quick",
            "quiet", "random", "rapid", "rather", "reader", "reason", "record", "recover",
            "reduce", "reflect", "regular", "relax", "remain", "remark", "remove", "repair",
            "repeat", "report", "require", "rescue", "respect", "result", "retire", "return",
            "review", "reward", "rhythm", "river", "rocket", "romance", "rotate", "round",
            "route", "royal", "safety", "sample", "satisfy", "school", "science", "screen",
            "script", "search", "season", "second", "secret", "secure", "select", "senior",
            "sense", "series", "service", "settle", "shadow", "share", "shield", "shift",
            "short", "signal", "silent", "silver", "simple", "sister", "skill", "smooth",
            "social", "society", "source", "space", "special", "spirit", "stable", "staff",
            "stage", "standard", "start", "station", "status", "steady", "stone", "storage",
            "story", "strategy", "street", "strong", "student", "studio", "subject", "success",
            "sudden", "suffer", "summer", "supply", "support", "surface", "surprise", "survey",
            "switch", "symbol", "system", "table", "talent", "target", "teacher", "temple",
            "tenant", "test", "theme", "theory", "there", "thrive", "ticket", "timber",
            "timely", "today", "together", "tomorrow", "topic", "total", "touch", "toward",
            "trade", "traffic", "travel", "treat", "trend", "trust", "tunnel", "twelve",
            "unable", "uniform", "unique", "united", "update", "upgrade", "useful", "usual",
            "vacuum", "valid", "valley", "value", "vanish", "vendor", "venture", "version",
            "victory", "video", "village", "visual", "voice", "volume", "voyage", "wait",
            "wallet", "wander", "warning", "wealth", "weather", "wedding", "weekend", "welcome",
            "window", "winner", "winter", "wisdom", "wonder", "worker", "world", "worry",
            "worthy", "writer", "yellow", "youth", "zebra", "zero", "zone"
        )
    }
}
