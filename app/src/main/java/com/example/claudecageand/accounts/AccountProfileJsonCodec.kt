package com.example.claudecageand.accounts

/**
 * Self-contained, robust JSON serializer/deserializer for [AccountProfile] records.
 * Avoids stubbed Android SDK classes (e.g. org.json.JSONObject) so that it functions
 * reliably in JVM local unit tests and in the Android runtime without external dependencies.
 */
object AccountProfileJsonCodec {

    fun toJson(profiles: List<AccountProfile>): String {
        return profiles.joinToString(prefix = "[", postfix = "]", separator = ",") { profile ->
            """{"id":"${escape(profile.id)}","displayName":"${escape(profile.displayName)}","createdAt":${profile.createdAt}}"""
        }
    }

    fun fromJson(json: String?): List<AccountProfile> {
        if (json.isNullOrBlank()) return emptyList()
        val list = mutableListOf<AccountProfile>()
        val objRegex = Regex("""\{([^{}]+)\}""")
        val idRegex = Regex(""""id"\s*:\s*"((?:\\.|[^"\\])*)"""")
        val nameRegex = Regex(""""displayName"\s*:\s*"((?:\\.|[^"\\])*)"""")
        val createdRegex = Regex(""""createdAt"\s*:\s*(\d+)""")

        for (match in objRegex.findAll(json)) {
            val content = match.groupValues[1]
            val id = idRegex.find(content)?.groupValues?.get(1)?.let { unescape(it) } ?: continue
            val name = nameRegex.find(content)?.groupValues?.get(1)?.let { unescape(it) } ?: continue
            val createdAt = createdRegex.find(content)?.groupValues?.get(1)?.toLongOrNull()
                ?: System.currentTimeMillis()
            list.add(AccountProfile(id = id, displayName = name, createdAt = createdAt))
        }
        return list
    }

    private fun escape(s: String): String {
        return s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }

    private fun unescape(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) {
                when (val next = s[i + 1]) {
                    '\\' -> sb.append('\\')
                    '"' -> sb.append('"')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    else -> sb.append(next)
                }
                i += 2
            } else {
                sb.append(c)
                i++
            }
        }
        return sb.toString()
    }
}
