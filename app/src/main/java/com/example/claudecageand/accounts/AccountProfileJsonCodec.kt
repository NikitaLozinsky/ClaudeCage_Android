package com.example.claudecageand.accounts

import org.json.JSONArray
import org.json.JSONObject

/**
 * Robust JSON serializer/deserializer for [AccountProfile] records using [org.json].
 * 100% immune to character escaping, nested braces, quotes, and whitespace irregularities.
 */
object AccountProfileJsonCodec {

    fun toJson(profiles: List<AccountProfile>): String {
        val array = JSONArray()
        for (profile in profiles) {
            val obj = JSONObject().apply {
                put("id", profile.id)
                put("displayName", profile.displayName)
                put("createdAt", profile.createdAt)
            }
            array.put(obj)
        }
        return array.toString()
    }

    fun fromJson(json: String?): List<AccountProfile> {
        if (json.isNullOrBlank()) return emptyList()
        val list = mutableListOf<AccountProfile>()
        try {
            val array = JSONArray(json)
            for (i in 0 until array.length()) {
                val obj = array.optJSONObject(i) ?: continue
                val id = obj.optString("id", "")
                val name = obj.optString("displayName", "")
                val createdAt = obj.optLong("createdAt", System.currentTimeMillis())
                if (id.isNotEmpty() && name.isNotEmpty()) {
                    list.add(AccountProfile(id = id, displayName = name, createdAt = createdAt))
                }
            }
        } catch (_: Exception) {
            return emptyList()
        }
        return list
    }
}
