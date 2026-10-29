# Keep Room generated code
-keep class * extends androidx.room.RoomDatabase { *; }
-keep @androidx.room.Entity class * { *; }
-dontwarn androidx.room.paging.**

# Keep model classes used for JSON (Gson) serialization
-keep class com.offlinevault.data.backup.BackupVault { *; }
-keep class com.offlinevault.data.backup.BackupItem { *; }
-keep class com.offlinevault.data.backup.BackupData { *; }
-keep class com.offlinevault.data.backup.EncryptedBackup { *; }
-keep class com.offlinevault.data.model.CustomField { *; }
-keep enum com.offlinevault.data.model.CustomFieldType { *; }
-keepattributes Signature
-keepattributes *Annotation*
