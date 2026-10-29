package com.offlinevault.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.offlinevault.data.dao.PasswordDao
import com.offlinevault.data.dao.VaultDao
import com.offlinevault.data.model.PasswordEntity
import com.offlinevault.data.model.PasswordHistoryEntity
import com.offlinevault.data.model.VaultEntity

@Database(
    entities = [VaultEntity::class, PasswordEntity::class, PasswordHistoryEntity::class],
    version = 6,
    exportSchema = true
)
abstract class AppDatabase : RoomDatabase() {

    abstract fun vaultDao(): VaultDao
    abstract fun passwordDao(): PasswordDao

    companion object {
        /** v2 encrypts metadata in place after unlock; the SQL shape itself is unchanged. */
        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) = Unit
        }

        /** v3 adds the recycle-bin soft-delete column. Purely additive — existing rows default to 0. */
        private val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE passwords ADD COLUMN deletedAt INTEGER NOT NULL DEFAULT 0")
            }
        }

        /** v4 adds the password-history table (additive). Must match Room's generated schema exactly. */
        private val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `password_history` (" +
                        "`id` TEXT NOT NULL, " +
                        "`passwordId` TEXT NOT NULL, " +
                        "`encryptedPassword` TEXT NOT NULL, " +
                        "`changedAt` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`id`), " +
                        "FOREIGN KEY(`passwordId`) REFERENCES `passwords`(`id`) " +
                        "ON UPDATE NO ACTION ON DELETE CASCADE)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_password_history_passwordId` " +
                        "ON `password_history` (`passwordId`)"
                )
            }
        }

        /** v5 adds the favorite/pin flag (additive). Existing rows default to not-favorited. */
        private val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE passwords ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0")
            }
        }

        /** Additive only: legacy rows have no extension payload and retain their original ciphertext. */
        internal val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE passwords ADD COLUMN encryptedCustomFields TEXT NOT NULL DEFAULT ''")
            }
        }

        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun get(context: Context): AppDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: databaseBuilder(
                    context.applicationContext,
                    // NEVER rename this file or the user's existing vault becomes orphaned.
                    "offline_vault.db"
                ).build()
                    .also { INSTANCE = it }
            }

        /** Used only by instrumentation migration tests with an isolated temporary database name. */
        internal fun openForMigrationTest(context: Context, databaseName: String): AppDatabase =
            databaseBuilder(context.applicationContext, databaseName).build()

        private fun databaseBuilder(context: Context, databaseName: String) =
            Room.databaseBuilder(context, AppDatabase::class.java, databaseName)
                // Data-safety policy: every schema bump MUST ship a Migration here. Do NOT add
                // fallbackToDestructiveMigration() — a missing migration should fail loudly,
                // never silently wipe the encrypted vault.
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6)
    }
}
