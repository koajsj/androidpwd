// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version "9.3.0" apply false
    id("com.google.devtools.ksp") version "2.3.9" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.3.21" apply false
}

subprojects {
    configurations.configureEach {
        resolutionStrategy.eachDependency {
            val coordinate = "${requested.group}:${requested.name}"
            when {
                requested.group == "io.netty" &&
                    requested.version?.startsWith("4.1.") == true ->
                    useVersion("4.1.136.Final")

                requested.group == "org.bouncycastle" &&
                    requested.name.endsWith("-jdk18on") ->
                    useVersion("1.85")

                coordinate == "org.apache.commons:commons-lang3" -> useVersion("3.20.0")
                coordinate == "org.apache.httpcomponents:httpclient" -> useVersion("4.5.14")
                coordinate == "org.bitbucket.b_c:jose4j" -> useVersion("0.9.6")
                coordinate == "org.jdom:jdom2" -> useVersion("2.0.6.1")
            }
        }
    }
}
