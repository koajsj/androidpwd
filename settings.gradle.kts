pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

// AGP's plugin classpath still requests older vulnerable transitive versions. Pin compatible
// patched releases before each project script resolves its plugin classpath.
gradle.beforeProject {
    buildscript.configurations.configureEach {
        resolutionStrategy.eachDependency {
            val coordinate = "${requested.group}:${requested.name}"
            when {
                requested.group == "org.bouncycastle" &&
                    requested.name.endsWith("-jdk18on") ->
                    useVersion("1.85")

                coordinate == "org.apache.commons:commons-lang3" -> useVersion("3.20.0")
                coordinate == "org.bitbucket.b_c:jose4j" -> useVersion("0.9.6")
                coordinate == "org.jdom:jdom2" -> useVersion("2.0.6.1")
            }
        }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "Offline Vault"
include(":app")
