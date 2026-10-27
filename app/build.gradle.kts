plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.claudecageand"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.example.claudecageand"
        minSdk = 33
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

tasks.register("copyApkToRoot") {
    doLast {
        val buildDir = layout.buildDirectory.get().asFile
        val debugApkDir = File(buildDir, "outputs/apk/debug")
        val apkFile = debugApkDir.listFiles()?.firstOrNull { it.extension == "apk" && !it.name.contains("unaligned") }
        if (apkFile != null) {
            val ver = "1.0"
            val targetName = "ClaudeCage-$ver.apk"
            val destInRoot = File(rootDir, targetName)
            apkFile.copyTo(destInRoot, overwrite = true)
            val destInOutput = File(debugApkDir, targetName)
            if (apkFile.name != targetName) {
                apkFile.copyTo(destInOutput, overwrite = true)
            }
            println("=========================================================")
            println("✅ APK READY IN PROJECT ROOT:")
            println("   -> ${destInRoot.absolutePath}")
            println("   -> Size: ${destInRoot.length()} bytes")
            println("=========================================================")
        }
    }
}

tasks.matching { it.name == "assembleDebug" }.configureEach {
    finalizedBy("copyApkToRoot")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.webkit)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.lifecycle.runtime.ktx)

    testImplementation(libs.junit)
    testImplementation(libs.mockito.core)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
