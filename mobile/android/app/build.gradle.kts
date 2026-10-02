plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.kirindesk.mobile"
    compileSdk = 35
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.kirindesk.mobile"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    // 签名口径（P1-B）：release 优先正式签名——keystore 位于仓库外
    // D:\kirin_rd\secrets\kirindesk-release.jks（RSA-4096，.gitignore 全局
    // /secrets/ 双保险），口令经环境变量注入，**缺失任意一项即回退 debug
    // 签名**（构建永不因口令缺失而断）：
    //   KIRIN_STORE_FILE      keystore 路径
    //   KIRIN_STORE_PASSWORD  store 口令
    //   KIRIN_KEY_ALIAS       key 别名（kirindesk）
    //   KIRIN_KEY_PASSWORD    key 口令
    // minify 关闭，规避 JNI 反射/回调被裁。
    val kirinStoreFile = providers.environmentVariable("KIRIN_STORE_FILE")
    val kirinStorePassword = providers.environmentVariable("KIRIN_STORE_PASSWORD")
    val kirinKeyAlias = providers.environmentVariable("KIRIN_KEY_ALIAS")
    val kirinKeyPassword = providers.environmentVariable("KIRIN_KEY_PASSWORD")
    val releaseSigningReady = kirinStoreFile.isPresent && kirinStorePassword.isPresent &&
        kirinKeyAlias.isPresent && kirinKeyPassword.isPresent
    signingConfigs {
        getByName("debug") { }
        if (releaseSigningReady) {
            create("kirinRelease") {
                storeFile = file(kirinStoreFile.get())
                storePassword = kirinStorePassword.get()
                keyAlias = kirinKeyAlias.get()
                keyPassword = kirinKeyPassword.get()
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = if (releaseSigningReady) {
                signingConfigs.getByName("kirinRelease")
            } else {
                // 回退：口令缺失（CI/他机）→ debug 签名可 sideload（P0 口径）。
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    packaging {
        jniLibs { useLegacyPackaging = false }
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
}
