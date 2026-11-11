plugins {
    id("com.android.application") version "8.5.2"
}

android {
    namespace = "com.tuapp.tvcleaner.adb"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.tuapp.tvcleaner.adb"
        minSdk = 26
        targetSdk = 34
        versionCode = 3
        versionName = "5.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
