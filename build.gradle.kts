plugins {
    kotlin("jvm") version "2.1.10"
    `maven-publish`
}

// PUBLISHING COORDINATE (set 25 Sep 2026). `network.tork` is not a verified
// namespace on Maven Central and nothing exists under it. The Java SDK owns
// io.github.torkjacobs:tork-governance (published, 0.1.0), so this module takes
// a DISTINCT artifactId under the same verified group rather than clobbering it.
group = "io.github.torkjacobs"
version = "0.3.0"

repositories { mavenCentral() }

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation(kotlin("test"))
    // Test scope only: reads the country-layer parity fixtures in
    // src/test/resources. The published artifact gains no dependency.
    testImplementation("com.google.code.gson:gson:2.8.9")
}

tasks.test { useJUnitPlatform() }

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            groupId = "io.github.torkjacobs"
            artifactId = "tork-governance-kotlin"
            version = "0.3.0"
        }
    }
}
