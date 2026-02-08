plugins {
    kotlin("jvm") version "2.1.10"
    `maven-publish`
}

group = "network.tork"
version = "0.1.0"

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

dependencies { testImplementation(kotlin("test")) }

tasks.test { useJUnitPlatform() }

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            groupId = "network.tork"
            artifactId = "tork-governance"
            version = "0.1.0"
        }
    }
}
