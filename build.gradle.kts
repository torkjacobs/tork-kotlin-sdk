plugins {
    kotlin("jvm") version "2.0.0"
    `maven-publish`
}

group = "network.tork"
version = "0.1.0"

repositories { mavenCentral() }

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
