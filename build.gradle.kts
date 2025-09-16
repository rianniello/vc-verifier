
plugins {
    kotlin("jvm") version "2.0.20"
    id("io.ktor.plugin") version "3.2.3"
}

application {
    mainClass.set("dev.rianniello.MainKt")
    applicationDefaultJvmArgs = listOf("-Duser.timezone=UTC")
}

repositories {
    mavenCentral()
}
dependencies {
    implementation("io.ktor:ktor-client-java:2.3.12")
    implementation("com.networknt:json-schema-validator:1.4.0")
    implementation("ch.qos.logback:logback-classic:1.4.14")
    implementation("com.nimbusds:nimbus-jose-jwt:10.5")
    implementation("com.networknt:json-schema-validator:1.5.8")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.20.0")
    implementation("com.apicatalog:titanium-json-ld:1.6.0")
    implementation("io.ktor:ktor-server-core-jvm")
    implementation("io.ktor:ktor-server-netty-jvm")
    implementation("io.ktor:ktor-server-auth-jvm")
    implementation("io.ktor:ktor-server-auth-jwt-jvm")
    implementation("io.ktor:ktor-server-content-negotiation-jvm")
    implementation("io.ktor:ktor-serialization-jackson-jvm")
}
