package dev.rianniello
import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.http.*
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion
import com.networknt.schema.ValidationMessage
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.*
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.*
import io.ktor.client.engine.java.Java
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.serialization.jackson.jackson
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import java.time.Instant
import java.util.*


data class AuthzReq(
    val client_id: String,
    val response_type: String = "vp_token",
    val response_mode: String = "query", // or "post"
    val redirect_uri: String,
    val nonce: String,
    val state: String,
    val presentation_definition_uri: String // or inline "presentation_definition"
)

val requestStore = mutableMapOf<String, String>() // state -> nonce
val issuerAllowlist = setOf("https://issuer.example.com/issuer") // tighten for your trust model

val universityIdSubjectSchema = """
{
  "${'$'}schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["id", "studentId", "givenName", "familyName", "status"],
  "properties": {
    "id":        { "type": "string" },
    "studentId": { "type": "string", "minLength": 3 },
    "givenName": { "type": "string" },
    "familyName":{ "type": "string" },
    "status":    { "type": "string", "enum": ["active","inactive","suspended","revoked"] }
  },
  "additionalProperties": true
}
""".trimIndent()

data class VerifyRequest(val credential: String)
data class VerifyResult(
    val valid: Boolean,
    val reason: String? = null,
    val subjectId: String? = null,
    val credentialType: List<String>? = null
)

class JwksCache(
    private val http: HttpClient,
    private val mapper: ObjectMapper = jacksonObjectMapper()
) {
    private val cache = mutableMapOf<String, JWKSet>() // jwks_uri -> JWKSet
    suspend fun get(jwksUri: String): JWKSet {
        return cache.getOrPut(jwksUri) {
            val resp = http.get(jwksUri)
            if (!resp.status.isSuccess()) error("JWKS fetch failed: ${resp.status}")
            val json = resp.bodyAsText()
            JWKSet.parse(json)
        }
    }
}

fun verifyJwtWithJwks(jwt: SignedJWT, jwks: JWKSet): Boolean {
    val kid = jwt.header.keyID
    val jwk: JWK? = if (kid != null) jwks.keys.firstOrNull { it.keyID == kid } else null
    val key = (jwk ?: jwks.keys.firstOrNull())?.toRSAKey() ?: return false
    val verifier: JWSVerifier = RSASSAVerifier(key.toRSAPublicKey())
    return jwt.verify(verifier)
}

val schemaFactory: JsonSchemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012)
val mapper: ObjectMapper = jacksonObjectMapper()
val subjectSchema = schemaFactory.getSchema(universityIdSubjectSchema)

fun main() {
    embeddedServer(Netty, port = 9080) { verifierModule() }.start(wait = true)
}

fun Application.verifierModule() {
    val base = "https://verifier.example.com"
    val mapper = com.fasterxml.jackson.module.kotlin.jacksonObjectMapper()

    install(ContentNegotiation) {
        jackson { registerKotlinModule() }
    }
    val http = HttpClient(Java)
    val jwksCache = JwksCache(http)

    routing {

        get("/vp-token") {
            val nonce = call.request.queryParameters["nonce"] //temp
            val vc = call.request.queryParameters["vc"]//temp
            val now = Instant.now()
            val claims = JWTClaimsSet.Builder()
                .issuer("did:example:holder")
                .audience("https://verifier.example.com/callback")
                .claim("nonce", nonce)
                .claim("vp", mapOf(
                    "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                    "type" to listOf("VerifiablePresentation"),
                    "verifiableCredential" to listOf(vc)
                ))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .jwtID(UUID.randomUUID().toString())
                .build()

            // Use HS256 with a throwaway secret (verifier isn’t checking VP signature)
            val header = JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build()
            val jwt = SignedJWT(header, claims)
            jwt.sign(MACSigner("01234567890123456789012345678901")) // 32-byte secret
            call.respond(jwt.serialize())
        }
        // POST /verify { "credential": "<jwt-vc>" }
        post("/verify") {
            val req = runCatching { call.receive<VerifyRequest>() }.getOrElse {
                call.respond(HttpStatusCode.BadRequest, VerifyResult(false, "Invalid JSON"))
                return@post
            }

            val signed = runCatching { SignedJWT.parse(req.credential) }.getOrElse {
                call.respond(HttpStatusCode.BadRequest, VerifyResult(false, "Not a JWT"))
                return@post
            }

            val claims = signed.jwtClaimsSet
            val now = Instant.now().epochSecond

            // ---- Core JWT checks ----
            // issuer string should be your issuer identifier (could be a DID or URL)
            val iss = claims.issuer ?: return@post call.respond(
                HttpStatusCode.BadRequest, VerifyResult(false, "Missing issuer")
            )
            val exp = claims.expirationTime?.toInstant()?.epochSecond ?: Long.MAX_VALUE
            val nbf = claims.notBeforeTime?.toInstant()?.epochSecond!!
            if (now < nbf) return@post call.respond(HttpStatusCode.BadRequest, VerifyResult(false, "Not yet valid"))
            if (now >= exp) return@post call.respond(HttpStatusCode.BadRequest, VerifyResult(false, "Expired"))

            // ---- Discover issuer JWKS (for demo assume your metadata advertises jwks_uri) ----
            // If you control the issuer, you know the jwks_uri; otherwise resolve via OIDC/OID4VCI metadata
            val jwksUri = when {
                iss.startsWith("https://issuer.example.com") -> "http://localhost:8080/.well-known/jwks.json"
                else -> return@post call.respond(HttpStatusCode.BadRequest, VerifyResult(false, "Unknown issuer"))
            }

            val jwks = runCatching { jwksCache.get(jwksUri) }.getOrElse {
                call.respond(HttpStatusCode.BadRequest, VerifyResult(false, "JWKS fetch failed"))
                return@post
            }

            if (!verifyJwtWithJwks(signed, jwks)) {
                call.respond(HttpStatusCode.BadRequest, VerifyResult(false, "Signature invalid"))
                return@post
            }

            // ---- VC claim checks ----
            val vc = claims.getJSONObjectClaim("vc") ?: return@post call.respond(
                HttpStatusCode.BadRequest, VerifyResult(false, "Missing vc claim")
            )
            val types = (vc["type"] as? List<*>)?.map { it.toString() }.orEmpty()
            if (!types.containsAll(listOf("VerifiableCredential", "UniversityID"))) {
                call.respond(HttpStatusCode.BadRequest, VerifyResult(false, "Wrong VC types: $types"))
                return@post
            }

            val credentialSubject = (vc["credentialSubject"] as? Map<*, *>) ?: emptyMap<String, Any>()
            val subjectJson = mapper.valueToTree<com.fasterxml.jackson.databind.JsonNode>(credentialSubject)
            val errors: Set<ValidationMessage> = subjectSchema.validate(subjectJson)
            if (errors.isNotEmpty()) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    VerifyResult(false, "Schema failed: ${errors.joinToString("; "){ it.message }}")
                )
                return@post
            }

            // ---- (Optional) Status / revocation (stub) ----
            // If you issue a status list URL in vc.credentialStatus, fetch and test bit.
            // val status = (vc["credentialStatus"] as? Map<*, *>)?.get("statusListCredential") as? String
            // ...fetch status list VC/JWT, decode bitstring, check index...

            call.respond(
                VerifyResult(
                    valid = true,
                    reason = null,
                    subjectId = credentialSubject["id"]?.toString(),
                    credentialType = types
                )
            )
        }

        // 1) Serve the Presentation Definition
        get("/pd/university-id") {
            val pd = mapOf(
                "id" to "pd-university-id",
                "input_descriptors" to listOf(
                    mapOf(
                        "id" to "university-id",
                        "name" to "University ID",
                        "constraints" to mapOf(
                            "fields" to listOf(
                                mapOf("path" to listOf("$.vc.type[*]"), "filter" to mapOf("type" to "string", "const" to "UniversityID")),
                                mapOf("path" to listOf("$.vc.credentialSubject.studentId"), "filter" to mapOf("type" to "string", "minLength" to 3)),
                                mapOf("path" to listOf("$.vc.credentialSubject.status"), "filter" to mapOf("type" to "string", "const" to "active"))
                            )
                        )
                    )
                )
            )
            call.respond(pd)
        }

        // 2) Build an authorization request (QR/deeplink payload)
        get("/authorize-presentation") {
            val state = java.util.UUID.randomUUID().toString()
            val nonce = java.util.UUID.randomUUID().toString()
            requestStore[state] = nonce

            val req = AuthzReq(
                client_id = "$base/callback",
                redirect_uri = "$base/callback",
                nonce = nonce,
                state = state,
                presentation_definition_uri = "$base/pd/university-id"
            )

            // Wallets vary: some accept an "openid-vc://" deeplink, others a plain JSON they parse from QR
            val deepLink = "openid-vc://?client_id=${req.client_id}" +
                    "&response_type=${req.response_type}" +
                    "&redirect_uri=${req.redirect_uri}" +
                    "&nonce=${req.nonce}" +
                    "&state=${req.state}" +
                    "&presentation_definition_uri=${req.presentation_definition_uri}"

            call.respond(
                mapOf(
                    "authorization_request_uri" to deepLink,
                    "state" to state,
                    "nonce" to nonce
                )
            )
        }

        // 3) Callback receiving vp_token + presentation_submission
        get("/callback") {
            val state = call.request.queryParameters["state"]
            val vpToken = call.request.queryParameters["vp_token"]
            val submission = call.request.queryParameters["presentation_submission"] // JSON string
            if (state == null || vpToken == null) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "missing vp_token or state"))
                return@get
            }

            val expectedNonce = requestStore.remove(state)
            if (expectedNonce == null) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "unknown or replayed state"))
                return@get
            }

            // Parse VP as JWT (JWT-based VP)
            val vpJwt = com.nimbusds.jwt.SignedJWT.parse(vpToken)
            val vpClaims = vpJwt.jwtClaimsSet

            // ---- Request binding checks ----
            val nonceInVp = vpClaims.getStringClaim("nonce") ?: vpClaims.getStringClaim("jti") // varies by wallet
            if (nonceInVp != expectedNonce) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "nonce mismatch"))
                return@get
            }

            // aud can be your verifier base/callback; accept if present and matches
            val audOk = vpClaims.audience?.isEmpty() != false || vpClaims.audience.contains("$base/callback")

            // Extract embedded VC(s) from VP claims (common patterns)
            // For JWT-VC in a JWT-VP, wallets often put VCs in "vp" or directly in a claim like "verifiableCredential"
            val vp = vpClaims.getJSONObjectClaim("vp") // may be null
            val vcList: List<String> = when {
                vp != null && vp["verifiableCredential"] is List<*> ->
                    (vp["verifiableCredential"] as List<*>).map { it.toString() }
                vpClaims.getClaim("verifiableCredential") is List<*> ->
                    (vpClaims.getClaim("verifiableCredential") as List<*>).map { it.toString() }
                else -> emptyList()
            }
            if (vcList.isEmpty()) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "no credentials in VP"))
                return@get
            }

            // Verify each VC (JWT-VC) signature & claims
            val verifiedCredentials = mutableListOf<Map<String, Any?>>()
            for (vcJwtStr in vcList) {
                val vcJwt = com.nimbusds.jwt.SignedJWT.parse(vcJwtStr)
                val vcClaims = vcJwt.jwtClaimsSet

                // 1) Issuer allowlist (tighten to your trust framework)
                val iss = vcClaims.issuer
                if (iss !in issuerAllowlist) {
                    call.respond(HttpStatusCode.BadRequest, mapOf("error" to "untrusted issuer: $iss"))
                    return@get
                }

                // 2) Fetch Issuer JWKS (cache it in prod)
                val jwksUri = "http://localhost:8080/.well-known/jwks.json"

                val jwks = com.nimbusds.jose.jwk.JWKSet.parse(
                    java.net.URL(jwksUri).readText()
                )
                val kid = vcJwt.header.keyID
                val jwk = jwks.keys.firstOrNull { it.keyID == kid } ?: jwks.keys.first()
                val pub = jwk.toRSAKey().toRSAPublicKey()
                val ok = vcJwt.verify(com.nimbusds.jose.crypto.RSASSAVerifier(pub))
                if (!ok) {
                    call.respond(HttpStatusCode.BadRequest, mapOf("error" to "VC signature invalid"))
                    return@get
                }

                // 3) Lifetime
                val now = java.time.Instant.now()
                if (vcClaims.expirationTime?.toInstant()?.isBefore(now) == true) {
                    call.respond(HttpStatusCode.BadRequest, mapOf("error" to "VC expired"))
                    return@get
                }

                // 4) Type + payload checks (UniversityID + status=active)
                val vc = vcClaims.getJSONObjectClaim("vc") ?: run {
                    call.respond(HttpStatusCode.BadRequest, mapOf("error" to "missing vc claim"))
                    return@get
                }
                val types = (vc["type"] as? List<*>)?.map { it.toString() } ?: emptyList()
                if (!types.containsAll(listOf("VerifiableCredential", "UniversityID"))) {
                    call.respond(HttpStatusCode.BadRequest, mapOf("error" to "wrong types: $types"))
                    return@get
                }
                val subject = (vc["credentialSubject"] as? Map<*, *>) ?: emptyMap<String, Any>()
                if (subject["status"]?.toString() != "active") {
                    call.respond(HttpStatusCode.BadRequest, mapOf("error" to "status not active"))
                    return@get
                }

                // 5) (Optional) Status List 2021 check if you include credentialStatus
                // val cs = vc["credentialStatus"] as? Map<*, *>
                // fetch cs["statusListCredential"], decode bitstring, test index...

                verifiedCredentials += mapOf(
                    "issuer" to iss,
                    "subjectId" to subject["id"],
                    "types" to types,
                    "studentId" to subject["studentId"]
                )
            }

            call.respond(
                mapOf(
                    "valid" to true,
                    "aud_ok" to audOk,
                    "state" to state,
                    "verified" to verifiedCredentials,
                    "submission" to submission // you can parse & validate against your PD here
                )
            )
        }
    }
}
