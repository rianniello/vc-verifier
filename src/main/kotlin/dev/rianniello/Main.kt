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
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.*
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
    install(ContentNegotiation) {
        jackson { registerKotlinModule() }
    }
    val http = HttpClient(Java)
    val jwksCache = JwksCache(http)

    routing {
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

        // (Optional) SKETCH: OID4VP authz req builder (QR/deeplink your wallets understand)
        // For a real flow you'd generate a request object (Pushed Authorization Request or URI),
        // include a Presentation Definition (DIF) describing UniversityID requirement, and accept vp_token at your redirect_uri.
        get("/authorize-presentation") {
            val requestUri = "openid-vc://?client_id=https://verifier.example.com/callback&scope=openid&response_type=vp_token&presentation_definition_uri=https://verifier.example.com/pd/university-id"
            call.respond(mapOf("authorization_request_uri" to requestUri))
        }
    }
}
