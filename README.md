# vc-verifier
Verify WC3 Verifiable Credential.

Verify (requires issuer running)
```
curl -X POST http://localhost:9080/verify \
  -H "Content-Type: application/json" \
  -d '{"credential":"<credential>"}'

{"valid":true,"reason":null,"subjectId":"did:example:holder123","credentialType":["VerifiableCredential","UniversityID"]}%
```
