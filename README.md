# vc-verifier
Verify WC3 Verifiable Credential.

Verify (requires issuer running)
```
curl -X POST http://localhost:9080/verify \
  -H "Content-Type: application/json" \
  -d '{"credential":"<credential from issuer>"}'

{"valid":true,"reason":null,"subjectId":"did:example:holder123","credentialType":["VerifiableCredential","UniversityID"]}%
```
---
Presentation
```
AR=$(curl -s http://localhost:9080/authorize-presentation)
STATE=$(jq -r .state <<<"$AR")
NONCE=$(jq -r .nonce <<<"$AR")
VP_TOKEN=$(curl -s "http://localhost:9080/vp-token?nonce=$NONCE&vc=<credential from issuer>")
curl -v "http://localhost:9080/callback?state=$STATE&vp_token=$VP_TOKEN&presentation_submission=%7B%7D"

{"valid":true,"aud_ok":true,"state":"<state>","verified":[{"issuer":"https://issuer.example.com/issuer","subjectId":"did:example:holder123","types":["VerifiableCredential","UniversityID"],"studentId":"S1234567"}],"submission":"{}"}%
```
