openid4vp://?client_id=did:web:did-doc-dts-preview.s3.eu-central-1.amazonaws.com:606a7acb-521f-44e1-8874-2caffbc31254&request_uri=https://openid.pre.vc-dts.sicpa.com/jwts/a9pirRj3IXMLDOwF2ri3



https://ewcpilot.eu/p2-explore-more-scenarios/

https://ewcpilot.eu/p2-explore-more-scenarios/

---

**OpenID4VP and SD-JWT Processing**

This document outlines the OpenID4VP presentation flow and the SD-JWT (Selective Disclosure JWT) verification process implemented in this application.

**OpenID4VP Flow Overview**

The application implements the following OpenID4VP (OpenID for Verifiable Presentations) flow:

1.  **Presentation Request Initiation**:
    *   The Relying Party (RP - this application) determines the need for a verifiable presentation from the user.
    *   The user is typically directed to a page or an interaction that triggers the generation of a presentation request.

2.  **Request Object Generation & QR Code Display**:
    *   The server dynamically generates a Request Object. This object is a signed JWS (JSON Web Signature) that details what the RP is requesting (e.g., specific credential types, claims).
    *   The Request Object is often presented to the user as a URI (e.g., `openid4vp://?request_uri=...` or by value) encoded within a QR code.

3.  **User Interaction with Wallet**:
    *   The user scans the QR code using their digital wallet that supports the OpenID4VP protocol.
    *   The wallet parses the request object and helps the user select the appropriate credentials and disclose the necessary claims.

4.  **Presentation Submission (`vp_token`)**:
    *   The wallet constructs a `vp_token` (Verifiable Presentation Token). This token contains the selected credentials and disclosed claims.
    *   In the case of SD-JWTs, the `vp_token` is a specially formatted string containing the SD-JWT (itself a JWS), the selective disclosures, and a Key Binding JWT.
    *   The wallet sends this `vp_token` to the RP's pre-defined `/callback` endpoint, typically via an HTTP `POST` request in the `application/x-www-form-urlencoded` format.

5.  **Server-Side Processing**:
    *   The server's `/callback` endpoint receives the `vp_token`.
    *   It then proceeds to verify and decode the `vp_token` to extract the user's claims.

**SD-JWT Verification at `/callback`**

When the `/callback` endpoint receives a `vp_token` that is an SD-JWT, the following verification and processing steps are performed:

1.  **Receive `vp_token`**: The `vp_token` string is extracted from the request body.

2.  **Outer JWS Wrapper Verification (if applicable)**:
    *   The `vp_token` may be wrapped in an outer JWS. This is often the case when the wallet sends the presentation. This outer JWS might include an `x5c` header containing the wallet's certificate chain.
    *   If an `x5c` header is present:
        *   The certificate chain is parsed.
        *   The signature of this outer JWS is verified against the public key extracted from the certificate. This step authenticates the sender of the `vp_token` (the wallet).
        *   Certificate details (subject, issuer, validity period) are extracted and logged for informational purposes.
    *   This outer verification is about the transport/wrapper, not the VC issuer's signature.

3.  **SD-JWT Decoding (`@sd-jwt/decode` library)**:
    *   The complete `vp_token` string (e.g., `JWS_part~disclosure1~disclosure2~KB_JWT_part`) is passed to the `@sd-jwt/decode` library.
    *   The library performs several critical functions:
        *   **Parses the SD-JWT Structure**: It separates the main JWS part of the SD-JWT, the list of disclosures, and the Key Binding JWT (if present).
        *   **Verifies Issuer Signature (Inner JWS)**: The JWS part of the SD-JWT (signed by the original Verifiable Credential Issuer) is cryptographically verified. This typically involves using information from the `cnf` (confirmation) claim within the SD-JWT's payload, which links the SD-JWT to the holder's key.
        *   **Validates Disclosures**: Each disclosure string is base64url decoded. The library then hashes each disclosed claim and compares it against the `_sd` (selectively disclosed) hash entries present in the main SD-JWT payload. This ensures the integrity and authenticity of the disclosed claims.
        *   **Key Binding JWT Verification**: If a Key Binding JWT is present, its signature is verified using the public key derived from the `cnf` claim in the SD-JWT. This step proves that the presenter possesses the private key associated with the SD-JWT, preventing replay attacks.

4.  **Claim Extraction (`getClaims`)**:
    *   After successful decoding and verification by the library, the `getClaims` function is used. This function combines the always-visible claims from the SD-JWT's main payload with the selectively disclosed claims (from the validated disclosures) to reconstruct the full set of revealed claims.

5.  **Data Storage and Frontend Preparation**:
    *   The extracted information (e.g., issuer, expiration time, issuance time from the SD-JWT payload), the verified claims, the overall verification status, and any relevant certificate details (from the outer JWS, if applicable) are stored temporarily on the server (in `currentVcDetails`).
    *   This data is then made available to the frontend via endpoints like `/vc-details` and `/photo` for display to the user.

**Visual Schema Placeholder**

A visual diagram illustrating these flows would be beneficial for a clearer understanding. Consider creating and inserting sequence diagrams for:

*   **The overall OpenID4VP interaction flow** (from request generation to presentation submission).
*   **The detailed SD-JWT validation steps** performed at the `/callback` endpoint by the server.