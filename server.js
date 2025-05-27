import express from 'express';
import QRCode from 'qrcode';
import fs from 'fs';
import { JWT, JWK } from 'jose';
import { signJWT } from './jwtUtils.js';  // Ton utilitaire de signature JWT
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = 3000;
app.use(express.json()); // Middleware to parse JSON bodies, ensure it's present

// Credential Configuration
const connectionCredentialConfig = {
  credential_type: "ConnectionCredential",
  credential_format: "jwt_vc_json",
  claims_supported: ["connection_id"],
  issuer_display_name: "My Demo Server",
  credential_issuer: `http://localhost:${PORT}`,
  types: ["VerifiableCredential", "ConnectionCredential"],
  doctype: "ConnectionCredentialDoc"
};

// Global variable to store the latest claim selection
let currentClaimSelection = {
    type: 'photo', // Default type
    claims: ["portrait", "given_name_latin1", "age_in_years"], // Default claims
    credential_type_filter: undefined // Default
};

// Endpoint to receive claim selection from the frontend
app.post('/update-claim-selection', (req, res) => {
    const { type, claims, credential_type_filter } = req.body;
    if (!type || !claims) {
        return res.status(400).json({ message: 'Missing type or claims in selection' });
    }
    currentClaimSelection = { type, claims, credential_type_filter };
    console.log('Updated claim selection:', currentClaimSelection);
    res.json({ message: 'Claim selection updated successfully on server.' });
});

// Route pour générer un JWT signé à partir d'un objet de présentation
app.get('/request-object/:value', async (req, res) => {
    const nonceFromRequest = req.params.value; // Or however you link the request to the selection
    
    let presentation_definition;

    if (currentClaimSelection && currentClaimSelection.credential_type_filter === "ConnectionCredential") {
        presentation_definition = {
            id: "vp-request-connection-id",
            input_descriptors: [
                {
                    id: "connection-id-descriptor",
                    name: "Connection ID Credential",
                    purpose: "Please provide your Connection ID credential.",
                    constraints: {
                        fields: [
                            {
                                path: ["$.vc.credentialSubject.connection_id"],
                                purpose: "We need your connection_id to identify your session."
                                // "filter": { "type": "string" } 
                            }
                        ],
                        limit_disclosure: "required",
                        // statuses: { "active": {"directive": "required"} }, // Optional
                        schema: [ 
                            { "uri": "VerifiableCredential" },
                            { "uri": "ConnectionCredential" }
                        ]
                    }
                }
            ]
        };
    } else if (currentClaimSelection && currentClaimSelection.claims) {
        // Generic presentation definition based on other selected claims
        // This part needs to be more dynamic based on `currentClaimSelection.type` and `currentClaimSelection.claims`
        // For simplicity, using a generic one or adapting the old one.
        // This needs to be carefully mapped from availableClaims in index.html to a valid presentation_definition
        const fields = currentClaimSelection.claims.map(claimPath => ({
            path: [`$.vc.credentialSubject.${claimPath}`, `$.${claimPath}`], // Adjust path as per your VC structure
            purpose: `We need your ${claimPath}`
        }));

        presentation_definition = {
            id: `vp-request-${currentClaimSelection.type || 'generic'}`,
            input_descriptors: [
                {
                    id: `${currentClaimSelection.type || 'generic'}-descriptor`,
                    // schema: { uri: "https_schema.org_Person" }, // This should be dynamic
                    // For now, let's assume a generic schema or derive it if possible
                    // If your VCs have a 'type' array, you could filter by that too.
                    // Example: schema: [{ uri: "VerifiableCredential" }, { uri: currentClaimSelection.type }]
                    // This is a simplification. Production would need robust mapping.
                    constraints: {
                        fields: fields.length > 0 ? fields : [{ path: ["$.dummy"], purpose: "Default field if no claims selected"}] 
                        // Ensure fields is not empty
                    }
                }
            ]
        };
        // A more robust way to define schema for other types:
        if (currentClaimSelection.type === "photo" || currentClaimSelection.type === "photo_name") {
             presentation_definition.input_descriptors[0].schema = [{ "uri": "urn:iso:std:iso:23220:cat:1:id" }]; // Example for mdoc
        } else if (currentClaimSelection.type === "pid") {
             presentation_definition.input_descriptors[0].schema = [{ "uri": "eu.europa.ec.eudi.pid.1" }]; // Example for PID
        } else {
            // Fallback or default schema
             presentation_definition.input_descriptors[0].schema = [{ "uri": "VerifiableCredential" }];
        }


    } else {
        // Fallback to a very generic definition if no selection is found
        presentation_definition = {
            id: "vp-request-default",
            input_descriptors: [{ id: "default-descriptor", purpose: "Please provide any relevant credential." }]
        };
    }

    const payload = {
        iss: "my_client_id", // This should be the RP's identifier
        aud: "wallet", // The wallet's identifier or a generic URI
        response_type: "vp_token",
        client_id: "my_client_id", // RP's client_id
        nonce: nonceFromRequest || uuidv4(), // Use nonce from request or generate new one
        response_mode: "direct_post",
        // response_uri: `http://localhost:${PORT}/presentation-submission`, // Wallet will POST here
        presentation_definition: presentation_definition
    };

    // Lire la clé privée depuis le fichier JSON
    const privJwk = JSON.parse(fs.readFileSync('./priv_jwk.json'));

    // Charger la clé privée à partir du JWK
    const privateKey = JWK.asKey(privJwk);

    // Signer le JWT avec la clé privée
    try {
        const token = JWT.sign(payload, privateKey, {
            algorithm: 'ES256', // Utilisation de l'algorithme elliptique (P-256)
            expiresIn: '1h',
            audience: 'wallet'
        });

        res.json({ request_object: token });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate request object' });
    }
});

// Autres routes et logique de serveur Express (comme tu l'as déjà configuré)

// Endpoint for DNS record (to provide RP's domain for request_uri)
app.get('/dns_rp', (req, res) => {
    // In a real scenario, this might be derived from request or config
    res.json({ dns_rp: `http://localhost:${PORT}` }); 
});


// Endpoint to generate QR Code (from index.html)
app.post('/generate-qrcode', async (req, res) => {
    const { text } = req.body;
    if (!text) {
        return res.status(400).json({ error: 'Text for QR code is missing' });
    }
    try {
        const qrCodeDataUrl = await QRCode.toDataURL(text);
        res.json({ qrCode: qrCodeDataUrl });
    } catch (err) {
        console.error('Failed to generate QR code:', err);
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});


// OPENID4VC Endpoints
app.get('/openid4vc/credential-offer', (req, res) => {
  const offer = {
    credential_issuer: connectionCredentialConfig.credential_issuer,
    credentials: [
      {
        format: connectionCredentialConfig.credential_format,
        types: connectionCredentialConfig.types,
        doctype: connectionCredentialConfig.doctype
      }
    ],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "static_pre_authorized_code_123",
        "tx_code": {
          "length": 4,
          "description": "Enter this code to authorize issuance",
          "input_mode": "numeric"
        }
      }
    }
  };
  res.json(offer);
});

app.post('/openid4vc/credential', async (req, res) => {
  // For now, we'll assume the pre-authorized code is static and valid
  // In a real scenario, you'd validate the code from req.body
  const { pre_authorized_code } = req.body; // Or however the wallet sends it

  // For this example, we'll use a static pre-authorized code
  if (pre_authorized_code !== "static_pre_authorized_code_123") {
     // Check if the code from the request matches the one in the offer
     // This is a simplified check. In a real app, you'd manage these codes securely.
    const providedCode = req.body.proof?.jwt; // Assuming the wallet sends it this way based on some specs
    if (providedCode !== "static_pre_authorized_code_123") {
        // A more robust check would be needed here, potentially involving a "proof" object
        // For now, we'll keep it simple and check a direct field or a proof field.
        // Let's assume the wallet sends the pre-authorized code in a specific field, e.g., `req.body.pre_authorized_code`
        // Or as part of a "proof" object, like `req.body.proof.jwt` if it's a self-signed JWT proof.
        // The exact structure depends on the OpenID4VC profile and wallet implementation.
        // For this example, let's assume it's directly in `req.body.pre_authorized_code` or `req.body.proof.jwt`
        if (req.body.pre_authorized_code !== "static_pre_authorized_code_123" && 
            (!req.body.proof || req.body.proof.jwt !== "static_pre_authorized_code_123")) {
            return res.status(401).json({ error: "Invalid pre-authorized code" });
        }
    }
  }


  const connection_id = uuidv4();
  const subject_identifier = "did:example:user123"; // Placeholder for user's DID

  const vcPayload = {
    iss: connectionCredentialConfig.credential_issuer,
    sub: subject_identifier,
    nbf: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60), // 1 year expiry
    iat: Math.floor(Date.now() / 1000),
    jti: `urn:uuid:${uuidv4()}`,
    vc: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: connectionCredentialConfig.types,
      credentialSubject: {
        id: subject_identifier,
        connection_id: connection_id
      }
    }
  };

  try {
    const privJwkJson = fs.readFileSync('./priv_jwk.json', 'utf8');
    const privJwk = JSON.parse(privJwkJson);
    const privateKey = JWK.asKey(privJwk);

    // Sign the VC using jose library
    const signedVc = JWT.sign(vcPayload, privateKey, {
        algorithm: 'ES256', // Ensure this matches the key type
        header: {
            kid: privateKey.kid // Optional: include key ID if present and needed
        }
    });
    
    // If using your custom signJWT, it might look like:
    // const signedVc = await signJWT(vcPayload, './priv_jwk.json'); 
    // Ensure signJWT is compatible with ES256 and the key format.

    res.json({
      format: connectionCredentialConfig.credential_format,
      credential: signedVc,
      // c_nonce: req.body.c_nonce, // If wallet sent a c_nonce
      // c_nonce_expires_in: req.body.c_nonce ? 86400 : undefined
    });

  } catch (error) {
    console.error("Error signing VC:", error);
    res.status(500).json({ error: 'Failed to sign credential' });
  }
});

// Lancer le serveur
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Placeholder for WebSocket broadcasting function
// You'll need to integrate your actual WebSocket setup here.
// For example, if using 'ws' package:
// import WebSocket, { WebSocketServer } from 'ws';
// const wss = new WebSocketServer({ server: yourHttpServer }); // Needs actual HTTP server
// function wsBroadcast(data) {
//   wss.clients.forEach(client => {
//     if (client.readyState === WebSocket.OPEN) {
//       client.send(JSON.stringify(data));
//     }
//   });
// }
// For now, a simple console log placeholder:
function wsBroadcast(data) {
    console.log("[WebSocket Broadcast]:", JSON.stringify(data, null, 2));
}

app.post('/presentation-submission', express.json(), async (req, res) => {
    try {
        const { vp_token, presentation_submission } = req.body;

        if (!vp_token) { // presentation_submission is optional by some wallets for a single VC in vp_token
            wsBroadcast({ type: 'PROCESSING_ERROR', payload: { error: 'Missing vp_token', details: 'vp_token is required in the submission.' } });
            return res.status(400).send('Missing vp_token');
        }

        // Assuming vp_token is the JWS of our ConnectionCredential.
        // A more generic solution would parse presentation_submission to find the VC.
        const vcJws = vp_token; 

        let publicKey;
        try {
            const jwksContent = fs.readFileSync('./jwks.json', 'utf-8'); // Ensure jwks.json is in the root
            const jwks = JSON.parse(jwksContent);
            if (!jwks.keys || jwks.keys.length === 0) {
                throw new Error("No keys found in jwks.json");
            }
            // For simplicity, using the first key. Ideally, match 'kid' from JWS header.
            // The key for verifying a self-issued VC (ConnectionCredential) is the server's own public key.
            publicKey = await JWK.asKey(jwks.keys[0]); 
        } catch (keyError) {
            console.error("Error loading public key:", keyError);
            wsBroadcast({ type: 'PROCESSING_ERROR', payload: { error: 'Server key error', details: keyError.message } });
            return res.status(500).json({ status: "error", message: "Server key configuration error." });
        }
        
        let decodedVcPayload;
        try {
            const { payload, protectedHeader } = await JWT.verify(vcJws, publicKey, {
                issuer: connectionCredentialConfig.credential_issuer, // Must be our server
                // clockTolerance: '5 minutes' // Optional: allow for clock skew
            });
            decodedVcPayload = payload;

            if (!decodedVcPayload.vc || 
                !decodedVcPayload.vc.type || 
                !decodedVcPayload.vc.type.includes("ConnectionCredential")) {
                throw new Error("VC is not a ConnectionCredential or type is missing/incorrect.");
            }
            const connectionId = decodedVcPayload.vc.credentialSubject.connection_id;
            if (!connectionId) {
                throw new Error("Connection ID missing in VC's credentialSubject.");
            }

            console.log(`Successfully verified ConnectionCredential. Connection ID: ${connectionId}`);
            wsBroadcast({
               type: 'VC_DATA_UPDATE',
               payload: {
                   status: "Connection ID Verified",
                   formattedVcData: { 
                       claims: [
                           { label: 'connection_id', value: connectionId, type: 'text' },
                           { label: 'Issuer (iss)', value: decodedVcPayload.iss, type: 'text'},
                           { label: 'Subject (sub)', value: decodedVcPayload.sub, type: 'text'},
                           { label: 'Issued At (iat)', value: new Date(decodedVcPayload.iat * 1000).toLocaleString(), type: 'text'},
                           { label: 'Expires At (exp)', value: new Date(decodedVcPayload.exp * 1000).toLocaleString(), type: 'text'}
                       ]
                   },
                   technicalDebugData: { 
                       jwtValidationSteps: [{step: "JWS Verification", status: "Success", details: "Signature and claims (iss, exp, nbf, iat) verified for ConnectionCredential."}],
                       serverAnalysis: [{timestamp: new Date().toISOString(), message: `Received and verified ConnectionCredential for ${connectionId}`}]
                   }
               }
            });

        } catch (verificationError) {
            console.error("VC Verification failed:", verificationError);
            wsBroadcast({ 
                type: 'PROCESSING_ERROR', 
                payload: { 
                    error: 'VC Verification Failed', 
                    details: verificationError.message,
                    receivedTokenSummary: vcJws.substring(0, 60) + "..." // Log a summary for brevity
                } 
            });
            return res.status(400).json({ status: "error", message: "VC verification failed: " + verificationError.message });
        }

        // If verification successful, respond 200 to the wallet.
        res.status(200).json({ status: "success", message: "Presentation received and is being processed." });

    } catch (error) {
        console.error('Error processing presentation:', error);
        wsBroadcast({ type: 'PROCESSING_ERROR', payload: { error: 'Server error processing presentation', details: error.message } });
        res.status(500).send('Server error processing presentation');
    }
});
