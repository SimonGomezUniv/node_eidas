// Si tu utilises des modules ES
import express from 'express';
import QRCode from 'qrcode';
import fs from 'fs';
import * as jose from 'jose'
import { SignJWT, importJWK } from 'jose';
import { decodeSdJwt, getClaims } from '@sd-jwt/decode';
import { digest } from '@sd-jwt/crypto-nodejs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import os from 'os';
import ws from 'ws'; // Default import for 'ws' module
import { v4 as uuidv4 } from 'uuid'; // Added for ConnectionCredential

// Correctly derive WebSocketServer and WebSocket
const WebSocketServer = ws.Server; 
const WebSocket = ws; // This provides access to WebSocket.OPEN, etc.

dotenv.config();

let currentClaimSelection = {
    type: 'photo', // Default type
    claims: ['portrait'], // Default claims for the default type, adjust if needed
    credential_type_filter: undefined // Add this for ConnectionCredential
};

const app = express();


// Function to get the local IP address
function getLocalIpAddress() {
  const interfaces = os.networkInterfaces();
  for (const interfaceName in interfaces) {
    for (const iface of interfaces[interfaceName]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1'; // Fallback to localhost
}

const localIp = getLocalIpAddress();
console.log(`Local IP Address: ${localIp}`);
// Load configuration from .env file
const config = {
  port: process.env.PORT || 3000,
  secretKey: process.env.SECRET_KEY || 'default_secret_key',
  dnsRp: process.env.DNS_RP || `http://${localIp}:${process.env.PORT || 3000}`,
};

var dns_rp = config.dnsRp;

console.log('Configuration loaded:', config);
// const PORT = 3000; // PORT from server.js is not needed, index.js uses config.port

// Credential Configuration for ConnectionCredential (from server.js)
const connectionCredentialConfig = {
  credential_type: "ConnectionCredential",
  credential_format: "jwt_vc_json",
  claims_supported: ["connection_id"],
  issuer_display_name: "My Demo Server",
  credential_issuer: config.dnsRp, // Updated to use config.dnsRp
  types: ["VerifiableCredential", "ConnectionCredential"],
  doctype: "ConnectionCredentialDoc" // A custom doctype
};

const privJwk = JSON.parse(fs.readFileSync('./priv_jwk.json'));
const privKey = await jose.importJWK(JSON.parse(fs.readFileSync('./priv_jwk.json')), 'ES256');

// Function to issue a Connection ID Verifiable Credential
async function issueConnectionIdVC() {
    const connection_id_uuid = uuidv4();
    const subject_uuid = uuidv4();
    const jti_uuid = uuidv4();

    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + (60 * 60); // 1 hour expiry

    const vcPayload = {
        iss: config.dnsRp,
        sub: `did:example:user:${subject_uuid}`,
        aud: "did:example:rp", // Placeholder audience
        nbf: iat,
        iat: iat,
        exp: exp,
        jti: jti_uuid,
        _sd_alg: "sha-256",
        vc: {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            type: ["VerifiableCredential", "ConnectionCredential"],
            vct: "ConnectionCredential",
            credentialSubject: {
                id: `did:example:user:${subject_uuid}`,
                connection_id: connection_id_uuid
            }
        }
    };

    try {
        const signedVcJwt = await new jose.SignJWT(vcPayload)
            .setProtectedHeader({ alg: 'ES256', kid: privJwk.kid })
            .sign(privKey);
        
        const sdJwtString = signedVcJwt + "~";
        return sdJwtString;
    } catch (error) {
        console.error("Error signing Connection ID VC:", error);
        throw new Error('Failed to issue Connection ID VC');
    }
}

// Middleware to parse JSON requests
app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: '50mb'}));

// Middleware to log the path of each request
app.use((req, res, next) => {
    console.log(`Path accessed: ${req.path}`);
    //console.log(req);
    next();
});

// Route to generate a QR code from a string
app.post('/generate-qrcode', async (req, res) => {
    const { text } = req.body;

    if (!text) {
        return res.status(400).json({ error: 'Text is required to generate QR code' });
    }

    try {
        const qrCodeDataURL = await QRCode.toDataURL(text);
        res.json({ qrCode: qrCodeDataURL });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});

// Route to log the value of XXXXX
app.get('/jwks/:value', (req, res) => {
    const { value } = req.params;
    console.log(`Received value: ${value}`);


    // Endpoint to serve JWKS (JSON Web Key Set)
        const jwks = {
            keys: [
                {
                    kty: 'RSA',
                    use: 'sig',
                    kid: '12345',
                    alg: 'RS256',
                    n: 'your-modulus-here',
                    e: 'AQAB'
                }
            ]
        };
        res.json(jwks);

});



// Route to generate a QR code from a string
app.get('/generate-qrcode', async (req, res) => {
    const { text } = req.query;

    if (!text) {
        return res.status(400).json({ error: 'Text is required to generate QR code' });
    }

    try {
        const qrCodeDataURL = await QRCode.toDataURL(text);
        res.json({ qrCode: qrCodeDataURL });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});

app.get("/test", (req, res) => {
    res.json("Test");
});


app.get("/dns_rp", (req, res) => {
    res.json({dns_rp:dns_rp});
})

const SECRET_KEY = 'your_secret_key';

// Route to generate a JWT from a JSON object
app.post('/generate-jwt', (req, res) => {
    const { payload } = req.body;

    if (!payload || typeof payload !== 'object') {
        return res.status(400).json({ error: 'A valid JSON object is required to generate JWT' });
    }

    try {
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate JWT' });
    }
});

var current_custom_request =  {
  "response_uri": `${dns_rp}/callback`,
  "aud": "https://self-issued.me/v2",
  "client_id_scheme": "did",
  "iss": "me",
  "response_type": "vp_token",
  "presentation_definition": {
    "id": "demo-request-photo-only",
    "input_descriptors": [
      {
        "id": "photo-only-request",
        "purpose": "Demander uniquement la photo du document",
        "constraints": {
          "fields": [
            {
              "path": ["$.iso23220.portrait"],
              "optional": false
            }
          ]
        }
      }
    ],
    "format": {
      "jwt_vp_json": {
        "alg": ["ES256"]
      },
      "jwt_vc_json": {
        "alg": ["ES256"]
      }
    }
  },
  "state": "demo-state-12345",
  "nonce": "demo-nonce-12345",
  "client_id": "did:web:your-rp.example.com",
  "client_metadata": {
    "client_name": "Demo RP - Just Photo",
    "logo_uri": `${config.dnsRp}/logo.png`,
    "vp_formats": {
      "jwt_vp_json": {
        "alg": ["ES256"]
      },
      "jwt_vc_json": {
        "alg": ["ES256"]
      }
    }
  },
  "response_mode": "direct_post"
};
app.get('/request-object-custom/:value', (req, res) => {
  
  var nounce = req.params.value;

    // 1. Charger ta clé privée depuis un fichier ou directement
const privJwk = JSON.parse(fs.readFileSync('./priv_jwk.json'));
// 2. Importer la clé pour la signature (ES256)
var payload = current_custom_request
importJWK(privJwk, 'ES256')
.then((privateKey) => {
  // 4. Signer en JWS (JWT compact)
  const jws = new SignJWT(payload)
  .setProtectedHeader({ alg: 'ES256', kid: 'my-key-id' })
  .setIssuedAt()
  .setExpirationTime('1h')
  .sign(privateKey)
  .then((token) => {
      res.send( token );
  })
  .catch((error) => {
      console.error('Error signing JWT:', error);
      res.status(500).json({ error: 'Failed to generate request object' });
  });
  })
})

app.get('/request-object-custom', (req, res) => {
  res.send(current_custom_request);
})

app.post('/request-object-custom', (req, res) => {
    const { payload } = req.body;

    if (!payload || typeof payload !== 'object') {
        return res.status(400).json({ error: 'A valid JSON object is required to generate JWT' });
    }

    current_custom_request = payload;
    console.log("current_custom_request", current_custom_request)
    res.json(current_custom_request);
})

// Helper function to build the presentation_definition object
function buildPresentationDefinition(selectionType, selectedClaims) {
    let requestedFields = [];
    let purpose = `Requesting ${selectionType} claims.`;
    // Use crypto.randomUUID() for truly unique IDs
    let inputDescriptorId = `descriptor-${selectionType}-${crypto.randomUUID()}`; 
    let presentationDefinitionId = `vp-request-${crypto.randomUUID()}`;

    if (selectedClaims && selectedClaims.length > 0) {
        selectedClaims.forEach(claimName => {
            let pathArray;
            // Adjust path based on claim type and known structures
            // For this refactoring, we'll use a simplified approach where claimName is expected to be
            // the direct key or a known key that maps to a path.
            if (selectionType === 'photo' && claimName === 'portrait') {
                pathArray = [`$.iso23220.portrait`]; 
            } else if (selectionType === 'photo') { 
                pathArray = [`$.iso23220.${claimName}`];
            } else if (selectionType === 'pid') {
                const pidClaimMapping = { // Example mapping
                    "firstName": "given_name",
                    "lastName": "family_name",
                    "email": "email",
                    "birthDate": "birthdate",
                    "addressStreet": "address.street_address",
                    "addressLocality": "address.locality",
                    "addressPostalCode": "address.postal_code",
                    "addressCountry": "address.country"
                    // Add other PID specific mappings as needed
                };
                pathArray = [`$.${pidClaimMapping[claimName] || claimName}`];
            } else if (selectionType === 'mail') { // Added 'mail' type explicitly
                 pathArray = [`$.mail`]; // Assuming 'mail' is the direct claim name
            } else if (selectionType === 'studentCard') { // Assuming direct claim names for studentCard
                pathArray = [`$.${claimName}`]; 
            } else { // Default for other types or unmapped claims
                pathArray = [`$.${claimName}`]; 
            }
            requestedFields.push({ path: pathArray, optional: false });
        });
    } else {
        requestedFields.push({ path: ["$.error_no_claims_selected"], optional: false });
        purpose = "Error: No claims were specified for the request.";
    }

    const presentationDefinition = {
        "id": presentationDefinitionId,
        "input_descriptors": [
            {
                "id": inputDescriptorId,
                "purpose": purpose,
                "constraints": {
                    "fields": requestedFields,
                    "limit_disclosure": "required"
                }
                // "schema": { "uri": "..." } // Schema might also vary by type
            }
        ],
        "format": { 
            "vc+sd-jwt": { // Preferred format
                "sd-jwt_alg_values": ["ES256"],
                "kb-jwt_alg_values": ["ES256"]
            },
            "jwt_vp_json": { "alg": ["ES256"] }, // Fallback/alternative
            "jwt_vc_json": { "alg": ["ES256"] }  // Fallback/alternative
        }
    };


    /* Remove filtering by VCT for now, as it is not needed in this context
    // Add VCT filter based on selectionType
    if (selectionType === 'pid') {
        presentationDefinition.input_descriptors[0].constraints.fields.unshift({
            path: ["$.vct"],
            filter: { type: "string", const: "eu.europa.ec.eudi.pid.1" }
        });
    } else if (selectionType === 'photo') {
        presentationDefinition.input_descriptors[0].constraints.fields.unshift({
            path: ["$.vct"],
            filter: { type: "string", const: "eu.europa.ec.eudi.photoid.1" }
        });
    } // Add other VCT filters for other types like 'studentCard', 'mail' if they have one
    */

 

    return presentationDefinition;
}

// Route to generate a JWT for /request-object
app.get('/request-object/:value', async (req, res) => {
    const originalNoncePart = req.params.value;
    // Using global privKey and privJwk as intended.

    if (currentClaimSelection && currentClaimSelection.credential_type_filter === "ConnectionCredential") {
        const presentation_definition_connection_id = {
            id: "vp-request-connection-id",
            input_descriptors: [{
                id: "connection-id-descriptor",
                name: "Connection ID Credential",
                purpose: "Please provide your Connection ID credential.",
                constraints: {
                    fields: [{
                        path: ["$.vc.credentialSubject.connection_id"],
                        purpose: "We need your connection_id to identify your session."
                    }],
                    limit_disclosure: "required",
                    schema: [{ "uri": "VerifiableCredential" }, { "uri": "ConnectionCredential" }]
                }
            }]
        };
        const payload_connection_id = {
            iss: config.dnsRp, // RP's identifier
            aud: "wallet", // Target wallet
            response_type: "vp_token",
            client_id: config.dnsRp, // RP's client_id
            nonce: `nonce-${originalNoncePart}-${uuidv4()}`,
            response_mode: "direct_post",
            response_uri: `${config.dnsRp}/callback`, // Wallet will POST here
            presentation_definition: presentation_definition_connection_id
        };
        try {
            const token = await new jose.SignJWT(payload_connection_id)
                .setProtectedHeader({ alg: 'ES256', kid: privJwk.kid }) // Use global privJwk for kid
                .setIssuedAt()
                .setExpirationTime('1h')
                .sign(privKey); // Use global privKey
            return res.type('application/jwt').send(token);
        } catch (error) {
            console.error('Error generating request object for ConnectionCredential:', error);
            return res.status(500).json({ error: 'Failed to generate request object for ConnectionCredential' });
        }
    }

    // Existing logic from index.js for other types
    const selectionType = currentClaimSelection.type;
    const selectedClaims = currentClaimSelection.claims;

    console.log(`Generating request object for type: ${selectionType}, claims: ${selectedClaims.join(', ')}, original nonce part: ${originalNoncePart}`);

    const dynamicPresentationDefinition = buildPresentationDefinition(selectionType, selectedClaims);

    const payload = {
        "response_uri": `${config.dnsRp}/callback`, // This is the general callback, not for ConnectionCredential submission
        "aud": "https://self-issued.me/v2", // Audience for general case
        "client_id_scheme": "redirect_uri",
        "iss": "me", // "me" or config.dnsRp? For self-issued, "me" might be okay. For RP-issued, config.dnsRp.
        "response_type": "vp_token",
        "presentation_definition": dynamicPresentationDefinition,
        "state": `state-${crypto.randomUUID()}`,
        "nonce": `nonce-${originalNoncePart}-${uuidv4()}`, // Enhanced nonce
        "client_id": `${config.dnsRp}`,
        "client_metadata": {
            "client_name": `Demo RP - Requesting ${selectionType.charAt(0).toUpperCase() + selectionType.slice(1)}`,
            "logo_uri": `${config.dnsRp}/logo.png`,
            "redirect_uris": [
              config.dnsRp
              ],
            "client_uri": config.dnsRp,
            "policy_uri": `${config.dnsRp}/policy.html`,
            "vp_formats": {
                "vc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                },
                "jwt_vp_json": { "alg": ["ES256"] },
                "jwt_vc_json": { "alg": ["ES256"] }
            }
        },
        "response_mode": "direct_post"
    };

    try {
        const jws_token_string = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256', kid: privJwk.kid })
            .setIssuedAt()
            .setExpirationTime('1h')
            .sign(privKey);
        
        res.type('application/jwt').send(jws_token_string);
    } catch (error) {
        console.error('Error generating dynamic request object:', error);
        res.status(500).json({ error: 'Failed to generate dynamic request object' });
    }
});

const jwks = JSON.parse(fs.readFileSync('./jwks.json')); // Loaded globally

app.get('/.well-known/jwks.json', (req, res) => {
  res.json(jwks);
});

// New endpoint for OpenID Credential Issuer configuration
app.get('/.well-known/openid-credential-issuer', (req, res) => {
  const issuerConfig = {
    "issuer": config.dnsRp,
    "credential_issuer": config.dnsRp, // New top-level field
    "credential_endpoint": `${config.dnsRp}/openid4vc/credential`,
    "jwks_uri": `${config.dnsRp}/.well-known/jwks.json`,
    "authorization_servers": [config.dnsRp], 
    "display": [{ 
        "name": "My Demo Issuer",
        "logo": {"uri": `${config.dnsRp}/logo.png`, "alt_text": "Issuer Logo"}
    }],
    "batch_credential_issuance": {"batch_size": 1}, 
    "nonce_endpoint": `${config.dnsRp}/openid4vc/nonce`, 
    "credential_configurations_supported": { 
      "ConnectionCredentialID": { // Renamed key back
        "format": "vc+sd-jwt", // Changed format
        "scope": "ConnectionCredentialID", // Updated scope
        "cryptographic_binding_methods_supported": ["JWK"], 
        "credential_signing_alg_values_supported": ["ES256"], 
        "proof_types_supported": { 
          "jwt":{"proof_signing_alg_values_supported":["ES256"]}
        },
        "display": [{ 
          "name": "Connection Credential", // Updated name
          "locale": "en-US",
          "logo": {"uri": `${config.dnsRp}/logo.png`, "alt_text": "Connection Credential Logo"},
          "background_color": "#12107C", 
          "text_color": "#FFFFFF"      
        }],
        "order": ["connection_id"], 
        "vct": `${config.dnsRp}/vc/ConnectionCredential`, // Updated vct
        "claims": { 
          "connection_id": {
            "display": [{"name": "Connection Identifier", "locale": "en-US"}]
          }
        }
        },
        "PIDCredential": { // New configuration for PID
            "format": "vc+sd-jwt",
            "scope": "PIDCredential", // Scope for PID
            "cryptographic_binding_methods_supported": ["JWK"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": { "proof_signing_alg_values_supported": ["ES256"] }
            },
            "display": [{
                "name": "Personal Identification Document (PID)",
                "locale": "en-US",
                "logo": { "uri": `${config.dnsRp}/logo-mojito.png`, "alt_text": "PID Credential Logo" }, // Assuming mojito logo or a generic one
                "background_color": "#006400", // Dark Green
                "text_color": "#FFFFFF"
            }],
            "order": [ // Define the order of claims if needed, or list them
                "portrait", "given_name_latin1", "family_name_latin1", "age_in_years", "issue_date",
                "resident_city_unicode", "nationality", "resident_address_unicode",
                "age_over_18", "name_at_birth", "expiry_date", "issuing_country", "birth_date"
            ],
            "vct": "iso23220_pid", 
            "claims": {
                "portrait": { "display": [{ "name": "Portrait", "locale": "en-US" }] },
                "given_name_latin1": { "display": [{ "name": "Given Name (Latin1)", "locale": "en-US" }] },
                "family_name_latin1": { "display": [{ "name": "Family Name (Latin1)", "locale": "en-US" }] },
                "age_in_years": { "display": [{ "name": "Age in Years", "locale": "en-US" }] },
                "issue_date": { "display": [{ "name": "Issue Date", "locale": "en-US" }] },
                "resident_city_unicode": { "display": [{ "name": "Resident City (Unicode)", "locale": "en-US" }] },
                "nationality": { "display": [{ "name": "Nationality", "locale": "en-US" }] },
                "resident_address_unicode": { "display": [{ "name": "Resident Address (Unicode)", "locale": "en-US" }] },
                "age_over_18": { "display": [{ "name": "Age Over 18", "locale": "en-US" }] },
                "name_at_birth": { "display": [{ "name": "Name at Birth", "locale": "en-US" }] },
                "expiry_date": { "display": [{ "name": "Expiry Date", "locale": "en-US" }] },
                "issuing_country": { "display": [{ "name": "Issuing Country", "locale": "en-US" }] },
                "birth_date": { "display": [{ "name": "Birth Date", "locale": "en-US" }] }
            }
      }
    }
  };
  res.json(issuerConfig);
});

// New GET endpoint for OAuth Authorization Server metadata
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const oauthServerConfig = {
    "issuer": config.dnsRp,
    "authorization_endpoint": `${config.dnsRp}/oauth2/authorize`,
    "device_authorization_endpoint": `${config.dnsRp}/oauth2/device_authorization`,
    "token_endpoint": `${config.dnsRp}/oauth2/token`,
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"],
    "jwks_uri": `${config.dnsRp}/.well-known/jwks.json`,
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
    "revocation_endpoint": `${config.dnsRp}/oauth2/revoke`,
    "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"],
    "introspection_endpoint": `${config.dnsRp}/oauth2/introspect`,
    "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"],
    "code_challenge_methods_supported": ["S256"],
    "tls_client_certificate_bound_access_tokens": true,
    "pushed_authorization_request_endpoint": `${config.dnsRp}/oauth2/par`
  };
  res.json(oauthServerConfig);
});

// New OAuth2 endpoints
app.get('/oauth2/authorize', (req, res) => {
  console.log("Endpoint /oauth2/authorize accessed");
  res.json({ message: "Endpoint accessed, check logs." });
});

app.get('/oauth2/device_authorization', (req, res) => {
  console.log("Endpoint /oauth2/device_authorization accessed");
  res.json({ message: "Endpoint accessed, check logs." });
});

app.post('/oauth2/token', async (req, res) => {
  console.log("Endpoint /oauth2/token (POST) accessed");
  console.log("Request body:", req.body);
  if (req.body.grant_type) {
    console.log("Grant type:", req.body.grant_type);
  }

  try {
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + 3600; // 1 hour

    const accessTokenPayload = {
        iss: config.dnsRp,
        sub: `user:${uuidv4()}`,
        aud: "urn:lissi:wallet:client", // Placeholder audience
        iat: iat,
        exp: exp,
        jti: uuidv4()
    };

    const signedAccessToken = await new jose.SignJWT(accessTokenPayload)
        .setProtectedHeader({ alg: 'ES256', kid: privJwk.kid })
        .sign(privKey);

    const cNonce = uuidv4();

    const responseObject = {
        access_token: signedAccessToken,
        token_type: "bearer",
        expires_in: 3600, // Match JWT's exp - iat
        c_nonce: cNonce,
        c_nonce_expires_in: 86400
    };

    res.status(200).json(responseObject);
  } catch (error) {
      console.error("Error in /oauth2/token route while generating token response:", error);
      res.status(500).json({ error: "Failed to generate token response", details: error.message });
  }
});

app.get('/oauth2/revoke', (req, res) => {
  console.log("Endpoint /oauth2/revoke accessed");
  res.json({ message: "Endpoint accessed, check logs." });
});

app.get('/oauth2/introspect', (req, res) => {
  console.log("Endpoint /oauth2/introspect accessed");
  res.json({ message: "Endpoint accessed, check logs." });
});

app.get('/oauth2/par', (req, res) => {
  console.log("Endpoint /oauth2/par accessed");
  res.json({ message: "Endpoint accessed, check logs." });
});
// End of new OAuth2 endpoints

var current_photo_html = ""
// Initialize currentVcDetails with a defined structure
var currentVcDetails = {
    vcType: null,
    claims: null,
    issuer: null,
    iat: null,
    exp: null,
    type: null, // Existing credential type
    verificationStatus: "Not Verified",
    verificationError: null,
    certificateSubject: null,
    certificateIssuer: null,
    certificateValidity: null
};

function resetCurrentVcDetails() {
    currentVcDetails = {
        vcType: null,
        claims: null,
        issuer: null,
        iat: null,
        exp: null,
        type: null,
        verificationStatus: "Not Verified",
        verificationError: null,
        certificateSubject: null,
        certificateIssuer: null,
        certificateValidity: null
    };
}

app.post('/callback', async (req, res) => {
  console.log("body")
  console.log(req.body)

  // Reset currentVcDetails at the beginning of the callback
  resetCurrentVcDetails();

  if(!req.body || !req.body.vp_token) { 
    console.log("No vp_token found in body")
    currentVcDetails.verificationStatus = "Error";
    currentVcDetails.verificationError = "No vp_token found in body";
    return res.status(400).send('No vp_token found in body');
  }
  const vpToken = req.body.vp_token;

  if (!vpToken) {
    currentVcDetails.verificationStatus = "Error";
    currentVcDetails.verificationError = "No vp_token found in body (empty)";
    return res.status(400).send('No vp_token found in body');
  }

  // Décodage non vérifié du JWS
  console.log('vp_token:', vpToken);
   
  var payload;
  try {
    payload = JSON.parse(Buffer.from(vpToken.split('.')[1], "base64").toString("utf8"));
    console.log(payload);
  } catch (e) {
    console.error("Failed to parse JWT payload:", e);
    currentVcDetails.vcType = "Unknown/Invalid JWT";
    currentVcDetails.verificationStatus = "Error";
    currentVcDetails.verificationError = "Failed to parse JWT payload";
    return res.status(400).send('Invalid vp_token format');
  }

  console.log('searching for verifiable credentials');
  var verifiablecredentials = vpToken;
  if(payload.vp && payload.vp.verifiableCredential && payload.vp.verifiableCredential[0]) {
      console.log('Verifiable credentials found in the payload');
      verifiablecredentials = payload.vp.verifiableCredential[0];
  } else {
    console.log("Using vpToken as Verifiable creds as no VP structure found in the payload");
    // Potentially treat vpToken itself as a JWT-VC if it's not an SD-JWT container
  }

  (async () => {
    // 0. Reset currentVcDetails (worker should know how, e.g., using resetCurrentVcDetails())
    //    currentVcDetails.vcType = null; // Will be set later
    // resetCurrentVcDetails(); // This is called at the beginning of the main app.post('/callback')
    currentVcDetails.vcType = null; // Initialize specific field

    let formattedVcData = { claims: [] };
    let technicalDebugData = { 
        certificate: null, 
        jwtValidationSteps: [], 
        serverAnalysis: [] 
    };
    const now = () => new Date().toISOString();

    technicalDebugData.serverAnalysis.push({ message: "Callback processing started.", timestamp: now() });

    const vpToken = req.body.vp_token; 

    technicalDebugData.serverAnalysis.push({ message: `Received vp_token (length: ${vpToken ? vpToken.length : 0}).`, timestamp: now() });

    if (!vpToken || typeof vpToken !== 'string') {
        currentVcDetails.verificationStatus = "Error: vpToken missing or invalid";
        currentVcDetails.verificationError = "vpToken was not provided or was not a string.";
        technicalDebugData.serverAnalysis.push({ message: currentVcDetails.verificationError, error: true, timestamp: now() });
        const errorBroadcastMessage = { 
            type: 'PROCESSING_ERROR', 
            payload: { 
                error: currentVcDetails.verificationError, 
                details: technicalDebugData, 
                status: currentVcDetails.verificationStatus 
            } 
        };
        console.log(`[${new Date().toISOString()}] About to broadcast ${errorBroadcastMessage.type} to ${clients.size} WebSocket client(s). Payload keys: ${Object.keys(errorBroadcastMessage.payload || {}).join(', ')}`);
        broadcast(errorBroadcastMessage);
        console.log(`[${new Date().toISOString()}] Successfully broadcasted ${errorBroadcastMessage.type}.`);
        return; 
    }

    try {
        technicalDebugData.serverAnalysis.push({ message: "Attempting to parse vpToken as JWS.", timestamp: now() });
        const outerParts = vpToken.split('.');
        if (outerParts.length < 3) { 
            currentVcDetails.vcType = "SD-JWT (Direct or Not a JWS structure)";
            currentVcDetails.verificationStatus = "Outer JWS processing skipped (not a JWS structure)";
            technicalDebugData.serverAnalysis.push({ message: "vpToken does not appear to be a JWS (less than 3 parts). Assuming direct SD-JWT.", warning: true, timestamp: now() });
            technicalDebugData.jwtValidationSteps.push({ step: 'Outer JWS Structure Check', status: 'Skipped', reason: 'Not a JWS structure (less than 3 parts)' });
        } else {
            const outerHeaderB64 = outerParts[0];
            const outerHeader = JSON.parse(Buffer.from(outerHeaderB64, 'base64url').toString());
            technicalDebugData.serverAnalysis.push({ message: "Parsed outer JWS header.", details: outerHeader, timestamp: now() });
            
            if (outerHeader.x5c && outerHeader.x5c[0]) {
                currentVcDetails.vcType = "SD-JWT (Wrapped in JWS with x5c)";
                technicalDebugData.serverAnalysis.push({ message: "x5c found in outer JWS header.", timestamp: now() });
                technicalDebugData.jwtValidationSteps.push({ step: 'Outer JWS x5c Certificate Extraction', status: 'Pending', timestamp: now() });
                const outer_x5c_cert_b64 = outerHeader.x5c[0];
                const outerCert = new crypto.X509Certificate(Buffer.from(outer_x5c_cert_b64, 'base64'));
                
                currentVcDetails.certificateSubject = outerCert.subject;
                currentVcDetails.certificateIssuer = outerCert.issuer;
                currentVcDetails.certificateValidity = { notBefore: outerCert.validFrom, notAfter: outerCert.validTo };
                technicalDebugData.certificate = { 
                    subject: outerCert.subject.toString(), // Convert to string for simpler JSON
                    issuer: outerCert.issuer.toString(), 
                    validity: { notBefore: outerCert.validFrom, notAfter: outerCert.validTo }
                };
                technicalDebugData.jwtValidationSteps.find(s => s.step === 'Outer JWS x5c Certificate Extraction').status = 'Success';
                technicalDebugData.jwtValidationSteps.find(s => s.step === 'Outer JWS x5c Certificate Extraction').details = `Subject: ${outerCert.subject}`;


                const outerVerifyStepName = 'Outer JWS Signature Verification (x5c)';
                technicalDebugData.jwtValidationSteps.push({ step: outerVerifyStepName, status: 'Pending', method: 'x5c', alg: outerHeader.alg, timestamp: now() });
                try {
                    const parts = vpToken.split('~'); 
                    const actualOuterJwsString = parts[0];
                    technicalDebugData.serverAnalysis.push({ message: `Outer JWS string for verification (actualOuterJwsString): ${actualOuterJwsString.substring(0,60)}...`, timestamp: now() });
                    
                    await jose.jwtVerify(actualOuterJwsString, outerCert.publicKey, { algorithms: [outerHeader.alg] });
                    
                    currentVcDetails.verificationStatus = "Verified (Outer JWS x5c)";
                    technicalDebugData.jwtValidationSteps.find(s => s.step === outerVerifyStepName).status = 'Success';
                    technicalDebugData.serverAnalysis.push({ message: "Outer JWS (actualOuterJwsString) verified successfully against x5c.", timestamp: now() });

                } catch (e) {
                    currentVcDetails.verificationStatus = "Verification Failed (Outer JWS x5c)";
                    currentVcDetails.verificationError = e.message || e.code || "Unknown verification error for Outer JWS";
                    technicalDebugData.jwtValidationSteps.find(s => s.step === outerVerifyStepName).status = 'Failed';
                    technicalDebugData.jwtValidationSteps.find(s => s.step === outerVerifyStepName).error = currentVcDetails.verificationError;
                    technicalDebugData.serverAnalysis.push({ message: `Outer JWS verification failed: ${currentVcDetails.verificationError}`, error: true, timestamp: now() });
                    const errorBroadcastMessage_OuterJWS = { 
                        type: 'PROCESSING_ERROR', 
                        payload: { error: currentVcDetails.verificationError, details: technicalDebugData, status: currentVcDetails.verificationStatus } 
                    };
                    console.log(`[${new Date().toISOString()}] About to broadcast ${errorBroadcastMessage_OuterJWS.type} to ${clients.size} WebSocket client(s). Payload keys: ${Object.keys(errorBroadcastMessage_OuterJWS.payload || {}).join(', ')}`);
                    broadcast(errorBroadcastMessage_OuterJWS);
                    console.log(`[${new Date().toISOString()}] Successfully broadcasted ${errorBroadcastMessage_OuterJWS.type}.`);
                    return; 
                }
            } else {
                currentVcDetails.vcType = "SD-JWT (Wrapped in JWS without x5c)";
                currentVcDetails.verificationStatus = "Verification Key Not Found (No x5c in Outer JWS)";
                technicalDebugData.serverAnalysis.push({ message: "Outer JWS has no x5c header. Cannot verify outer signature via x5c.", warning: true, timestamp: now() });
                technicalDebugData.jwtValidationSteps.push({ step: 'Outer JWS x5c Certificate Extraction', status: 'Skipped', reason: 'No x5c header' });
                technicalDebugData.jwtValidationSteps.push({ step: 'Outer JWS Signature Verification (x5c)', status: 'Skipped', reason: 'No x5c header' });
            }
        }

        // SD-JWT Decoding
        const decodeStepName = 'SD-JWT Decoding (@sd-jwt/decode)';
        technicalDebugData.jwtValidationSteps.push({ step: decodeStepName, status: 'Pending', input_length: vpToken.length, timestamp: now() });
        let decodedSdJwt;
        try {
            decodedSdJwt = await decodeSdJwt(vpToken, digest); 
            technicalDebugData.jwtValidationSteps.find(s => s.step === decodeStepName).status = 'Success';
            technicalDebugData.jwtValidationSteps.find(s => s.step === decodeStepName).details = {
                issuer: decodedSdJwt.jwt.payload.iss,
                disclosuresFound: decodedSdJwt.disclosures && decodedSdJwt.disclosures.length > 0,
                kbJwtPresent: !!decodedSdJwt.keyBindingJwt // Check if Key Binding JWT is present
            };
            technicalDebugData.serverAnalysis.push({ message: "SD-JWT decoded successfully.", details: { issuer: decodedSdJwt.jwt.payload.iss, disclosures: decodedSdJwt.disclosures ? decodedSdJwt.disclosures.length : 0 }, timestamp: now() });
            technicalDebugData.serverAnalysis.push({ message: `Inner SD-JWT JWS Header: ${JSON.stringify(decodedSdJwt.jwt.header)}`, timestamp: now() });
            technicalDebugData.serverAnalysis.push({ message: `Inner SD-JWT JWS Payload: ${JSON.stringify(decodedSdJwt.jwt.payload)}`, timestamp: now() });

        } catch (error) {
            currentVcDetails.verificationStatus = "JWS Processing Error";
            currentVcDetails.verificationError = error.message || "SD-JWT decoding failed.";
            technicalDebugData.jwtValidationSteps.find(s => s.step === decodeStepName).status = 'Failed';
            technicalDebugData.jwtValidationSteps.find(s => s.step === decodeStepName).error = currentVcDetails.verificationError;
            technicalDebugData.serverAnalysis.push({ message: `Error decoding SD-JWT: ${currentVcDetails.verificationError}`, level: "Error", details: { stack: error.stack }, timestamp: now() });
            
            const errorBroadcastMessage_SdJwtDecode = { 
                type: 'PROCESSING_ERROR', 
                payload: { error: currentVcDetails.verificationError, details: technicalDebugData, status: currentVcDetails.verificationStatus } 
            };
            // Note: The console.log before broadcast was using messageToBroadcast which is not defined here. Corrected to use the local const.
            console.log(`[${new Date().toISOString()}] About to broadcast ${errorBroadcastMessage_SdJwtDecode.type} to ${clients.size} WebSocket client(s). Payload keys: ${Object.keys(errorBroadcastMessage_SdJwtDecode.payload || {}).join(', ')}`);
            broadcast(errorBroadcastMessage_SdJwtDecode);
            console.log(`[${new Date().toISOString()}] Successfully broadcasted ${errorBroadcastMessage_SdJwtDecode.type}.`);

            // Do not return yet, try to populate currentVcDetails with what we have
            if(!currentVcDetails.vcType) currentVcDetails.vcType = "Unknown/Error";
             // Populate currentVcDetails with any partial data before final broadcast
             if (decodedSdJwt && decodedSdJwt.jwt && decodedSdJwt.jwt.payload) {
                const sdJwtPayload = decodedSdJwt.jwt.payload;
                currentVcDetails.issuer = sdJwtPayload.iss;
                currentVcDetails.iat = sdJwtPayload.iat;
                currentVcDetails.exp = sdJwtPayload.exp;
                currentVcDetails.type = sdJwtPayload.vc && sdJwtPayload.vc.type ? sdJwtPayload.vc.type : 'N/A';
                // If decoding failed but we have the payload, use it for claims if no disclosures
                if (!decodedSdJwt.disclosures || decodedSdJwt.disclosures.length === 0) {
                    currentVcDetails.claims = sdJwtPayload; 
                }
            }
            // Final broadcast with error state if it still falls through here after SD-JWT decode error (should be caught by return above)
            const finalErrorBroadcastMessage = { 
                type: 'PROCESSING_ERROR', 
                payload: { error: currentVcDetails.verificationError, details: technicalDebugData, status: currentVcDetails.verificationStatus } 
            };
             console.log(`[${new Date().toISOString()}] About to broadcast ${finalErrorBroadcastMessage.type} (SD-JWT post-population) to ${clients.size} WebSocket client(s). Payload keys: ${Object.keys(finalErrorBroadcastMessage.payload || {}).join(', ')}`);
             broadcast(finalErrorBroadcastMessage);
             console.log(`[${new Date().toISOString()}] Successfully broadcasted ${finalErrorBroadcastMessage.type} (SD-JWT post-population).`);
            return; // Now return after broadcasting error
        }


        // Populate currentVcDetails (as it was, for /vc-details endpoint)
        if (decodedSdJwt && decodedSdJwt.jwt && decodedSdJwt.jwt.payload) {
            const sdJwtPayload = decodedSdJwt.jwt.payload; // Renamed for clarity
            currentVcDetails.issuer = sdJwtPayload.iss;
            currentVcDetails.iat = sdJwtPayload.iat;
            currentVcDetails.exp = sdJwtPayload.exp;
            currentVcDetails.type = sdJwtPayload.vc && sdJwtPayload.vc.type ? sdJwtPayload.vc.type : 'N/A';

            const claimsStepName = 'Claim Extraction (getClaims)';
            technicalDebugData.jwtValidationSteps.push({ step: claimsStepName, status: 'Pending', timestamp: now() });
            if (decodedSdJwt.disclosures && decodedSdJwt.disclosures.length > 0) { 
                technicalDebugData.serverAnalysis.push({ message: "Extracting claims from SD-JWT payload and disclosures...", timestamp: now() });
                try {
                    const claims = await getClaims(
                        decodedSdJwt.jwt.payload, 
                        decodedSdJwt.disclosures,
                        digest,
                    );
                    currentVcDetails.claims = claims; // Store raw claims
                    technicalDebugData.jwtValidationSteps.find(s => s.step === claimsStepName).status = 'Success';
                    technicalDebugData.jwtValidationSteps.find(s => s.step === claimsStepName).details = { claimCount: Object.keys(claims).length };
                    technicalDebugData.serverAnalysis.push({ message: `Extracted Claims: ${JSON.stringify(claims).substring(0,100)}...`, timestamp: now() });
                    
                    // Populate formattedVcData.claims
                    const processedNestedKeys = new Set(); // Keep track of keys handled by nested logic

                    // Handle specific nested image claims first
                    if (claims.iso23220 && typeof claims.iso23220 === 'object' && claims.iso23220.portrait && typeof claims.iso23220.portrait === 'string' && claims.iso23220.portrait.startsWith('data:image')) {
                        formattedVcData.claims.push({
                            type: 'image',
                            label: 'Portrait (ISO23220)', 
                            value: claims.iso23220.portrait
                        });
                        // If iso23220 object should not be processed further by the main loop (e.g., if it ONLY contains the portrait or other fields are not desired)
                        // processedNestedKeys.add('iso23220'); 
                        // For now, we'll let other fields in iso23220 be processed by the loop if they exist,
                        // but the portrait itself is handled.
                    }

                    if (claims.photoid && typeof claims.photoid === 'object' && claims.photoid.portrait && typeof claims.photoid.portrait === 'string' && claims.photoid.portrait.startsWith('data:image')) {
                        formattedVcData.claims.push({
                            type: 'image',
                            label: 'Portrait (Photo ID)', 
                            value: claims.photoid.portrait
                        });
                        // processedNestedKeys.add('photoid');
                    }

                    for (const [key, value] of Object.entries(claims)) {
                        // Skip keys that were part of already processed nested structures if we decided to fully consume them
                        if (processedNestedKeys.has(key)) {
                            continue;
                        }

                        let label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()); // Basic formatting
                        
                        // Handle top-level direct image claims (e.g., a 'portrait' key directly in claims, or any data URI)
                        // This condition needs to be careful not to re-process what was handled above if those objects are iterated.
                        // The pre-loop handling is specific to known nested structures.
                        // This part handles flat claims like "portrait": "data:image..."
                        if ( (key === 'portrait' || (typeof value === 'string' && value.startsWith('data:image'))) && 
                             !(key === 'iso23220' && typeof value === 'object' && value.portrait) && // Avoid reprocessing the whole iso23220 object as an image
                             !(key === 'photoid' && typeof value === 'object' && value.portrait) ) { // Avoid reprocessing the whole photoid object as an image
                             
                            // Check if this exact image value was already added from a nested structure
                            const isAlreadyAdded = formattedVcData.claims.some(c => c.type === 'image' && c.value === value);
                            if (!isAlreadyAdded) {
                                formattedVcData.claims.push({ type: 'image', label: label, value: value });
                            }
                        } else if (key === 'given_name') {
                            formattedVcData.claims.push({ type: 'text', label: 'Given Name', value: value });
                        } else if (key === 'family_name') {
                            formattedVcData.claims.push({ type: 'text', label: 'Family Name', value: value });
                        } else if (key === 'email' || key === 'mail') {
                            formattedVcData.claims.push({ type: 'text', label: 'Email', value: value });
                        } else if (key === 'birth_date' || key === 'birthdate') {
                            formattedVcData.claims.push({ type: 'text', label: 'Birth Date', value: value });
                        } else if (key !== 'iso23220' && key !== 'photoid') { // Avoid processing parent objects if their portraits were handled
                             // Default for other claims - can be refined
                            // Ensure we don't add an image claim again if it wasn't caught by the specific image logic above
                            const isPotentiallyImage = typeof value === 'string' && value.startsWith('data:image');
                            const isAlreadyAddedAsImage = isPotentiallyImage && formattedVcData.claims.some(c => c.type === 'image' && c.value === value);

                            if (!isAlreadyAddedAsImage) {
                                formattedVcData.claims.push({ type: 'text', label: label, value: typeof value === 'object' ? JSON.stringify(value) : value });
                            }
                        } else if (typeof value === 'object' && value !== null) { 
                            // For 'iso23220' or 'photoid' objects, if they weren't fully skipped by processedNestedKeys,
                            // iterate their non-portrait fields as text.
                            for (const [subKey, subValue] of Object.entries(value)) {
                                if (subKey === 'portrait' && (typeof subValue === 'string' && subValue.startsWith('data:image'))) {
                                    continue; // Already handled
                                }
                                let subLabel = `${label} - ${subKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`;
                                formattedVcData.claims.push({ type: 'text', label: subLabel, value: typeof subValue === 'object' ? JSON.stringify(subValue) : subValue });
                            }
                        }
                    }
                    if (!currentVcDetails.verificationStatus.includes("Failed")) { // If not already failed by outer JWS
                       currentVcDetails.verificationStatus = "Verified (SD-JWT Processed)";
                    }

                } catch (claimError) {
                    currentVcDetails.verificationStatus = "Error Processing Claims";
                    currentVcDetails.verificationError = claimError.message || "Failed to get claims from SD-JWT.";
                    technicalDebugData.jwtValidationSteps.find(s => s.step === claimsStepName).status = 'Failed';
                    technicalDebugData.jwtValidationSteps.find(s => s.step === claimsStepName).error = currentVcDetails.verificationError;
                    technicalDebugData.serverAnalysis.push({ message: `Error extracting claims: ${currentVcDetails.verificationError}`, error: true, timestamp: now() });
                }
            } else {
                technicalDebugData.serverAnalysis.push({ message: "No disclosures found in SD-JWT, cannot extract detailed claims using getClaims. Using JWS payload as claims.", warning: true, timestamp: now() });
                currentVcDetails.claims = decodedSdJwt.jwt.payload; // Fallback to JWS payload if no disclosures
                technicalDebugData.jwtValidationSteps.find(s => s.step === claimsStepName).status = 'Skipped';
                technicalDebugData.jwtValidationSteps.find(s => s.step === claimsStepName).reason = 'No disclosures present';
                 // Populate formattedVcData.claims from JWS payload
                for (const [key, value] of Object.entries(currentVcDetails.claims)) {
                     let label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                     formattedVcData.claims.push({ type: 'text', label: label, value: typeof value === 'object' ? JSON.stringify(value) : value });
                }
                 if (!currentVcDetails.verificationStatus.includes("Failed")) {
                    currentVcDetails.verificationStatus = "Verified (SD-JWT Processed, No Disclosures)";
                 }
            }

        } else {
            currentVcDetails.verificationError = (currentVcDetails.verificationError ? currentVcDetails.verificationError + "; " : "") + "Failed to decode essential SD-JWT payload parts (iss, iat, etc.).";
            technicalDebugData.serverAnalysis.push({ message: `Could not decode essential parts of the SD-JWT payload. ${currentVcDetails.verificationError}`, error: true, timestamp: now() });
            if (currentVcDetails.verificationStatus === "Not Verified" || !currentVcDetails.verificationStatus.includes("Failed")) { 
                currentVcDetails.verificationStatus = "Error: SD-JWT payload decoding issue";
            }
        }
        
        // Populate currentVcDetails (as it was, for /vc-details endpoint)
        // This section ensures currentVcDetails.claims is populated before signature check.
        if (decodedSdJwt && decodedSdJwt.jwt && decodedSdJwt.jwt.payload) {
            // ... (existing logic for populating currentVcDetails.issuer, iat, exp, type) ...
            // ... (existing logic for claim extraction into currentVcDetails.claims and formattedVcData) ...
        }

        // New Signature Verification Logic for ConnectionCredential
        let isConnectionCredential = false;
        let vcForVerification = null;
        let presentedVcType = currentVcDetails.claims?.vct || (currentVcDetails.claims?.vc?.type ? currentVcDetails.claims.vc.type.join('/') : 'Unknown');
        
        // Ensure presentedVcType is a string, default to 'Unknown' if not determinable
        if(typeof presentedVcType !== 'string' && !Array.isArray(presentedVcType)) {
             presentedVcType = 'Unknown';
        } else if (Array.isArray(presentedVcType)) {
             presentedVcType = presentedVcType.join('/');
        }


        if (presentedVcType === 'ConnectionCredential' || presentedVcType.includes('ConnectionCredential')) {
            isConnectionCredential = true;
            if (decodedSdJwt && decodedSdJwt.jwt && typeof decodedSdJwt.jwt.compact === 'function') {
                 vcForVerification = decodedSdJwt.jwt.compact();
            } else if (decodedSdJwt && decodedSdJwt.jwt && typeof decodedSdJwt.jwt.compact === 'string') { 
                vcForVerification = decodedSdJwt.jwt.compact;
            } else if (outerParts.length >=3 && !vpToken.includes('~')) { 
                vcForVerification = vpToken; // vpToken is the JWS string itself
            }
             technicalDebugData.serverAnalysis.push({ message: `Identified ConnectionCredential. JWS for verification: ${vcForVerification ? vcForVerification.substring(0,30) + '...' : 'null'}`, timestamp: now() });
        }

        let isSignatureValid = null; 
        let verificationErrorMessage = null;

        if (isConnectionCredential && vcForVerification) {
            const sigVerifyStepName = 'ConnectionCredential Signature Verification';
            technicalDebugData.jwtValidationSteps.push({ step: sigVerifyStepName, status: 'Pending', method: 'Server JWKS', timestamp: now() });
            try {
                if (!jwks || !jwks.keys || jwks.keys.length === 0) {
                    throw new Error("Server JWKS not configured for verification.");
                }
                // Assuming the first key in jwks is the relevant one for ConnectionCredential.
                // This might need refinement if multiple keys are used for different VC types.
                const publicKeyToVerify = await jose.importJWK(jwks.keys[0], decodedSdJwt?.jwt.header.alg || 'ES256'); 
                
                await jose.jwtVerify(vcForVerification, publicKeyToVerify, {
                    issuer: connectionCredentialConfig.credential_issuer 
                    // Optionally add audience check if your ConnectionCredential has a specific audience
                    // audience: config.dnsRp 
                });
                isSignatureValid = true;
                technicalDebugData.jwtValidationSteps.find(s => s.step === sigVerifyStepName).status = 'Success';
                technicalDebugData.serverAnalysis.push({ message: 'ConnectionCredential signature verified successfully.', timestamp: now() });
                console.log('ConnectionCredential signature verified successfully.');
            } catch (err) {
                console.error('ConnectionCredential signature verification failed:', err);
                isSignatureValid = false;
                verificationErrorMessage = err.message;
                technicalDebugData.jwtValidationSteps.find(s => s.step === sigVerifyStepName).status = 'Failed';
                technicalDebugData.jwtValidationSteps.find(s => s.step === sigVerifyStepName).error = err.message;
                technicalDebugData.serverAnalysis.push({ message: `ConnectionCredential signature verification failed: ${err.message}`, error: true, timestamp: now() });
            }
        } else if (isConnectionCredential && !vcForVerification) {
             technicalDebugData.serverAnalysis.push({ message: 'ConnectionCredential identified, but no JWS string found for verification.', warning: true, timestamp: now() });
             isSignatureValid = false; // Cannot verify
             verificationErrorMessage = "Could not extract JWS from the presented ConnectionCredential for verification.";
        }


        // Final broadcast message preparation
        let finalMessage;
        if (currentVcDetails.verificationStatus.includes("Error") || currentVcDetails.verificationStatus.includes("Failed")) {
            finalMessage = { 
                type: 'PROCESSING_ERROR', 
                payload: { 
                    error: currentVcDetails.verificationError || "A processing error occurred", 
                    details: {
                        ...technicalDebugData, // Spread existing technicalDebugData
                        is_signature_valid: isSignatureValid,
                        verification_error_message: verificationErrorMessage,
                        vc_type_processed: presentedVcType
                    }, 
                    status: currentVcDetails.verificationStatus 
                } 
            };
        } else {
            finalMessage = { 
                type: 'VC_DATA_UPDATE', 
                payload: { 
                    formattedVcData, 
                    technicalDebugData, // technicalDebugData is already augmented by signature check steps
                    status: currentVcDetails.verificationStatus,
                    is_signature_valid: isSignatureValid,
                    verification_error_message: verificationErrorMessage,
                    vc_type_processed: presentedVcType
                } 
            };
        }
        console.log(`[${new Date().toISOString()}] About to broadcast ${finalMessage.type} to ${clients.size} WebSocket client(s). Payload keys: ${Object.keys(finalMessage.payload || {}).join(', ')}`);
        broadcast(finalMessage);
        console.log(`[${new Date().toISOString()}] Successfully broadcasted ${finalMessage.type}.`);

    } catch (error) { // Catch for the main try-block (outermost)
        // Ensure these fields are added even in the outermost catch
        const presentedVcTypeOnError = currentVcDetails.claims?.vct || (currentVcDetails.claims?.vc?.type ? currentVcDetails.claims.vc.type.join('/') : 'Unknown (error)');
        const isSignatureValidOnError = null; // Or based on any partial check done
        const verificationErrorMessageOnError = error.message; // Or a specific message

        currentVcDetails.verificationStatus = "JWS Processing Error (Outer Catch)";
        currentVcDetails.verificationError = (currentVcDetails.verificationError ? currentVcDetails.verificationError + "; " : "") + (error.message || "General processing error in callback.");
        technicalDebugData.serverAnalysis.push({ message: `Outer catch error in /callback: ${error.message}`, level: "Error", details: { stack: error.stack }, timestamp: now() });
        if(!currentVcDetails.vcType) currentVcDetails.vcType = "Unknown/Error";
        
        const outerCatchErrorMsg = { 
            type: 'PROCESSING_ERROR', 
            payload: { 
                error: currentVcDetails.verificationError, 
                details: {
                     ...technicalDebugData, // Spread existing technicalDebugData
                     is_signature_valid: isSignatureValidOnError,
                     verification_error_message: verificationErrorMessageOnError,
                     vc_type_processed: presentedVcTypeOnError
                }, 
                status: currentVcDetails.verificationStatus 
            } 
        };
        console.log(`[${new Date().toISOString()}] About to broadcast ${outerCatchErrorMsg.type} (Outer Catch) to ${clients.size} WebSocket client(s). Payload keys: ${Object.keys(outerCatchErrorMsg.payload || {}).join(', ')}`);
        broadcast(outerCatchErrorMsg);
        console.log(`[${new Date().toISOString()}] Successfully broadcasted ${outerCatchErrorMsg.type} (Outer Catch).`);
    }
    // Log final state of currentVcDetails for the /vc-details endpoint
    console.log('Final currentVcDetails before response to wallet:', JSON.stringify(currentVcDetails, null, 2));
  })();

    res.send('ok'); // Respond to the wallet that POST was received
});


app.get('/photo', (req, res) => { 
    // This endpoint is now less relevant for detailed claims, as they are in formattedVcData via WebSocket.
    // It might still be used by the old frontend logic or for direct image access if needed.
    // For now, it returns the old current_photo_html.
    // Consider deprecating or changing if current_photo_html is fully removed.
    if (current_photo_html) {
        res.send(`${current_photo_html}`);
    } else {
        // Find the portrait from the most recent currentVcDetails.claims if available
        let photoData = null;
        if (currentVcDetails && currentVcDetails.claims) {
            photoData = currentVcDetails.claims['iso23220.portrait'] || currentVcDetails.claims['portrait'];
        }
        if (photoData) {
             res.send(`<img src="${photoData}" alt="Portrait from VC Details"/>`);
        } else {
             res.status(404).send("No photo data available.");
        }
    }
});
app.get('/reset-photo', (req, res) => { 
  current_photo_html = ""; // Clear the old variable
  resetCurrentVcDetails(); // Reset main details store
  // Also broadcast a reset/clear message to WebSocket clients
  broadcast({ type: 'VC_DATA_RESET', payload: { message: "VC Data has been reset." } });
  res.send("VC Data and photo reset.");
});


var current_status = '';
app.get('/status', (req, res) => {   
    res.send(current_status);
});


app.get('/vc-details', (req, res) => {
    if (currentVcDetails) {
        res.json(currentVcDetails);
    } else {
        res.status(404).json({ error: 'VC details not found' });
    }
});

app.get('/vc', async (req, res) => {   
    
  const jwk = JSON.parse(fs.readFileSync('./issuer-private-key.json', 'utf8'));
  console.log('🔑 Private Key JWK:\n', jwk);
  const privateKey = await importJWK(jwk, 'ES256');
  
  // Données du credential
  const payload = {
    iss: "http://smngmz.com",
    sub: 'did:example:123',
    nbf: Math.floor(Date.now() / 1000),
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
      credentialSubject: {
        givenName: 'Alice',
        familyName: 'Doe',
        degree: 'Bachelor of Science and Arts'
      }
    }
  };
  
  // Signer le JWT
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', kid: jwk.kid, typ: 'JWT' })
    .sign(privateKey);
  
  console.log('🔐 Verifiable Credential JWT:\n');
  console.log(jwt);
  
  res.send(jwt);
});

// OPENID4VC Endpoints (from server.js)
app.get('/openid4vc/credential-offer', (req, res) => {
  const offer = {
    credential_issuer: connectionCredentialConfig.credential_issuer, // Uses updated config
    // Replaced 'credentials' array with 'credential_configuration_ids'
    credential_configuration_ids: ["ConnectionCredentialID"], // Reverted value
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "static_pre_authorized_code_123" // Static code for now, tx_code removed
        // "tx_code" field removed
      }
    }
  };
  res.json(offer);
});

// New GET endpoint for PID Credential Offer
app.get('/openid4vc/pid-credential-offer', (req, res) => {
  const offer = {
    credential_issuer: config.dnsRp, // Use existing config variable for issuer URL
    credential_configuration_ids: ["PIDCredential"], // Reference the new PID configuration
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "static_pid_pre_authorized_code_456" // A distinct static code for PID
      }
    }
  };
  res.json(offer);
});

// New GET endpoint for generating a nonce
app.get('/openid4vc/nonce', (req, res) => {
  res.json({ "c_nonce": "nonce_123" });
});

// issuePidVC function (as provided in the prompt)
async function issuePidVC() {
    const subject_uuid = uuidv4(); // Use uuidv4 if not already imported/available
    const jti_uuid = uuidv4();
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + (365 * 24 * 60 * 60); // 1 year expiry

    // Static PID data
    const pidClaims = {
        "portrait": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", // Placeholder 1x1 transparent PNG
        "given_name_latin1": "Sophie",
        "family_name_latin1": "Martin", // Added as PID usually has family name
        "age_in_years": 30,
        "issue_date": "2024-01-15",
        "resident_city_unicode": "Paris",
        "nationality": "FRA",
        "resident_address_unicode": "123 Rue de Exemple, 75001 Paris",
        "age_over_18": true,
        "name_at_birth": "Sophie Dupont",
        "expiry_date": "2034-01-14",
        "issuing_country": "FRA",
        "birth_date": "1994-03-10" // Added as PID usually has birth date
    };

    const vcPayload = {
        iss: config.dnsRp, // Use existing config variable
        sub: `did:example:user:${subject_uuid}`,
        nbf: iat,
        iat: iat,
        exp: exp,
        jti: `urn:uuid:${jti_uuid}`,
        _sd_alg: "sha-256",
        vc: {
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"], // Add relevant contexts
            type: ["VerifiableCredential", "PIDCredential", "Iso18013DriversLicense"], // Include PID specific type and Iso18013DriversLicense as per vct for now
            vct: "iso23220_pid", // Match the configuration
            credentialSubject: {
                id: `did:example:user:${subject_uuid}`,
                ...pidClaims // Spread the static claims here
            }
        }
    };
    console.log("PID VC Payload for SD-JWT:", JSON.stringify(vcPayload, null, 2));

    try {
        const signedVc = await new jose.SignJWT(vcPayload)
            .setProtectedHeader({ alg: 'ES256', kid: privJwk.kid }) // Use global privJwk and privKey
            .sign(privKey);
        
        const sdJwtString = signedVc + "~"; // Append tilde for SD-JWT format
        return sdJwtString;
    } catch (error) {
        console.error("Error signing PID VC:", error);
        throw new Error('Failed to issue PID VC');
    }
}

app.post('/openid4vc/credential', async (req, res) => {
    // Log Authorization Header
    if (req.headers.authorization) {
        console.log("Authorization header present in /openid4vc/credential request.");
        const authHeaderParts = req.headers.authorization.split(' ');
        if (authHeaderParts.length === 2) {
            console.log(`Authorization type: ${authHeaderParts[0]}, Token starts with: ${authHeaderParts[1].substring(0, 10)}...`);
        } else {
            console.log("Authorization header format looks non-standard.");
        }
    } else {
        console.log("No Authorization header in /openid4vc/credential request.");
    }

    // Log c_nonce from Request Body
    if (req.body.c_nonce) {
        console.log("c_nonce received in /openid4vc/credential request body:", req.body.c_nonce);
    } else {
        console.log("No c_nonce in /openid4vc/credential request body.");
    }
    
    // Log entire request body for debugging purposes
    console.log("Full request body in /openid4vc/credential:", JSON.stringify(req.body, null, 2));


    // Determine credential type to issue
    let credentialToIssue;
    let formatToIssue = "vc+sd-jwt"; // Default format

    // Check based on credential_configuration_id from the request body
    const requestedConfigId = req.body.credential_configuration_id; 
    console.log("Requested credential_configuration_id:", requestedConfigId);

    if (requestedConfigId === "PIDCredential") {
        console.log("Issuing PID Credential based on configuration ID.");
        try {
            credentialToIssue = await issuePidVC();
        } catch (error) {
            console.error("Error calling issuePidVC:", error);
            return res.status(500).json({ error: 'Failed to generate PID credential' });
        }
    } else { 
        console.log("Issuing ConnectionCredential (default or ConnectionCredentialID requested).");
        try {
            const connection_id_for_vc = uuidv4(); 
            const subject_identifier_for_vc = `did:example:user:${uuidv4()}`;
            const jti_for_vc = `urn:uuid:${uuidv4()}`;
            const iat_for_vc = Math.floor(Date.now() / 1000);
            const exp_for_vc = iat_for_vc + (365 * 24 * 60 * 60); // 1 year

            const connVcPayload = {
                iss: connectionCredentialConfig.credential_issuer,
                sub: subject_identifier_for_vc,
                nbf: iat_for_vc,
                iat: iat_for_vc,
                exp: exp_for_vc,
                jti: jti_for_vc,
                _sd_alg: "sha-256",
                vc: {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    type: connectionCredentialConfig.types, 
                    vct: connectionCredentialConfig.credential_type, 
                    credentialSubject: { id: subject_identifier_for_vc, connection_id: connection_id_for_vc }
                }
            };
            console.log("Connection VC Payload for SD-JWT:", JSON.stringify(connVcPayload, null, 2));
            const signedConnVc = await new jose.SignJWT(connVcPayload)
                .setProtectedHeader({ alg: 'ES256', kid: privJwk.kid })
                .sign(privKey);
            credentialToIssue = signedConnVc + "~";
        } catch (error) {
            console.error("Error generating Connection ID VC in modified endpoint:", error);
            return res.status(500).json({ error: 'Failed to generate Connection ID credential' });
        }
    }

    if (credentialToIssue) {
        res.type(formatToIssue === 'vc+sd-jwt' ? 'application/vc+sd-jwt' : 'application/json'); 
        res.json({
            format: formatToIssue,
            credential: credentialToIssue,
        });
    } else {
        console.error("Credential to issue was not generated.");
        return res.status(500).json({ error: 'Internal server error: Could not determine credential to issue.' });
    }
});

app.post('/presentation-submission', async (req, res) => {
    try {
        const { vp_token /*, presentation_submission */ } = req.body;
        if (!vp_token) {
            broadcast({ type: 'PROCESSING_ERROR', payload: { error: 'Missing vp_token', details: 'vp_token is required in the submission.' } });
            return res.status(400).send('Missing vp_token');
        }
        const vcJws = vp_token; // Simplification for ConnectionCredential flow

        // Use global jwks from index.js
        if (!jwks.keys || jwks.keys.length === 0) {
             broadcast({ type: 'PROCESSING_ERROR', payload: { error: 'Server key error', details: "No keys found in global jwks.json" } });
             return res.status(500).json({ status: "error", message: "Server key configuration error." });
        }
        // Assuming the first key is the server's public key for verifying self-issued VCs.
        // For VCs issued by others, you'd need a more sophisticated key retrieval mechanism (e.g., DID resolution).
        const publicKeyToVerify = await jose.importJWK(jwks.keys[0], 'ES256'); 

        let decodedVcPayload;
        try {
            const { payload /*, protectedHeader */ } = await jose.jwtVerify(vcJws, publicKeyToVerify, {
                issuer: connectionCredentialConfig.credential_issuer, // Verify issuer matches our server
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
            broadcast({
               type: 'VC_DATA_UPDATE',
               payload: {
                   status: "Connection ID Verified",
                   formattedVcData: { 
                       claims: [
                           { label: 'Connection ID', value: connectionId, type: 'text' },
                           { label: 'Issuer', value: decodedVcPayload.iss, type: 'text'},
                           { label: 'Subject', value: decodedVcPayload.sub, type: 'text'},
                           { label: 'Issued At', value: new Date(decodedVcPayload.iat * 1000).toLocaleString(), type: 'text'},
                           { label: 'Expires At', value: new Date(decodedVcPayload.exp * 1000).toLocaleString(), type: 'text'}
                       ]
                   },
                   technicalDebugData: { 
                       jwtValidationSteps: [{step: "JWS Verification (ConnectionCredential)", status: "Success", details: "Signature and claims (iss, exp, nbf, iat) verified."}],
                       serverAnalysis: [{timestamp: new Date().toISOString(), message: `Received and verified ConnectionCredential for ${connectionId}`}]
                   }
               }
            });
        } catch (verificationError) {
            console.error("VC Verification failed:", verificationError);
            broadcast({ 
                type: 'PROCESSING_ERROR', 
                payload: { 
                    error: 'VC Verification Failed', 
                    details: verificationError.message,
                    receivedTokenSummary: vcJws.substring(0, 60) + "..." 
                } 
            });
            return res.status(400).json({ status: "error", message: "VC verification failed: " + verificationError.message });
        }
        res.status(200).json({ status: "success", message: "Presentation received and is being processed." });
    } catch (error) {
        console.error('Error processing presentation:', error);
        broadcast({ type: 'PROCESSING_ERROR', payload: { error: 'Server error processing presentation', details: error.message } });
        res.status(500).send('Server error processing presentation');
    }
});

// Replaced /update-claim-selection with the version from server.js that handles credential_type_filter
app.post('/update-claim-selection', (req, res) => {
    const { type, claims, credential_type_filter } = req.body;
    if (!type || !claims) { // Keep basic validation
        return res.status(400).json({ message: 'Missing type or claims in selection' });
    }
    currentClaimSelection = { type, claims, credential_type_filter };
    console.log('Updated claim selection:', currentClaimSelection);
    res.json({ message: 'Claim selection updated successfully on server.' });
});

// Serve static files from the "public" directory
app.use(express.static('public'));

// Start the server and capture the HTTP server instance
const server = app.listen(config.port, () => {
    console.log(`Server is running on ${config.dnsRp}`);
});

// Initialize WebSocket Server
const wss = new WebSocketServer({ server });
const clients = new Set();

console.log('WebSocket server initialized.');

wss.on('connection', (ws) => {
    clients.add(ws);
    console.log('New WebSocket client connected. Total clients:', clients.size);

    ws.isAlive = true; // Initialize for ping/pong
    ws.on('pong', () => {
        ws.isAlive = true;
        console.log(`[${new Date().toISOString()}] Pong received from a client.`);
    });

    // Debug: Inspect currentVcDetails on new connection
    console.log('New WebSocket client connected. Inspecting currentVcDetails:');
    console.log('currentVcDetails exists:', !!currentVcDetails);
    if (currentVcDetails) {
        console.log('currentVcDetails.vcType:', currentVcDetails.vcType);
        console.log('currentVcDetails.claims exist:', !!currentVcDetails.claims);
        console.log('currentVcDetails.verificationStatus:', currentVcDetails.verificationStatus);
        console.log('currentVcDetails.issuer:', currentVcDetails.issuer); // Log a few more potentially relevant fields
        console.log('currentVcDetails.exp:', currentVcDetails.exp);
    } else {
        console.log('currentVcDetails is null or undefined.');
    }

    // Send last known VC state to the newly connected client
    // Adjusted condition to be more robust: check vcType OR a meaningful verificationStatus
    if (currentVcDetails && (currentVcDetails.vcType || (currentVcDetails.verificationStatus && currentVcDetails.verificationStatus !== "Not Verified"))) {
        let messageToSend;
        const status = currentVcDetails.verificationStatus || "N/A";

        // Simplified reconstruction of formattedVcData
        let formattedVcDataToSend = { claims: [] };
        if (currentVcDetails.claims) {
            Object.entries(currentVcDetails.claims).forEach(([key, value]) => {
                let claimLabel = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                
                // Basic handling for known nested structures that produce images
                if (key === 'iso23220' && typeof value === 'object' && value && value.portrait && typeof value.portrait === 'string' && value.portrait.startsWith('data:image')) {
                    formattedVcDataToSend.claims.push({ type: 'image', label: 'Portrait (ISO23220)', value: value.portrait });
                } else if (key === 'photoid' && typeof value === 'object' && value && value.portrait && typeof value.portrait === 'string' && value.portrait.startsWith('data:image')) {
                    formattedVcDataToSend.claims.push({ type: 'image', label: 'Portrait (Photo ID)', value: value.portrait });
                } 
                // Handle direct 'portrait' claim if not part of the objects above
                else if (key === 'portrait' && typeof value === 'string' && value.startsWith('data:image')) {
                     if (!formattedVcDataToSend.claims.some(c => c.type === 'image' && c.value === value)) { // Avoid duplicates if already added
                        formattedVcDataToSend.claims.push({ type: 'image', label: 'Portrait', value: value });
                     }
                }
                // Avoid adding the parent objects 'iso23220' or 'photoid' themselves if their main image content was extracted
                else if (typeof value === 'object' && (key === 'iso23220' || key === 'photoid')) {
                    // Optionally iterate other fields if needed, for now, we skip the parent object
                }
                // General text claims
                else {
                     formattedVcDataToSend.claims.push({
                        type: (typeof value === 'string' && value.startsWith('data:image')) ? 'image' : 'text',
                        label: claimLabel,
                        value: typeof value === 'object' ? JSON.stringify(value) : String(value) // Ensure value is stringified if object
                    });
                }
            });
        }

        // Simplified reconstruction of technicalDebugData
        let technicalDebugDataToSend = {
            certificate: (currentVcDetails.certificateSubject || currentVcDetails.certificateIssuer) ? { 
                subject: String(currentVcDetails.certificateSubject || 'N/A'), 
                issuer: String(currentVcDetails.certificateIssuer || 'N/A'), 
                validity: currentVcDetails.certificateValidity ? { 
                    notBefore: String(currentVcDetails.certificateValidity.notBefore || 'N/A'), 
                    notAfter: String(currentVcDetails.certificateValidity.notAfter || 'N/A') 
                } : { notBefore: 'N/A', notAfter: 'N/A' }
            } : null,
            jwtValidationSteps: (currentVcDetails.jwtValidationSteps || [{ step: "Last state retrieval", status: "Info", details: "Partial validation data from memory." }]),
            serverAnalysis: (currentVcDetails.serverAnalysis || [{ message: "Retrieved last known VC state on connection.", timestamp: new Date().toISOString() }])
        };
        
        if (status.toLowerCase().includes("error") || status.toLowerCase().includes("failed")) {
            messageToSend = {
                type: 'PROCESSING_ERROR',
                payload: {
                    error: currentVcDetails.verificationError || "Previously recorded error",
                    details: technicalDebugDataToSend,
                    status: status
                }
            };
        } else {
            messageToSend = {
                type: 'VC_DATA_UPDATE',
                payload: {
                    formattedVcData: formattedVcDataToSend,
                    technicalDebugData: technicalDebugDataToSend,
                    status: status
                }
            };
        }

        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(messageToSend));
            console.log('Sent last known VC state to newly connected client.');
        } else {
            console.log('Client disconnected before last VC state could be sent.');
        }
    } else {
        console.log('No significant last VC state to send to new client.');
        // Optionally send a RESET message if that's desired for a clean slate
        // if (ws.readyState === WebSocket.OPEN) {
        //    ws.send(JSON.stringify({ type: 'VC_DATA_RESET', payload: { message: "Waiting for new data..." } }));
        // }
    }

    ws.on('message', (message) => {
        // Log message as Buffer, then try to parse as string
        console.log('Received WebSocket message (Buffer):', message);
        try {
            const messageString = message.toString(); // Convert Buffer to string
            console.log('Received WebSocket message (String):', messageString);
            // Example: Echo message back to client
            // ws.send(`Echo: ${messageString}`); 
        } catch (e) {
            console.error('Failed to convert WebSocket message to string:', e);
        }
    });

    ws.on('close', () => {
        clients.delete(ws);
        console.log('WebSocket client disconnected. Total clients:', clients.size);
    });

    ws.on('error', (error) => {
        console.error('WebSocket client error. Message:', error.message, 'Stack:', error.stack);
        // Optionally, remove the client from the set if an error occurs that leads to disconnection
        // clients.delete(ws); // This might be redundant if 'close' is always called after 'error' for disconnections
    });
});

// Broadcasting Function
function broadcast(data) {
  const messageString = JSON.stringify(data); // Stringify once before the loop
  // console.log(`Broadcasting message to ${clients.size} clients: ${messageString}`); // Original log, can be too verbose with full payload
  
  clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) { // WebSocket.OPEN is correct here
        try {
            client.send(messageString);
        } catch (e) {
            console.error('Error sending message to a WebSocket client. Error:', e.message, 'Stack:', e.stack);
            // Optional: If send fails, the client might be unusable.
            // clients.delete(client); 
        }
    } else {
        console.warn('Client not open, skipping broadcast for this client. ReadyState:', client.readyState);
    }
  });
}

// Example: Periodically broadcast a message (for testing purposes)
// setInterval(() => {
//   broadcast({ type: 'time', timestamp: new Date().toLocaleTimeString() });
// }, 10000);

// Ping/Pong Mechanism
const interval = setInterval(function pingAllClients() {
  wss.clients.forEach(function eachClient(clientWs) { 
    if (clientWs.isAlive === false) {
      console.log(`[${new Date().toISOString()}] Terminating unresponsive WebSocket client (no pong received). Client readyState: ${clientWs.readyState}`);
      return clientWs.terminate();
    }
    clientWs.isAlive = false; 
    clientWs.ping(() => {}); 
    // Optional: console.log(`[${new Date().toISOString()}] Ping sent to a client. Client readyState: ${clientWs.readyState}`);
  });
}, 30000); // Every 30 seconds

wss.on('close', function handleWssClose() {
  console.log(`[${new Date().toISOString()}] WebSocket server shutting down, clearing ping interval.`);
  clearInterval(interval);
});