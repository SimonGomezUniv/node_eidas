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

// Correctly derive WebSocketServer and WebSocket
const WebSocketServer = ws.Server; 
const WebSocket = ws; // This provides access to WebSocket.OPEN, etc.

dotenv.config();

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
const PORT = 3000;

const privJwk = JSON.parse(fs.readFileSync('./priv_jwk.json'));
const privKey = await jose.importJWK(JSON.parse(fs.readFileSync('./priv_jwk.json')), 'ES256');


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


// Route to generate a JWT for /request-object
app.get('/request-object/:value', (req, res) => {

  var nounce = req.params.value;

    // 1. Charger ta clé privée depuis un fichier ou directement
const privJwk = JSON.parse(fs.readFileSync('./priv_jwk.json'));
// 2. Importer la clé pour la signature (ES256)
importJWK(privJwk, 'ES256')
.then((privateKey) => {

    // 3. Créer ton payload
        var  payload = {
            iss: "my_client_id",
            aud: "wallet",
            response_type: "vp_token",
            client_id: "my_client_id",
            scope: "openid",
            //nonce: "123456",
            nonce: Math.floor(100000 + Math.random() * 900000).toString(), // Generate a random 6-digit number
            response_mode: "direct_post",
            presentation_definition: {
                id: "vp-request-1",
                input_descriptors: [
                    {
                        id: "name-descriptor",
                        schema: {
                            uri: "https://schema.org/Person"
                        },
                        constraints: {
                            fields: [
                                {
                                    path: ["$.name", "$.given_name"],
                                    purpose: "We need your name to complete KYC"
                                }
                            ]
                        }
                    }
                ]
            }
        };

payload = {
    "response_uri": `${dns_rp}/callback`,
    "aud": "https://self-issued.me/v2",
    "client_id_scheme": "did",
    "iss": "me",
    "response_type": "vp_token",
    "presentation_definition": {
      "id": "a63f2daa-608d-486f-b3a3-921d72d65321",
      "input_descriptors": [
        {
          "id": "fa7a3fe2-5668-49ac-b862-ed2334379839",
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.vct"
                ],
                "optional": false,
                "filter": {
                  "type": "string",
                  "const": "eu.europa.ec.eudi.photoid.1"
                }
              },
              {
                "path": [
                  "$.photoid.travel_document_number"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.iso23220.family_name_latin1"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.iso23220.given_name_latin1"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.iso23220.birth_date"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.iso23220.sex"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.iso23220.portrait"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.iso23220.issuing_country"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.iso23220.expiry_date"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.iso23220.nationality"
                ],
                "optional": false
              }
            ],
            "limit_disclosure": "required"
          },
          "purpose": "Choose a valid Photo ID document."
        },
        {
          "id": "fa7a3fe2-5668-49ac-b862-ed23343798392",
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.vct"
                ],
                "optional": false,
                "filter": {
                  "type": "string",
                  "const": "eu.europa.ec.eudi.pcd.1"
                }
              },
              {
                "path": [
                  "$.phone"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.email_address"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.city_address"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.country_address"
                ],
                "optional": false
              },
              {
                "path": [
                  "$.street_address"
                ],
                "optional": false
              }
            ],
            "limit_disclosure": "required"
          },
          "purpose": "Choose a self-issued credential with personal details verification."
        }
      ],
      "format": {
        "vc+sd-jwt": {
          "sd-jwt_alg_values": [
            "ES256"
          ],
          "kb-jwt_alg_values": [
            "ES256"
          ]
        }
      }
    },
    "state": "9e040a2e-1fcd-4fd8-b823-a8bc83cc71d4",
    "nonce": "1Xdf9C3Zb4ywsIEFuNyS",
    "client_id": "did:web:did-doc-dts-preview.s3.eu-central-1.amazonaws.com:606a7acb-521f-44e1-8874-2caffbc31254",
    "client_metadata": {
      "client_name": "Hotel Benidorm",
      "logo_uri": "https://ewc.pre.vc-dts.sicpa.com/logo2.png",
      "subject_syntax_types_supported": [
        "did:indy",
        "did:v1",
        "did:ion",
        "did:ebsi",
        "did:key",
        "did:web",
        "did:ethr",
        "did:pkh",
        "did:jwk",
        "did:cheqd",
        "did:webs",
        "did:dns",
        "did:kscirc",
        "did:ling",
        "did:webvh",
        "did:iden3"
      ],
      "vp_formats": {
        "jwt_vc_json": {
          "alg": [
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "EdDSA",
            "Ed25519",
            "Ed448"
          ]
        },
        "jwt_vp_json": {
          "alg": [
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "EdDSA",
            "Ed25519",
            "Ed448"
          ]
        },
        "ldp_vc": {
          "proof_type": [
            "Ed25519Signature2018",
            "EcdsaSecp256k1Signature2019"
          ]
        },
        "ldp_vp": {
          "proof_type": [
            "Ed25519Signature2018",
            "EcdsaSecp256k1Signature2019"
          ]
        },
        "vc+sd-jwt": {
          "sd-jwt_alg_values": [
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "EdDSA",
            "Ed25519",
            "Ed448"
          ],
          "kb-jwt_alg_values": [
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "EdDSA",
            "Ed25519",
            "Ed448"
          ]
        }
      }
    },
    "response_mode": "direct_post"
  }

// payload photo sans sécurisation SD-JWT
payload = {
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
  }


  if(nounce.startsWith("name")) {
    console.log("Using Name Payload")
    // payload photo sans sécurisation SD-JWT
        payload = {
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
                  "purpose": "Demander le mail uniquement",
                  "constraints": {
                    "fields": [
                            {
                              "path": [
                                "$.vct"
                              ]
                              /*,
                              "filter": {
                                "type": "string",
                                "const": "https://pidissuer.demo.connector.lissi.io/pid"
                              }
                                */
                            },
                            {
                              "path": [
                                "$.given_name"
                              ]
                            },
                            {
                              "path": [
                                "$.family_name"
                              ]
                            },
                            {
                              "path": [
                                "$.birthdate"
                              ]
                            },
                            {
                              "path": [
                                "$.address.street_address"
                              ]
                            },
                            {
                              "path": [
                                "$.address.locality"
                              ]
                            },
                            {
                              "path": [
                                "$.address.postal_code"
                              ]
                            },
                            {
                              "path": [
                                "$.address.country"
                              ]
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
            "nonce": `${nounce}`,
            "client_id": `${config.dnsRp}`,
            "client_metadata": {
              "client_name": "Demo RP - Just Mail",
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
          }
        }


        if(nounce.startsWith("mail")) {
          console.log("Using Mail Payload")
          // payload photo sans sécurisation SD-JWT
              payload = {
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
                        "purpose": "Demander le mail uniquement",
                        "constraints": {
                          "fields": [
      
                            {
                              "path": [
                                "$.mail"
                              ],
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
                  "nonce": `${nounce}`,
                  "client_id": `${config.dnsRp}`,
                  "client_metadata": {
                    "client_name": "Demo RP - Just Mail",
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
                }
              }
      
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
});


const jwks = JSON.parse(fs.readFileSync('./jwks.json'));

app.get('/.well-known/jwks.json', (req, res) => {
  res.json(jwks);
});




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
        
        // Final broadcast message preparation
        let finalMessage;
        if (currentVcDetails.verificationStatus.includes("Error") || currentVcDetails.verificationStatus.includes("Failed")) {
            finalMessage = { 
                type: 'PROCESSING_ERROR', 
                payload: { 
                    error: currentVcDetails.verificationError || "A processing error occurred", 
                    details: technicalDebugData, 
                    status: currentVcDetails.verificationStatus 
                } 
            };
        } else {
            finalMessage = { 
                type: 'VC_DATA_UPDATE', 
                payload: { 
                    formattedVcData, 
                    technicalDebugData, 
                    status: currentVcDetails.verificationStatus 
                } 
            };
        }
        console.log(`[${new Date().toISOString()}] About to broadcast ${finalMessage.type} to ${clients.size} WebSocket client(s). Payload keys: ${Object.keys(finalMessage.payload || {}).join(', ')}`);
        broadcast(finalMessage);
        console.log(`[${new Date().toISOString()}] Successfully broadcasted ${finalMessage.type}.`);

    } catch (error) { // Catch for the main try-block (outermost)
        currentVcDetails.verificationStatus = "JWS Processing Error (Outer Catch)";
        currentVcDetails.verificationError = (currentVcDetails.verificationError ? currentVcDetails.verificationError + "; " : "") + (error.message || "General processing error in callback.");
        technicalDebugData.serverAnalysis.push({ message: `Outer catch error in /callback: ${error.message}`, level: "Error", details: { stack: error.stack }, timestamp: now() });
        if(!currentVcDetails.vcType) currentVcDetails.vcType = "Unknown/Error";
        
        const outerCatchErrorMsg = { 
            type: 'PROCESSING_ERROR', 
            payload: { 
                error: currentVcDetails.verificationError, 
                details: technicalDebugData, 
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