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
    // resetCurrentVcDetails(); // Already called at the beginning of app.post('/callback')
    currentVcDetails.vcType = null; 

    const vp_token = req.body.vp_token; // This is the full token string from the user
    let rawSdJwtForDecode; // Declare here // Use a new distinct variable name

    console.log('Received vp_token:', vp_token); // Log the full token

    if (!vp_token || typeof vp_token !== 'string') {
        console.error('vp_token is missing or not a string');
        currentVcDetails.verificationStatus = "Error: vp_token missing or invalid";
        currentVcDetails.verificationError = "vp_token was not provided or was not a string.";
        // return or res.send() appropriately if this function directly sends response
        return; // Assuming for now this async block is self-contained before response
    }

    try {
        const outerParts = vp_token.split('.');
        if (outerParts.length < 3) { // A JWS must have 3 parts
            console.warn('vp_token does not look like a JWS. Assuming it is a direct SD-JWT.');
            rawSdJwtForDecode = vp_token.trim(); // Assign to the new variable
            console.log('IMMEDIATE LOG direct assignment - rawSdJwtForDecode (first 50 chars):', rawSdJwtForDecode.substring(0, 50)); 
            currentVcDetails.vcType = "SD-JWT (Direct)"; // Or potentially "Unknown JWT"
            currentVcDetails.verificationStatus = "Outer JWS processing skipped (not a JWS structure)";
        } else {
            const outerHeaderB64 = outerParts[0];
            const outerHeader = JSON.parse(Buffer.from(outerHeaderB64, 'base64url').toString());
            console.log('Outer JWS Header:', JSON.stringify(outerHeader, null, 2));
            
            // Extract raw SD-JWT from outer JWS payload BEFORE x5c check or other JWS processing
            const outerPayloadB64 = outerParts[1];
            rawSdJwtForDecode = Buffer.from(outerPayloadB64, 'base64url').toString().trim(); // Assign to the new variable
            console.log('IMMEDIATE LOG after outer payload extraction - rawSdJwtForDecode (first 50 chars):', rawSdJwtForDecode.substring(0, 50)); 

            if (outerHeader.x5c && outerHeader.x5c[0]) {
                currentVcDetails.vcType = "SD-JWT (Wrapped in JWS with x5c)";
                const outer_x5c_cert_b64 = outerHeader.x5c[0];
                const outerCert = new crypto.X509Certificate(Buffer.from(outer_x5c_cert_b64, 'base64'));

                currentVcDetails.certificateSubject = outerCert.subject;
                currentVcDetails.certificateIssuer = outerCert.issuer;
                currentVcDetails.certificateValidity = { notBefore: outerCert.validFrom, notAfter: outerCert.validTo };

                try {
                    // IMPORTANT: jwtVerify typically returns the payload as a parsed object if it's JSON.
                    // For an SD-JWT string payload, we need to ensure we get the raw string.
                    // This might mean using a different jose function or option if jwtVerify auto-parses.
                    // For this step, let's TRY jwtVerify and get payload. If it's an object,
                    // we'll need to see its structure. The SD-JWT is the *payload* of this outer JWS.
                    // The payload of the outer JWS is the *second part* of the vp_token.
                    // rawSdJwtInputForDecode is already set from outerParts[1] and trimmed.

                    // Now verify the outer JWS signature
                    // If vp_token includes disclosures (e.g., "JWS~disclosure1~disclosure2"),
                    // only the JWS part should be used for verification.
                    const parts = vp_token.split('~');
                    const actualOuterJwsString = parts[0];
                    console.log('Actual Outer JWS string for verification:', actualOuterJwsString);
                    
                    // The jose.jwtVerify by default returns a parsed JSON payload if the payload is JSON.
                    // The SD-JWT string is NOT JSON. We need the raw payload string.
                    // The previous extraction: rawSdJwtForDecode = Buffer.from(outerParts[1], 'base64url').toString(); IS LIKELY STILL THE MOST RELIABLE WAY TO GET THE SD-JWT STRING.
                    // The verification only confirms the signature for header & payload.
                    // So, keep the existing rawSdJwtForDecode extraction, just use actualOuterJwsString for verification call.
                    await jose.jwtVerify(actualOuterJwsString, outerCert.publicKey, { algorithms: [outerHeader.alg] });
                    
                    currentVcDetails.verificationStatus = "Verified (Outer JWS x5c)";
                    // console.log('Outer JWS verified successfully. Extracted SD-JWT string for further processing.'); // Original log
                    console.log('Outer JWS (actualOuterJwsString) verified successfully against x5c.');
                    // rawSdJwtForDecode is already correctly set from outerParts[1]

                } catch (e) {
                    console.error('Outer JWS verification failed:', e);
                    currentVcDetails.verificationStatus = "Verification Failed (Outer JWS x5c)";
                    currentVcDetails.verificationError = e.message || e.code || "Unknown verification error";
                    return; // Stop processing
                }
            } else {
                currentVcDetails.vcType = "SD-JWT (Wrapped in JWS without x5c)";
                console.warn('Outer JWS has no x5c header. Cannot verify outer signature via x5c.');
                currentVcDetails.verificationStatus = "Verification Key Not Found (No x5c in Outer JWS)";
                // If no x5c, we might assume the payload is the SD-JWT and proceed without outer verification,
                // or treat it as an error depending on policy. For now, extract and proceed.
                // rawSdJwtInputForDecode is already correctly set from outerParts[1]
            }
        }

        // 1. Now, rawSdJwtForDecode contains the string to be processed by decodeSdJwt
        if (!rawSdJwtForDecode || typeof rawSdJwtForDecode !== 'string') {
            console.error('Error: SD-JWT string for decoding is missing or not a string.');
            currentVcDetails.verificationStatus = "Error: SD-JWT string input invalid for decoding";
            currentVcDetails.verificationError = "Internal error: SD-JWT string was not correctly prepared.";
            return;
        }

        // console.log('Processing SD-JWT string:', rawSdJwtForDecode); // Redundant with below
        // This is where the previous sd-jwt decoding logic begins:

        console.log('--- Debugging SD-JWT Input ---');
        console.log('Raw string being passed to decodeSdJwt:', rawSdJwtForDecode); 

        if (rawSdJwtForDecode && typeof rawSdJwtForDecode === 'string') {
            const jwsPartOfSdJwt = rawSdJwtForDecode.split('~')[0];
            console.log('JWS part of rawSdJwtForDecode (Header.Payload.Signature):', jwsPartOfSdJwt);
            const sdJwtJwsParts = jwsPartOfSdJwt.split('.');
            
            if (sdJwtJwsParts.length === 3) {
                try {
                    const innerHeader = Buffer.from(sdJwtJwsParts[0], 'base64url').toString();
                    console.log('SD-JWT Inner JWS Header (decoded):', innerHeader);
                    // Attempt to parse to see if it's valid JSON, but log the string anyway
                    try {
                        console.log('SD-JWT Inner JWS Header (parsed JSON):', JSON.parse(innerHeader));
                    } catch (jsonParseError) {
                        console.warn('SD-JWT Inner JWS Header is not valid JSON:', jsonParseError.message);
                    }

                    const innerPayload = Buffer.from(sdJwtJwsParts[1], 'base64url').toString();
                    console.log('SD-JWT Inner JWS Payload (decoded):', innerPayload);
                    // Attempt to parse to see if it's valid JSON
                    try {
                        console.log('SD-JWT Inner JWS Payload (parsed JSON):', JSON.parse(innerPayload));
                    } catch (jsonParseError) {
                        console.warn('SD-JWT Inner JWS Payload is not valid JSON:', jsonParseError.message);
                    }
                    
                    console.log('SD-JWT Inner JWS Signature (first 10 chars):', sdJwtJwsParts[2] ? sdJwtJwsParts[2].substring(0, 10) + '...' : 'Not present');
                } catch (e) {
                    console.error('Error base64url decoding/processing parts of SD-JWT JWS:', e.message);
                }
            } else {
                console.warn('JWS part of rawSdJwtForDecode does not have 3 components separated by dots:', jwsPartOfSdJwt);
            }
        } else {
            console.warn('rawSdJwtForDecode is null, undefined, or not a string before attempting to parse its JWS components.');
        }
        console.log('--- End Debugging SD-JWT Input ---');
        
        const decodedSdJwt = await decodeSdJwt(rawSdJwtForDecode, digest); // Use the distinct variable

        // Populate issuer, iat, exp, type from decodedSdJwt.jwt.payload
        // (as in previous versions, ensure paths are correct e.g. decodedSdJwt.jwt.payload.iss)
        if (decodedSdJwt && decodedSdJwt.jwt && decodedSdJwt.jwt.payload) {
            const payload = decodedSdJwt.jwt.payload;
            currentVcDetails.issuer = payload.iss;
            currentVcDetails.iat = payload.iat;
            currentVcDetails.exp = payload.exp;
            currentVcDetails.type = payload.vc && payload.vc.type ? payload.vc.type : 'N/A';

             // Populate photo from claims if available (moved here as it depends on claims)
            if (decodedSdJwt.disclosures) { // Ensure disclosures are present before getting claims
                const claims = await getClaims(
                    decodedSdJwt.jwt.payload, // from the JWS part of the SD-JWT
                    decodedSdJwt.disclosures,
                    digest,
                );
                currentVcDetails.claims = claims;
                console.log('SD-JWT Claims:', JSON.stringify(claims, null, 2));
                
                var photoBase64 = "";
                if(claims && claims.iso23220 && claims.iso23220.portrait) {
                    console.log("Photo found in the claims")
                    photoBase64 = claims.iso23220.portrait; 
                }
                current_photo_html = `  <img src="${photoBase64}" /> <text id='jsonData'> ${JSON.stringify(claims)}</text>`
            } else {
                console.warn('No disclosures found in SD-JWT, cannot extract detailed claims.');
                currentVcDetails.claims = decodedSdJwt.jwt.payload; // Fallback to payload if no disclosures
            }

        } else {
             console.error('Could not decode essential parts of the SD-JWT payload.');
             currentVcDetails.verificationError = (currentVcDetails.verificationError ? currentVcDetails.verificationError + "; " : "") + "Failed to decode essential SD-JWT payload parts (iss, iat, etc.).";
             // Do not overwrite verificationStatus if it was set by outer JWS checks
             if (currentVcDetails.verificationStatus === "Not Verified") { // only if not set by outer checks
                currentVcDetails.verificationStatus = "Error: SD-JWT payload decoding issue";
             }
        }

        // IMPORTANT: The logic that previously tried to find x5c *inside* decodedSdJwt.jwt.compact
        // should be REMOVED. The x5c from the outer JWS (if present) is the relevant one for *that* signature.
        // The SD-JWT's own JWS part (decodedSdJwt.jwt.compact) is typically NOT signed with an x5c itself.
        // Its trust comes from the issuer (iss claim) and potentially its binding to the holder via cnf claim.
        // If the outer JWS was verified, that adds a layer of authenticity to the contained SD-JWT.

    } catch (error) {
        console.error('Error processing vp_token in /callback:', error);
        // Set general error if not already more specific
        if (currentVcDetails.verificationStatus === "Not Verified" || !currentVcDetails.verificationStatus) {
             currentVcDetails.verificationStatus = "JWS Processing Error"; // General fallback
        }
        currentVcDetails.verificationError = (currentVcDetails.verificationError ? currentVcDetails.verificationError + "; " : "") + (error.message || "General processing error.");
        // Add stack trace to server logs for more detailed debugging, but not to client-facing error message.
        console.error('Error Stack for server logs:', error.stack); 
        if (error.details) { // If the error object has a details property, log it.
            console.error('Error Details for server logs:', error.details);
        }
        if(!currentVcDetails.vcType) currentVcDetails.vcType = "Unknown/Error";
    }
    console.log('Final currentVcDetails before response:', JSON.stringify(currentVcDetails, null, 2));
  })();



    // Affichage d'une image HTML avec base64
    res.send('ok');
});


app.get('/photo', (req, res) => {   
    res.send(`${current_photo_html}`);
});
app.get('/reset-photo', (req, res) => { 
  current_photo_html = "";    
  resetCurrentVcDetails(); // Use the reset function
  res.send(`${current_photo_html}`);
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
// Start the server
app.listen(config.port, () => {
    console.log(`Server is running on ${config.dnsRp}`);
});