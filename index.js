// Si tu utilises des modules ES
import express from 'express';
import QRCode from 'qrcode';
import fs from 'fs';
import * as jose from 'jose'
import { SignJWT, importJWK } from 'jose';
import { decodeSdJwt, getClaims } from '@sd-jwt/decode';
import { digest } from '@sd-jwt/crypto-nodejs';
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
                      ,
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


app.post('/callback', async (req, res) => {
  console.log("body")
    const vpToken = req.body.vp_token;

    if (!vpToken) {
        return res.status(400).send('No vp_token found in body');
    }

    // Décodage non vérifié du JWS
    console.log('vp_token:', vpToken);
   
var payload = vpToken.split('.')[1];
payload = JSON.parse(atob(payload));
console.log(payload);

console.log('searching for verifiable credentials');
var verifiablecredentials = vpToken
/**/
if(payload.vp && payload.vp.verifiableCredential) {
    console.log('Verifiable credentials found in the payload');
    verifiablecredentials = payload.vp.verifiableCredential[0];
    
}else{
  console.log("Using Payload as Verifiable creds as no VP found in the payload")
}
/**/
//console.log(payload.vp.verifiableCredential);
//console.log(verifiablecredentials);
//verifiablecredentials = JSON.parse(atob(verifiablecredentials));


(async () => {
  const sdjwt = verifiablecredentials;
  const decodedSdJwt = await decodeSdJwt(sdjwt, digest);


  // Get the claims from the SD JWT
  const claims = await getClaims(
    decodedSdJwt.jwt.payload,
    decodedSdJwt.disclosures,
    digest,
  );

  console.log('The claims are:');
  console.log(JSON.stringify(claims));
  var photoBase64 = "";

  
  if(claims && claims.iso23220 && claims.iso23220.portrait) {
    console.log("Photo found in the claims")
    photoBase64 = claims.iso23220.portrait; 
  }
  current_photo_html = `  <img src="${photoBase64}" /> <text id='jsonData'> ${JSON.stringify(claims)}</text>`
})();



    // Affichage d'une image HTML avec base64
    res.send('ok');
});


app.get('/photo', (req, res) => {   
    res.send(`${current_photo_html}`);
});
app.get('/reset-photo', (req, res) => { 
  current_photo_html = "";    
  res.send(`${current_photo_html}`);
});


var current_status = '';
app.get('/status', (req, res) => {   
    res.send(current_status);
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