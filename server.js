import express from 'express';
import QRCode from 'qrcode';
import fs from 'fs';
import { JWT, JWK } from 'jose';
import { signJWT } from './jwtUtils.js';  // Ton utilitaire de signature JWT

const app = express();
const PORT = 3000;

// Route pour générer un JWT signé à partir d'un objet de présentation
app.get('/request-object/:value', async (req, res) => {
    const payload = {
        iss: "my_client_id",
        aud: "wallet",
        response_type: "vp_token",
        client_id: "my_client_id",
        scope: "openid",
        nonce: "123456",
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

// Lancer le serveur
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
