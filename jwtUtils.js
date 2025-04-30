// Si tu utilises des modules ES
import { SignJWT, importJWK } from 'jose';
import fs from 'fs';

// Fonction pour signer un JWT
export const signJWT = async (privJwkPath, payload) => {
  try {
    // Lire la clé privée depuis un fichier
    const privJwk = JSON.parse(fs.readFileSync(privJwkPath));

    // Importer la clé privée en format JWK
    const privateKey = await importJWK(privJwk, 'ES256');

    // Signer le JWT avec la clé privée
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256', kid: 'my-key-id' })  // Utilise 'kid' pour l'identifier
      .setIssuedAt()
      .setExpirationTime('5m') // Définir un délai d'expiration (ex: 5 minutes)
      .sign(privateKey);

    return jwt;
  } catch (err) {
    console.error('Error signing JWT:', err);
    throw err;
  }
};
