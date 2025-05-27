import { readFile } from 'fs/promises';

const filePath = './vctoken_lissi.txt';

try {
  const data = await readFile(filePath, 'utf8');
  process(data);
} catch (error) {
  console.error(`Error reading file: ${error.message}`);
}



function process(data) {
    console.log("Data read from file:");
    data.split('~').forEach((segment,i) => {
     
      console.log("Segment:", i);
      console.log("Segment length:", segment.length);
      console.log("Segment type:", typeof segment); 
      console.log("Segment content:", segment);
     
      verifyJwtWithPublicKeyInHeader(segment).then((payload) => {
        console.log("Payload:", payload);
      }).catch((err) => {
        console.error("Error verifying JWT:", err.message);
      });

     
      segment.split('.').forEach((part, index) => {
        try {
          const decoded = Buffer.from(part, 'base64').toString('utf8');
          console.log(`JWT Part ${ + 1}:`);
          const json = JSON.parse(decoded);
          console.log( json);
        } catch (err) {
          console.error(`Error decoding JWT part ${index + 1}:`, err.message);
        }
      });

      
     
    });
/*
    console.log("Data length:", data.length);
    console.log("Data type:", typeof data);
    */
}

import { decodeProtectedHeader, jwtVerify } from 'jose';

/**
 * Vérifie la validité d'un JWT avec la clé publique présente dans le header
 * @param {string} token Le JWT à vérifier
 * @returns {Promise<object>} Le payload si signature valide, sinon throw une erreur
 */
export async function verifyJwtWithPublicKeyInHeader(token) {
  try {
    // Extraire le header protégé (décodage base64url)
    const header = decodeProtectedHeader(token);
    console.log('Header JWT décodé :', header);

    // Recherche de la clé publique dans le header
    if (!header.jwk && !header.x5c) {
      console.log('Erreur : Pas de clé publique dans le header JWT (jwk ou x5c attendu)');
      throw new Error('Pas de clé publique dans le header JWT (jwk ou x5c attendu)');
    }

    let key;

    if (header.jwk) {
      console.log('Clé publique JWK trouvée dans le header');
      key = header.jwk;
    } else if (header.x5c && header.x5c.length > 0) {
      console.log('Certificat x5c trouvé dans le header, conversion en PEM');
      const certBase64 = header.x5c[0];
      const certPem = `-----BEGIN CERTIFICATE-----\n${certBase64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
      key = certPem;
    }

    // Validation du token avec la clé extraite
    const { payload } = await jwtVerify(token, key);
    console.log('Vérification de la signature : OK');
    return payload;

  } catch (error) {
    console.log('Vérification de la signature : KO', error.message);
    throw error;
  }
}
