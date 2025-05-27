
import { readFile } from 'fs/promises';
import { createHash } from 'node:crypto';

const filePath = './vctoken_lissi.txt';

try {
  const data = await readFile(filePath, 'utf8');
  process(data);
} catch (error) {
  console.error(`Error reading file: ${error.message}`);
}

function process(data) {
    const [sdJwt, disclosuresJSON, vpToken] = data.split("~");
    var disclosures = JSON.parse(Buffer.from(disclosuresJSON, 'base64url').toString('utf8'))

    // Ensuite tu appelles la fonction de vérification :
    verifyPresentation({ sdJwt, disclosures, vpToken })
    .then(valid => {
        console.log(valid ? "✅ Présentation valide" : "❌ Présentation invalide");
    })
    .catch(err => {
        console.error("❌ Erreur lors de la vérification :", err);
    });

}

// Fonction principale pour parser et vérifier un SD-JWT dans le cadre d'une présentation OpenID4VP
// Entrée : un objet avec les trois parties
// - sdJwt: le JWT principal signé par l'Issuer
// - disclosures: un tableau de disclosures (ou JWT contenant ce tableau)
// - vpToken: le JWT contenant le nonce, audience, etc.

import { jwtVerify, importX509 } from 'jose'
import * as jose from 'jose';

// Helper pour décoder un JWT sans vérification
function decodeJwt(token) {
  const [header, payload] = token.split('.').slice(0, 2).map((part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8')));
  return { header, payload };
}



/**
 * Vérifie une présentation SD-JWT composée de 3 parties : sdJwt, disclosures, vpToken
 * @param {Object} param0
 * @param {string} param0.sdJwt - Le JWT principal signé contenant les `sd_hash`
 * @param {string[]} param0.disclosures - Les disclosures sous forme de tableau JSON
 * @param {string} param0.vpToken - JWT enveloppe contenant le challenge (nonce, aud, etc.)
 * @returns {Promise<boolean>} true si tout est valide
 */
export async function verifyPresentation({ sdJwt, disclosures, vpToken }) {
  // Parse l'en-tête du SD-JWT
  const [headerB64] = sdJwt.split('.');
  const headerJson = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
  console.log("Header JWT :", headerJson);

  // Vérifie que le x5c est présent
  if (!headerJson.x5c || !Array.isArray(headerJson.x5c) || headerJson.x5c.length === 0) {
    throw new Error("Certificat (x5c) manquant dans l'en-tête du SD-JWT");
  }

  // Récupère le certificat principal (premier dans la chaîne)
  const certPem = `-----BEGIN CERTIFICATE-----\n${headerJson.x5c[0].match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;

  // Importe la clé publique à partir du certificat X.509
  const publicKey = await importX509(certPem, headerJson.alg);

  // Vérifie la signature du SD-JWT
  let payload;
  try {
    const result = await jwtVerify(sdJwt, publicKey);
    console.log("Payload SD-JWT :", result.payload);
    payload = result.payload;
    console.log("✅ Signature SD-JWT valide");
  } catch (err) {
    console.error("❌ Signature SD-JWT invalide :", err.message);
    return false;
  }

  // Vérification des disclosures (ici simplifiée)
  const expectedHashes = payload._sd || [];
  console.log(disclosures)
  const actualHashes = disclosures.map(disclosure =>
    createHash('sha256').update(disclosure).digest('base64url')
    
  );
console.log("Hashes attendus :", expectedHashes);
  console.log("Hashes trouvés :", actualHashes);
  const allMatched = actualHashes.every(hash => expectedHashes.includes(hash));
  if (!allMatched) {
    console.error("❌ Les disclosures ne correspondent pas aux sd_hash attendus");
    return false;
  }

  console.log("✅ Les disclosures sont valides");

  // Vérifie le vp_token (signature et contenu simplifié)
  try {
    const vpResult = await jwtVerify(vpToken, publicKey); // ou autre clé selon le cas
    const vpPayload = vpResult.payload;
    console.log("✅ VP Token valide :", vpPayload);
    if (!vpPayload.nonce || !vpPayload.aud || !vpPayload._sd_hash) {
      console.error("❌ Champs attendus manquants dans le vp_token");
      return false;
    }
  } catch (err) {
    console.error("❌ Erreur lors de la vérification du vp_token :", err.message);
    return false;
  }

  return true;
}
