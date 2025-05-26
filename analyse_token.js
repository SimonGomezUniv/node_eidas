import fs from 'fs/promises';
import jwt from 'jsonwebtoken';
import { X509Certificate } from '@peculiar/x509';

async function main() {
  try {
    // Lire le token depuis fichier
    const token = (await fs.readFile('./vctoken_lissi.txt', 'utf-8')).trim();

    // Extraire le header
    const encodedHeader = token.split('.')[0];
    const decodedHeaderJson = Buffer.from(encodedHeader, 'base64').toString('utf8');
    const decodedHeader = JSON.parse(decodedHeaderJson);

    if (!decodedHeader.x5c || decodedHeader.x5c.length === 0) {
      throw new Error("Le header JWT ne contient pas de certificat x5c");
    }

    const certBase64 = decodedHeader.x5c[0];
    // Formater en PEM
    const certPem =
      "-----BEGIN CERTIFICATE-----\n" +
      certBase64.match(/.{1,64}/g).join('\n') +
      "\n-----END CERTIFICATE-----";

      console.log("Certificat PEM :");
        console.log(certPem);

    // Afficher les infos du certificat
    const cert = new X509Certificate(certPem);
    console.log("Certificat extrait :");
    console.log("Sujet (subject) :", cert.subject);
    console.log("Émetteur (issuer) :", cert.issuer);
    console.log("Validité :", cert.notBefore, "à", cert.notAfter);

    // Vérifier le JWT avec le certificat
    jwt.verify(token, certPem, { algorithms: ['ES256'] }, (err, payload) => {
      if (err) {
        console.error("JWT non valide :", err.message);
      } else {
        console.log("JWT valide !");
        console.log("Payload :", payload);
      }
    });
  } catch (err) {
    console.error("Erreur :", err.message);
  }
}

main();
