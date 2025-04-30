import fs from 'fs';
import jwt from 'jsonwebtoken';
import { jwtVerify, importJWK } from 'jose';

// Ton JWT à valider (exemple)
const token = 'eyJhbGciOiJFUzI1NiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJteV9jbGllbnRfaWQiLCJhdWQiOiJ3YWxsZXQiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJteV9jbGllbnRfaWQiLCJzY29wZSI6Im9wZW5pZCIsIm5vbmNlIjoiMTIzNDU2IiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0IiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiJ2cC1yZXF1ZXN0LTEiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJuYW1lLWRlc2NyaXB0b3IiLCJzY2hlbWEiOnsidXJpIjoiaHR0cHM6Ly9zY2hlbWEub3JnL1BlcnNvbiJ9LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC5uYW1lIiwiJC5naXZlbl9uYW1lIl0sInB1cnBvc2UiOiJXZSBuZWVkIHlvdXIgbmFtZSB0byBjb21wbGV0ZSBLWUMifV19fV19LCJpYXQiOjE3NDYwNDU1NDQsImV4cCI6MTc0NjA0OTE0NH0.WXGsex6nOCu5f6ImGPR2Ay_lrf_o4PYJ0YrJmhZmBQT_-FdXUAUuwBOi83J4_SQVz1vv2LJy1LS6Vgv5EKW5Pw'; // à remplacer

(async () => {
  // 1. Lire le JWKS
  const jwks = JSON.parse(fs.readFileSync('./jwks.json', 'utf8'));
  const jwk = jwks.keys[0]; // ou chercher le bon `kid` si plusieurs

  // 2. Importer la clé publique JWK → WebCryptoKey
  const publicKey = await importJWK(jwk, 'ES256');

  // 3. Vérifier le JWT avec `jose` (plus simple que jsonwebtoken)

  try {
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['ES256'],
      issuer: 'my_client_id', // facultatif mais recommandé
      audience: 'wallet'      // idem
    });
    console.log('✅ JWT vérifié avec succès:', payload);
  } catch (err) {
    console.error('❌ Échec de vérification:', err.message);
  }
})();
