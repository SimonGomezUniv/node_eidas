import fs from 'fs';
import { SignJWT, importJWK } from 'jose';

// 1. Charger ta clé privée depuis un fichier ou directement
const privJwk = JSON.parse(fs.readFileSync('./priv_jwk.json'));
// 2. Importer la clé pour la signature (ES256)
const privateKey = await importJWK(privJwk, 'ES256');

// 3. Créer ton payload
const payload = {
  iss: 'my_client_id',
  aud: 'wallet',
  nonce: '123456',
  response_type: 'vp_token',
  scope: 'openid'
};

// 4. Signer en JWS (JWT compact)
const jws = await new SignJWT(payload)
  .setProtectedHeader({ alg: 'ES256', kid: 'my-key-id' })
  .setIssuedAt()
  .setExpirationTime('1h')
  .sign(privateKey);

console.log('✅ JWS généré :\n', jws);
