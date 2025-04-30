import { generateKeyPair, exportJWK } from 'jose';

(async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256', {
        extractable: true
      });

  const pubJwk = await exportJWK(publicKey);
  const privJwk = await exportJWK(privateKey);

  pubJwk.kid = 'my-key-id';
  privJwk.kid = 'my-key-id';

  console.log('Public JWKS:', JSON.stringify({ keys: [pubJwk] }, null, 2));
  console.log('Private JWK:', JSON.stringify(privJwk, null, 2));
})();
