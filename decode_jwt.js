import * as jose from 'jose';
import { readFileSync } from 'fs';

const filePath = './jwt_demo_no_sd-jwt.data';
const jwtData = readFileSync(filePath, 'utf8');
//console.log('JWT Data:', jwtData);

var payload = jwtData.split('.')[1];
payload = JSON.parse(atob(payload));
//console.log(payload);
var verifiablecredentials = payload.vp.verifiableCredential[0]
//console.log(verifiablecredentials);
//verifiablecredentials = JSON.parse(atob(verifiablecredentials));


import { decodeSdJwt, getClaims } from '@sd-jwt/decode';
import { digest } from '@sd-jwt/crypto-nodejs';

(async () => {
  const sdjwt = verifiablecredentials;
  const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
  console.log('The decoded SD JWT is:');
  console.log(JSON.stringify(decodedSdJwt, null, 2));
  console.log(
    '================================================================',
  );

  // Get the claims from the SD JWT
  const claims = await getClaims(
    decodedSdJwt.jwt.payload,
    decodedSdJwt.disclosures,
    digest,
  );

  console.log('The claims are:');
  console.log(JSON.stringify(claims.iso23220.portrait, null, 2));
})();