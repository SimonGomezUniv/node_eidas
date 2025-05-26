import { spawn } from 'child_process';
import fetch from 'node-fetch';
import { generateKeyPair, SignJWT, importJWK, exportJwk, decodeJwt } from 'jose';
import assert from 'assert';
import { v4 as uuidv4 } from 'uuid';

const SERVER_URL = 'http://localhost:3000';
let serverProcess;
let walletKeys; // To store generated wallet keys for tests

// Function to generate ES256 keys
async function generateAndSetWalletKeys() {
    const alg = 'ES256'; // Matching server's privJwk.json
    const { publicKey, privateKey } = await generateKeyPair(alg);
    const publicJwk = await exportJwk(publicKey);
    // publicJwk.kid = uuidv4(); // Assign kid if needed
    walletKeys = { publicKey, privateKey, publicJwk, alg };
}

async function startServer() {
    return new Promise((resolve, reject) => {
        // Ensure index.js is executable or called with node
        serverProcess = spawn('node', ['index.js'], { stdio: 'inherit' });
        serverProcess.on('spawn', () => {
            console.log('Server process spawned. Waiting for it to be ready...');
            // Simple delay to allow server to start. In a robust setup, you'd poll an endpoint.
            setTimeout(() => {
                console.log('Assuming server is ready.');
                resolve();
            }, 3000); // Adjust as needed
        });
        serverProcess.on('error', (err) => {
            console.error('Failed to start server process:', err);
            reject(err);
        });
        serverProcess.on('exit', (code, signal) => {
            // console.log(`Server process exited with code ${code} and signal ${signal}`);
        });
    });
}

async function stopServer() {
    return new Promise((resolve) => {
        if (!serverProcess || serverProcess.killed) {
            resolve();
            return;
        }
        serverProcess.on('exit', () => {
            // console.log('Server process terminated.');
            serverProcess = null;
            resolve();
        });
        console.log('Stopping server...');
        serverProcess.kill('SIGINT');
        // Force kill if it doesn't terminate gracefully after a timeout
        setTimeout(() => {
            if (serverProcess && !serverProcess.killed) {
                console.log('Forcing server termination...');
                serverProcess.kill('SIGKILL');
            }
            resolve(); // Ensure promise resolves even if force kill was needed or already exited
        }, 2000);
    });
}

async function postJson(url, body) {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return response; // Return the full response object
}

async function getJson(url) {
    const response = await fetch(url);
    const text = await response.text(); // Read body as text first
    if (!response.ok) {
        throw new Error(`GET ${url} failed with ${response.status}: ${text}`);
    }
    try {
        return JSON.parse(text); // Then attempt to parse as JSON
    } catch (e) {
        return text; // If not JSON, return as text (e.g. "ok" from /callback)
    }
}


// Test Suite
describe('SIOP Authentication Tests', function() {
    this.timeout(20000); // Increase timeout for the whole suite (server start/stop + tests)

    before(async function() {
        this.timeout(10000); // Timeout for server start and key generation
        await generateAndSetWalletKeys(); // Generate wallet keys once
        await startServer();
        try {
            await getJson(`${SERVER_URL}/reset-photo`); // Reset server state
            console.log("Server state reset via /reset-photo for initial setup.");
        } catch (e) {
            console.warn("Initial /reset-photo failed, proceeding. Error:", e.message);
        }
    });

    after(async function() {
        this.timeout(5000); // Timeout for server stop
        await stopServer();
    });

    describe('Request Object Generation for SIOP', function() {
        it('should generate a valid SIOP request object', async function() {
            const updateResponse = await postJson(`${SERVER_URL}/update-claim-selection`, { type: 'siop', claims: [] });
            assert(updateResponse.ok, `Failed to update claim selection: ${await updateResponse.text()}`);
            const updateBody = await updateResponse.json();
            assert(updateBody.success, 'Claim selection update was not successful.');

            const clientNoncePart = uuidv4();
            const requestObjectJws = await getJson(`${SERVER_URL}/request-object/${clientNoncePart}`);
            assert(typeof requestObjectJws === 'string', 'Request object JWS was not a string.');

            const decodedPayload = decodeJwt(requestObjectJws);
            assert(decodedPayload, 'Failed to decode request object JWS.');
            assert(decodedPayload.presentation_definition, 'presentation_definition missing.');
            
            const pd = decodedPayload.presentation_definition;
            assert(pd.input_descriptors && pd.input_descriptors.length > 0, 'input_descriptors missing or empty.');
            const inputDescriptor = pd.input_descriptors[0];
            assert.strictEqual(inputDescriptor.purpose, "Authenticate using your self-managed digital identity (SIOP).", "Purpose mismatch.");
            assert.deepStrictEqual(inputDescriptor.constraints.fields, [], "Fields should be empty for SIOP request.");
            assert.strictEqual(decodedPayload.client_id, SERVER_URL, "client_id mismatch");
            assert(decodedPayload.nonce.includes(clientNoncePart), "Client nonce part missing from overall nonce");
            assert.strictEqual(decodedPayload.response_uri, `${SERVER_URL}/callback`, "Response URI mismatch");
        });
    });

    describe('/callback Endpoint for SIOP VPs', function() {
        // Helper function to create a self-issued VC JWT
        async function createSiopVcJwt(_walletKeys, vcAudience, _vcNonce, credentialSubjectData) {
            const vcPayload = {
                iss: `did:jwk:${uuidv4()}`, // Placeholder DID
                sub: `did:jwk:${uuidv4()}`, // Placeholder DID, typically same as iss for SIOP VC
                aud: vcAudience, 
                // nonce: _vcNonce, // Nonce for VC itself is usually not part of SIOP flow for id_token_vc
                exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
                iat: Math.floor(Date.now() / 1000),
                vc: {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    type: ["VerifiableCredential", "SiopAuthenticationCredential"],
                    credentialSubject: credentialSubjectData
                },
                cnf: { jwk: _walletKeys.publicJwk }
            };
            vcPayload.sub = vcPayload.iss; // For SIOP, VC iss and sub are the same (holder's DID)

            return await new SignJWT(vcPayload)
                .setProtectedHeader({ alg: _walletKeys.alg, kid: _walletKeys.publicJwk.kid /* Can be omitted if JWK has no kid */ })
                .sign(_walletKeys.privateKey);
        }

        // Helper function to create a SIOP VP JWT
        async function createSiopVpJwt(_walletKeys, vcJwtString, vpAudience, vpRequestNonce, vpState) {
            const decodedVcPayload = decodeJwt(vcJwtString);
            const vpPayload = {
                iss: decodedVcPayload.iss, // VP issuer is the holder, same as VC issuer
                sub: decodedVcPayload.sub, // VP subject is the holder, same as VC subject
                aud: vpAudience, 
                nonce: vpRequestNonce, 
                exp: Math.floor(Date.now() / 1000) + (60 * 5), // 5 minutes
                iat: Math.floor(Date.now() / 1000),
                state: vpState,
                vp: {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    type: ["VerifiablePresentation"],
                    verifiableCredential: [vcJwtString]
                }
            };
            return await new SignJWT(vpPayload)
                .setProtectedHeader({ alg: _walletKeys.alg, kid: _walletKeys.publicJwk.kid /* Can be omitted */ })
                .sign(_walletKeys.privateKey);
        }

        beforeEach(async function() {
            try {
                await getJson(`${SERVER_URL}/reset-photo`);
            } catch (e) {
                console.warn("Could not reset state via /reset-photo before callback test:", e.message);
            }
        });

        it('should process a valid SIOP VP', async function() {
            // Simulate nonce from a previous request object
            const simulatedRequestNonce = `nonce-${uuidv4()}-${uuidv4()}`; 
            const rpAudience = SERVER_URL;
            const userCredentialSubject = { user_id: uuidv4(), message: "SIOP Auth Granted" };
            
            const vcJwt = await createSiopVcJwt(walletKeys, rpAudience, "vc_nonce_placeholder", userCredentialSubject);
            const vpJwt = await createSiopVpJwt(walletKeys, vcJwt, rpAudience, simulatedRequestNonce, "test-state-valid");

            const callbackResponse = await postJson(`${SERVER_URL}/callback`, { vp_token: vpJwt });
            assert(callbackResponse.ok, `Callback failed: ${await callbackResponse.text()}`);
            const callbackBodyText = await callbackResponse.text();
            assert.strictEqual(callbackBodyText, "ok", `Callback response body was "${callbackBodyText}", expected "ok"`);
            
            const details = await getJson(`${SERVER_URL}/vc-details`);
            assert.strictEqual(details.verificationStatus, "Verified (SIOP)", `Verification status mismatch. Error: ${details.verificationError}`);
            assert.strictEqual(details.vcType, "Self-Issued VC (SIOP)", "VC Type mismatch");
            assert.deepStrictEqual(details.claims.user_id, userCredentialSubject.user_id, "Claim user_id mismatch");
            assert(details.claims.pairwise_identifier, "Pairwise identifier should be present");
            
            const nonceStep = details.technicalDebugData.jwtValidationSteps.find(s => s.step === 'SIOP Nonce Check');
            assert(nonceStep, "Nonce check step missing");
            assert.strictEqual(nonceStep.details.nonce, simulatedRequestNonce, "Nonce in tech debug data mismatch");
        });

        it('should reject SIOP VP with signature mismatch', async function() {
            const simulatedRequestNonce = `nonce-${uuidv4()}-${uuidv4()}`;
            const rpAudience = SERVER_URL;
            const userCredentialSubject = { data: "sig_mismatch_test" };

            const vcJwt = await createSiopVcJwt(walletKeys, rpAudience, "vc_nonce_sig", userCredentialSubject);
            
            const rogueAlg = 'ES256';
            const { privateKey: roguePrivateKey } = await generateKeyPair(rogueAlg);
            // Sign VP with a different key than declared in VC's cnf.jwk
            const vpJwt = await new SignJWT({
                    iss: decodeJwt(vcJwt).iss, sub: decodeJwt(vcJwt).sub, aud: rpAudience, nonce: simulatedRequestNonce,
                    exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000),
                    vp: { verifiableCredential: [vcJwt] }
                })
                .setProtectedHeader({ alg: rogueAlg })
                .sign(roguePrivateKey); // Signed with rogue key

            const callbackResponse = await postJson(`${SERVER_URL}/callback`, { vp_token: vpJwt });
            assert(callbackResponse.ok, `Callback should be OK (200) to acknowledge receipt.`);
            
            const details = await getJson(`${SERVER_URL}/vc-details`);
            assert.strictEqual(details.verificationStatus, "Verification Failed (SIOP)", "Status should be SIOP failure.");
            assert(details.verificationError.toLowerCase().includes("signature verification failed") || 
                   details.verificationError.toLowerCase().includes("failed to verify signature"), 
                `Error message should indicate signature failure, got: ${details.verificationError}`);
        });

        it('should reject SIOP VP with audience mismatch in VC/VP', async function() {
            const simulatedRequestNonce = `nonce-${uuidv4()}-${uuidv4()}`;
            const rpAudience = SERVER_URL;
            const wrongAudience = "https://attacker.com";
            const userCredentialSubject = { data: "aud_mismatch_test" };

            // Scenario 1: VC audience is wrong
            let vcJwt = await createSiopVcJwt(walletKeys, wrongAudience, "vc_nonce_aud1", userCredentialSubject);
            let vpJwt = await createSiopVpJwt(walletKeys, vcJwt, rpAudience, simulatedRequestNonce, "state_aud_vc_wrong");

            let callbackResponse = await postJson(`${SERVER_URL}/callback`, { vp_token: vpJwt });
            assert(callbackResponse.ok);
            let details = await getJson(`${SERVER_URL}/vc-details`);
            assert.strictEqual(details.verificationStatus, "Verification Failed (SIOP)", "Status for VC aud mismatch");
            assert(details.verificationError.includes("Audience mismatch"), `Error for VC aud mismatch, got: ${details.verificationError}`);

            // Scenario 2: VP audience is wrong (VC audience is correct for RP)
            await getJson(`${SERVER_URL}/reset-photo`); 
            vcJwt = await createSiopVcJwt(walletKeys, rpAudience, "vc_nonce_aud2", userCredentialSubject);
            vpJwt = await createSiopVpJwt(walletKeys, vcJwt, wrongAudience, simulatedRequestNonce, "state_aud_vp_wrong");
            
            callbackResponse = await postJson(`${SERVER_URL}/callback`, { vp_token: vpJwt });
            assert(callbackResponse.ok);
            details = await getJson(`${SERVER_URL}/vc-details`);
            assert.strictEqual(details.verificationStatus, "Verification Failed (SIOP)", "Status for VP aud mismatch");
            assert(details.verificationError.includes("Audience mismatch"), `Error for VP aud mismatch, got: ${details.verificationError}`);
        });
    });
});

console.log("SIOP Test file loaded. Run with: npx mocha test_siop.mjs");
