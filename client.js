const { generateKeyPairSync, publicEncrypt, createSign, createPrivateKey } = require('crypto');
const axios = require("axios");
const fs = require('fs');

const args = process.argv.slice(2);
const command = args[0];

switch (command) {
    case 'generate-keys':
    case '-gk':
        generateKeyPair();
        break;
    case 'submit-public-key':
    case '-spk':
        submitPublicKey(args[1])
        break;
    case 'sign-message':
    case '-sm':
        signMessage(args[1]);
        break;
    case 'verify-message':
    case '-vm':
        verifyMessage(args[1], args[2]);
        break;
    case 'help':
    case '-h':
        console.log('Usage: node client.js [command]');
        console.log('Commands:');
        console.log('  generate-keys, -gk: Generate a new keypair');
        console.log('  submit-public-key, -spk: Send public key to server (server password required)');
        console.log('  sign-message, -sm: Sign the provided message');
        console.log('  verify-message, -vm: Verify message');
        break;
    default:
        console.log('Invalid command');
        process.exit(1);
}


/**
 * Generates a new RSA key pair and saves them to files.
 */
function generateKeyPair() {
    console.log('Generating key pair...');
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    fs.writeFileSync('private_key.pem', privateKey);
    fs.writeFileSync('public_key.pem', publicKey);

    console.log('Key pair generated and stored successfully.');
}

/**
 * Submits the public key to the server with password authentication.
 * 
 * This function reads the public key from the 'public_key.pem' file and sends it
 * to the server. The provided password is sent as a Base64 encoded Basic Auth header.
 * 
 * @param {string} password - The password for server authentication.
 * @throws {Error} If there's an error reading the public key or making the request.
 * @returns {Promise<void>} A promise that resolves when the key is successfully submitted.
 */
async function submitPublicKey(password) {
    const publicKey = fs.readFileSync('public_key.pem', 'utf8');
    // Sending the password in the Auth-header seemed more secure than sending
    // in the body of the request
    try {
        const response = await axios.post('http://localhost:3000/submit-public-key',
            { publicKey },
            {
                headers: {
                    'Authorization': `Basic ${Buffer.from(password).toString('base64')}`,
                    'Content-Type': 'application/json'
                }
            }
        );
    } catch (error) {
        console.error('Error submitting public key:', error.message);
        throw error;
    }
    console.log('Public key submitted successfully.');
}

/**
 * Signs a message using the private key file.
 * 
 * This function reads the private key, signs the provided message,
 * and outputs the message and its signature to the terminal.
 * 
 * @param {string} message - The message to be signed.
 * @throws {Error} Error reading the private key or signing the message.
 */
function signMessage(message) {
    const privateKey = fs.readFileSync('private_key.pem', 'utf8');
    // RSA-SHA256 combines the strengths of both RSA and SHA-256
    const sign = createSign('RSA-SHA256');
    sign.update(message);
    sign.end();
    const signature = sign.sign(privateKey, 'base64');
    // console.log(`Message: ${message}`);
    // console.log(`Signature: ${signature}`);
    return { message, signature };
}

/**
 * Verifies a message signature.
 * 
 * This function sends the message and its signature to the server for verification.
 * 
 * @param {string} message - The message to be verified.
 * @param {string} signature - The signature of the message to be verified.
 * @throws {Error} If there's an error making the request.
 * @returns {Promise<void>} A promise that resolves when the verification completes.
 */

async function verifyMessage(message, signature) {
    console.log('Verifying message: ', message);
    console.log('Signature: ', signature);
    const response = await axios.post('http://localhost:3000/verify-message',
        { message, signature },
        {
            headers: {
                'Content-Type': 'application/json'
            }
        }
    );
    console.log('Server response:', response.data);
}
