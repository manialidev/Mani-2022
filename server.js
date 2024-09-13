const express = require('express');
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const { createVerify } = require("crypto");

const app = express();
app.use(bodyParser.json());

let serverPassword = "";
let storedPublicKey = "";

const PORT = process.env.PORT || 3000;

const saltRounds = 10;
const password = process.argv[2] || null;
if (!password) {
    console.error('Password is required as a CLI argument');
    process.exit(1);
}

bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err);
        process.exit(1);
    }
    serverPasswordHash = hash;
});

/**
 * POST route to submit a public key to the server.
 */
app.post("/submit-public-key", async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return res.status(401).send('Authorization header missing or invalid');
    }
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const password = credentials;
    console.log('Password:', password);
    console.log('Public Key:', req.body.publicKey);

    try {
        const isPasswordValid = await bcrypt.compare(password, serverPasswordHash);
        if (!isPasswordValid) {
            return res.status(401).send('Invalid password');
        }
    } catch (error) {
        console.error('Error comparing passwords:', error);
        return res.status(500).send('Internal server error');
    }

    storedPublicKey = req.body.publicKey;
    res.send('Public key received');
});

/**
 * POST route to verify a signed message.
 */
app.post("/verify-message", async (req, res) => {
    const { message, signature } = req.body;
    console.log('Received message:', message);
    console.log('Received signature:', signature);
    if (!message || !signature) {
        return res.status(400).send('Message or signature missing');
    }

    try {
        const verify = createVerify("RSA-SHA256");
        verify.update(message);
        console.log("Stored Public Key:", storedPublicKey);
        const isVerified = verify.verify(storedPublicKey, signature, "base64");
        console.log("Signature verification:", isVerified);
        res.send({
            valid: isVerified
        });
    } catch (error) {
        console.error("Error verifying signature:", error);
        res.status(500).send('Error verifying signature');
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
