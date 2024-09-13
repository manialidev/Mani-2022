### CLI Message Signing and Verification

CLI application that allows you to sign and verify messages.

#### Dependencies

```
npm install
```

#### Running the program

1. Start the server with a password:

```
node server.js <password>
```

2. Submit the public key to the server:

```
node client.js -spk <password of the server>
```

3. Enter the message you want to sign:

```
node client.js -sm <message>
```

4. Enter the message you want to verify:
```
node client.js -vm <message> <signature>
```

The server will respond with the verification result
```
Verification result: <result>
```
