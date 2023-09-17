// Adapted from BD TSM docs

const { TSMClient, algorithms, curves } = require('@sepior/tsm');
const crypto = require("crypto");
const creds = require("./creds.json");
const bitcoin = require("bitcoinjs-lib");


let example = async function() {

    // Initialize a separate SDK for each MPC node in the TSM
    // Remember to change player count and threshold to match you configuration
    let playerCount = 3;
    let threshold = 1;
    let tsmClient1 = await TSMClient.init(playerCount, threshold, [
        {
            url: creds.urls[0],
            userID: creds.userID,
            password: creds.passwords[0]
        }]);

    let tsmClient2 = await TSMClient.init(playerCount, threshold, [
        {
            url: creds.urls[1],
            userID: creds.userID,
            password: creds.passwords[1]
        }]);


    let tsmClient3 = await TSMClient.init(playerCount, threshold, [
        {
            url: creds.urls[2],
            userID: creds.userID,
            password: creds.passwords[2]
        }]);


    // Step 1: Generate a key in the TSM

    // The three SDKs need to first agree on a unique session ID.
    let sessionID = "keygen" + Date.now().toString();

    // Each SDK must call keygenWithSessionID with the session ID.
    let results = await Promise.all([
        tsmClient1.keygenWithSessionID(algorithms.ECDSA, sessionID, curves.SECP256K1),
        tsmClient2.keygenWithSessionID(algorithms.ECDSA, sessionID, curves.SECP256K1),
        tsmClient3.keygenWithSessionID(algorithms.ECDSA, sessionID, curves.SECP256K1)]);

    // As a result of the interactive protocol, each SDK receives the key ID.
    keyID = results[0];
    console.log("Generated key with key ID:", keyID);

    let chainPath = new Uint32Array([49,1,0,0,0]); 
    let [,pk] = await tsmClient1.publicKey(algorithms.ECDSA, keyID,  new Uint32Array());
    let chainCode = await tsmClient1.chainCode(algorithms.ECDSA, keyID,  new Uint32Array());
    
    // Derive a p2wpkh address from the key
    let [,derivedPubKey] = await tsmClient1.derive(algorithms.ECDSA, curves.SECP256K1, pk, chainCode, chainPath);
    let addressPubKey = await pk2Sec1Compressed(tsmClient1, derivedPubKey);

    console.log(addressPubKey.toString('hex'))

    let address = bitcoin.payments.p2wpkh(
        {
            pubkey: addressPubKey,
            network: bitcoin.networks.regtest
        }).address;

        console.log(`segwit address is ${address}`);

    let pkh = bitcoin.crypto.hash160(addressPubKey).toString('hex');

        console.log(`pkh is ${pkh}`);
}

async function pk2Sec1Compressed(tsmClient, pk) {
    let [curveName, X, Y] = await tsmClient.parsePublicKey(algorithms.ECDSA, pk);
    let xBytes = Buffer.from(X);
    let prefix = (Y[31] & 0x01) === 0x00 ? Buffer.from([0x02]) : Buffer.from([0x03]);
    return Buffer.concat([prefix, xBytes]);
}


example();