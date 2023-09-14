const bitcoin = require('bitcoinjs-lib')
const { alice, bob } = require('./wallets.json');
const { TSMClient, algorithms } = require('@sepior/tsm');
const network = bitcoin.networks.regtest
const creds = require("./creds.json");

const ECPairFactory = require('ecpair');
const ecc = require('tiny-secp256k1');
const ECPair = ECPairFactory.ECPairFactory(ecc);

//From funding transaction 
const TX_ID = 'a6526375731c7e2677f9a8b2b2122e1b5c316a823072eddd9c80364f50b0afbd';
const VOUT = 0;
const TX_HASH = '02000000000101e85917fd0509c84329864078e9ed4da0d1fdb0d46ec81edb352ebe326c2ad5a40000000000feffffff0200e1f505000000001600143e62c54881dd37418848d266a712018ff11dff0d7310102401000000160014a723e9cc41d51c72eb17be12db7cebe38c2819e402473044022016cad14bf612e14b33c33bf500e349fc777e88c0f56e14ef48036709a9fd83c30220326ecfd6f26407aa63b35fa0a90e318f1dd9bd539654a80ff773cf5cdb61cc71012102720cafaf7ce2cd5430cada4f1a21de6a6a7872d6b34c11c3cb4e1c5fb2089344cc000000';

// Id of key generated in TSM
keyId = 'T6ebdn3KJw31tXgG8JbpHBwVchO7';
publicKeyHash = '308c8ce5df3056fa78e6f9dcb3a128adac9445c7'; // public key hash for funded address


async function example() {
    const psbt = new bitcoin.Psbt({ network })
        .addInput({
            hash: TX_ID,
            index: VOUT,
            witnessUtxo: {
                script: Buffer.from('0014' + publicKeyHash, 'hex'),
                value: 1e8,
            },
        })
        .addOutput({
            address: bob[1].p2pkh,
            value: 999e5,
        })


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

    let chainPath = new Uint32Array([49, 1, 0, 0, 0]);

    let [pk, pkDER] = await tsmClient1.publicKey(algorithms.ECDSA, keyId, chainPath);
    const pkCompressed = await pk2Sec1Compressed(tsmClient1, pkDER);
    const pkRaw = pk.export({ format:"der", type: "spki" });
    pkBytes = pkRaw.slice(23);

    console.log("do presigning");
    let sessionID = "signing" + Date.now().toString();
    presigCount = 5;
    results = await Promise.all([
        tsmClient1.presigGenWithSessionID(algorithms.ECDSA, sessionID, keyId, presigCount),
        tsmClient2.presigGenWithSessionID(algorithms.ECDSA, sessionID, keyId, presigCount),
        tsmClient3.presigGenWithSessionID(algorithms.ECDSA, sessionID, keyId, presigCount)
    ]);

    let presigIDs = results[0];
    console.log("presigIDs:", presigIDs);

    const signer = {
        network: network,
        publicKey: pkCompressed,
        sign: async (hash) => {
            const [partialSig1, ,] = await tsmClient1.partialSignWithPresig(algorithms.ECDSA, keyId, presigIDs[0], chainPath, hash);
            const [partialSig2, ,] = await tsmClient2.partialSignWithPresig(algorithms.ECDSA, keyId, presigIDs[0], chainPath, hash);
            const [partialSig3, ,] = await tsmClient3.partialSignWithPresig(algorithms.ECDSA, keyId, presigIDs[0], chainPath, hash);

            let [signature,] = await tsmClient1.finalize(algorithms.ECDSA, [partialSig1, partialSig2, partialSig3]);
            console.log("Signature:", Buffer.from(signature).toString('hex'));

            var asn = require('asn1.js');
            var ECSignature = asn.define('ECSignature', function () {
                this.seq().obj(
                    this.key('R').int(),
                    this.key('S').int()
                );
            });

            var sig = ECSignature.decode(Buffer.from(signature), 'der');
            srSignature = sig.R.toString('hex').padStart(64, '0') + sig.S.toString('hex').padStart(64, '0');
            return Buffer.from(srSignature, 'hex');
        }
    }

    await psbt.signInputAsync(0, signer)
    const validator = (pubkey, msghash, signature) => ECPair.fromPublicKey(pubkey).verify(msghash, signature);
    valcheckStat = psbt.validateSignaturesOfInput(0, validator)
    console.log(`validator check status: ${valcheckStat}`);

    psbt.finalizeAllInputs()

    console.log('Transaction hexadecimal:')
    console.log(psbt.extractTransaction().toHex())

}

async function pk2Sec1Compressed(tsmClient, pk) {
    let [curveName, X, Y] = await tsmClient.parsePublicKey(algorithms.ECDSA, pk);
    let xBytes = Buffer.from(X);
    let prefix = (Y[31] & 0x01) === 0x00 ? Buffer.from([0x02]) : Buffer.from([0x03]);
    return Buffer.concat([prefix, xBytes]);
}

example();
