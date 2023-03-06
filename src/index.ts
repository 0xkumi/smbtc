import {
    initEccLib,
    address,
    networks,
    script,
    Signer,
    payments,
    crypto,
    Psbt,
} from "bitcoinjs-lib";
import './webserver'
import './web3'
import { broadcast, waitUntilUTXO, getTxFromBlock } from "./blockstream_utils";
import { ECPairFactory, ECPairAPI, TinySecp256k1Interface } from 'ecpair';
import { Taptree } from "bitcoinjs-lib/src/types";
import { witnessStackToScriptWitness } from "./witness_stack_to_script_witness";
import { commitTxToEVM } from "./web3";
import { execSync } from 'child_process'


const tinysecp: TinySecp256k1Interface = require('tiny-secp256k1');
initEccLib(tinysecp as any);
const ECPair: ECPairAPI = ECPairFactory(tinysecp);
const network = networks.regtest;
const COOKIE = `/home/david/WORK/Projects/esplora/data_bitcoin_regtest/bitcoin/regtest/.cookie`
//sleep
function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}



export async function inscribe(hexString: string){
    console.log("inscribe ", hexString)
    const privateKey = process.argv[3]
    var privateKeyBuffer = Buffer.from(privateKey, 'hex');
    var keyPair = ECPair.fromPrivateKey(privateKeyBuffer);
    await start_taptree(keyPair, hexString);
}

async function start() {
    let cmd = process.argv[2]
    

    let state:any = {}
    switch (cmd) {
        case "server":
            const privateKey = process.argv[3]
            if (!privateKey) {
                console.error("Please input private key!")
                return
            }
            let blkHeight = 0;
            while (true) {
                try {
                    let data = await getTxFromBlock(blkHeight)
                    if (data != "") {
                        try {
                            let a = script.toASM(Buffer.from(data, "hex"))
                            if( a.split(" ")[4] == '73627463'){
                                let txHex = a.split(" ")[5]
                                // console.log("receive", txHex)
                                await commitTxToEVM('0x'+txHex)
                            }                            
                        } catch(err){}
                    }
                    blkHeight++;
                } catch(err){
                    await sleep(1000);
                }
            }
        case "create":
            const keypair = ECPair.makeRandom({ network });
            var tweakedSigner = tweakSigner(keypair, { network });
            var tweakedP2TR = payments.p2tr({
                pubkey: toXOnly(tweakedSigner.publicKey),
                network
            });
            console.log("Receive Taproot Public key: ", tweakedP2TR.address)
            console.log("Private key: ", keypair.privateKey?.toString("hex"))
            break
    }
}

async function start_taptree(keypair: Signer, data: string) {
    // Create a tap tree with two spend paths
    // One path should allow spending using secret
    // The other path should pay to another pubkey

    // Make random key for hash_lock
    const tweakedSigner = tweakSigner(keypair, { network });

    // Generate an address from the tweaked public key
    const p2pktr = payments.p2tr({
        pubkey: toXOnly(tweakedSigner.publicKey),
        network
    });
    const p2pktr_addr = p2pktr.address ?? "";


    const hash_lock_keypair = ECPair.makeRandom({ network });
    // console.log("prepare inscribe event", data)

    const dataBuff = Buffer.from(data, 'hex');
    const chunkSize = 512
    let dataHex = ''
    for (let i = 0; i < dataBuff.length; i += chunkSize) {
        const chunk = dataBuff.subarray(i, i + chunkSize);
        dataHex += chunk.toString("hex") + ' '
    }
    // Construct script to pay to hash_lock_keypair if the correct preimage/secret is provided
    const hash_script_asm = `${toXOnly(hash_lock_keypair.publicKey).toString('hex')} OP_CHECKSIG OP_FALSE OP_IF ${Buffer.from("sbtc").toString("hex")} ${dataHex.trim()} OP_ENDIF`;
    const hash_lock_script = script.fromASM(hash_script_asm);
    
    const hash_lock_redeem = {
        output: hash_lock_script,
        redeemVersion: 192,
    };
    
    const scriptTree: Taptree = hash_lock_redeem

    const script_p2tr = payments.p2tr({
        internalPubkey: toXOnly(keypair.publicKey),
        scriptTree,
        redeem: hash_lock_redeem,
        network
    });

    const script_addr = script_p2tr.address ?? '';

    const p2pk_p2tr = payments.p2tr({
        internalPubkey: toXOnly(keypair.publicKey),
        network
    });


    /*
    =============================   COMMIT TX ==================================
    */
    // execSync(`bitcoin-core.cli -regtest -rpccookiefile=${COOKIE} sendtoaddress  ${script_addr} 0.01`)
    // console.log(`Waiting till UTXO is detected at this Address: ${p2pktr_addr}`);
    let utxos = await waitUntilUTXO(p2pktr_addr)
    // console.log(`Trying the P2PK path with UTXO ${utxos[0].txid}:${utxos[0].vout}`);

    const p2pk_psbt = new Psbt({ network });
    p2pk_psbt.addInput({
        hash: utxos[0].txid,
        index: utxos[0].vout,
        witnessUtxo: { value: utxos[0].value, script: p2pk_p2tr.output! },
        tapInternalKey: toXOnly(keypair.publicKey)
    });

    p2pk_psbt.addOutput({
        address: script_addr,
        value: utxos[0].value - 50000
    });

    p2pk_psbt.signInput(0, tweakedSigner);
    p2pk_psbt.finalizeAllInputs();

    let tx = p2pk_psbt.extractTransaction();
    // console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
    let txid = await broadcast(tx.toHex());
    // console.log(`Success! Txid is ${txid}`);

    /*
    =============================   REVEAL TX ==================================
    */

    // console.log(`Waiting till UTXO is detected at this Address: ${script_addr}`);
    utxos = await waitUntilUTXO(script_addr)
    // console.log(`Trying the Hash lock spend path with UTXO ${utxos[0].txid}:${utxos[0].vout}`);

    const tapLeafScript = {
        leafVersion: hash_lock_redeem.redeemVersion,
        script: hash_lock_redeem.output,
        controlBlock: script_p2tr.witness![script_p2tr.witness!.length - 1]
    };

    const psbt = new Psbt({ network });
    psbt.addInput({
        hash: utxos[0].txid,
        index: utxos[0].vout,
        witnessUtxo: { value: utxos[0].value, script: script_p2tr.output! },
        tapLeafScript: [
            tapLeafScript
        ]
    });

    psbt.addOutput({
        address: p2pktr_addr,
        value: utxos[0].value - 50000
    });

    psbt.signInput(0, hash_lock_keypair);

    // We have to construct our witness script in a custom finalizer

    const customFinalizer = (_inputIndex: number, input: any) => {
        const scriptSolution = [
            input.tapScriptSig[0].signature,
        ];
        const witness = scriptSolution
            .concat(tapLeafScript.script)
            .concat(tapLeafScript.controlBlock);

        return {
            finalScriptWitness: witnessStackToScriptWitness(witness)
        }
    }

    psbt.finalizeInput(0, customFinalizer);

    tx = psbt.extractTransaction();
    // console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
    txid = await broadcast(tx.toHex());
    console.log(`Success! Txid is ${txid}`);
    execSync(`bitcoin-core.cli -regtest -rpccookiefile=${COOKIE} -generate 1`)
}

start().then(() => process.exit());

function tweakSigner(signer: Signer, opts: any = {}): Signer {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    let privateKey: Uint8Array | undefined = signer.privateKey!;
    if (!privateKey) {
        throw new Error('Private key is required for tweaking signer!');
    }
    if (signer.publicKey[0] === 3) {
        privateKey = tinysecp.privateNegate(privateKey);
    }

    const tweakedPrivateKey = tinysecp.privateAdd(
        privateKey,
        tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash),
    );
    if (!tweakedPrivateKey) {
        throw new Error('Invalid tweaked private key!');
    }

    return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
        network: opts.network,
    });
}

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
    return crypto.taggedHash(
        'TapTweak',
        Buffer.concat(h ? [pubKey, h] : [pubKey]),
    );
}

function toXOnly(pubkey: Buffer): Buffer {
    return pubkey.subarray(1, 33)
}