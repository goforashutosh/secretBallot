import {
    isReady,
    shutdown,
    Field,
    Mina,
    PrivateKey,
    PublicKey,
    AccountUpdate,
  } from 'snarkyjs';

import {writeFileSync, readFileSync} from 'fs';

await isReady;

console.log('SnarkyJS loaded');

const N = 2n**2n;

let priv_key_array: string[] = [];
let pub_key_array: string[] = [];

for (let i=0; i<N; i++){
    let priv_key = PrivateKey.random();
    let pub_key = priv_key.toPublicKey();
    // can use const senderPrivateKey = PrivateKey.fromBase58('EKEQc95...'); later
    priv_key_array.push(priv_key.toBase58());
    pub_key_array.push(pub_key.toBase58());
}

console.log(priv_key_array);

const json_priv_keys = JSON.stringify(priv_key_array);
const json_pub_keys = JSON.stringify(pub_key_array);

writeFileSync('keys/private_keys.json', json_priv_keys, 'utf8');
writeFileSync('keys/public_keys.json', json_pub_keys, 'utf8');



console.log('Shutting down');

await shutdown();


