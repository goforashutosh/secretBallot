// run using 
// npm run build && node build/src/readKeys.js
import {
    isReady,
    shutdown,
    Field,
    Mina,
    PrivateKey,
    PublicKey,
    AccountUpdate,
    MerkleTree,
    MerkleMap,
    Poseidon
  } from 'snarkyjs';

import {
    secretBallot,
    VoterListMerkleWitness, 
    VoteCountMerkleWitness
  } from './secretBallot.js';

import {readFileSync} from 'fs';
import * as inputs from './inputs.js';

import * as assert from 'assert';

await isReady;

console.log('SnarkyJS loaded');

let priv_key_array_str: string[] = [];
let pub_key_array_str: string[] = [];

priv_key_array_str = JSON.parse(readFileSync('keys/private_keys.json', 'utf8'));
pub_key_array_str = JSON.parse(readFileSync('keys/public_keys.json', 'utf8'));

console.log(priv_key_array_str);
console.log(pub_key_array_str);

let priv_key_array: PrivateKey[] = [];
let pub_key_array: PublicKey[] = [];

priv_key_array = priv_key_array_str.map(key => PrivateKey.fromBase58(key));
pub_key_array = pub_key_array_str.map(key => PublicKey.fromBase58(key));

// need to add 1 to make the height right
let voter_list_tree = new MerkleTree(inputs.log_num_voters + 1);
let pub_key_hash_arr: Field[] = pub_key_array.map(key => Poseidon.hash(key.toFields()));

voter_list_tree.fill(pub_key_hash_arr);

function displayTree(mtree:MerkleTree){
  let h = mtree.height;
  for(let i= 0; i<h; i++){
    console.log("Level:", i);
    for(let j=0; j < 2**(h-1-i); j++){
      console.log(mtree.getNode(i,BigInt(j)).toString());
    }
  }
}

console.log("The Merkle Tree is:");
// displayTree(voter_list_tree);
console.log("Root is: ", voter_list_tree.getRoot().toString());

let vote_count_tree = new MerkleTree(inputs.log_options + 1);
let nullifier_map = new MerkleMap();

// updates the nullifier_map and vote_count_tree after a successful vote
function updateOffChainState(nullifier_hash: Field, vote_option: bigint){
  nullifier_map.set(nullifier_hash, Field(1));
  const current_votes = vote_count_tree.getNode(0, vote_option);
  vote_count_tree.setLeaf(vote_option, current_votes.add(1));
}

// Smart contract deployment

const useProof = false;

const Local = Mina.LocalBlockchain({ proofsEnabled: useProof });
Mina.setActiveInstance(Local);

const { privateKey: deployerKey, publicKey: deployerAccount } = Local.testAccounts[0];

// ----------------------------------------------------
// Create a public/private key pair. The public key is our address and where we will deploy to
const zkAppPrivateKey = PrivateKey.random();
const zkAppAddress = zkAppPrivateKey.toPublicKey();

function dispAllVar(zk_app_inst: secretBallot){
  console.log("All variables of the contract are:")
  console.log("voter list root: ", zk_app_inst.voter_list_root.get().toString());
  console.log("vote count root: ", zk_app_inst.vote_count_root.get().toString());
  console.log("nullifier map root: ", zk_app_inst.nullifier_map_root.get().toString());
  console.log("initialised_flag: ", zk_app_inst.initialised_flag.get().toString());
  console.log("ballot_ID: ", zk_app_inst.ballot_ID.get().toString());
}

// create an instance of secretBallot - and deploy it to zkAppAddress
const zkAppInstance = new secretBallot(zkAppAddress);
const deployTxn = await Mina.transaction(deployerAccount, () => {
  AccountUpdate.fundNewAccount(deployerAccount);
  zkAppInstance.deploy();
  // zkAppInstance.initState(Field.random(), voter_list_tree.getRoot()); // this doesn't work here
});
console.log("\n--- init() called ---");
await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();
dispAllVar(zkAppInstance);


// call initState() separately
const txn1 = await Mina.transaction(deployerAccount, () => {
  zkAppInstance.initState(Field.random(), voter_list_tree.getRoot());
});
console.log("\n--- initState() called ---");
await txn1.prove(); 
await txn1.sign([deployerKey]).send();
dispAllVar(zkAppInstance);

console.log("The vote count tree is: ")
displayTree(vote_count_tree);

{
  // call vote()- correctly
  // create witness for index 0
  const voter_list_witness = new VoterListMerkleWitness(voter_list_tree.getWitness(0n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  const nullifier_hash = Poseidon.hash(priv_key_array[0].toFields().concat([ballot_ID]))
  const nullifier_witness = nullifier_map.getWitness(nullifier_hash);

  const option = 0n;
  const vote_count_witness = new VoteCountMerkleWitness(vote_count_tree.getWitness(option))
  const currentVotes = vote_count_tree.getNode(0, option);

  console.log("\n--- vote() called correctly ---");
  console.log("Before if - nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());

  try{
    const txn2 = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[0], 
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn2.prove(); 
    const txn2_result = await txn2.sign([deployerKey]).send();
    if (txn2_result.isSuccess){
      // update off chain state
      updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After if- nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  
}

{
  // call vote()- incorrectly- wrong voter list witness
  // create witness for index 2
  const voter_list_witness = new VoterListMerkleWitness(voter_list_tree.getWitness(2n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  const nullifier_hash = Poseidon.hash(priv_key_array[1].toFields().concat([ballot_ID]))
  const nullifier_witness = nullifier_map.getWitness(nullifier_hash);

  const option = 0n;
  const vote_count_witness = new VoteCountMerkleWitness(vote_count_tree.getWitness(option))
  const currentVotes = vote_count_tree.getNode(0, option);

  console.log("\n--- vote() called incorrectly- wrong voter list witness ---");
  console.log("Before if - nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());

  try{
    const txn2 = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[1], 
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn2.prove(); 
    const txn2_result = await txn2.sign([deployerKey]).send();
    if (txn2_result.isSuccess){
      // update off chain state
      updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After if- nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  
}

{
  // call vote()- incorrectly- wrong private key
  // create witness for index 1
  const voter_list_witness = new VoterListMerkleWitness(voter_list_tree.getWitness(1n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  const nullifier_hash = Poseidon.hash(priv_key_array[1].toFields().concat([ballot_ID]))
  const nullifier_witness = nullifier_map.getWitness(nullifier_hash);

  const option = 0n;
  const vote_count_witness = new VoteCountMerkleWitness(vote_count_tree.getWitness(option))
  const currentVotes = vote_count_tree.getNode(0, option);

  console.log("\n--- vote() called incorrectly- wrong private key ---");
  console.log("Before if - nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());

  try{
    const txn2 = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[2], 
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn2.prove(); 
    const txn2_result = await txn2.sign([deployerKey]).send();
    if (txn2_result.isSuccess){
      // update off chain state
      updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After if- nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  
}

{
  // call vote()- correctly
  // create witness for index 1
  const voter_list_witness = new VoterListMerkleWitness(voter_list_tree.getWitness(1n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  const nullifier_hash = Poseidon.hash(priv_key_array[1].toFields().concat([ballot_ID]))
  const nullifier_witness = nullifier_map.getWitness(nullifier_hash);

  const option = 1n;
  const vote_count_witness = new VoteCountMerkleWitness(vote_count_tree.getWitness(option))
  const currentVotes = vote_count_tree.getNode(0, option);

  console.log("\n--- vote() called correctly ---");
  console.log("Before if - nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());

  try{
    const txn2 = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[1], 
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn2.prove(); 
    const txn2_result = await txn2.sign([deployerKey]).send();
    if (txn2_result.isSuccess){
      // update off chain state
      updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After if- nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  
}

console.log("The vote count tree is: ")
displayTree(vote_count_tree);

/*


{
  // call vote()- correctly
  console.log("\n--- vote() called - correctly ---");
  // create witness for index 2
  const voter_list_witness = new VoterListMerkleWitness(voter_list_tree.getWitness(2n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  const nullifier_hash = Poseidon.hash(priv_key_array[2].toFields().concat([ballot_ID]))
  const nullifier_witness = nullifier_map.getWitness(nullifier_hash);


  console.log("Before if nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());
  try{
    const txn2 = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[2], // private key is wrong
        voter_list_witness, 
        nullifier_witness
      )
    });
    await txn2.prove(); 
    const txn2_result = await txn2.sign([deployerKey]).send();
    if (txn2_result.isSuccess){
      // set nullifier_map[nullifier_hash] = 1
      nullifier_map.set(nullifier_hash, Field(1));
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After if nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
}

{
  // call vote()- attempt double voting
  console.log("\n--- vote() called - attempt double voting ---");
  // create witness for index 0
  const voter_list_witness = new VoterListMerkleWitness(voter_list_tree.getWitness(0n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  const nullifier_hash = Poseidon.hash(priv_key_array[0].toFields().concat([ballot_ID]))
  const nullifier_witness = nullifier_map.getWitness(nullifier_hash);

  console.log("Before if nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());
  try{
    const txn2 = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[0],
        voter_list_witness, 
        nullifier_witness
      )
    });
    await txn2.prove(); 
    const txn2_result = await txn2.sign([deployerKey]).send();
    if (txn2_result.isSuccess){
      // set nullifier_map[nullifier_hash] = 1
      nullifier_map.set(nullifier_hash, Field(1));
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After if nullifier_map[nullifier_hash]:", nullifier_map.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
}
*/

console.log('Shutting down');

await shutdown();

/*
Questions: 
1) Can we simply change the contract if we know its private key?
2) Are the public keys of people interacting with contract visible to the public?
*/


