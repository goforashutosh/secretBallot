// run using 
// npm run build && node build/src/singleVote-main.js
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
  Poseidon,
  UInt32
} from 'snarkyjs';

import {
  secretBallot
} from './secretBallot.js';

import {
  VoterListMerkleWitness, 
  VoteCountMerkleWitness
} from './voteAggregation.js';

import {offChainStorage, displayTree, dispAllVar} from './offChainStorage.js'


import {readFileSync} from 'fs';
import * as inputs from './inputs.js';

await isReady;

console.log('SnarkyJS loaded');

let priv_key_array_str: string[] = [];
let pub_key_array_str: string[] = [];

priv_key_array_str = JSON.parse(readFileSync('keys/private_keys.json', 'utf8'));
pub_key_array_str = JSON.parse(readFileSync('keys/public_keys.json', 'utf8'));

// console.log(priv_key_array_str);
console.log("\nThe public keys are: ");
console.log(pub_key_array_str);

let priv_key_array: PrivateKey[] = [];
let pub_key_array: PublicKey[] = [];

priv_key_array = priv_key_array_str.map(key => PrivateKey.fromBase58(key));
pub_key_array = pub_key_array_str.map(key => PublicKey.fromBase58(key));

let pub_key_hash_arr: Field[] = pub_key_array.map(key => Poseidon.hash(key.toFields()));

let offChainVar = new offChainStorage(inputs.log_num_voters, inputs.log_options, pub_key_hash_arr);

console.log("\nThe voter list Merkle tree is:");
displayTree(offChainVar.voterListTree);


// Smart contract deployment

const useProof = false;

const Local = Mina.LocalBlockchain({ proofsEnabled: useProof });
Mina.setActiveInstance(Local);

const { privateKey: deployerKey, publicKey: deployerAccount } = Local.testAccounts[0];

// ----------------------------------------------------
// Create a public/private key pair. The public key is our address and where we will deploy to
const zkAppPrivateKey = PrivateKey.random();
const zkAppAddress = zkAppPrivateKey.toPublicKey();

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
// using code blocks allows me to copy paste easily
{
  const txn = await Mina.transaction(deployerAccount, () => {
    zkAppInstance.initState(Field.random(), offChainVar.voterListTree.getRoot());
  });
  console.log("The block length is", Local.getNetworkState().blockchainLength.toString());
  console.log("\n--- initState() called ---");
  await txn.prove(); 
  await txn.sign([deployerKey]).send();
  dispAllVar(zkAppInstance);

  console.log("\nThe vote count tree is: ")
  displayTree(offChainVar.voteCountTree);
  console.log("The block length is", Local.getNetworkState().blockchainLength.toString());
}

{
  // call vote()- correctly

  console.log("\nBlock length increased to 10");
  Local.setBlockchainLength(UInt32.from(10));

  console.log("\n--- vote() called correctly for private_key[0]- voting for option 0 ---");
  
  // create witness for index 0
  const voter_list_witness = new VoterListMerkleWitness(offChainVar.voterListTree.getWitness(0n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  const nullifier_hash = Poseidon.hash(priv_key_array[0].toFields().concat([ballot_ID]))
  const nullifier_witness = offChainVar.nullifierMap.getWitness(nullifier_hash);

  const option = 0n;
  const vote_count_witness = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(option))
  const currentVotes = offChainVar.voteCountTree.getNode(0, option);

  console.log("Before txn call - (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());

  // should use a different account for submitting the vote txn than what is used for voting
  // can use any account to submit txn-- account should only know what the correct private key is
  try{
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[0], 
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn.prove(); 
    const txn_result = await txn.sign([deployerKey]).send();
    // update the off chain state only if the txn succeeds
    if (txn_result.isSuccess){
      // update off chain state
      offChainVar.updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After txn call- (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  console.log("The block length is", Local.getNetworkState().blockchainLength.toString());
}

{
  // call vote()- incorrectly- wrong voter list witness
  console.log("\n--- vote() called incorrectly- wrong voter list witness ---");
  
  // create witness for index 2
  const voter_list_witness = new VoterListMerkleWitness(offChainVar.voterListTree.getWitness(2n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  // private_key[1] used - not yet voted with this
  const nullifier_hash = Poseidon.hash(priv_key_array[1].toFields().concat([ballot_ID]))
  const nullifier_witness = offChainVar.nullifierMap.getWitness(nullifier_hash);

  const option = 0n;
  const vote_count_witness = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(option))
  const currentVotes = offChainVar.voteCountTree.getNode(0, option);

  console.log("Before txn call - (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
  
  try{
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[1], 
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn.prove(); 
    const txn_result = await txn.sign([deployerKey]).send();
    // update the off chain state only if the txn succeeds
    if (txn_result.isSuccess){
      // update off chain state
      offChainVar.updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After txn call- (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  console.log("The block length is", Local.getNetworkState().blockchainLength.toString());
}

{
  // call vote()- incorrectly- wrong private key
  console.log("\n--- vote() called incorrectly- wrong private key ---");
  // create witness for index 1
  const voter_list_witness = new VoterListMerkleWitness(offChainVar.voterListTree.getWitness(1n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  // private_key[1] used - not yet voted with this
  const nullifier_hash = Poseidon.hash(priv_key_array[1].toFields().concat([ballot_ID]))
  const nullifier_witness = offChainVar.nullifierMap.getWitness(nullifier_hash);

  const option = 0n;
  const vote_count_witness = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(option))
  const currentVotes = offChainVar.voteCountTree.getNode(0, option);

  console.log("Before txn call - (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
  
  try{
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[2],  // wrong private_key; correct would be priv_key_array[1]
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn.prove(); 
    const txn_result = await txn.sign([deployerKey]).send();
    // update the off chain state only if the txn succeeds
    if (txn_result.isSuccess){
      // update off chain state
      offChainVar.updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After txn call- (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  console.log("The block length is", Local.getNetworkState().blockchainLength.toString());
}

{
  // Shows the events created while voting
  const events = await zkAppInstance.fetchEvents(UInt32.from(10), UInt32.from(10));
  console.log("\nThe events in block length=10 are: ")
  events.forEach((elem, index, arr) => {
    console.log(elem.type, JSON.stringify(elem.event))
  })
}

{
  console.log("\nBlock length increased to 11");
  Local.setBlockchainLength(UInt32.from(11));

  // call vote()- correctly
  console.log("\n--- vote() called correctly for private_key[1] - voting for option 1---");
  // create witness for index 1
  const voter_list_witness = new VoterListMerkleWitness(offChainVar.voterListTree.getWitness(1n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  // private_key[1] used - not yet voted with this
  const nullifier_hash = Poseidon.hash(priv_key_array[1].toFields().concat([ballot_ID]))
  const nullifier_witness = offChainVar.nullifierMap.getWitness(nullifier_hash);

  // vote for option 1
  const option = 1n;
  const vote_count_witness = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(option))
  const currentVotes = offChainVar.voteCountTree.getNode(0, option);

  console.log("Before txn call - (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
  
  try{
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[1], 
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn.prove(); 
    const txn_result = await txn.sign([deployerKey]).send();
    // update the off chain state only if the txn succeeds
    if (txn_result.isSuccess){
      // update off chain state
      offChainVar.updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After txn call- (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  console.log("The block length is", Local.getNetworkState().blockchainLength.toString());
}

{
  // call vote()- incorrectly- double voting attempted
  console.log("\n--- vote() called incorrectly- double voting attempted ---");
  // create witness for index 1
  const voter_list_witness = new VoterListMerkleWitness(offChainVar.voterListTree.getWitness(1n));
  const ballot_ID = zkAppInstance.ballot_ID.get();

  // private_key[1] used - not yet voted with this
  const nullifier_hash = Poseidon.hash(priv_key_array[1].toFields().concat([ballot_ID]))
  const nullifier_witness = offChainVar.nullifierMap.getWitness(nullifier_hash);

  // vote for option 1
  const option = 1n;
  const vote_count_witness = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(option))
  const currentVotes = offChainVar.voteCountTree.getNode(0, option);

  console.log("Before txn call - (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
  
  try{
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.vote(
        priv_key_array[1], 
        voter_list_witness, 
        nullifier_witness, 
        vote_count_witness,
        currentVotes
      )
    });

    await txn.prove(); 
    const txn_result = await txn.sign([deployerKey]).send();
    // update the off chain state only if the txn succeeds
    if (txn_result.isSuccess){
      // update off chain state
      offChainVar.updateOffChainState(nullifier_hash, option);
    }
  } catch(err: any){
    console.error("Error:", err.message);
  } finally {
    console.log("After txn call- (local) nullifierMap[nullifier_hash]:", offChainVar.nullifierMap.get(nullifier_hash).toString());
    dispAllVar(zkAppInstance);
  }
  console.log("The block length is", Local.getNetworkState().blockchainLength.toString());
}

{
  // Shows the events created while voting
  const events = await zkAppInstance.fetchEvents(UInt32.from(11), UInt32.from(11));
  console.log("\nThe events in block length=11 are: ")
  events.forEach((elem, index, arr) => {
    console.log(elem.type, JSON.stringify(elem.event))
  })
}

console.log("\nThe vote count tree is: ")
displayTree(offChainVar.voteCountTree);

console.log('Shutting down');

await shutdown();

