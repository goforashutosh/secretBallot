// run using 
// npm run build && node build/src/voteAggr-main.js

// helpful code: 
// https://github.com/es92/zkApp-examples/blob/main/09-recursion/src/vote.ts

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
  UInt32, 
  SelfProof,
  Experimental, 
  verify, 
  Struct, 
  MerkleMapWitness
} from 'snarkyjs';

import {
  secretBallot
} from './secretBallot.js';

import {
  voteTxn,
  voteDataProof, 
  offChainStateChange, 
  offChainStateProofs, 
  VoterListMerkleWitness, 
  VoteCountMerkleWitness
} from './voteAggregation.js'

import {readFileSync} from 'fs';
import * as inputs from './inputs.js';

// import assert;
// var assert = require('assert');

/**
* Displays all relevant state variables of the zkapp
* @param zk_app_inst The zkapp you want to display
*/
function dispAllVar(zk_app_inst: secretBallot){
  console.log("\nAll state variables of the contract are:")
  console.log("voter list root: ", zk_app_inst.voter_list_root.get().toString());
  console.log("vote count root: ", zk_app_inst.vote_count_root.get().toString());
  console.log("nullifier map root: ", zk_app_inst.nullifier_map_root.get().toString());
  console.log("initialised_flag: ", zk_app_inst.initialised_flag.get().toString());
  console.log("ballot_ID: ", zk_app_inst.ballot_ID.get().toString());
}

/**
* Function displays the given Merkle tree level by level
* @param mtree is the Merkle tree you want to display
*/
function displayTree(mtree: MerkleTree){
  let h = mtree.height;
  for(let i= 0; i<h; i++){
    console.log("Level:", i);
    for(let j=0; j < 2**(h-1-i); j++){
      console.log(mtree.getNode(i,BigInt(j)).toString());
    }
  }
}

/**
 * Used to store the Merkle trees and maps
 */
class offChainStorage{
  readonly voterListTree: MerkleTree;
  voteCountTree: MerkleTree; 
  nullifierMap: MerkleMap;
  
  /**
   * @param log_num_voters is the ceiling of the log of the number of voters
   * @param log_options is the ceiling of the log of the number of voting options
   * @param voterList is array containing hashes of public keys which are allowed to vote
   */
  constructor(log_num_voters: number, log_options: number, voterList: Field[]){
    // need to add 1 to make the height right
    this.voterListTree = new MerkleTree(log_num_voters + 1);
    this.voteCountTree= new MerkleTree(log_options + 1);
    this.nullifierMap= new MerkleMap();

    this.voterListTree.fill(voterList);

  }

  /**  
  * Used to update the nullifierMap and voteCountTree after a successful vote
  */
  updateOffChainState(nullifier_hash: Field, vote_option: bigint){
    this.nullifierMap.set(nullifier_hash, Field(1));
    const current_votes = this.voteCountTree.getNode(0, vote_option);
    this.voteCountTree.setLeaf(vote_option, current_votes.add(1));
  }
}

/**
 * This function takes an array (length=N) of proofs and merges proofs (2i, 2i+1) to create an array of proofs ceil(N/2) long. This can be parallelised in practice
 * @param seqProofs The array of proofs to merge. 
 */
async function _singleStepMergeSequentialProofs(seqProofs: Array<SelfProof<offChainStateChange>>){
  const N = seqProofs.length;
  let mergedProofs = new Array<SelfProof<offChainStateChange>>();
  const newN = Math.ceil(N/2);
  for(let i=0; i<newN-1; i++){  
    // need to deep copy
    const mergeProofStateChange = 
      new offChainStateChange({
      // initialise stateChange with the first proofs public input
      ballotID: seqProofs[2*i].publicInput.ballotID,
      voterListRoot: seqProofs[2*i].publicInput.voterListRoot,

      nullifierMapRoot: seqProofs[2*i].publicInput.nullifierMapRoot,
      voteCountRoot: seqProofs[2*i].publicInput.voteCountRoot, 

      // change the modified variables to the second proofs variables
      modifiedNullifierMapRoot: seqProofs[2*i+1].publicInput.modifiedNullifierMapRoot,
      modifiedVoteCountRoot: seqProofs[2*i+1].publicInput.modifiedVoteCountRoot
    });
    console.log("Merging", 2*i, "and", 2*i+1);
    mergedProofs.push(await offChainStateProofs.merge(mergeProofStateChange, seqProofs[2*i], seqProofs[2*i+1]))
  }
  // divide the last merge proof element into two cases depending on parity of N
  if(N%2 === 0){
    const mergeProofStateChange = 
      new offChainStateChange({
      // initialise stateChange with the first proofs public input
      ballotID: seqProofs[2*(newN-1)].publicInput.ballotID,
      voterListRoot: seqProofs[2*(newN-1)].publicInput.voterListRoot,

      nullifierMapRoot: seqProofs[2*(newN-1)].publicInput.nullifierMapRoot,
      voteCountRoot: seqProofs[2*(newN-1)].publicInput.voteCountRoot, 

      // change the modified variables to the second proofs variables
      modifiedNullifierMapRoot: seqProofs[2*(newN-1)+1].publicInput.modifiedNullifierMapRoot,
      modifiedVoteCountRoot: seqProofs[2*(newN-1)+1].publicInput.modifiedVoteCountRoot
    }); 
    console.log("Merging", 2*(newN-1), "and", 2*(newN-1)+1);
    mergedProofs.push(await offChainStateProofs.merge(mergeProofStateChange, seqProofs[2*(newN-1)], seqProofs[2*(newN-1)+1]))
  } else {
    // in case N is odd just push the last element on the mergeProof array
    mergedProofs.push(seqProofs[N-1]);
  }
  return mergedProofs;
}

/**
 * This function takes an array (length=N) of proofs and merges all the proofs into a single proof by repeatedly calling _singleStepMergeSequentialProofs
 * @param seqProofs The array of proofs to merge. 
 */
async function mergeSequentialProofs(seqProofs: Array<SelfProof<offChainStateChange>>){
  let mergedProofs = seqProofs;
  while(mergedProofs.length > 1){
    console.log("Calling _singleStepMergeSequentialProofs; len(mergedProofs)", mergedProofs.length);
    mergedProofs = await _singleStepMergeSequentialProofs(mergedProofs);
  }
  return mergedProofs[0];
}

await isReady;

console.time('prog_timer')
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

// create verfication key for local proofs
console.log('Compiling voteDataProof...');
const vk_dict1 = await voteDataProof.compile();


console.log('Compiling offChainStateProofs...');
const vk_dict2 = await offChainStateProofs.compile();

console.log("Success compiling");


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

const ballot_ID = zkAppInstance.ballot_ID.get();

async function createVote(priv_key_index: number, option: bigint): Promise<SelfProof<voteTxn>>{
  const voter_list_witness = new VoterListMerkleWitness(offChainVar.voterListTree.getWitness(BigInt(priv_key_index)));
  
  const nullifier_hash = Poseidon.hash(priv_key_array[priv_key_index].toFields().concat([ballot_ID]))
  const txn_public_data = new voteTxn({
    nullifierHash: nullifier_hash,
    voteChoice: Field(option), 
    voterListTreeRoot: offChainVar.voterListTree.getRoot(),
    ballotID: ballot_ID
  });
  let voteProof = voteDataProof.verifyData(txn_public_data, priv_key_array[priv_key_index], voter_list_witness);
  return voteProof;
}

console.log("Simulating the voters now:")

// if I try async proof production I get:
// Error: It seems you're running multiple provers concurrently within the same JavaScript thread, which, at the moment, is not supported and would lead to bugs. 
let voteProofs =  new Array<SelfProof<voteTxn>>();
for (let i=0; i<priv_key_array.length; i++){
  voteProofs.push(await createVote(i, 0n));
}

// The program should not require private keys any more
priv_key_array = [];
console.log("Private keys deleted from program memory");

console.log("Simulating the vote Aggregator now on:")

// Aggregator verifies if the votes it received are valid
let verifyVotePromises: Promise<boolean>[] = [];
for(let i=0; i<voteProofs.length; i++){
  verifyVotePromises.push(voteDataProof.verify(voteProofs[i]));
}
const verifyVotesResults= await Promise.all(verifyVotePromises);
console.log("Vote verification results: ", verifyVotesResults);

let seqVoteProofs = new Array<SelfProof<offChainStateChange>>();
// sequentially apply all the votes in the voteProofs array, generate offChainStateProofs for them, store the relevant state changes and create local proofs for them
for(let i=0; i<voteProofs.length; i++){
  // skip if vote is invalid
  if(!verifyVotesResults[i]){
    continue;
  }
  const voterListRoot=  offChainVar.voterListTree.getRoot();
  const nullifierMapRoot = offChainVar.nullifierMap.getRoot();
  const voteCountRoot = offChainVar.voteCountTree.getRoot();
  const nullifierWitness = offChainVar.nullifierMap.getWitness(voteProofs[i].publicInput.nullifierHash);
  const voteCountWitness = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(voteProofs[i].publicInput.voteChoice.toBigInt()));
  const currentVotes = offChainVar.voteCountTree.getNode(0, voteProofs[i].publicInput.voteChoice.toBigInt());

  // update state by applying the vote to it
  offChainVar.updateOffChainState(voteProofs[i].publicInput.nullifierHash, voteProofs[i].publicInput.voteChoice.toBigInt());
  const modifiedNullifierMapRoot = offChainVar.nullifierMap.getRoot();
  const modifiedVoteCountRoot = offChainVar.voteCountTree.getRoot();
  const stateChange = new offChainStateChange({
    ballotID: ballot_ID,
    voterListRoot: voterListRoot,
    nullifierMapRoot: nullifierMapRoot,
    voteCountRoot: voteCountRoot,
    modifiedNullifierMapRoot: modifiedNullifierMapRoot, 
    modifiedVoteCountRoot: modifiedVoteCountRoot
  });
  seqVoteProofs.push(await offChainStateProofs.vote(stateChange, voteProofs[i], nullifierWitness, voteCountWitness, currentVotes));
}

console.log("Calling mergeSequentialProofs");

const mergedVoteProof = await mergeSequentialProofs(seqVoteProofs);

console.log("Verifying mergedVoteProof");

const verifMergedProof = await offChainStateProofs.verify(mergedVoteProof);

console.log("mergedVoteProof verification result = ", verifMergedProof);

console.log("Asserting stuff");
mergedVoteProof.publicInput.modifiedNullifierMapRoot.assertEquals(offChainVar.nullifierMap.getRoot());
mergedVoteProof.publicInput.modifiedVoteCountRoot.assertEquals(offChainVar.voteCountTree.getRoot());
mergedVoteProof.publicInput.nullifierMapRoot.assertEquals(zkAppInstance.nullifier_map_root.get());
mergedVoteProof.publicInput.voteCountRoot.assertEquals(zkAppInstance.vote_count_root.get());

{
  // call aggregateVote() on the zkApp

  console.log("\n--- aggregateVote() called correctly ---");
  
  try{
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.aggregateVote(mergedVoteProof)
    });

    console.log("Hello1");
    await txn.prove(); 
    console.log("Hello1");
    const txn_result = await txn.sign([deployerKey]).send();
    if (txn_result.isSuccess){
      console.log("Transaction successful");
    }
  } catch(err: any){
    // console.error("Error:", err.message);
    throw err;
  } finally {
  }
}

dispAllVar(zkAppInstance);
console.log("The root of offChainVar.nullifierMap", offChainVar.nullifierMap.getRoot().toString());
console.log("The root of offChainVar.voteCountTree", offChainVar.voteCountTree.getRoot().toString());


console.timeEnd('prog_timer')
await shutdown();

// this takes 24min