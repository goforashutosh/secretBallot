// run using 
// npm run build && node build/src/main.js
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
  secretBallot,
  VoterListMerkleWitness, 
  VoteCountMerkleWitness
} from './secretBallot.js';

import {readFileSync} from 'fs';
import * as inputs from './inputs.js';

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

