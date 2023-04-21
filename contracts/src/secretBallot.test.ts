// run using 
// npm run build && npm run test

/*
 This file is just the main file converted to a bunch of tests
*/

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

/**
 * Displays all relevant state variables of the zkapp
 * @param zk_app_inst The zkapp you want to display
 */
function dispAllVar(zk_app_inst: secretBallot){
  console.log("\nAll variables of the contract are:")
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
function displayTree(mtree:MerkleTree){
  let h = mtree.height;
  for(let i= 0; i<h; i++){
    console.log("Level:", i);
    for(let j=0; j < 2**(h-1-i); j++){
      console.log(mtree.getNode(i,BigInt(j)).toString());
    }
  }
}

await isReady;

// console.log('SnarkyJS loaded');

let priv_key_array_str: string[] = [];
let pub_key_array_str: string[] = [];

priv_key_array_str = JSON.parse(readFileSync('keys/private_keys.json', 'utf8'));
pub_key_array_str = JSON.parse(readFileSync('keys/public_keys.json', 'utf8'));

// console.log(priv_key_array_str);
// console.log(pub_key_array_str);

let priv_key_array: PrivateKey[] = [];
let pub_key_array: PublicKey[] = [];

priv_key_array = priv_key_array_str.map(key => PrivateKey.fromBase58(key));
pub_key_array = pub_key_array_str.map(key => PublicKey.fromBase58(key));

// need to add 1 to make the height right
let voter_list_tree = new MerkleTree(inputs.log_num_voters + 1);

let pub_key_hash_arr: Field[] = pub_key_array.map(key => Poseidon.hash(key.toFields()));
voter_list_tree.fill(pub_key_hash_arr);

// console.log("The Merkle Tree is:");
// displayTree(voter_list_tree);
// console.log("Root is: ", voter_list_tree.getRoot().toString());

let vote_count_tree = new MerkleTree(inputs.log_options + 1);
let nullifier_map = new MerkleMap();

/**  
 * Used to update the nullifier_map and vote_count_tree after a successful vote
 */
function updateOffChainState(nullifier_hash: Field, vote_option: bigint){
  nullifier_map.set(nullifier_hash, Field(1));
  const current_votes = vote_count_tree.getNode(0, vote_option);
  vote_count_tree.setLeaf(vote_option, current_votes.add(1));
}


describe('secretBallot testing', () => {

  const N = 2**inputs.log_num_voters;
  let zkAppInstance: secretBallot, 
  interactionAccount: PublicKey,
  interactionKey: PrivateKey,
  randomFieldElem: Field;
  
  beforeAll(async ()=>{
    // Smart contract deployment

    const useProof = false;

    const Local = Mina.LocalBlockchain({ proofsEnabled: useProof });
    Mina.setActiveInstance(Local);

    const { privateKey: deployerKey, publicKey: deployerAccount } = Local.testAccounts[0];

    interactionAccount = Local.testAccounts[0].publicKey;
    interactionKey = Local.testAccounts[0].privateKey;

    // Create a public/private key pair. The public key is our address and where we will deploy to
    const zkAppPrivateKey = PrivateKey.random();
    const zkAppAddress = zkAppPrivateKey.toPublicKey();

    // create an instance of secretBallot - and deploy it to zkAppAddress
    zkAppInstance = new secretBallot(zkAppAddress);
    const deployTxn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkAppInstance.deploy();
      // zkAppInstance.initState(Field.random(), voter_list_tree.getRoot()); // this doesn't work here
    });
    // console.log("\n--- init() called ---");
    await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();
    // dispAllVar(zkAppInstance);

    // call initState() separately
    randomFieldElem = Field.random();
    const txn1 = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.initState(randomFieldElem, voter_list_tree.getRoot());
    });
    // console.log("\n--- initState() called ---");
    await txn1.prove(); 
    await txn1.sign([deployerKey]).send();

    expect(zkAppInstance.voter_list_root.get())
      .toEqual(voter_list_tree.getRoot());
    expect(zkAppInstance.ballot_ID.get())
      .toEqual(randomFieldElem);
    expect(zkAppInstance.initialised_flag.get().toField())
      .toEqual(Field(1));
    expect(zkAppInstance.vote_count_root.get())
      .toEqual(vote_count_tree.getRoot());
    expect(zkAppInstance.nullifier_map_root.get())
      .toEqual(nullifier_map.getRoot());
  });

  afterAll(async () => {
    setTimeout(shutdown, 0);
  });

  it('vote() called correctly', async () => {
    
    // vote once
    const idx = Math.floor(Math.random() * N);

    const voter_list_witness = new VoterListMerkleWitness(voter_list_tree.getWitness(BigInt(idx)));
    const ballot_ID = zkAppInstance.ballot_ID.get();
  
    const nullifier_hash = Poseidon.hash(priv_key_array[idx].toFields().concat([ballot_ID]))
    const nullifier_witness = nullifier_map.getWitness(nullifier_hash);
  
    const option = 0n;
    const vote_count_witness = new VoteCountMerkleWitness(vote_count_tree.getWitness(option))
    const currentVotes = vote_count_tree.getNode(0, option);
  
    // no votes lodged should be 0
    expect(nullifier_map.get(nullifier_hash)).toEqual(Field(0));
  
    try{
      const txn2 = await Mina.transaction(interactionAccount, () => {
        zkAppInstance.vote(
          priv_key_array[idx], 
          voter_list_witness, 
          nullifier_witness, 
          vote_count_witness,
          currentVotes
        )
      });
  
      await txn2.prove(); 
      const txn2_result = await txn2.sign([interactionKey]).send();
      if (txn2_result.isSuccess){
        // update off chain state
        updateOffChainState(nullifier_hash, option);
      }
      expect(nullifier_map.get(nullifier_hash)).toEqual(Field(1));
      expect(vote_count_tree.getNode(0, 0n)).toEqual(Field(1));
      expect(vote_count_tree.getNode(0, 1n)).toEqual(Field(0));
      expect(zkAppInstance.vote_count_root.get())
        .toEqual(vote_count_tree.getRoot());
      expect(zkAppInstance.nullifier_map_root.get())
        .toEqual(nullifier_map.getRoot());
      // don't change: 
      expect(zkAppInstance.voter_list_root.get())
        .toEqual(voter_list_tree.getRoot());
      expect(zkAppInstance.ballot_ID.get())
        .toEqual(randomFieldElem);
      expect(zkAppInstance.initialised_flag.get().toField())
          .toEqual(Field(1));
    } catch(err: any){
      throw err;
    }

    // vote one more time
    const idx2 = (idx + 1)%N;

    const voter_list_witness2 = new VoterListMerkleWitness(voter_list_tree.getWitness(BigInt(idx2)));
  
    const nullifier_hash2 = Poseidon.hash(priv_key_array[idx2].toFields().concat([ballot_ID]))
    const nullifier_witness2 = nullifier_map.getWitness(nullifier_hash2);
  
    const option2 = 1n;
    const vote_count_witness2 = new VoteCountMerkleWitness(vote_count_tree.getWitness(option2))
    const currentVotes2 = vote_count_tree.getNode(0, option2);
  
    // no votes lodged should be 0
    expect(nullifier_map.get(nullifier_hash2)).toEqual(Field(0));
  
    try{
      const txn3 = await Mina.transaction(interactionAccount, () => {
        zkAppInstance.vote(
          priv_key_array[idx2], 
          voter_list_witness2, 
          nullifier_witness2, 
          vote_count_witness2,
          currentVotes2
        )
      });
  
      await txn3.prove(); 
      const txn3_result = await txn3.sign([interactionKey]).send();
      if (txn3_result.isSuccess){
        // update off chain state
        updateOffChainState(nullifier_hash2, option2);
      }
    } catch(err: any){
      throw err;
    }
    expect(nullifier_map.get(nullifier_hash)).toEqual(Field(1));
    expect(nullifier_map.get(nullifier_hash2)).toEqual(Field(1));

    expect(vote_count_tree.getNode(0, 0n)).toEqual(Field(1));
    expect(vote_count_tree.getNode(0, 1n)).toEqual(Field(1));

    expect(zkAppInstance.vote_count_root.get())
      .toEqual(vote_count_tree.getRoot());
    expect(zkAppInstance.nullifier_map_root.get())
      .toEqual(nullifier_map.getRoot());

    // don't change: 
    expect(zkAppInstance.voter_list_root.get())
      .toEqual(voter_list_tree.getRoot());
    expect(zkAppInstance.ballot_ID.get())
      .toEqual(randomFieldElem);
    expect(zkAppInstance.initialised_flag.get().toField())
        .toEqual(Field(1));

    
    // I couldn't get this part to work
    
    // attempt double voting using idx2
    /*
    const vote_count_witness3 = new VoteCountMerkleWitness(vote_count_tree.getWitness(option2))
    const currentVotes3 = vote_count_tree.getNode(0, option2);
    
    expect(async () => {
      const txn4 = await Mina.transaction(interactionAccount, () => {
        zkAppInstance.vote(
          priv_key_array[idx2], 
          voter_list_witness2, 
          nullifier_witness2, 
          vote_count_witness3,
          currentVotes3
        )
      });
  
      await txn4.prove(); 
      const txn4_result = await txn4.sign([interactionKey]).send();
      if (txn4_result.isSuccess){
        // update off chain state
        updateOffChainState(nullifier_hash2, option2);
      }
  }).toThrow();

  expect(nullifier_map.get(nullifier_hash)).toEqual(Field(1));
  expect(nullifier_map.get(nullifier_hash2)).toEqual(Field(1));

  expect(vote_count_tree.getNode(0, 0n)).toEqual(Field(1));
  expect(vote_count_tree.getNode(0, 1n)).toEqual(Field(1));

  expect(zkAppInstance.vote_count_root.get())
    .toEqual(vote_count_tree.getRoot());
  expect(zkAppInstance.nullifier_map_root.get())
    .toEqual(nullifier_map.getRoot());

  // don't change: 
  expect(zkAppInstance.voter_list_root.get())
    .toEqual(voter_list_tree.getRoot());
  expect(zkAppInstance.ballot_ID.get())
    .toEqual(randomFieldElem);
  expect(zkAppInstance.initialised_flag.get().toField())
    .toEqual(Field(1));
  */
  })

})
