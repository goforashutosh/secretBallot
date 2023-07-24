// run using 
// npm run build && npm run test

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
    secretBallot
  } from './secretBallot.js';

import {
    VoterListMerkleWitness, 
    VoteCountMerkleWitness, 
  } from './voteAggregation.js'

import {readFileSync} from 'fs';
import * as inputs from './inputs.js';


if ((inputs.log_num_voters <1) || (inputs.log_options <1 )){
  throw new Error('The inputs log_num_voters and log_options should both be at least 1 for testing.')
}

await isReady;

console.log('SnarkyJS loaded');

let priv_key_array_str: string[] = [];
let pub_key_array_str: string[] = [];

priv_key_array_str = JSON.parse(readFileSync('keys/private_keys.json', 'utf8'));
pub_key_array_str = JSON.parse(readFileSync('keys/public_keys.json', 'utf8'));

// console.log(priv_key_array_str);
// console.log("\nThe public keys are: ");
// console.log(pub_key_array_str);

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


describe('secretBallot testing', () => {

  const N = 2**inputs.log_num_voters;
  const idx = Math.floor(Math.random() * N);

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
      zkAppInstance.initState(randomFieldElem, offChainVar.voterListTree.getRoot());
    });
    // console.log("\n--- initState() called ---");
    await txn1.prove(); 
    await txn1.sign([deployerKey]).send();

    expect(zkAppInstance.voter_list_root.get())
      .toEqual(offChainVar.voterListTree.getRoot());
    expect(zkAppInstance.ballot_ID.get())
      .toEqual(randomFieldElem);
    expect(zkAppInstance.initialised_flag.get().toField())
      .toEqual(Field(1));
    expect(zkAppInstance.vote_count_root.get())
      .toEqual(offChainVar.voteCountTree.getRoot());
    expect(zkAppInstance.nullifier_map_root.get())
      .toEqual(offChainVar.nullifierMap.getRoot());
  });

  afterAll(async () => {
    setTimeout(shutdown, 0);
  });
    

  it('vote() called correctly and double voting attempt', async () => {
    
    // vote once

    const voter_list_witness = new VoterListMerkleWitness(offChainVar.voterListTree.getWitness(BigInt(idx)));
    const ballot_ID = zkAppInstance.ballot_ID.get();
  
    const nullifier_hash = Poseidon.hash(priv_key_array[idx].toFields().concat([ballot_ID]))
    const nullifier_witness = offChainVar.nullifierMap.getWitness(nullifier_hash);
  
    const option = 0n;
    const vote_count_witness = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(option))
    const currentVotes = offChainVar.voteCountTree.getNode(0, option);
  
    // no votes lodged should be 0
    expect(offChainVar.nullifierMap.get(nullifier_hash)).toEqual(Field(0));

    try{
      const txn = await Mina.transaction(interactionAccount, () => {
        zkAppInstance.vote(
          priv_key_array[idx], 
          voter_list_witness, 
          nullifier_witness, 
          vote_count_witness,
          currentVotes
        )
      });
  
      await txn.prove(); 
      const txn_result = await txn.sign([interactionKey]).send();
      // update the off chain state only if the txn succeeds
      if (txn_result.isSuccess){
        // update off chain state
        offChainVar.updateOffChainState(nullifier_hash, option);
      }
      
      // offChainVar are correctly updated
      expect(offChainVar.nullifierMap.get(nullifier_hash)).toEqual(Field(1));
      expect(offChainVar.voteCountTree.getNode(0, 0n)).toEqual(Field(1));
      expect(offChainVar.voteCountTree.getNode(0, 1n)).toEqual(Field(0));
      
      // on chain state is correctly updated
      expect(zkAppInstance.vote_count_root.get())
        .toEqual(offChainVar.voteCountTree.getRoot());
      expect(zkAppInstance.nullifier_map_root.get())
        .toEqual(offChainVar.nullifierMap.getRoot());
      
      // these on chain variables don't change: 
      expect(zkAppInstance.voter_list_root.get())
        .toEqual(offChainVar.voterListTree.getRoot());
      expect(zkAppInstance.ballot_ID.get())
        .toEqual(randomFieldElem);
      expect(zkAppInstance.initialised_flag.get().toField())
          .toEqual(Field(1));
    } catch(err: any){
      throw err;
    }

    // vote one more time with the next key
    const idx2 = (idx + 1)%N;

    const voter_list_witness2 = new VoterListMerkleWitness(offChainVar.voterListTree.getWitness(BigInt(idx2)));
  
    const nullifier_hash2 = Poseidon.hash(priv_key_array[idx2].toFields().concat([ballot_ID]))
    const nullifier_witness2 = offChainVar.nullifierMap.getWitness(nullifier_hash2);
  
    const option2 = 1n;
    const vote_count_witness2 = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(option2))
    const currentVotes2 = offChainVar.voteCountTree.getNode(0, option2);
  
    // no votes lodged should be 0
    expect(offChainVar.nullifierMap.get(nullifier_hash2)).toEqual(Field(0));
  
    try{
      const txn = await Mina.transaction(interactionAccount, () => {
        zkAppInstance.vote(
          priv_key_array[idx2], 
          voter_list_witness2, 
          nullifier_witness2, 
          vote_count_witness2,
          currentVotes2
        )
      });
  
      await txn.prove(); 
      const txn_result = await txn.sign([interactionKey]).send();
      if (txn_result.isSuccess){
        // update off chain state
        offChainVar.updateOffChainState(nullifier_hash2, option2);
      }
    } catch(err: any){
      throw err;
    }
    // off chain state is correctly updated
    expect(offChainVar.nullifierMap.get(nullifier_hash)).toEqual(Field(1));
    expect(offChainVar.nullifierMap.get(nullifier_hash2)).toEqual(Field(1));

    expect(offChainVar.voteCountTree.getNode(0, 0n)).toEqual(Field(1));
    expect(offChainVar.voteCountTree.getNode(0, 1n)).toEqual(Field(1));

    // on chain state is correctly updated
    expect(zkAppInstance.vote_count_root.get())
      .toEqual(offChainVar.voteCountTree.getRoot());
    expect(zkAppInstance.nullifier_map_root.get())
      .toEqual(offChainVar.nullifierMap.getRoot());

    // these on chain variables don't change: 
    expect(zkAppInstance.voter_list_root.get())
      .toEqual(offChainVar.voterListTree.getRoot());
    expect(zkAppInstance.ballot_ID.get())
      .toEqual(randomFieldElem);
    expect(zkAppInstance.initialised_flag.get().toField())
        .toEqual(Field(1));

    
    // attempt double voting using idx2

    const vote_count_witness3 = new VoteCountMerkleWitness(offChainVar.voteCountTree.getWitness(option2))
    const currentVotes3 = offChainVar.voteCountTree.getNode(0, option2);
    

    await expect(async () => {
      const txn = await Mina.transaction(interactionAccount, () => {
        zkAppInstance.vote(
          priv_key_array[idx2], 
          voter_list_witness2, 
          nullifier_witness2,
          vote_count_witness3,
          currentVotes3
        )
      });
  
      await txn.prove(); 
      const txn_result = await txn.sign([interactionKey]).send();
      if (txn_result.isSuccess){
        // update off chain state
        offChainVar.updateOffChainState(nullifier_hash2, option2);
      }
    }).rejects.toThrow();

    // everything remains the same as before
    expect(offChainVar.nullifierMap.get(nullifier_hash)).toEqual(Field(1));
    expect(offChainVar.nullifierMap.get(nullifier_hash2)).toEqual(Field(1));

    expect(offChainVar.voteCountTree.getNode(0, 0n)).toEqual(Field(1));
    expect(offChainVar.voteCountTree.getNode(0, 1n)).toEqual(Field(1));

    expect(zkAppInstance.vote_count_root.get())
      .toEqual(offChainVar.voteCountTree.getRoot());
    expect(zkAppInstance.nullifier_map_root.get())
      .toEqual(offChainVar.nullifierMap.getRoot());

    expect(zkAppInstance.voter_list_root.get())
      .toEqual(offChainVar.voterListTree.getRoot());
    expect(zkAppInstance.ballot_ID.get())
      .toEqual(randomFieldElem);
    expect(zkAppInstance.initialised_flag.get().toField())
      .toEqual(Field(1));
    
  });

  /* TODO: modify code so that witness testing can also be done- tests are run asynchronously so need to be careful
  */
})
