// run using 
// npm run build && node build/src/voteAggregation.js
import {
  Field,
  PrivateKey,
  PublicKey,
  MerkleTree,
  MerkleMap,
  Poseidon,
  SelfProof,
  Experimental, 
  verify, 
  Struct, 
  MerkleMapWitness, 
  MerkleWitness,
  Proof
} from 'snarkyjs';

import * as inputs from './inputs.js';

// root is also one of the levels
export class VoterListMerkleWitness extends MerkleWitness(inputs.log_num_voters + 1){}
export class VoteCountMerkleWitness extends MerkleWitness(inputs.log_options + 1){}

/**
* Struct to store data related to an end user's vote
*/ 
export class voteTxn extends Struct({
  nullifierHash: Field, 
  voteChoice: Field, 
  // none of these change during the voting 
  voterListTreeRoot: Field, 
  ballotID: Field
}){}

/**
 * This is used by the end user to create a proof that he is a valid voter and his nullifierHash is correct
 * verifyData fn on this will be used by both the zkapp on MINA and the aggregator
 */
export const voteDataProof = Experimental.ZkProgram({
  publicInput: voteTxn,
  methods: {
    verifyData: {
      privateInputs: [PrivateKey, VoterListMerkleWitness],
      method(
        voterInfo: voteTxn, 
        votingKey: PrivateKey, 
        voterListWitness: VoterListMerkleWitness
      ) {
          const leafVal = Poseidon.hash(
            votingKey.toPublicKey().toFields()
          );

          leafVal.assertEquals(
            Poseidon.hash(
              votingKey.toPublicKey().toFields()
            )
          );

          // verify that the leaf is in the voterListTree
          const calculatedRoot = voterListWitness.calculateRoot(leafVal);
          voterInfo.voterListTreeRoot.assertEquals(calculatedRoot);

          // verify that the nullifierHash is valid
            
          const derivedNullifierHash = Poseidon.hash(votingKey.toFields().concat([voterInfo.ballotID]));
          // The derivedNullifierHash is correctly generated = hash(privateKey.toFields(), ballot_ID)
          derivedNullifierHash.assertEquals(
            Poseidon.hash(votingKey.toFields().concat([voterInfo.ballotID]))
          );
          
          // ensure that the provided nullifier is correct
          voterInfo.nullifierHash.assertEquals(derivedNullifierHash);
      }
    }
  }
});

// In the following, we are using the Rollup idea for high throughput given at:
// https://docs.minaprotocol.com/zkapps/tutorials/recursion

/**
 * This Struct contains the mutable state variables of the zkapp and their modified values. 
 * This is used as a public input for aggregator proofs, which show that there exist a valid transition between the original and modified state variables
 */
export class offChainStateChange extends Struct({
  ballotID: Field,
  voterListRoot: Field,

  nullifierMapRoot: Field,
  voteCountRoot: Field, 

  modifiedNullifierMapRoot: Field,
  modifiedVoteCountRoot: Field
}) {}

/**
 * Best way to view these is that you are trying to convince the on chain verifier that a certain state transition is valid. 
 * The simplest is the single vote transition given by the vote method, which just takes one vote and applies it to the state to create a state transition. 
 * The merge method combines two consecutive valid state transitions and creates a proof for the validity of the combined transition. 
 */
export const offChainStateProofs = Experimental.ZkProgram({
  publicInput: offChainStateChange,
  methods : {
    vote: {
      privateInputs: [
        Experimental.ZkProgram.Proof(voteDataProof), 
        MerkleMapWitness, 
        VoteCountMerkleWitness, 
        Field
      ],
      method(
        stateChange: offChainStateChange, 
        voteProof: Proof<voteTxn>, 
        nullifierWitness: MerkleMapWitness, 
        voteCountWitness: VoteCountMerkleWitness, 
        voteCountLeafVal: Field
        ){

          // make sure that the vote data provided is valid
          voteProof.verify();

          voteProof.publicInput.voterListTreeRoot.assertEquals(stateChange.voterListRoot);
          voteProof.publicInput.ballotID.assertEquals(stateChange.ballotID);
          
          // The following makes sure that :
          // 1) the value at the key location is 0 for the witness AND
          // 2) witness is correct for some key
          // 3) the key is indeed the nullifierHash
          // => nullifierMap[nullifierHash] = 0
          const [calcNullifierRoot, calcNullifierKey] = nullifierWitness.computeRootAndKey(Field(0));
          stateChange.nullifierMapRoot.assertEquals(calcNullifierRoot);
          calcNullifierKey.assertEquals(voteProof.publicInput.nullifierHash);

          // // Vote and update vote count tree
          const claimedVoteCountRoot = voteCountWitness.calculateRoot(voteCountLeafVal);
          stateChange.voteCountRoot.assertEquals(claimedVoteCountRoot);

          stateChange.modifiedVoteCountRoot.assertEquals(
              voteCountWitness.calculateRoot(voteCountLeafVal.add(1))
          );
          
          // // set nullifier_map[nullifierHash] = 1
          const [newNullifierRoot, _] = nullifierWitness.computeRootAndKey(Field(1));
          stateChange.modifiedNullifierMapRoot.assertEquals(newNullifierRoot);
          
        }
    },
    merge: {
      privateInputs: [SelfProof, SelfProof], 
      method(
        stateChange: offChainStateChange, 
        proof1: SelfProof <offChainStateChange>, 
        proof2: SelfProof <offChainStateChange>, 
      ){
        proof1.verify(); 
        proof2.verify(); 

        stateChange.voterListRoot.assertEquals(proof1.publicInput.voterListRoot);
        stateChange.voterListRoot.assertEquals(proof2.publicInput.voterListRoot);

        stateChange.ballotID.assertEquals(proof1.publicInput.ballotID);
        stateChange.ballotID.assertEquals(proof2.publicInput.ballotID);

        stateChange.nullifierMapRoot.assertEquals(proof1.publicInput.nullifierMapRoot);
        stateChange.voteCountRoot.assertEquals(proof1.publicInput.voteCountRoot);
        
        proof1.publicInput.modifiedNullifierMapRoot.assertEquals(proof2.publicInput.nullifierMapRoot);
        proof1.publicInput.modifiedVoteCountRoot.assertEquals(proof2.publicInput.voteCountRoot);

        proof2.publicInput.modifiedNullifierMapRoot.assertEquals(stateChange.modifiedNullifierMapRoot);
        proof2.publicInput.modifiedVoteCountRoot.assertEquals(stateChange.modifiedVoteCountRoot);
      }
    }
  }
})

// https://github.com/es92/zkApp-examples/blob/main/09-recursion/src/rollup.ts
export let offChainStateProofs_zkps_ = Experimental.ZkProgram.Proof(offChainStateProofs);
export class offChainStateProofs_zkps extends offChainStateProofs_zkps_ {}
