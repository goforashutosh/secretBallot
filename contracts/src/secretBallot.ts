import {
    Field,
    SmartContract,
    state,
    State,
    method,
    Bool,
    MerkleTree,
    MerkleWitness,
    MerkleMap,
    PrivateKey,
    Poseidon,
    MerkleMapWitness,
  } from 'snarkyjs';

import * as inputs from './inputs.js';

/*
  Helpful code:
  https://github.com/o1-labs/docs2/blob/main/examples/zkapps/05-common-types-and-functions/src/BasicMerkleTreeContract.ts
  merkle_tree.js
  merkle_map.js
*/

// root is also one of the levels
export class VoterListMerkleWitness extends MerkleWitness(inputs.log_num_voters + 1){}
export class VoteCountMerkleWitness extends MerkleWitness(inputs.log_options + 1){}


export class secretBallot extends SmartContract {
    
    @state(Field) voter_list_root = State<Field>();
    @state(Field) nullifier_map_root = State<Field>();
    @state(Field) vote_count_root = State<Field>();

    @state(Bool) initialised_flag = State<Bool>();
    @state(Field) ballot_ID = State<Field>();

    // TODO: add a time limit using this.network.blocklength

    init(){
        super.init();
        this.initialised_flag.set(Bool(false));

        // set the nullifier map root to the root of a new MerkleMap object
        this.nullifier_map_root.set((new MerkleMap()).getRoot());

        // all options have 0 votes at the start
        this.vote_count_root.set((new MerkleTree(inputs.log_options + 1)).getRoot());
        // declare these for printing
        this.voter_list_root.set(Field(0));
        this.ballot_ID.set(Field(0));
    }

    /**
     * @param ID should be a random field element, so people can't correlate votes across different polls
     * @param voterListRoot is the Merkle tree root for the voter list
     */
    @method initState(ID: Field, voterListRoot: Field){
        // only allow initState if state has not been initialised before
        this.initialised_flag.assertEquals(Bool(false));
        this.voter_list_root.set(voterListRoot);
        this.ballot_ID.set(ID);
        this.initialised_flag.set(Bool(true));
    }

    /**  
     * @param privKey is your private key for which hash(public_key) is a part of the voter list Merkle tree
     * @param voterListWitness is the witness that your hash(public_key) belongs in the voter list tree
     * @param nullifierWitness is the MerkleMap witness for proving: nullifier_map[nullifierHash] =0
     * @param voteCountWitness is the witness for the index you wish to vote for in the vote count Merkle tree
     * @param voteCountLeafVal is the current vote count for the above index
    */
    @method vote(
        privKey: PrivateKey, 
        voterListWitness: VoterListMerkleWitness, 
        nullifierWitness: MerkleMapWitness, 
        voteCountWitness: VoteCountMerkleWitness, 
        voteCountLeafVal: Field
        ){
            // only allow voting after initialisation
            this.initialised_flag.assertEquals(Bool(true));

            // import all state variables
            const currentRoot = this.voter_list_root.get();
            this.voter_list_root.assertEquals(currentRoot);

            const currentNullifierRoot = this.nullifier_map_root.get();
            this.nullifier_map_root.assertEquals(currentNullifierRoot);

            const currentVoteCountRoot = this.vote_count_root.get();
            this.vote_count_root.assertEquals(currentVoteCountRoot);

            const ballotID = this.ballot_ID.get();
            this.ballot_ID.assertEquals(ballotID);

            // The given private key generates the public key which hashes to the leaf
            const leafVal = Poseidon.hash(
                privKey.toPublicKey().toFields()
            );
            leafVal.assertEquals(
                Poseidon.hash(
                    privKey.toPublicKey().toFields()
                )
            );

            // verify that the leaf is in the voter_list_tree
            const calculatedRoot = voterListWitness.calculateRoot(leafVal);
            this.voter_list_root.assertEquals(calculatedRoot);

            
            // verify that the voter has not already voted
            
            const nullifierHash = Poseidon.hash(privKey.toFields().concat([ballotID]));
            // The nullifier hash is correctly generated = hash(privateKey.toFields(), ballot_ID)
            nullifierHash.assertEquals(
                Poseidon.hash(privKey.toFields().concat([ballotID]))
            );

            // The nullifer hash has not been used before <=> private key has not been used before for this vote
            
            /*
            The following makes sure that :
            1) the value at the key location is 0 for the witness AND
            2) witness is correct for some key
            3) the key is indeed the nullifierHash
            => nullifier_map[nullifierHash] = 0
            */
            const [calc_nullifier_root, calc_nullifier_key] = nullifierWitness.computeRootAndKey(Field(0));
            currentNullifierRoot.assertEquals(calc_nullifier_root);
            calc_nullifier_key.assertEquals(nullifierHash);

            // Vote and update vote count tree
            const claimedVoteCountRoot = voteCountWitness.calculateRoot(voteCountLeafVal);
            this.vote_count_root.assertEquals(claimedVoteCountRoot);

            this.vote_count_root.set(
                voteCountWitness.calculateRoot(voteCountLeafVal.add(1))
            );
            
            // set nullifier_map[nullifierHash] = 1
            const [new_nullifier_root, _] = nullifierWitness.computeRootAndKey(Field(1));
            this.nullifier_map_root.set(new_nullifier_root);
    }
}