// run using 
// npm run build && node build/src/main.js
import {
  Field,
  MerkleTree,
  MerkleMap,
} from 'snarkyjs';

import {
  secretBallot
} from './secretBallot.js';

/**
* Displays all relevant state variables of the zkapp
* @param zk_app_inst The zkapp you want to display
*/
export function dispAllVar(zk_app_inst: secretBallot){
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
export function displayTree(mtree: MerkleTree){
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
export class offChainStorage{
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