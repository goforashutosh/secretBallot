# Secret Ballot

We implement a private voting zkapp. The idea was to try to implement single stage private voting, say like on Twitter- one where participants do not need to register to vote first, as was done in <a href=https://github.com/dymitrlubczyk/mina-voter>Minataur</a>. In a voting procedure with a registration step, users are required to make sure that sufficiently many people have signed up for voting before them but not voted and also that sufficient time has passed between their registration and voting transactions, so that their vote may be private. This can be difficult. Further, it seemed like bad UX. We also allow for the aggregation of user votes off-chain, which ensures a high voting throughput for the users.

## Single stage voting

In our implementation, a centralized party (let's assume honest for now) sets up the voting contract (called `secretBallot`), which includes as state variables:

1. a randomly chosen `ballot_ID `
2. the root of the Merkle tree containing the hash of public keys contained in the list of voters
3. the root of a Merkle tree storing the votes for different options
4. a MerkleMap storing nullifiers `(hash(private_key, ballot_ID))`, which record whether a key has been used for voting or not.

In order, to vote, the user controlling the key pair `(sk, pk)` (secret/private key, public key) proves to the contract that:

1. `hash(pk)` belongs in the voter list
2. `pk` is derived from `sk`
3. the `hash(sk, ballot_ID)` has not been used to vote before: `nullifierMap[hash(sk, ballot_ID)] = 0`.

Together these 3 imply that the user controls a `sk` which is eligible to vote but has not been used to vote yet (Note that we are placing some assumption on the amount of information that is leaked by these hashes, especially if the same `sk` is used for multiple votes; also see <a href = https://hackmd.io/@liangcc/nullifier#>this</a> for more information on nullifiers).

The user also needs to provide the correct witness and the number of votes for the option, he chooses to vote for.

The zkapp is implemented in [secretBallot.ts](contracts/src/secretBallot.ts) and an example program using the vote function described above is in [singleVote-main.ts](contracts/src/singleVote-main.ts).

## Vote aggregation

We also provide the functionality to aggregate the votes of multiple voters into a single proof and use that to modify the on-chain state. This is achieved using the recursion feature of zk proofs on MINA. We follow the idea for implementing rollups described in [here](https://docs.minaprotocol.com/zkapps/tutorials/recursion).

The Structs and ZKPrograms required for aggregation are implemented and described in [voteAggregation.ts](contracts/src/voteAggregation.ts). An example program, which generates multiple votes and aggregates them is presented in [voteAggr-main.ts](contracts/src/voteAggr-main.ts).

## Best way to run

1. Set the inputs in [inputs.ts](contracts/src/inputs.ts).

2. Build the project

```sh
npm run build
```

3. Create new keys

```sh
node build/src/createKeys.js
```

4. Run the desired example file

```sh
node build/src/singleVote-main.js
```

or

```sh
node build/src/voteAggr-main.js
```
