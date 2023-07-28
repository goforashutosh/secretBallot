# Secret Ballot 

*Update 28 Jul, 2023: I have added vote aggregation using recursion for ZKPs. This is yet to be fully tested, and I also need to add comments.* 

We implement a private voting zkapp. The idea was to try to implement single stage private voting, say like on Twitter- one where participants do not need to register to vote first, as was done in <a href=https://github.com/dymitrlubczyk/mina-voter>Minataur</a>. In a voting procedure with a registration step, users are required to make sure that sufficiently many people have signed up for voting before them but not voted and also that sufficient time has passed between their registration and voting transactions, so that their vote may be private. This can be difficult. Further, it seemed like bad UX. 

In our implementation, a centralized party (let's assume honest for now) sets up the voting contract (called `secretBallot`), which includes as state variables: 
1. a randomly chosen `ballot_ID `
2. the root of the Merkle tree containing the hash of public keys contained in the list of voters
3. the root of a Merkle tree storing the votes for different options
4. a MerkleMap storing nullifiers `(hash(private_key, ballot_ID))`, which record whether a key has been used for voting or not. 

In order, to vote, the user controlling the key pair `(sk, pk)` (secret/private key, public key) proves to the contract that:

1. `hash(pk)` belongs in the voter list 
2. `pk` is derived from `sk`
3. the `hash(sk, ballot_ID)` has not been used to vote before: `nullifierMap[hash(sk, ballot_ID)] = 0`.

<!-- https://hackmd.io/@liangcc/nullifier# -->
Together these 3 imply that the user controls a `sk` which is eligible to vote but has not been used to vote yet (Note that we are placing some assumption on the amount of information that is leaked by these hashes, especially if the same `sk` is used for multiple votes). 

The user also needs to provide the correct witness and the number of votes for the option, he chooses to vote for. 

## Best way to run
Set inputs in inputs.ts. Then, run createNewKeysAndRun.sh file. This will create new keys and run the main file, which runs the code as an example. main.ts should be readable :)

## How to build

```sh
npm run build
```

```sh
npm run test
npm run testw # watch mode
```
