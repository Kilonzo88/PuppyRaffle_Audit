# About the Project
The project is a Raffle upon which winners can win a variety of dog NFTS with varying values. The highest value NFT also ther rarest is shiba-Inu, followed by st-Bernard, and the most common but least valuable is pug.

## Questioning the project
- Outdated compiler version
- The project does storage packing with the aim of saving gas. Not sure if that works
- The project only allows new players to enter as an array. What if only  a single player wants to enter the raffle?
- No reentrance guard
- Weak Randomness: Historically, using block.difficulty (and block.timestamp) for randomness is insecure. Miners or validators can manipulate these values slightly to influence the "random" outcome and win the raffle themselves. This is a common vulnerability known as Weak Randomness.
- withdrawFees() should only be called by the contract's owner