# About the Project
The project is a Raffle upon which winners can win a variety of dog NFTS with varying values. The highest value NFT also ther rarest is shiba-Inu, followed by st-Bernard, and the most common but least valuable is pug.

## Highs
-DoS attack: The loop can be exploited b asically adding many entrants at a given time with the aim of propping up the gas fees to render the protocol expensive for new entrants
## Questioning the project
- Outdated compiler version
- The project does storage packing with the aim of saving gas. Not sure if that works
- The project only allows new players to enter as an array. What if only  a single player wants to enter the raffle?
- No reentrance guard
- Weak Randomness: Historically, using block.difficulty (and block.timestamp) for randomness is insecure. Miners or validators can manipulate these values slightly to influence the "random" outcome and win the raffle themselves. This is a common vulnerability known as Weak Randomness. Fix is implementing chainlink VRF
- withdrawFees() should only be called by the contract's owner
- Separate external calls to the same potentially malicious contract (the winner) is risky: Investigate whether this is true with the 

