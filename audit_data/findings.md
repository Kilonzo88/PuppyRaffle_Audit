### [M-#] TITLE Checking For Duplicate Players in `PuppyRaffle::enterRaffle` by Looping through The Players Array is a Potential DOS Attack Incrementing Gas Costs For Future Entrants

**Description:** The `PuppyRaffle::enterRaffle` function iterates through the `players` array to check for duplicates. However, it performs this check using a nested loop, comparing each player to every other player in the array. This implementation creates a quadratic time complexity O(n^2) relative to the number of players.

``` solidity
// @audit Dos Attack
for(uint256 i = 0; i < players.length -1; i++){
    for(uint256 j = i+1; j< players.length; j++){
    require(players[i] != players[j],"PuppyRaffle: Duplicate Player");
  }
}
```

**Impact:** The gas costs for entering the raffle will significantly increase as more players join. This is due to the quadratic increase in the number of comparisons required to check for duplicates. Eventually, the gas cost to enter the raffle will exceed the block gas limit, creating a Denial of Service (DoS) vulnerability where no new players can enter the raffle. 

**Proof of Concept:**

If we have 2 sets of 150 players enter, the gas costs will be as such:
- 1st 150 players: ~12873449 gas
- 2nd 150 players: ~40998589 gas

This is more than 3x more expensive for the second 150 players.

<details>
<summary>Proof of Code</summary>

```solidity
function testDenialOfService() public {
      // Foundry lets us set a gas price
      vm.txGasPrice(1);

      // Creates 150 addresses
      uint256 playersNum = 150;
      address[] memory players = new address[](playersNum);
      for (uint256 i = 0; i < players.length; i++) {
          players[i] = address(i);
      }

      // Gas calculations for first 150 players
      uint256 gasStart = gasleft();
      puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
      uint256 gasEnd = gasleft();
      uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
      console.log("Gas cost of the first 150 players: ", gasUsedFirst);

      // Creates another array of 150 players
      address[] memory playersTwo = new address[](playersNum);
      for (uint256 i = 0; i < playersTwo.length; i++) {
          playersTwo[i] = address(i + playersNum);
      }

      // Gas calculations for second 150 players
      uint256 gasStartTwo = gasleft();
      puppyRaffle.enterRaffle{value: entranceFee * players.length}(playersTwo);
      uint256 gasEndTwo = gasleft();
      uint256 gasUsedSecond = (gasStartTwo - gasEndTwo) * tx.gasprice;
      console.log("Gas cost of the second 150 players: ", gasUsedSecond);

      assert(gasUsedSecond > gasUsedFirst);
  }
```
</details>

**Recommended Mitigation:** 
1. Consider allowing duplicates. Users can make new wallet addresses anyway, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.

2. Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a `uint256` id, and the mapping would be a player address mapped to the raffle Id.

```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+           require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+           addressToRaffleId[newPlayers[i]] = raffleId;
        }

-   // Check for duplicates
-   for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
    }
```

3. Alternatively, you could use [OpenZeppelin's EnumerableSet library](https://docs.openzeppelin.com/contracts/5.x/api/utils#EnumerableSet).