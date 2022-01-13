pragma solidity >=0.5.0 <0.6.0;

contract modexpTest {
    address owner = msg.sender;
    // uint256 g = 65537;
    uint256 acc1 = 4;
    uint256 acc2 = 4;
    uint256 n = 64267128908800428819374131825165050331096755438880365643907981349455423818223;

    modifier onlyOwner{
        require (msg.sender == owner);
        _;
    }
    
    function mexpMethod(uint x) public{
        acc1 = mexp(acc1, x, n);
    }

    function prepMethod(uint x) public{
        uint base = acc2;
        uint modulus = n;
        uint result;

        assembly {
            // free memory pointer
            let memPtr := mload(0x40)
            // length of base, exponent, modulus
            mstore(memPtr, 0x20)
            mstore(add(memPtr, 0x20), 0x20)
            mstore(add(memPtr, 0x40), 0x20)
            // assign base, exponent, modulus
            mstore(add(memPtr, 0x60), base)
            mstore(add(memPtr, 0x80), x)
            mstore(add(memPtr, 0xa0), modulus)
            // call the precompiled contract BigModExp (0x05)
            let success := call(gas, 0x05, 0x0, memPtr, 0xc0, memPtr, 0x20)
            switch success
            case 0 {
                revert(0x0, 0x0)
            } default {
                result := mload(memPtr)
            }
        }
        acc2 = result;
    }
    
    function getAcc1() public view returns (uint256){
        return acc1;
    }

    function getAcc2() public view returns (uint256){
        return acc2;
    }
    
    /**
     * @dev Compute modular exponential (x ** k) % m
     * @param x k m
     * @return uint
     */
   function mexp(uint x, uint k, uint m) internal pure returns (uint r) {
       r = 1;
       for (uint s = 1; s <= k; s *= 2) {
            if (k & s != 0) r = mulmod(r, x, m);
            x = mulmod(x, x, m);
       }
    }
}