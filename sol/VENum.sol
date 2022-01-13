pragma solidity >=0.5.0 <0.6.0;
pragma experimental ABIEncoderV2;

contract venum {
    address owner = msg.sender;
    uint256 Ac = 1;
    uint256 acN = 72254457867470719938938495559676057516509089362369981914474612970086346252537;
    uint256 hashQ = 565150966737506074175715793592567238421;

    modifier onlyOwner{
        require (msg.sender == owner);
        _;
    }

    function setAc(uint256 acc) public onlyOwner{
        Ac = acc;
    }

    function verify(string memory tokenStrings, string[] memory encResults, uint256 vo) public returns (bool){
        uint256 h = hashset(encResults);
        uint x = stringToPrime(concatenate(tokenStrings, "-", uint2str(h)));
        return (Ac == callBigModExp(vo, x, acN));
    }

    function hashset(string[] memory l) internal returns (uint256){
        uint256 h = 1;
        for (uint i = 0; i < l.length; i++) {
            h = h*stringToNum(l[i]) % hashQ;
        }
        return h;
    }

    // string to 128-bit prime
    function stringToPrime(string memory data) internal returns (uint){
        uint n = stringToNum(data);
        while (true) {
            if (probablyPrime(n)) {
                return n;
            }
            else {
                n = n + 1;
            }
        }
    }
    
    // string to uint128
    function stringToNum(string memory data) internal returns (uint128){
        bytes memory sBytes = bytes(data);
        bytes32 hash = sha256(sBytes);
        // return hash;
        // bytes16 last16Hash = 0;
        bytes16[2] memory last16Hashs = [bytes16(0), 0];
        assembly {
            // mstore(last16Hashs, hash)
            mstore(add(last16Hashs, 16), hash)
        }
        return uint128(last16Hashs[1]);
    }
    
    function concatenate(string memory a, string memory b, string memory c) internal pure returns (string memory){
        string memory s = string(abi.encodePacked(a, b, c));
        return s;
    }

    // function uint256ToBytes(uint256 x) public returns (bytes memory) {
    //     bytes memory b = new bytes(32);
    //     assembly { mstore(add(b, 32), x) }
    // }

    function uint2str(uint _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    // miller rabin test
    function probablyPrime(uint256 n) internal returns (bool) {
        if (n == 2 || n == 3) {
            return true;
        }

        if (n % 2 == 0 || n < 2) {
            return false;
        }

        uint256 t = 0;
        uint256 s = n - 1;
        while (t % 2 == 0) {
            s = s / 2;
            t++;
        }

        uint256[3] memory alist = [uint256(2), uint256(7), uint256(61)]; 

        for (uint256 i = 0; i < 3; i++) {
            uint256 a = alist[i];
            uint256 v = callBigModExp(a, s, n);
            if (v!=1) {
                uint256 j = 0;
                while (v!=n-1) {
                    if (j==t-1) {
                        return false;
                    }
                    else {
                        j = j+1;
                        // v = (v ** 2) % n;
                        v = callBigModExp(v, 2, n);
                    }
                }
            }
        }
        return true;
    }

    // // Write (n - 1) as 2^t * s
    // function getSandT(uint256 n) public pure returns (uint256[2] memory) {
    //     uint256 t = 0;
    //     uint256 s = n - 1;
    //     while (t % 2 == 0) {
    //         s = s / 2;
    //         t++;
    //     }
    //     uint256[2] memory ret;
    //     ret[0] = s;
    //     ret[1] = t;
    //     return ret;
    // }

    // mod exp
    function callBigModExp(uint256 base, uint256 exponent, uint256 modulus) internal returns (uint256 result) {
        assembly {
            // free memory pointer
            let memPtr := mload(0x40)
            // length of base, exponent, modulus
            mstore(memPtr, 0x20)
            mstore(add(memPtr, 0x20), 0x20)
            mstore(add(memPtr, 0x40), 0x20)
            // assign base, exponent, modulus
            mstore(add(memPtr, 0x60), base)
            mstore(add(memPtr, 0x80), exponent)
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
    }
}