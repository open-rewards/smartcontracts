// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/access/Ownable.sol";

contract OpenRewards is Ownable {

    address trustedSigner = 0x9e332ADe73A162544c0C1fAD996dB8b3EF4a9f77;

    string public repo;
    string public metadata;
    address public safeAddress = address(0);
    string public poolType;
    uint public payoutDuration;
    address public splitsAddress = address(0);
    address[] public oldSplits;
    string[] public contributorUsernames;

    mapping (address => string) usernameMap;
    mapping (string => address) reverseUsernameMap;

    constructor(string memory _repo, string memory _metadata) {
        repo = _repo;
        metadata = _metadata;
    }

    function setContributors(string[] memory _contributorUsernames) public onlyOwner {
        contributorUsernames = _contributorUsernames;
    }

    function setAddress(string memory username, uint nonce, bytes memory signature) public {
        require(verify(trustedSigner, msg.sender, username, nonce, signature), "unable to verify signature");
        usernameMap[msg.sender] = username;
        reverseUsernameMap[username] = msg.sender;
    }

    function setSafe(address _safeAddress) public onlyOwner {
        safeAddress = _safeAddress;
    }

    function setSplits(address _splitsAddress) public onlyOwner {
        if (splitsAddress != address(0)) {
            oldSplits.push(splitsAddress);
        }
        splitsAddress = _splitsAddress;
    }

    function setState(address _safeAddress, address _splitsAddress, string calldata _poolType, uint _payoutDuration) public onlyOwner {
        safeAddress = _safeAddress;
        splitsAddress = _splitsAddress;
        poolType = _poolType;
        payoutDuration = _payoutDuration;
    }

    function getMessageHash(
        address _to,
        string memory _username,
        uint _nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_to, _username, _nonce));
    }

     function getEthSignedMessageHash(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    function verify(
        address _signer,
        address _to,
        string memory _username,
        uint _nonce,
        bytes memory signature
    ) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(_to, _username, _nonce);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == _signer;
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }
        // implicitly return (r, s, v)
    }
}
