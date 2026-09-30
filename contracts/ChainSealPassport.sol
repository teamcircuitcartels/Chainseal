// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title ChainSeal batch passport (ERC-721)
/// @notice One token per sealed batch. Stores only the Merkle root, never raw sensor data.
contract ChainSealPassport is ERC721URIStorage, Ownable {
    uint256 public nextId;
    mapping(uint256 => bytes32) public merkleRoot;
    mapping(uint256 => bool) public flagged;      // true if the batch recorded a cold-chain alert

    event PassportMinted(uint256 indexed tokenId, bytes32 root, address indexed to);

    constructor() ERC721("ChainSeal Passport", "CSEAL") Ownable(msg.sender) {}

    function mint(address to, bytes32 root, string calldata metadataURI, bool hadAlert) external onlyOwner returns (uint256 id) {
        id = nextId++;
        _safeMint(to, id);
        _setTokenURI(id, metadataURI);
        merkleRoot[id] = root;
        flagged[id] = hadAlert;
        emit PassportMinted(id, root, to);
    }

    /// @notice Anyone can check a reading hash belongs to the batch behind a token.
    function verify(uint256 id, bytes32 leaf, bytes32[] calldata proof, bool[] calldata isLeft) external view returns (bool) {
        require(proof.length == isLeft.length, "bad proof");
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            h = isLeft[i] ? sha256(abi.encodePacked(proof[i], h)) : sha256(abi.encodePacked(h, proof[i]));
        }
        return h == merkleRoot[id];
    }
}
