// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.6.0;

import {ECDSA} from "@openzeppelin/contracts/cryptography/ECDSA.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {TREE_DEPTH} from "./libs/Merkle.sol";
import {CheckpointLib, Checkpoint} from "./libs/CheckpointLib.sol";
import {CheckpointFraudProofs} from "./CheckpointFraudProofs.sol";

enum FraudType {
    Whitelist,
    Premature,
    MessageId,
    Root
}

struct Attribution {
    FraudType fraudType;
    // for comparison with staking epoch
    uint48 timestamp;
}

/**
 * @title AttributeCheckpointFraud
 * @dev The AttributeCheckpointFraud contract is used to attribute fraud to a specific ECDSA checkpoint signer.
 */
contract AttributeCheckpointFraud is Ownable {
    using CheckpointLib for Checkpoint;
    using Address for address;

    CheckpointFraudProofs public checkpointFraudProofs;

    mapping(address => bool) public merkleTreeWhitelist;

    mapping(address => mapping(bytes32 => Attribution)) internal _attributions;

    constructor() public {
        checkpointFraudProofs = new CheckpointFraudProofs();
    }

    function _recover(
        Checkpoint memory checkpoint,
        bytes memory signature
    ) internal pure returns (address signer, bytes32 digest) {
        digest = checkpoint.digest();
        signer = ECDSA.recover(digest, signature);
    }

    function _attribute(
        bytes memory signature,
        Checkpoint memory checkpoint,
        FraudType fraudType
    ) internal {
        (address signer, bytes32 digest) = _recover(checkpoint, signature);
        require(
            _attributions[signer][digest].timestamp == 0,
            "fraud already attributed to signer for digest"
        );
        _attributions[signer][digest] = Attribution({
            fraudType: fraudType,
            timestamp: uint48(block.timestamp)
        });
    }

    function attributions(
        Checkpoint memory checkpoint,
        bytes memory signature
    ) external view returns (Attribution memory) {
        (address signer, bytes32 digest) = _recover(checkpoint, signature);
        return _attributions[signer][digest];
    }

    function whitelist(address merkleTree) external onlyOwner {
        require(
            merkleTree.isContract(),
            "merkle tree must be a valid contract"
        );
        merkleTreeWhitelist[merkleTree] = true;
    }

    function attributeWhitelist(
        Checkpoint memory checkpoint,
        bytes memory signature
    ) external {
        require(
            checkpointFraudProofs.isLocal(checkpoint),
            "checkpoint must be local"
        );

        require(
            !merkleTreeWhitelist[checkpoint.merkleTreeAddress()],
            "merkle tree is whitelisted"
        );

        _attribute(signature, checkpoint, FraudType.Whitelist);
    }

    function attributePremature(
        Checkpoint memory checkpoint,
        bytes memory signature
    ) external {
        require(
            checkpointFraudProofs.isPremature(checkpoint),
            "checkpoint must be premature"
        );

        _attribute(signature, checkpoint, FraudType.Premature);
    }

    function attributeMessageId(
        Checkpoint memory checkpoint,
        bytes32[TREE_DEPTH] memory proof,
        bytes32 actualMessageId,
        bytes memory signature
    ) external {
        require(
            checkpointFraudProofs.isFraudulentMessageId(
                checkpoint,
                proof,
                actualMessageId
            ),
            "checkpoint must have fraudulent message ID"
        );

        _attribute(signature, checkpoint, FraudType.MessageId);
    }

    function attributeRoot(
        Checkpoint memory checkpoint,
        bytes32[TREE_DEPTH] memory proof,
        bytes memory signature
    ) external {
        require(
            checkpointFraudProofs.isFraudulentRoot(checkpoint, proof),
            "checkpoint must have fraudulent root"
        );

        _attribute(signature, checkpoint, FraudType.Root);
    }
}
