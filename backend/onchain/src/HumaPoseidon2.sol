// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Poseidon2} from "./Poseidon2.sol";

/// @title HumaPoseidon2
/// @notice Huma's Poseidon2 sponge (Poseidon2.sol) as its own contract, so HumaPagesV4 stays under the contract size limit.
contract HumaPoseidon2 {
    /// @notice Poseidon2 sponge hash of field elements, as Huma's circuits and reader compute it.
    function hash(uint256[] calldata input) external pure returns (uint256) {
        return Poseidon2.hash(input);
    }

}
