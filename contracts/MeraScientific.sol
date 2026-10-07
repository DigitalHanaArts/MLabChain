// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Capped} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Pausable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";

/// @title Mera Scientific Work Token
/// @notice EVM representation of MERA. This contract is NOT a trustless L1↔EVM bridge.
/// A dedicated bridge/mint role must be controlled by an audited, threshold-governed bridge.
contract MeraScientific is
    ERC20,
    ERC20Capped,
    ERC20Burnable,
    ERC20Permit,
    ERC20Pausable,
    AccessControlDefaultAdminRules
{
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint256 public constant MAX_SUPPLY = 100_000_000 * 10 ** 8;

    mapping(bytes32 => bool) public usedDepositIds;

    error DepositAlreadyProcessed();
    error ZeroDepositId();

    constructor(address admin, address bridgeMinter, address pauser)
        ERC20("Mera Scientific", "MERA")
        ERC20Capped(MAX_SUPPLY)
        ERC20Permit("Mera Scientific")
        AccessControlDefaultAdminRules(2 days, admin)
    {
        _grantRole(MINTER_ROLE, bridgeMinter);
        _grantRole(PAUSER_ROLE, pauser);
    }

    function decimals() public pure override returns (uint8) {
        return 8;
    }

    /// @notice Mint a representation of locked native MERA on another chain.
    /// @dev `depositId` must be globally unique and attested by the bridge authority.
    function bridgeMint(address to, uint256 amount, bytes32 depositId)
        external
        onlyRole(MINTER_ROLE)
    {
        if (depositId == bytes32(0)) revert ZeroDepositId();
        if (usedDepositIds[depositId]) revert DepositAlreadyProcessed();
        usedDepositIds[depositId] = true;
        _mint(to, amount);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Capped, ERC20Pausable)
    {
        super._update(from, to, value);
    }
}
