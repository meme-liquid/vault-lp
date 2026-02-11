# vault-lp

**Passive LP Vaults for MemeLiquid Perpetuals**

Program ID: `MEMELPhk8VXcqAPzY9ooyHGQKbTLpEkpavJ2XQJSsP3`

---

## What is vault-lp?

vault-lp is a Solana program that lets anyone earn yield by providing liquidity to MemeLiquid's on-chain perpetual markets. Users deposit native SOL into market-specific vaults, and their capital is pooled together to serve as the counterparty to leveraged traders.

When traders lose on their positions, the vault profits. When traders win, the vault takes a loss. Over time, since the majority of perpetual traders are net unprofitable, LP vault depositors tend to earn positive returns.

## Why we built it

MemeLiquid's perpetual markets (percolator-prog) require liquidity providers (LPs) to take the other side of every trade. Previously, only technically sophisticated users could run an LP — it required setting up a matcher, managing keys, and monitoring positions manually.

vault-lp solves this by:

- **Making LP accessible to everyone** — deposit SOL with one click, no technical knowledge needed
- **Pooling liquidity** — many users contribute to one deep liquidity pool per market
- **Automating everything** — SOL wrapping, CPI deposits, share tracking all handled on-chain
- **Zero lock-ups** — withdraw anytime, no cooldowns, no penalties

## How it works

```
User deposits SOL
      |
      v
vault-lp program wraps SOL to wSOL
      |
      v
CPI DepositCollateral to percolator-prog
      |
      v
User receives vault shares (on-chain data, non-transferable)
      |
      v
Traders trade against the vault's LP position
      |
      v
Vault value changes based on trader PnL
      |
      v
User withdraws: shares burned, native SOL returned
```

### Key design decisions

- **Share-based accounting**: User positions are stored as on-chain PDA data, not SPL tokens. Shares cannot be traded or transferred — this eliminates manipulation risk.
- **No program upgrade required**: vault-lp is a standalone program that interacts with percolator-prog via CPI. The perpetual markets program was not modified.
- **Native SOL UX**: Users send and receive native SOL. All wSOL wrapping/unwrapping happens inside the program automatically.
- **Market isolation**: Each market (LIQUID/SOL, Buttcoin/SOL) has its own independent vault. Losses in one market do not affect another.

## Instructions

The program has three instructions:

### `initialize_vault`

Admin-only. Creates a vault for a specific perpetual market.

- Creates VaultState PDA (`["vault_lp", slab]`)
- Creates wSOL transit ATA for the vault PDA
- CPI InitLP on percolator-prog (vault PDA becomes the LP owner)
- Verifies LP index post-CPI

### `deposit`

Anyone can call. Deposits native SOL into the vault.

1. Reads LP capital + PnL from the slab to calculate vault value
2. Computes shares to issue: `new_shares = deposit * total_shares / vault_value`
3. Wraps SOL: `SystemProgram::transfer` + `SyncNative`
4. CPI `DepositCollateral` to percolator-prog
5. Updates UserPosition PDA with new shares
6. Updates VaultState total_shares

### `withdraw`

Anyone can call. Burns shares and returns native SOL.

1. Reads vault value from slab
2. Computes withdrawal amount: `lamports = shares * vault_value / total_shares`
3. Decrements shares in UserPosition and VaultState (before CPI for reentrancy safety)
4. CPI `WithdrawCollateral` from percolator-prog
5. Transfers wSOL to user's temporary ATA
6. Closes ATA to unwrap — native SOL goes to user's wallet

## Account structures

### VaultState

PDA seeds: `["vault_lp", slab_pubkey]`

| Field | Type | Description |
|-------|------|-------------|
| slab | Pubkey | Target market slab |
| lp_idx | u16 | LP index in percolator-prog |
| lp_account_id | u64 | LP account ID |
| unit_scale | u32 | Cached from slab config |
| total_shares | u128 | Total shares issued across all depositors |
| admin | Pubkey | Admin authority |
| bump | u8 | PDA bump |
| matcher_program | Pubkey | Matcher program ID |
| matcher_context | Pubkey | Matcher context account |
| percolator_program | Pubkey | percolator-prog ID |
| collateral_mint | Pubkey | wSOL (NATIVE_MINT) |
| vault_pubkey | Pubkey | Percolator vault token account |

### UserPosition

PDA seeds: `["position", vault_state_pubkey, user_pubkey]`

| Field | Type | Description |
|-------|------|-------------|
| vault | Pubkey | Which vault this position belongs to |
| owner | Pubkey | User's wallet |
| shares | u128 | User's share count |
| bump | u8 | PDA bump |

## Deployed vaults

| Market | Vault PDA | LP Index |
|--------|-----------|----------|
| LIQUID/SOL | `3VTYKwZjZYm6jNGyDLdvzk4AWa7wDproMgtHmCPsC7nn` | #188 |
| Buttcoin/SOL | `GRaVXM4hMrLFxQ5okFNbgSuBVbLFqdfLnN1h1TCUXmzm` | #19 |

## Risks

**This is experimental software. Deposits are not guaranteed.**

- **Trader profitability risk**: If traders are net profitable, the vault value decreases and depositors lose SOL.
- **Smart contract risk**: Although the program has been carefully developed, it has not been formally audited. Bugs could result in loss of funds.
- **Market risk**: Each vault is tied to a specific perpetual market. Extreme volatility or market manipulation could cause outsized losses.
- **Liquidity risk**: During periods of high withdrawals, the vault may have insufficient free capital if positions are open.
- **Oracle risk**: Vault withdrawals depend on oracle price accuracy. Stale or manipulated oracle prices could affect withdrawal amounts.

Only deposit what you can afford to lose.

## Yield sources

Vault depositors earn from three sources:

1. **Trader losses**: When traders close losing positions, those losses become vault profit. This is the primary yield source.
2. **Funding rate**: Traders with open positions pay periodic funding fees based on market imbalance. These fees flow to the LP.
3. **Trading spread**: The matcher charges a spread on every trade execution. A portion of this spread accrues to the LP position.

## Technical details

- **Framework**: Anchor 0.30.1
- **Dependencies**: anchor-lang, anchor-spl (token operations)
- **CPI targets**: percolator-prog (`DP2EbA2v6rmkmNieZpnjumXosuXQ93r9jyb9eSzzkf1x`)
- **Slab offsets**: Verified from `slab.ts` — ENGINE_OFF=392, ENGINE_ACCOUNTS_OFF=9136, ACCOUNT_SIZE=240
- **Build**: `cargo-build-sbf` with blake3 pinned to v1.5.5 for Solana toolchain compatibility

### Build from source

```bash
git clone https://github.com/meme-liquid/vault-lp.git
cd vault-lp

# Pin blake3 for Solana toolchain compatibility
cargo +solana update -p blake3@1.8.3 --precise 1.5.5

# Build
cargo-build-sbf
```

The compiled program will be at `target/deploy/vault_lp.so`.

## License

All rights reserved. This software is proprietary to MemeLiquid.
