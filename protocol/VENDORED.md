# Protocol source provenance

`protocol/` is tracked directly by this repository. A normal clone includes the
Rust workspace, Solidity contracts, selected proof setup, and Solidity
dependencies; no submodule initialization or separate protocol checkout is needed.
Make protocol changes here and commit them with the application changes that use
them. The Rust workspace under `rust/` remains separate from the root workspace.

The initial import preserves the files and executable modes from these pinned
revisions, except for the removed `.gitmodules` files:

| Directory relative to `protocol/` | Source repository | Imported commit |
| --- | --- | --- |
| `.` | <https://github.com/mingyech/zkapi> | `8b2d4e3da921f956e1eb6b93afbf722a877c060c` |
| `contracts/lib/forge-std` | <https://github.com/foundry-rs/forge-std> | `0844d7e1fc5e60d77b68e469bff60265f236c398` |
| `contracts/lib/openzeppelin-contracts` | <https://github.com/OpenZeppelin/openzeppelin-contracts> | `5fd1781b1454fd1ef8e722282f86f9293cacf256` |
| `contracts/lib/openzeppelin-contracts/lib/erc4626-tests` | <https://github.com/a16z/erc4626-tests> | `232ff9ba8194e406967f52ecc5cb52ed764209e9` |
| `contracts/lib/openzeppelin-contracts/lib/forge-std` | <https://github.com/foundry-rs/forge-std> | `3b20d60d14b343ee4f908cb8079495c07f5e8981` |
| `contracts/lib/openzeppelin-contracts/lib/halmos-cheatcodes` | <https://github.com/a16z/halmos-cheatcodes> | `7328abe100445fc53885c21d0e713b95293cf14c` |

The third-party libraries retain their upstream license files. Their own
documentation may describe upstream submodule workflows; those workflows do not
apply to this repository. Update these libraries as ordinary tracked files and
record their new revisions here. `contracts/foundry.lock` records the imported
direct dependency versions.

The files in `setup/v2/` are unchanged from the pinned protocol revision. In
particular, this import does not regenerate the proving keys or verifiers.

## Included dependency sources

The import revisions above describe provenance. The included OpenZeppelin
sources are Ownable, Ownable2Step, Context, ReentrancyGuard and StorageSlot,
with their license. `Ownable2Step.sol`, added for the vault's two-step
ownership transfer, is byte-for-byte the file of the recorded revision
(v5.6.1). The included forge-std sources are its helpers and licenses.
