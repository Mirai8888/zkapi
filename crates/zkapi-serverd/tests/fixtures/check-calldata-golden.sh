#!/usr/bin/env bash
# Regenerate the golden vault calldata with Forge (VaultCalldataGolden.t.sol,
# Solidity's abi.encodeCall) and compare it with vault_calldata_golden.json,
# which zkapi-serverd's watcher::tests::golden_calldata_matches_forge_abi_encode
# pins its encoders against. With --update, rewrite the JSON instead.
# Needs forge and node; uses the vendored forge-std of protocol/contracts.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$here/../../../.." && pwd -P)
golden="$here/vault_calldata_golden.json"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/src" "$work/test"
cp "$here/VaultCalldataGolden.t.sol" "$work/test/"
cat >"$work/foundry.toml" <<EOF
[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["$repo/protocol/contracts/lib"]
remappings = ["forge-std/=$repo/protocol/contracts/lib/forge-std/src/"]
solc = "0.8.28"
EOF

(cd "$work" && forge test --match-contract GoldenTest -vv) >"$work/forge.log"

node - "$work/forge.log" "$golden" "${1:-}" <<'JS'
const fs = require("node:fs");
const [log, goldenPath, mode] = process.argv.slice(2);
const lines = fs.readFileSync(log, "utf8").split("\n").map((line) => line.trim());
const start = lines.indexOf("Logs:");
if (start < 0) throw new Error("forge printed no logs");
const vectors = {};
for (let i = start + 1; i + 1 < lines.length; i += 2) {
  const [name, hex] = [lines[i], lines[i + 1]];
  if (!/^[a-z]+$/.test(name) || !/^0x[0-9a-f]+$/.test(hex)) break;
  vectors[name] = hex;
}
const golden = JSON.parse(fs.readFileSync(goldenPath, "utf8"));
const names = ["defeat", "raise", "escape", "close", "retire"];
if (mode === "--update") {
  for (const name of names) golden[name] = vectors[name];
  fs.writeFileSync(goldenPath, `${JSON.stringify(golden, null, 2)}\n`);
  console.log(`updated ${goldenPath}`);
  process.exit(0);
}
let failed = false;
for (const name of names) {
  if (!vectors[name]) {
    console.error(`forge did not print ${name}`);
    failed = true;
  } else if (vectors[name] !== golden[name]) {
    console.error(`${name}: vault_calldata_golden.json differs from forge's abi.encodeCall`);
    failed = true;
  }
}
if (failed) process.exit(1);
console.log(`golden calldata matches forge: ${names.join(", ")}`);
JS
