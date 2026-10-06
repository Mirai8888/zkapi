#!/usr/bin/env bash
set -euo pipefail

# Test every crate the maintained patches change, in a tree from prepare-zkapi.sh.
# The crates come from the patches themselves: companion.patch's crates/NAME/
# paths are tested in the companion workspace, protocol-transport.patch's
# rust/crates/NAME/ paths in the protocol workspace (which the companion
# workspace excludes). A patch that starts changing another crate has that
# crate's tests run here without a workflow change.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
zkapi_dir=${1:?Usage: test-companion.sh PREPARED_ZKAPI_DIRECTORY}
zkapi_dir=$(cd -- "$zkapi_dir" && pwd)
patch_dir="$repo_dir/zkapi-clientd/internal/zkapi"
# shellcheck source=zkapi-clientd/packaging/zkapi-source.env
source "$repo_dir/zkapi-clientd/packaging/zkapi-source.env"
python3 "$script_dir/verify-zkapi-source.py" "$zkapi_dir" "$OA_COMPANION_COMMIT" "$OA_PROTOCOL_COMMIT"

# Run the tests of each crate directory PATCH changes under PREFIX/, in WORKSPACE.
# A crate's directory is its package name; cargo refuses a name it does not know.
test_patched_crates() {
    local patch=$1 prefix=$2 workspace=$3 crate crates=''
    local packages=()
    while IFS= read -r crate; do
        packages+=(-p "$crate")
        crates="$crates $crate"
    done < <(sed -n "s|^diff --git a/$prefix/\([^/][^/]*\)/.*|\1|p" "$patch" | sort -u)
    if [[ ${#packages[@]} -eq 0 ]]; then
        echo "$(basename "$patch") changes no crate under $prefix/; refusing to report it tested." >&2
        return 1
    fi
    echo "Testing $(basename "$patch") crates in $workspace:$crates"
    (cd "$workspace" && cargo test --release --locked "${packages[@]}")
}

test_patched_crates "$patch_dir/companion.patch" crates "$zkapi_dir"
test_patched_crates "$patch_dir/protocol-transport.patch" rust/crates "$zkapi_dir/protocol/rust"
echo "Tested every crate changed by companion.patch and protocol-transport.patch"
