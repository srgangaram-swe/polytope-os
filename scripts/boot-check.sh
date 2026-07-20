#!/bin/sh
set -eu

sh -n "$0"

cargo_command=${POLYTOPE_CARGO:-cargo}
evidence_dir=${POLYTOPE_EVIDENCE_DIR:-target/polytope/evidence}
image_dir=${POLYTOPE_IMAGE_DIR:-target/polytope}
verified_dir=$image_dir/verified
loader_path=$verified_dir/polytope-boot-uefi.efi
kernel_path=$verified_dir/polytope-kernel-x86_64
map_path=$verified_dir/polytope-kernel-x86_64.map
normal_image=$image_dir/polytope-x86_64.img

mkdir -p "$evidence_dir" "$image_dir" "$verified_dir"

"$cargo_command" xtask repro-check \
    --scenario normal \
    --output "$normal_image" \
    --verified-loader-output "$loader_path" \
    --verified-kernel-output "$kernel_path" \
    --verified-kernel-map-output "$map_path" >"$evidence_dir/reproducibility.json"
"$cargo_command" xtask inspect-kernel \
    --kernel "$kernel_path" \
    --map "$map_path" >"$evidence_dir/kernel-layout.json"
"$cargo_command" xtask boot-test \
    --image "$normal_image" \
    --scenario normal \
    --timeout-secs 15 >"$evidence_dir/boot-normal.json"
"$cargo_command" xtask timeout-probe \
    --image "$normal_image" \
    --scenario normal \
    --timeout-secs 2 >"$evidence_dir/boot-timeout.json"

for scenario in bad-version truncated panic; do
    scenario_image=$image_dir/$scenario.img
    "$cargo_command" xtask image \
        --loader "$loader_path" \
        --kernel "$kernel_path" \
        --output "$scenario_image" \
        --scenario "$scenario" >"$evidence_dir/image-$scenario.json"
    "$cargo_command" xtask boot-test \
        --image "$scenario_image" \
        --scenario "$scenario" \
        --timeout-secs 15 >"$evidence_dir/boot-$scenario.json"
done

"$cargo_command" xtask baseline \
    --image "$normal_image" \
    --scenario normal \
    --runs 10 \
    --output "$evidence_dir/boot-baseline.json" >/dev/null

echo "Sprint 02 boot evidence: $evidence_dir"
