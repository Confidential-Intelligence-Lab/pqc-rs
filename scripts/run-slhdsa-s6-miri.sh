#!/usr/bin/env bash
set -euo pipefail

export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-disable-isolation}"

PACKAGE="pqc-rs-slh-dsa"

run_filter() {
  local filter="$1"

  echo
  echo "== SLH-DSA bounded Miri: ${filter} =="

  cargo +nightly miri test \
    -p "${PACKAGE}" \
    --lib \
    --all-features \
    "${filter}"
}

# Lightweight structural modules.
run_filter 'address::'
run_filter 'conversion::'
run_filter 'message_digest::'

# WOTS structural, bounds, and malformed-input paths.
run_filter 'wots::tests::chain_'
run_filter 'wots::tests::checksum_'
run_filter 'wots::tests::message_digits_'
run_filter 'wots::tests::sign_rejects_'
run_filter 'wots::tests::public_key_from_signature_rejects_'

# FORS structural, index, bounds, and malformed-input paths.
run_filter 'fors::tests::message_to_indices_'
run_filter 'fors::tests::secret_value_index_'
run_filter 'fors::tests::selected_leaf_rejects_'
run_filter 'fors::tests::node_rejects_'
run_filter 'fors::tests::sign_rejects_'
run_filter 'fors::tests::public_key_from_signature_rejects_'
run_filter 'fors::tests::tree_root_from_signature_rejects_'
run_filter 'fors::tests::authentication_path_rejects_'

# XMSS bounds, tree arithmetic, and malformed-input paths.
run_filter 'xmss::tests::authentication_path_rejects_'
run_filter 'xmss::tests::leaf_rejects_'
run_filter 'xmss::tests::node_rejects_'
run_filter 'xmss::tests::parent_node_rejects_'
run_filter 'xmss::tests::root_from_signature_rejects_'
run_filter 'xmss::tests::root_rejects_'
run_filter 'xmss::tests::sign_rejects_'

# Hypertree bounds, layer arithmetic, signature slicing, and validation.
run_filter 'hypertree::tests::initial_position_rejects_'
run_filter 'hypertree::tests::invalid_layer_is_rejected'
run_filter 'hypertree::tests::layer_context_rejects_'
run_filter 'hypertree::tests::signature_buffer_validation_'
run_filter 'hypertree::tests::sign_rejects_'
run_filter 'hypertree::tests::root_from_signature_rejects_'
run_filter 'hypertree::tests::xmss_address_rejects_'
run_filter 'hypertree::tests::inconsistent_dimensions_are_rejected'

echo
echo "SLH-DSA bounded Miri campaign complete."
