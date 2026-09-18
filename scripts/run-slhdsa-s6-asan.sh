#!/usr/bin/env bash
set -euo pipefail

host="$(rustc -vV | sed -n 's/^host: //p')"

case "${host}" in
  aarch64-apple-darwin|x86_64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo "AddressSanitizer is not configured for host ${host}" >&2; exit 2 ;;
esac

export RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes"
export RUSTDOCFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1:strict_string_checks=1}"

PACKAGE="pqc-rs-slh-dsa"

run_filter() {
  local filter="$1"

  echo
  echo "== SLH-DSA bounded ASan: ${filter} =="

  cargo +nightly test \
    -p "${PACKAGE}" \
    --lib \
    --all-features \
    --target "${host}" \
    "${filter}"
}

# Structural parsing / conversion.
run_filter 'address::'
run_filter 'conversion::'
run_filter 'message_digest::'

# WOTS bounds and malformed-input paths.
run_filter 'wots::tests::chain_'
run_filter 'wots::tests::checksum_'
run_filter 'wots::tests::message_digits_'
run_filter 'wots::tests::sign_rejects_'
run_filter 'wots::tests::public_key_from_signature_rejects_'

# FORS bounds and malformed-input paths.
run_filter 'fors::tests::message_to_indices_'
run_filter 'fors::tests::secret_value_index_'
run_filter 'fors::tests::selected_leaf_rejects_'
run_filter 'fors::tests::node_rejects_'
run_filter 'fors::tests::sign_rejects_'
run_filter 'fors::tests::public_key_from_signature_rejects_'
run_filter 'fors::tests::tree_root_from_signature_rejects_'
run_filter 'fors::tests::authentication_path_rejects_'

# XMSS bounds and malformed-input paths.
run_filter 'xmss::tests::authentication_path_rejects_'
run_filter 'xmss::tests::leaf_rejects_'
run_filter 'xmss::tests::node_rejects_'
run_filter 'xmss::tests::parent_node_rejects_'
run_filter 'xmss::tests::root_from_signature_rejects_'
run_filter 'xmss::tests::root_rejects_'
run_filter 'xmss::tests::sign_rejects_'

# Hypertree bounds and signature slicing.
run_filter 'hypertree::tests::initial_position_rejects_'
run_filter 'hypertree::tests::invalid_layer_is_rejected'
run_filter 'hypertree::tests::layer_context_rejects_'
run_filter 'hypertree::tests::signature_buffer_validation_'
run_filter 'hypertree::tests::sign_rejects_'
run_filter 'hypertree::tests::root_from_signature_rejects_'
run_filter 'hypertree::tests::xmss_address_rejects_'
run_filter 'hypertree::tests::inconsistent_dimensions_are_rejected'

echo
echo "SLH-DSA bounded ASan campaign complete."
