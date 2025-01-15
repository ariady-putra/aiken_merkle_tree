//// This file contains the implementation of a `spend_validator` function that validates a spend transaction
//// using a **Merkle tree**. It also includes a test case for the `spend_validator` function.

use aiken/builtin
use aiken/cbor
use aiken/collection/list
use aiken/fuzz
use aiken_merkle_tree/mt.{Proof, Root, from_list, get_proof, is_member, root}
use cardano/transaction.{OutputReference, Transaction}
use test_kit/fuzzy
use test_kit/fuzzy/fuzzer.{data_fuzzer, output_reference_fuzzer}

pub type MyDatum {
  merkle_root: Root,
}

pub type MyRedeemer {
  my_proof: Proof<Data>,
  user_data: Data,
}

/// The `spend_validator` function validates a spend transaction by checking if the user data is a member of
/// the Merkle tree with the given Merkle root and proof.
///
/// @param datum - The `MyDatum` object containing the Merkle root.
/// @param redeemer - The `MyRedeemer` object containing the proof and user data.
/// @param _tx - The transaction data.
validator spend_validator {
  spend(
    datum: Option<MyDatum>,
    redeemer: MyRedeemer,
    _o_ref: OutputReference,
    _tx: Transaction,
  ) {
    expect Some(MyDatum { merkle_root }) = datum
    let MyRedeemer { my_proof, user_data } = redeemer

    is_member(merkle_root, user_data, my_proof, cbor.serialise)
  }

  else(_) {
    fail
  }
}

// ## Test cases for the spend_validator function.

test spend_validator_dog() {
  let dog = "dog"
  let data = [dog, "cat", "mouse"] |> list.map(builtin.b_data)
  let merkle_tree = from_list(data, cbor.serialise)
  // trace merkle_tree
  let user_data: Data = dog
  expect Some(proof) = get_proof(merkle_tree, user_data, cbor.serialise)
  // trace proof
  let datum = Some(MyDatum { merkle_root: root(merkle_tree) })
  let redeemer = MyRedeemer { my_proof: proof, user_data }

  let placeholder_utxo =
    OutputReference { transaction_id: #"", output_index: 0 }

  let tx = transaction.placeholder

  spend_validator.spend(datum, redeemer, placeholder_utxo, tx)
}

test spend_validator_cat() {
  let cat = "cat"
  let data = ["dog", cat, "mouse"] |> list.map(builtin.b_data)
  let merkle_tree = from_list(data, cbor.serialise)
  // trace merkle_tree
  let user_data: Data = cat
  expect Some(proof) = get_proof(merkle_tree, user_data, cbor.serialise)
  // trace proof
  let datum = Some(MyDatum { merkle_root: root(merkle_tree) })
  let redeemer = MyRedeemer { my_proof: proof, user_data }

  let placeholder_utxo =
    OutputReference { transaction_id: #"", output_index: 0 }

  let tx = transaction.placeholder

  spend_validator.spend(datum, redeemer, placeholder_utxo, tx)
}

test spend_validator_mouse() {
  let mouse = "mouse"
  let data = ["dog", "cat", mouse] |> list.map(builtin.b_data)
  let merkle_tree = from_list(data, cbor.serialise)
  // trace merkle_tree
  let user_data: Data = mouse
  expect Some(proof) = get_proof(merkle_tree, user_data, cbor.serialise)
  // trace proof
  let datum = Some(MyDatum { merkle_root: root(merkle_tree) })
  let redeemer = MyRedeemer { my_proof: proof, user_data }

  let placeholder_utxo =
    OutputReference { transaction_id: #"", output_index: 0 }

  let tx = transaction.placeholder

  spend_validator.spend(datum, redeemer, placeholder_utxo, tx)
}

test spend_validator_prop(
  ((data, user_data), placeholder_utxo) via fuzzy.tuple(
    fuzz.list_with_elem(data_fuzzer()),
    output_reference_fuzzer(),
  ),
) {
  let merkle_tree = from_list(data, cbor.serialise)
  expect Some(proof) = get_proof(merkle_tree, user_data, cbor.serialise)
  // proof |> cbor.diagnostic |> fuzz.label
  let datum = Some(MyDatum { merkle_root: root(merkle_tree) })
  let redeemer = MyRedeemer { my_proof: proof, user_data }

  let tx = transaction.placeholder

  spend_validator.spend(datum, redeemer, placeholder_utxo, tx)
}
