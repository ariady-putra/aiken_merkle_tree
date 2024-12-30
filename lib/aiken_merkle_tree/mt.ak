//// This code is sourced from https://github.com/aiken-lang/trees/blob/main/lib/aiken/trees/mt.ak
////
//// A purely functional implementation of **MerkleTrees** that is suitable for
//// usage on-chain. Note, however, that the construction of `MerkleTree` and
//// membership proofs are still expected to happen *off-chain* while only the
//// proof verification should be done on-chain.
////
//// This implementation uses exclusively **SHA-256** as a hashing algorithm.
////
//// The code ported to Aiken from [Hydra](https://github.com/input-output-hk/hydra/blob/master/plutus-merkle-tree/src/Plutus/MerkleTree.hs)

use aiken/collection/list
use aiken/crypto.{Hash, Sha2_256}
use aiken/option
use aiken/primitive/bytearray

/// An opaque representation of a [`MerkleTree`](#MerkleTree). See
/// [`from_list`](#from_list) to construct a tree from a list of elements.
pub opaque type MerkleTree<a> {
  Empty
  Leaf { value: a, hash: Hash<Sha2_256, a> }
  Node { root: Root, left: MerkleTree<a>, right: MerkleTree<a> }
}

/// A proof of existence in the tree. See:
///
/// - [`get_proof`](#get_proof) to construct a proof from a given element.
/// - [`is_member`](#is_member) to verify a given proof against a known root.
///
pub type Proof<a> =
  List<ProofItem<a>>

/// An opaque proof element.
pub opaque type ProofItem<a> {
  Left(Root)
  Right(Root)
}

/// An opaque root. Use [`to_hash`](#to_hash) and
/// [`from_hash`](#from_hash) to convert back-and-forth between this and
/// classic hashes. This type exists mainly to disambiguate between standard
/// value (leaf) hash from tree hashes.
pub opaque type Root {
  inner: ByteArray,
}

/// Cheap equality of two [`MerkleTrees`](#MerkleTree) by comparing their root
/// hashes. For large trees, this is much faster than using `==`.
pub fn equals(left: MerkleTree<a>, right: MerkleTree<a>) -> Bool {
  root(left) == root(right)
}

/// Returns a total numbers of elements in the tree.
pub fn size(self: MerkleTree<a>) -> Int {
  when self is {
    Empty -> 0
    Leaf { .. } -> 1
    Node { left, right, .. } -> size(left) + size(right)
  }
}

test size_1() {
  let items = []
  ( from_list(items, identity) |> size ) == 0
}

test size_2() {
  let items = ["dog"]
  ( from_list(items, identity) |> size ) == 1
}

test size_3() {
  let items = ["dog", "cat", "mouse"]
  ( from_list(items, identity) |> size ) == 3
}

/// Returns `True` when the tree has no elements. `False` otherwise.
pub fn is_empty(self: MerkleTree<a>) -> Bool {
  when self is {
    Empty -> True
    _ -> False
  }
}

test is_empty_1() {
  from_list([], identity)
    |> is_empty
}

test is_empty_2() {
  from_list(["dog"], identity)
    |> is_empty
    |> not
}

// ## Merkle Root

/// Returns the [`Root`](#Root) of a given [`MerkleTree`](#MerkleTree).
pub fn root(self: MerkleTree<a>) -> Root {
  when self is {
    Empty -> Root(#"")
    Leaf { hash, .. } -> Root(hash)
    Node { root, .. } -> root
  }
}

test root_1() {
  from_list([], identity)
    |> root
    |> to_hash
    |> option.is_none
}

test root_2() {
  let dog = "dog"
  let mt = from_list([dog], identity)

  root(mt) == (
    dog
      |> crypto.sha2_256
      |> from_hash
  )
}

test root_3() {
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"

  let hash =
    mouse
      |> crypto.sha2_256
      |> bytearray.concat(cat |> crypto.sha2_256, _)
      |> crypto.sha2_256
      |> bytearray.concat(dog |> crypto.sha2_256, _)
      |> crypto.sha2_256

  Some(hash) == (
    from_list([dog, cat, mouse], identity)
      |> root
      |> to_hash
  )
}

/// Convert any [`Hash`](https://aiken-lang.github.io/stdlib/aiken/crypto.html#Hash) into a merkle [`Root`](#Root).
///
/// This operation is _unsafe_ unless you are sure that the given hash digest was produced from a valid merkle tree.
pub fn from_hash(hash: Hash<alg, a>) -> Root {
  Root(hash)
}

/// Convert a [`Root`](#Root) into a simple [`Hash`](https://aiken-lang.github.io/stdlib/aiken/crypto.html#Hash), when possible.
///
/// Roots from empty trees have no hash whatsoever.
pub fn to_hash(self: Root) -> Option<Hash<Sha2_256, a>> {
  if self.inner == "" {
    None
  } else {
    Some(self.inner)
  }
}

// ## Merkle Tree

fn do_from_list(
  items: List<a>,
  length: Int,
  serialise: fn(a) -> ByteArray,
) -> MerkleTree<a> {
  when items is {
    [] -> Empty

    [value] -> Leaf { value, hash: value |> serialise |> crypto.sha2_256 }

    _ -> {
      let cutoff: Int = length / 2

      let left =
        items
          |> list.take(cutoff)
          |> do_from_list(cutoff, serialise)
      let right =
        items
          |> list.drop(cutoff)
          |> do_from_list(length - cutoff, serialise)

      let root = combine(root(left), root(right))

      Node { root, left, right }
    }
  }
}

/// Construct a [`MerkleTree`](#MerkleTree) from a list of values.
///
/// Note that, while this operation is do-able on-chain, it is expensive and
/// preferably done off-chain.
pub fn from_list(items: List<a>, serialise: fn(a) -> ByteArray) -> MerkleTree<a> {
  do_from_list(items, items |> list.length, serialise)
}

test from_list_0() {
  from_list([], identity) == Empty
}

test from_list_1() {
  let dog = "dog"

  from_list([dog], identity) == Leaf {
    value: dog,
    hash: dog |> crypto.sha2_256,
  }
}

test from_list_2() {
  let dog = "dog"
  let cat = "cat"

  from_list([dog, cat], identity) == Node {
    root: combine(
      dog |> crypto.sha2_256 |> Root,
      cat |> crypto.sha2_256 |> Root,
    ),
    left: Leaf { value: dog, hash: dog |> crypto.sha2_256 },
    right: Leaf { value: cat, hash: cat |> crypto.sha2_256 },
  }
}

///     root
///     hash
///  ┌ concat ┐
/// hash    hash
/// dog    concat
///       hash hash
///       cat  mouse
test from_list_3() {
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"

  let root_hash =
    mouse
      |> crypto.sha2_256
      |> bytearray.concat(cat |> crypto.sha2_256, _)
      |> crypto.sha2_256
      |> bytearray.concat(dog |> crypto.sha2_256, _)
      |> crypto.sha2_256
  //
  //   let hash =
  //     bytearray.concat(
  //       dog |> crypto.sha2_256,
  //       bytearray.concat(cat |> crypto.sha2_256, mouse |> crypto.sha2_256)
  //         |> crypto.sha2_256,
  //     )
  //       |> crypto.sha2_256
  //   expect hash == root_hash
  //
  let root_from_list = from_list([dog, cat, mouse], identity) |> root
  let root_from_hash = root_hash |> from_hash

  root_from_list == root_from_hash
}

///          root
///          hash
///    ┌─── concat ───┐
///   hash          hash
///  concat        concat
/// hash hash    hash  hash
/// dog  cat     mouse mouse
test from_list_4() {
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"
  let prime = mouse

  let root_hash =
    bytearray.concat(
      bytearray.concat(dog |> crypto.sha2_256, cat |> crypto.sha2_256)
        |> crypto.sha2_256,
      bytearray.concat(mouse |> crypto.sha2_256, prime |> crypto.sha2_256)
        |> crypto.sha2_256,
    )
      |> crypto.sha2_256

  let root_from_list = from_list([dog, cat, mouse, prime], identity) |> root
  let root_from_hash = root_hash |> from_hash

  root_from_list == root_from_hash
}

///          root
///          hash
///    ┌─── concat ───┐
///   hash          hash
///  concat      ┌ concat ┐
/// hash hash   hash    hash
/// bear dog    cat    concat
///                  hash  hash
///                  mouse prime
test from_list_5() {
  let bear = "bear"
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"
  let prime = "prime"

  let hash_concat =
    fn(a, b) { bytearray.concat(a |> crypto.sha2_256, b |> crypto.sha2_256) }
  let root_hash =
    hash_concat(
      hash_concat(bear, dog),
      hash_concat(cat, hash_concat(mouse, prime)),
    )
      |> crypto.sha2_256
  //
  // 123( // Node
  //     [_
  //         h'5DB0BF03C0068219076D092CFD93C8E39FFCAC48DB273BF95A61D9BE39901D98', // Node.root
  //         123( // Node
  //             [_
  //                 h'79F923ADC926AC4CE7E8AB2E32807E56C038217D577B1EC7A7B5CFA051DD7356', // Node.root
  //                 122(
  //                     [_ h'62656172', h'BC98BB50E8094B2AC3CEB90BA2512587C0513CD294A07EFCFDCF467198DA6266'] // Leaf { value, hash }
  //                 ), // Node.left
  //                 122(
  //                     [_ h'646F67', h'CD6357EFDD966DE8C0CB2F876CC89EC74CE35F0968E11743987084BD42FB8944'] // Leaf { value, hash }
  //                 ) // Node.right
  //             ]
  //         ), // Node.left
  //         123( // Node
  //             [_
  //                 h'A6F3AD94B99FD724C78A939956A433559C7D954772EFB4EDB0C92AB6EF2BE714', // Node.root
  //                 122(
  //                     [_ h'636174', h'77AF778B51ABD4A3C51C5DDD97204A9C3AE614EBCCB75A606C3B6865AED6744E'] // Leaf { value, hash }
  //                 ), // Node.left
  //                 123( // Node
  //                     [_
  //                         h'81AE7338D6FFDE97C0A0AE6E4E115BEC7D2FE477BE27DD229FE0FC70F3C94E4B', // Node.root
  //                         122(
  //                             [_ h'6D6F757365', h'47C5C28CAE2574CDF5A194FE7717DE68F8276F4BF83E653830925056AEB32A48'] // Leaf { value, hash }
  //                         ), // Node.left
  //                         122(
  //                             [_ h'7072696D65', h'DCCC5D01DABCD1C0B9FA89C91E7F4BDE603121EE0172B4FF394E6BB30D295E41'] // Leaf { value, hash }
  //                         ) // Node.right
  //                     ]
  //                 ) // Node.right
  //             ]
  //         ) // Node.right
  //     ]
  // )
  //
  let root_from_list =
    from_list([bear, dog, cat, mouse, prime], identity) |> root
  let root_from_hash = root_hash |> from_hash

  root_from_list == root_from_hash
}

///                   root
///                   hash
///          ┌────── concat ──────┐
///         hash                hash
///    ┌── concat ──┐        ┌ concat ┐
///   hash        hash      hash    hash
/// bumblebee    concat     cat    concat
///            hash  hash        hash  hash
///            bear  dog         mouse prime
test from_list_6() {
  let bumblebee = "bumblebee"
  let bear = "bear"
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"
  let prime = "prime"

  let hash_concat =
    fn(a, b) { bytearray.concat(a |> crypto.sha2_256, b |> crypto.sha2_256) }
  let root_hash =
    hash_concat(
      hash_concat(bumblebee, hash_concat(bear, dog)),
      hash_concat(cat, hash_concat(mouse, prime)),
    )
      |> crypto.sha2_256

  let root_from_list =
    from_list([bumblebee, bear, dog, cat, mouse, prime], identity) |> root
  let root_from_hash = root_hash |> from_hash

  root_from_list == root_from_hash
}

///                      root
///                      hash
///          ┌───────── concat ─────────┐
///         hash                      hash
///    ┌── concat ──┐           ┌─── concat ───┐
///   hash        hash         hash          hash
/// bumblebee    concat       concat         concat
///            hash  hash   hash  hash     hash  hash
///            bear  dog    cat   mouse    prime jazz
test from_list_7() {
  let bumblebee = "bumblebee"
  let bear = "bear"
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"
  let prime = "prime"
  let jazz = "jazz"

  let hash_concat =
    fn(a, b) { bytearray.concat(a |> crypto.sha2_256, b |> crypto.sha2_256) }
  let root_hash =
    hash_concat(
      hash_concat(bumblebee, hash_concat(bear, dog)),
      hash_concat(hash_concat(cat, mouse), hash_concat(prime, jazz)),
    )
      |> crypto.sha2_256

  let root_from_list =
    from_list([bumblebee, bear, dog, cat, mouse, prime, jazz], identity) |> root
  let root_from_hash = root_hash |> from_hash

  root_from_list == root_from_hash
}

///                             root
///                             hash
///                ┌────────── concat ──────────┐
///               hash                        hash
///        ┌──── concat ───┐            ┌─── concat ────┐
///       hash           hash          hash           hash
///      concat         concat        concat         concat
///   hash    hash    hash  hash    hash  hash    hash    hash
/// bumblebee bear    dog   cat     mouse prime   jazz  ironhide
test from_list_8() {
  let bumblebee = "bumblebee"
  let bear = "bear"
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"
  let prime = "prime"
  let jazz = "jazz"
  let ironhide = "ironhide"

  let hash_concat =
    fn(a, b) { bytearray.concat(a |> crypto.sha2_256, b |> crypto.sha2_256) }
  let root_hash =
    hash_concat(
      hash_concat(hash_concat(bumblebee, bear), hash_concat(dog, cat)),
      hash_concat(hash_concat(mouse, prime), hash_concat(jazz, ironhide)),
    )
      |> crypto.sha2_256

  let root_from_list =
    from_list(
      [bumblebee, bear, dog, cat, mouse, prime, jazz, ironhide],
      identity,
    )
      |> root
  let root_from_hash = root_hash |> from_hash

  root_from_list == root_from_hash
}

///                              root
///                              hash
///                ┌─────────── concat ───────────┐
///               hash                          hash
///        ┌──── concat ───┐            ┌───── concat ─────┐
///       hash           hash          hash              hash
///      concat         concat        concat        ┌── concat ──┐
///   hash    hash    hash  hash    hash  hash     hash        hash
/// bumblebee bear    dog   cat     mouse prime    jazz       concat
///                                                        hash    hash
///                                                      ironhide ratchet
test from_list_9() {
  let bumblebee = "bumblebee"
  let bear = "bear"
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"
  let prime = "prime"
  let jazz = "jazz"
  let ironhide = "ironhide"
  let ratchet = "ratchet"

  let hash_concat =
    fn(a, b) { bytearray.concat(a |> crypto.sha2_256, b |> crypto.sha2_256) }
  let root_hash =
    hash_concat(
      hash_concat(hash_concat(bumblebee, bear), hash_concat(dog, cat)),
      hash_concat(
        hash_concat(mouse, prime),
        hash_concat(jazz, hash_concat(ironhide, ratchet)),
      ),
    )
      |> crypto.sha2_256

  let root_from_list =
    from_list(
      [bumblebee, bear, dog, cat, mouse, prime, jazz, ironhide, ratchet],
      identity,
    )
      |> root
  let root_from_hash = root_hash |> from_hash

  expect
    get_proof(
      from_list(
        [bumblebee, bear, dog, cat, mouse, prime, jazz, ironhide, ratchet],
        identity,
      ),
      ironhide,
      identity,
    ) == Some(
      [
        Right(ratchet |> crypto.sha2_256 |> Root),
        Left(jazz |> crypto.sha2_256 |> Root),
        Left(hash_concat(mouse, prime) |> crypto.sha2_256 |> Root),
        Left(
          hash_concat(hash_concat(bumblebee, bear), hash_concat(dog, cat))
            |> crypto.sha2_256
            |> Root,
        ),
      ],
    )

  root_from_list == root_from_hash
}

/// Deconstruct a [`MerkleTree`](#MerkleTree) back to a list of elements.
pub fn to_list(self: MerkleTree<a>) -> List<a> {
  when self is {
    Empty -> []
    Leaf { value, .. } -> [value]
    Node { left, right, .. } -> list.concat(to_list(left), to_list(right))
  }
}

test to_list_1() {
  let items = []
  ( from_list(items, identity) |> to_list() ) == items
}

test to_list_2() {
  let items = ["dog"]
  ( from_list(items, identity) |> to_list() ) == items
}

test to_list_3() {
  let items = ["dog", "cat", "mouse"]
  ( from_list(items, identity) |> to_list() ) == items
}

// ## Merkle Proof

/// Check whether an element is part of a [`MerkleTree`](#MerkleTree) using only
/// its root hash and a [`Proof`](#Proof).
///
/// The proof (and verification) is guaranteed to be in log(n) of the size of
/// the tree, which is / why such data-structures are interesting.
pub fn is_member(
  root: Root,
  item: a,
  proof: Proof<a>,
  serialise: fn(a) -> ByteArray,
) -> Bool {
  verify_proof(root, item |> serialise |> crypto.sha2_256, proof)
}

fn do_get_proof(
  self: MerkleTree<a>,
  item_hash: Hash<Sha2_256, a>,
  proof: Proof<a>,
) -> Option<Proof<a>> {
  when self is {
    Empty -> None

    Leaf { hash, .. } ->
      if hash == item_hash {
        Some(proof)
      } else {
        None
      }

    Node { left, right, .. } -> {
      let try_left =
        left |> do_get_proof(item_hash, [right |> root |> Right, ..proof])
      let try_right =
        right |> do_get_proof(item_hash, [left |> root |> Left, ..proof])

      option.choice([try_left, try_right])
    }
  }
}

/// Construct a membership [`Proof`](#Proof) from an element and a [`MerkleTree`](#MerkleTree).
///
/// Returns `None` when the element isn't a member of the tree to begin with.
///
/// Note that the proof is empty (i.e. `[]`) for trees that have a single element.
pub fn get_proof(
  self: MerkleTree<a>,
  item: a,
  serialise: fn(a) -> ByteArray,
) -> Option<Proof<a>> {
  self |> do_get_proof(item |> serialise |> crypto.sha2_256, [])
}

test get_proof_1() {
  get_proof(from_list([], identity), "dog", identity) == None
}

test get_proof_2() {
  get_proof(
    from_list(["dog", "cat", "mouse", "horse", "pig", "bull"], identity),
    "parrot",
    identity,
  ) == None
}

test get_proof_3() {
  let mt = from_list(["dog"], identity)
  expect Some(proof) = get_proof(mt, "dog", identity)

  and {
    (proof == [])?,
    is_member(mt |> root, "dog", proof, identity)?,
  }
}

test get_proof_is_member_1() {
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"
  let mt = from_list([dog, cat, mouse], identity)

  expect Some(dog_proof) = get_proof(mt, dog, identity)
  expect Some(cat_proof) = get_proof(mt, cat, identity)
  expect Some(mouse_proof) = get_proof(mt, mouse, identity)

  let all_members = and {
      is_member(mt |> root, dog, dog_proof, identity)?,
      is_member(mt |> root, cat, cat_proof, identity)?,
      is_member(mt |> root, mouse, mouse_proof, identity)?,
    }

  let check_sizes = and {
      (list.length(dog_proof) == 1)?,
      (list.length(cat_proof) == 2)?,
      (list.length(mouse_proof) == 2)?,
    }

  all_members? && check_sizes?
}

test get_proof_is_member_2() {
  let dog = "dog"
  let cat = "cat"
  let mouse = "mouse"
  let mt = from_list([dog, cat, mouse], identity)

  expect Some(dog_proof) = get_proof(mt, dog, identity)

  is_member(mt |> root, cat, dog_proof, identity)
    |> not
}

/// An alternative version of [`is_member`](#is_member) where the element to
/// check is directly provided as hash. This assumes the hash pre-image was
/// produced using same serialization method as for constructing the tree.
///
/// Returns `True` when the `Proof` is valid for the provided element hash
/// digest and tree root. Said differently, returns `True` when the
/// original element is indeed part of the tree. Returns `False` otherwise.
pub fn verify_proof(
  root: Root,
  item_hash: Hash<Sha2_256, a>,
  proof: Proof<a>,
) -> Bool {
  when proof is {
    [] -> root == Root(item_hash)

    [head, ..tail] ->
      when head is {
        Left(left) ->
          verify_proof(root, combine(left, item_hash |> Root).inner, tail)

        Right(right) ->
          verify_proof(root, combine(item_hash |> Root, right).inner, tail)
      }
  }
}

// ----- Internal

fn combine(left: Root, right: Root) -> Root {
  bytearray.concat(left.inner, right.inner)
    |> crypto.sha2_256
    |> Root
}
