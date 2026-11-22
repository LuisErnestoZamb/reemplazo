//! Shared test helpers for the `dom` suite: a structural invariant
//! walker run against every adversarial fixture (arena links, parent
//! pointers, sibling chains, depth and node caps).

#![allow(dead_code)]

use dom::{DEPTH_CAP, Document, NODE_CAP, NodeKind};
use std::collections::HashSet;

/// Assert the document is a well-formed tree: every node reachable
/// exactly once from the root (no cycles, no orphans), every child's
/// parent pointer consistent, depth ≤ [`DEPTH_CAP`], size ≤
/// [`NODE_CAP`]. Iterative — a cycle in a hostile fixture must fail
/// the assertion, never hang the test via recursion.
pub fn check(doc: &Document) {
    let root = doc.root();
    assert!(doc.node(root).is_some(), "root missing");
    assert!(
        doc.node(root).and_then(|n| n.parent).is_none(),
        "root must have no parent"
    );
    let mut visited: HashSet<usize> = HashSet::new();
    let mut work: Vec<(usize, usize)> = vec![(root, 0)];
    while let Some((id, depth)) = work.pop() {
        assert!(visited.insert(id), "node {id} visited twice (cycle?)");
        assert!(depth <= DEPTH_CAP, "depth {depth} exceeds DEPTH_CAP");
        let node = doc.node(id).expect("id came from the tree");
        if id != root {
            assert!(
                node.parent.is_some(),
                "non-root node {id} has no parent link"
            );
        }
        let mut child = node.first_child;
        while let Some(cid) = child {
            let c = doc.node(cid).expect("child id must exist in arena");
            assert_eq!(
                c.parent,
                Some(id),
                "child {cid} parent pointer does not point at {id}"
            );
            // Depth counts *elements* only: text under the deepest
            // element sits one level deeper in the arena but does not
            // open an element (the builder's cap is on open elements).
            let child_depth = if matches!(c.kind, NodeKind::Element(_)) {
                depth + 1
            } else {
                depth
            };
            work.push((cid, child_depth));
            child = c.next_sibling;
        }
    }
    assert_eq!(
        visited.len(),
        doc.node_count(),
        "unreachable nodes in the arena"
    );
    assert!(doc.node_count() <= NODE_CAP, "node cap exceeded");
}

/// Every element name in the document, document order (iterative).
pub fn element_names(doc: &Document) -> Vec<String> {
    let mut out = Vec::new();
    let mut work: Vec<usize> = vec![doc.root()];
    while let Some(id) = work.pop() {
        let Some(node) = doc.node(id) else {
            break;
        };
        if let NodeKind::Element(e) = &node.kind {
            out.push(e.name.clone());
        }
        let mut kids = Vec::new();
        let mut cur = node.first_child;
        while let Some(cid) = cur {
            kids.push(cid);
            cur = doc.node(cid).and_then(|n| n.next_sibling);
        }
        for kid in kids.into_iter().rev() {
            work.push(kid);
        }
    }
    out
}
