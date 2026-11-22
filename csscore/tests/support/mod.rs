//! Shared test arena for the `csscore` host tests: a tiny `Tree`
//! implementation (the crate itself depends on nothing, not even `dom`).
#![allow(dead_code)]

use csscore::{Computed, ElementRef, Stylesheet, Tree};

/// Attributes a test element carries.
#[derive(Clone, Copy, Default)]
pub struct A {
    pub id: Option<&'static str>,
    pub class: Option<&'static str>,
    pub style: Option<&'static str>,
}

impl A {
    pub fn id(mut self, value: &'static str) -> Self {
        self.id = Some(value);
        self
    }

    pub fn class(mut self, value: &'static str) -> Self {
        self.class = Some(value);
        self
    }

    pub fn style(mut self, value: &'static str) -> Self {
        self.style = Some(value);
        self
    }
}

struct Node {
    parent: Option<usize>,
    name: Option<&'static str>,
    attrs: A,
}

/// Arena: index 0 is the document root (not an element).
pub struct TestTree {
    nodes: Vec<Node>,
}

impl TestTree {
    pub fn new() -> Self {
        TestTree {
            nodes: vec![Node {
                parent: None,
                name: None,
                attrs: A::default(),
            }],
        }
    }

    pub fn add(&mut self, parent: usize, name: &'static str, attrs: A) -> usize {
        let id = self.nodes.len();
        self.nodes.push(Node {
            parent: Some(parent),
            name: Some(name),
            attrs,
        });
        id
    }

    /// Parse `css` and cascade it onto `node`.
    pub fn style(&self, node: usize, css: &str) -> Computed {
        csscore::compute(self, node, &Stylesheet::parse(css))
    }
}

impl Tree for TestTree {
    fn parent_element(&self, node: usize) -> Option<usize> {
        let parent = self.nodes.get(node)?.parent?;
        // The root (index 0) is not an element.
        self.nodes.get(parent)?.name?;
        Some(parent)
    }

    fn element(&self, node: usize) -> Option<ElementRef<'_>> {
        let node = self.nodes.get(node)?;
        Some(ElementRef {
            name: node.name?,
            id: node.attrs.id,
            class: node.attrs.class,
            style: node.attrs.style,
        })
    }
}
