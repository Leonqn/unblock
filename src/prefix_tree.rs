use std::collections::BTreeMap;

#[derive(Default, Debug)]
pub struct PrefixTree {
    root: Node,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
struct Node {
    terminal: bool,
    children: BTreeMap<String, Node>,
}

impl PrefixTree {
    pub fn add(&mut self, domain: String) {
        fn add(node: &mut BTreeMap<String, Node>, parts: &mut Vec<String>) {
            if let Some(part) = parts.pop() {
                let terminal = parts.is_empty();
                node.entry(part)
                    .and_modify(|x| {
                        x.terminal = x.terminal || terminal;
                        add(&mut x.children, parts);
                    })
                    .or_insert_with(|| {
                        let mut new_node = Node {
                            children: BTreeMap::new(),
                            terminal,
                        };
                        add(&mut new_node.children, parts);
                        new_node
                    });
            }
        }
        let mut domain: Vec<_> = domain.split('.').map(ToOwned::to_owned).collect();

        add(&mut self.root.children, &mut domain)
    }

    pub fn contains(&self, domain: &str) -> bool {
        fn contains(node: &Node, parts: &mut Vec<&str>) -> bool {
            if let Some(part) = parts.pop() {
                if let Some(node) = node.children.get(part) {
                    contains(node, parts)
                } else {
                    node.children.contains_key("*")
                }
            } else {
                node.terminal || node.children.contains_key("*")
            }
        }

        let mut domain: Vec<_> = domain.split('.').collect();
        contains(&self.root, &mut domain)
    }
}

#[cfg(test)]
mod tests {
    use super::PrefixTree;
    use quickcheck_macros::quickcheck;

    #[test]
    fn tree_tests() {
        let mut tree = PrefixTree::default();
        tree.add("www.test.ru".to_owned());
        tree.add("www.test2.ru".to_owned());
        tree.add("*.asd.tu".to_owned());

        assert!(tree.contains("www.test.ru"));
        assert!(tree.contains("www.test2.ru"));
        assert!(tree.contains("www.asd.tu"));
        assert!(tree.contains("asd.tu"));
        assert!(!tree.contains("tu"));
    }

    #[quickcheck]
    fn all_inserted_strings_should_exist(strs: Vec<String>) -> bool {
        let mut tree = PrefixTree::default();
        for str in strs.iter() {
            tree.add(str.to_owned());
        }
        strs.iter().all(|x| tree.contains(x))
    }
}
