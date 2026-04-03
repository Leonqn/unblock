#[derive(Default, Debug)]
pub struct PrefixTree {
    root: Node,
}

#[derive(Debug, Default)]
struct Node {
    terminal: bool,
    children: Vec<(String, Node)>,
}

impl Node {
    fn find(&self, key: &str) -> Option<&Node> {
        self.children.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn get_or_insert(&mut self, key: String) -> &mut Node {
        if let Some(pos) = self.children.iter().position(|(k, _)| *k == key) {
            &mut self.children[pos].1
        } else {
            self.children.push((key, Node::default()));
            &mut self.children.last_mut().unwrap().1
        }
    }
}

impl PrefixTree {
    pub fn add(&mut self, domain: String) {
        let domain = domain.trim_matches('.');
        if domain.is_empty() {
            self.root.terminal = true;
            return;
        }
        let mut parts = domain.rsplit('.').filter(|p| !p.is_empty()).peekable();
        let mut node = &mut self.root;
        while let Some(part) = parts.next() {
            let is_last = parts.peek().is_none();
            node = node.get_or_insert(part.to_string());
            if is_last {
                node.terminal = true;
                node.children.clear();
            }
            if node.terminal && !is_last {
                return;
            }
        }
    }

    pub fn contains(&self, domain: &str) -> bool {
        let mut node = &self.root;
        for part in domain.rsplit('.').filter(|p| !p.is_empty()) {
            if node.terminal {
                return true;
            }
            if let Some(child) = node.find(part) {
                node = child;
            } else {
                return node.find("*").is_some();
            }
        }
        node.terminal || node.find("*").is_some()
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

    #[test]
    fn adding_parent_domain_removes_children() {
        let mut tree = PrefixTree::default();
        tree.add("www.test.ru".to_owned());
        tree.add("api.test.ru".to_owned());
        tree.add("test.ru".to_owned());

        assert!(tree.contains("test.ru"));
        assert!(tree.contains("www.test.ru"));
        assert!(tree.contains("api.test.ru"));
        assert!(tree.contains("anything.test.ru"));
        // children should be pruned
        let test_node = tree.root.find("ru").unwrap().find("test").unwrap();
        assert!(test_node.children.is_empty());
    }

    #[test]
    fn specific_domain_does_not_override_parent() {
        let mut tree = PrefixTree::default();
        tree.add("test.ru".to_owned());
        tree.add("www.test.ru".to_owned());

        assert!(tree.contains("test.ru"));
        assert!(tree.contains("www.test.ru"));
        assert!(tree.contains("anything.test.ru"));
        // children should stay empty — www.test.ru is redundant
        let test_node = tree.root.find("ru").unwrap().find("test").unwrap();
        assert!(test_node.children.is_empty());
    }

    #[test]
    fn wildcard_matches_any_subdomain() {
        let mut tree = PrefixTree::default();
        tree.add("*.example.com".to_owned());

        // wildcard matches any single label
        assert!(tree.contains("www.example.com"));
        assert!(tree.contains("api.example.com"));
        assert!(tree.contains("anything.example.com"));
        // wildcard also matches deeper subdomains (because * node is terminal,
        // and terminal means "everything below matches")
        assert!(tree.contains("deep.sub.example.com"));
        // bare domain matches too (the for loop ends, then node.find("*").is_some())
        assert!(tree.contains("example.com"));
        // unrelated domain does not match
        assert!(!tree.contains("example.org"));
        assert!(!tree.contains("com"));

        // wildcard scoped to specific subdomain
        tree.add("*.sub.example.org".to_owned());
        assert!(tree.contains("www.sub.example.org"));
        assert!(tree.contains("deep.nested.sub.example.org"));
        assert!(tree.contains("sub.example.org"));
        // other subdomains of example.org should NOT match
        assert!(!tree.contains("other.example.org"));
        assert!(!tree.contains("example.org"));
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
