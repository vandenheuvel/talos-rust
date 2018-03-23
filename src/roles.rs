use std::collections::HashMap;

pub type RoleName = String;
pub struct Rule {
    pub parent: RoleName,
    pub child: RoleName,
}
impl Rule {
    fn new(parent: &str, child: &str) -> Rule { Rule { parent: parent.to_string(), child: child.to_string(), } }
}

pub struct RoleGraph {
    roles: HashMap<String, String>,
}

impl RoleGraph {
    pub fn from_rules(rules: Vec<Rule>) -> Result<RoleGraph, String> {
        let mut roles = HashMap::new();
        for rule in rules.into_iter() {
            if roles.contains_key(&rule.child) {
                return Err(format!("Child \"{}\" already has parent \"{}\"",
                                   rule.child, rule.parent));
            } else {
                roles.insert(rule.child, rule.parent);
            }
        }

        Ok(RoleGraph { roles, })
    }
    pub fn get_group_names(&self, first_name: &str) -> Vec<RoleName> {
        let mut names: Vec<String> = Vec::new();
        names.push(first_name.to_string());

        let mut to_resolve = first_name;
        while let Some(name) = self.roles.get(to_resolve) {
            names.push(name.clone());
            to_resolve = name;
        }

        names
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_single() {
        let rules = vec![Rule::new("X", "Y")];
        let graph = RoleGraph::from_rules(rules).unwrap();

        assert_eq!(graph.get_group_names("Y"), vec!["Y".to_string(), "X".to_string()]);
    }

    #[test]
    fn test_multiple() {
        let rules = vec![Rule::new("X", "Y"), Rule::new("Y", "Z")];
        let graph = RoleGraph::from_rules(rules).unwrap();

        assert_eq!(graph.get_group_names("Z"), vec!["Z".to_string(),
                                                    "Y".to_string(),
                                                    "X".to_string()]);
    }

    #[test]
    fn test_multi_parent() {
        let rules = vec![Rule::new("Y", "X"), Rule::new("Z", "X")];
        let graph = RoleGraph::from_rules(rules);

        assert!(graph.is_err());
    }
}