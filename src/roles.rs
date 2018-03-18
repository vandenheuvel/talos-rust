use std::collections::HashMap;

pub type RoleName = String;
pub struct Rule {
    pub parent: RoleName,
    pub child: RoleName,
}

pub struct RoleGraph {
    roles: HashMap<String, String>,
}

impl RoleGraph {
    pub fn from_rules(rules: Vec<Rule>) -> RoleGraph {
        let mut roles = HashMap::new();
        for rule in rules.into_iter() {
            if roles.contains_key(&rule.child) {
                panic!();
            } else {
                roles.insert(rule.child, rule.parent);
            }
        }

        RoleGraph { roles, }
    }
    pub fn get_group_names(&self, first_name: RoleName) -> Vec<RoleName> {
        let mut names = Vec::new();
        names.push(first_name.clone());

        let mut to_resolve = &first_name;
        while let Some(name) = self.roles.get(to_resolve) {
            names.push(name.clone());
            to_resolve = name;
        }

        names
    }
}

pub struct Role {
    name: RoleName,
    sub_roles: Vec<Role>
}
