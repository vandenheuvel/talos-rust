use roles::RoleGraph;
use permissions::PermissionTree;
use roles::RoleName;
use std::collections::HashMap;

pub struct AccessChecker {
    role_graph: RoleGraph,
    permission_tree: PermissionTree,
    environment: Environment,
}

impl AccessChecker {
    pub fn new(role_graph: RoleGraph, permission_tree: PermissionTree) -> AccessChecker {
        AccessChecker { role_graph, permission_tree, environment: Environment {
            variables: HashMap::new(),
            sets: HashMap::new(),
        }, }
    }
    fn has_permission_for(&self, name: RoleName, resource: Vec<String>) -> bool {
        let names = self.role_graph.get_group_names(name);
        self.permission_tree.has_permission_for(names, resource, &self.environment)
    }
    pub fn set_environment(&mut self, environment: Environment) { self.environment = environment; }
}

pub struct Environment {
    pub variables: HashMap<String, String>,
    pub sets: HashMap<String, Vec<String>>,
}
