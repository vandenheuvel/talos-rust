use std::collections::HashMap;
use std::vec::IntoIter;

use access_checker::Environment;
use parse::{Permission as ParsedPermission, PermissionKind, PermissionRule};
use roles::RoleName;

pub struct PermissionTree {
    root_nodes: HashMap<String, RootNode>,
}
impl PermissionTree {
    pub fn from_rules(rules: Vec<PermissionRule>) -> PermissionTree {
        let mut roots = HashMap::new();
        for rule in rules.into_iter() {
            if !roots.contains_key(&rule.role_name) {
                roots.insert(rule.role_name.to_string(), RootNode {
                    permission: Permission::Deny,
                    sub_nodes: Vec::new(),
                });
            }
            roots.get_mut(&rule.role_name).unwrap().add_permission_rule(rule.permission,
                                                                       rule.resource.into_iter());
        }
        PermissionTree {
            root_nodes: roots,
        }
    }
    pub fn has_permission_for(&self,
                              names: Vec<RoleName>,
                              resource: Vec<String>,
                              environment: &Environment) -> bool {
        names.into_iter()
            .map(|name| self.root_nodes.get(&name))
            .any(|node| match node {
                Some(root) => root.has_permission_for(&resource[..], environment),
                None => false,
            })
    }
}

pub trait Node {
    fn has_permission_for(&self, object: &[String], environment: &Environment) -> bool;
    fn sub_node_has_permission_for(&self,
                                   object: &[String],
                                   environment: &Environment) -> bool {
        self.sub_nodes().iter()
            .any(|node| node.has_permission_for(object, environment))
    }
    fn add_sub_node(&mut self, node: Box<Node>);
    fn sub_nodes(&self) -> &Vec<Box<Node>>;
    fn add_permission_rule(&mut self,
                           parsed_permission: ParsedPermission,
                           mut resource: IntoIter<PermissionKind>) {
        // TODO: Reuse nodes if they already exist
        let at_deepest_level = resource.len() == 1;
        let permission = if at_deepest_level {
            match parsed_permission {
                ParsedPermission::Allow => Permission::Allow,
                ParsedPermission::Deny  => Permission::Deny,
            }
        } else { Permission::None };

        let permission_kind = resource.next().unwrap();
        let mut new_node: Box<Node> = match permission_kind {
            PermissionKind::Literal(resource_name) => Box::new(LiteralNode {
                resource_name,
                permission,
                sub_nodes: Vec::new(),
            }),
            PermissionKind::Variable(variable_name) => Box::new(VariableNode {
                variable_name,
                permission,
                sub_nodes: Vec::new(),
            }),
            PermissionKind::Set(set_name) => Box::new(SetNode {
                set_name,
                permission,
                sub_nodes: Vec::new(),
            }),
            PermissionKind::Universal => Box::new(UniversalNode {
                permission,
                sub_nodes: Vec::new(),
            }),
        };

        if !at_deepest_level {
            new_node.add_permission_rule(parsed_permission, resource);
        }

        self.add_sub_node(Box::from(new_node));
    }
}

pub struct RootNode {
    permission: Permission,
    sub_nodes: Vec<Box<Node>>,
}
impl Node for RootNode {
    fn has_permission_for(&self, object: &[String], environment: &Environment) -> bool {
        self.sub_node_has_permission_for(object, environment)
    }
    fn add_sub_node(&mut self, node: Box<Node>) { self.sub_nodes.push(node) }
    fn sub_nodes(&self) -> &Vec<Box<Node>> { &self.sub_nodes }
}

struct LiteralNode {
    resource_name: String,
    permission: Permission,
    sub_nodes: Vec<Box<Node>>,
}
impl Node for LiteralNode {
    fn has_permission_for(&self, object: &[String], environment: &Environment) -> bool {
        if object[0] == self.resource_name {
            return if object.len() == 1 { true } else {
                 self.sub_node_has_permission_for(&object[1..], environment)
            }
        }
        false
    }
    fn add_sub_node(&mut self, node: Box<Node>) { self.sub_nodes.push(node) }
    fn sub_nodes(&self) -> &Vec<Box<Node>> { &self.sub_nodes }
}

struct VariableNode {
    variable_name: String,
    permission: Permission,
    sub_nodes: Vec<Box<Node>>,
}
impl Node for VariableNode {
    fn has_permission_for(&self, object: &[String], environment: &Environment) -> bool {
        if let Some(resource_name) = environment.variables.get(&self.variable_name) {
            if object[0] == *resource_name {
                return if object.len() == 1 { self.permission.into() } else {
                    self.sub_node_has_permission_for(&object[1..], environment)
                }
            }
        }
        false
    }
    fn add_sub_node(&mut self, node: Box<Node>) { self.sub_nodes.push(node) }
    fn sub_nodes(&self) -> &Vec<Box<Node>> { &self.sub_nodes }
}

struct SetNode {
    set_name: String,
    permission: Permission,
    sub_nodes: Vec<Box<Node>>,
}
impl Node for SetNode {
    fn has_permission_for(&self, object: &[String], environment: &Environment) -> bool {
        if let Some(set) = environment.sets.get(&self.set_name) {
            if set.contains(&object[0]) {
                return if object.len() == 1 { self.permission.into() } else {
                    self.sub_node_has_permission_for(&object[1..], environment)
                }
            }
        }
        false
    }
    fn add_sub_node(&mut self, node: Box<Node>) { self.sub_nodes.push(node) }
    fn sub_nodes(&self) -> &Vec<Box<Node>> { &self.sub_nodes }
}

struct UniversalNode {
    permission: Permission,
    sub_nodes: Vec<Box<Node>>,
}
impl Node for UniversalNode {
    fn has_permission_for(&self, object: &[String], environment: &Environment) -> bool {
        return if object.len() == 1 { self.permission.into() } else {
            self.sub_node_has_permission_for(&object[1..], environment)
        }
    }
    fn add_sub_node(&mut self, node: Box<Node>) { self.sub_nodes.push(node) }
    fn sub_nodes(&self) -> &Vec<Box<Node>> { &self.sub_nodes }
}

#[derive(Copy, Clone)]
pub enum Permission {
    Allow,
    Deny,
    None,
}

impl From<Permission> for bool {
    fn from(permission: Permission) -> bool {
        match permission {
            Permission::Allow => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_permission_tree() {
        let role_name = "X".to_string();
        let tree = PermissionTree::from_rules(vec![PermissionRule {
            permission: ParsedPermission::Allow,
            role_name: role_name.clone(),
            resource: vec![PermissionKind::Literal("a".to_string())],
        }]);

        assert!(tree.has_permission_for(vec![role_name.clone()],
                                        vec!["a".to_string()],
                                        &Environment {
                                            variables: HashMap::new(),
                                            sets: HashMap::new(),
                                        }));
    }
}