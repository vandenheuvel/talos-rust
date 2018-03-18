use access_checker::AccessChecker;
use roles::{RoleGraph, Rule as RoleRule};
use permissions::PermissionTree;


pub fn parse(description: String) -> Result<AccessChecker, ()> {
    let rules: Vec<Rule> = description.lines()
        .map(|line| line.split_whitespace().collect())
        .map(to_rule)
        .collect();
    let (role_rules, permission_rules) = split_rules(rules);
    let role_graph = RoleGraph::from_rules(role_rules);
    let permission_tree = PermissionTree::from_rules(permission_rules);

    Ok(AccessChecker::new(role_graph, permission_tree))
}

fn to_rule(line: Vec<&str>) -> Rule {
    match line.as_slice() {
        [group, ">", name] => {
            Rule::Role(group.to_string(), name.to_string())
        },
        [permission, name, resource] => {
            let permission = match *permission {
                "allow" => Permission::Allow,
                "deny" => Permission::Deny,
                _ => panic!(),
            };
            let resource = resource.split('/')
                .map(|word| match word.chars().collect::<Vec<_>>().as_slice() {
                ['[', variable_name.., ']'] => PermissionKind::Variable(variable_name.into_iter().collect()),
                ['{', set_name.., '}']      => PermissionKind::Set(set_name.into_iter().collect()),
                ['*']                       => PermissionKind::Universal,
                literal                     => PermissionKind::Literal(literal.into_iter().collect()),
            }).collect();

            Rule::Permission(permission, name.to_string(), resource)
        },
        _ => panic!(),
    }
}

fn split_rules(mixed: Vec<Rule>) -> (Vec<RoleRule>, Vec<PermissionRule>) {
    let (mut role_rules , mut permission_rules) = (Vec::new(), Vec::new());

    for rule in mixed.into_iter() {
        match rule {
            Rule::Role(parent, child)
                => role_rules.push(RoleRule { parent, child, }),
            Rule::Permission(permission, role_name, resource)
                => permission_rules.push(PermissionRule{ permission, role_name, resource, }),
        }
    }

    (role_rules, permission_rules)
}

type RoleName = String;
enum Rule {
    Role(RoleName, RoleName),
    Permission(Permission, RoleName, Resource),
}

pub struct PermissionRule {
    pub permission: Permission,
    pub role_name: RoleName,
    pub resource: Resource,
}

pub enum PermissionKind {
    Literal(String),
    Variable(String),
    Set(String),
    Universal,
}
pub type Resource = Vec<PermissionKind>;

#[derive(Copy, Clone)]
pub enum Permission {
    Allow,
    Deny,
}
