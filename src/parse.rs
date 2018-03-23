use access_checker::AccessChecker;
use roles::{RoleGraph, Rule as RoleRule};
use permissions::PermissionTree;


pub fn parse(description: String) -> Result<AccessChecker, String> {
    let rules: Vec<Rule> = match description.lines()
        .filter(|line| line.starts_with("#"))
        .map(|line| line.split_whitespace().collect())
        .map(to_rule).collect() {
        Ok(v) => v,
        Err(message) => return Err(format!("Could not convert line \"{:?}\" to a rule.", message)),
    };
    let (role_rules, permission_rules) = split_rules(rules);
    let role_graph = RoleGraph::from_rules(role_rules)?;
    let permission_tree = PermissionTree::from_rules(permission_rules);

    Ok(AccessChecker::new(role_graph, permission_tree))
}

fn to_rule(line: Vec<&str>) -> Result<Rule, String> {
    match line.as_slice() {
        [group, ">", name] => {
            Ok(Rule::Role(group.to_string(), name.to_string()))
        },
        [permission, name, resource] if resource.starts_with("/") => {
            let permission = match *permission {
                "allow" => Permission::Allow,
                "deny" => Permission::Deny,
                _ => return Err(format!("Permission type \"{}\" not known.", permission)),
            };
            let name = name.to_string();
            let resource = resource.split('/').skip(1) // Skip the empty &str
                .map(|word| match word.chars().collect::<Vec<_>>().as_slice() {
                    ['[', variable_name.., ']'] => PermissionKind::Variable(variable_name.into_iter().collect()),
                    ['{', set_name.., '}']      => PermissionKind::Set(set_name.into_iter().collect()),
                    ['*']                       => PermissionKind::Universal,
                    literal                     => PermissionKind::Literal(literal.into_iter().collect()),
            }).collect();

            Ok(Rule::Permission(permission, name, resource))
        },
        _ => return Err(format!("Parsing line \"{:?}\" failed: unknown format.", line)),
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
#[derive(Debug, Eq, PartialEq)]
enum Rule {
    Role(RoleName, RoleName),
    Permission(Permission, RoleName, Resource),
}

pub struct PermissionRule {
    pub permission: Permission,
    pub role_name: RoleName,
    pub resource: Resource,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PermissionKind {
    Literal(String),
    Variable(String),
    Set(String),
    Universal,
}
pub type Resource = Vec<PermissionKind>;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Permission {
    Allow,
    Deny,
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_to_rule() {
        let line = "Admin > User".split_whitespace().collect();
        let result = to_rule(line);
        let expected = Ok(Rule::Role("Admin".to_string(), "User".to_string()));
        assert_eq!(result, expected);

        let line = "x".split_whitespace().collect();
        let result = to_rule(line);
        assert!(result.is_err());

        let line = "a b c d".split_whitespace().collect();
        let result = to_rule(line);
        assert!(result.is_err());

        let line = "deny\tJeff\t/resource".split_whitespace().collect();
        let result = to_rule(line);
        let expected = Ok(Rule::Permission(Permission::Deny,
                                           "Jeff".to_string(),
                                           vec![PermissionKind::Literal("resource".to_string())]));
        assert_eq!(result, expected);
    }
}