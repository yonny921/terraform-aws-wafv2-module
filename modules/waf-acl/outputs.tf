output "web_acl_arns" {
  description = "Mapa de ARNs de todas las Web ACLs creadas."
  value = {
    for k, v in aws_wafv2_web_acl.this : k => v.arn
  }
}

output "web_acl_ids" {
  description = "Mapa de IDs de todas las Web ACLs creadas."
  value = {
    for k, v in aws_wafv2_web_acl.this : k => v.id
  }
}

output "ip_set_arns" {
  description = "Mapa de ARNs de todos los IP Sets creados."
  value = {
    for k, v in aws_wafv2_ip_set.this : k => v.arn
  }
}

output "regex_pattern_set_arns" {
  description = "Mapa de ARNs de todos los Regex Pattern Sets creados."
  value = {
    for k, v in aws_wafv2_regex_pattern_set.this : k => v.arn
  }
}