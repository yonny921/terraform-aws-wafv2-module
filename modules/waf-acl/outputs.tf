output "web_acl_arns" {
  description = "Mapa de Nombres a ARNs de los WAFs creados"
  value       = { for k, v in aws_wafv2_web_acl.this : k => v.arn }
}

output "arn_map" {
  description = "Mapa de Nombres de IP Set a sus ARNs"
  value       = { for k, v in aws_wafv2_ip_set.this : k => v.arn }
}