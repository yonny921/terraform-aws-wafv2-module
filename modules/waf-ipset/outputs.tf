output "arn_map" {
  description = "Mapa de Nombres de IP Set a sus ARNs"
  value       = { for k, v in aws_wafv2_ip_set.this : k => v.arn }
}