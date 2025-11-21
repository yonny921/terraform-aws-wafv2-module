resource "aws_wafv2_ip_set" "this" {
  for_each = var.ip_sets_config

  name               = each.key
  description        = each.value.description
  scope              = var.scope
  ip_address_version = each.value.ip_version
  addresses          = each.value.addresses
}