resource "aws_wafv2_web_acl_logging_configuration" "this" {
  for_each = { for k, v in var.logging_configs : k => v if v.enabled }

  log_destination_configs = each.value.destination_arns
  resource_arn            = var.waf_arns[each.key]

  dynamic "redacted_fields" {
    for_each = each.value.redacted_fields != null ? each.value.redacted_fields.headers : []
    
    content {
      single_header {
        name = redacted_fields.value
      }
    }
  }

  dynamic "redacted_fields" {
    for_each = (each.value.redacted_fields != null && try(each.value.redacted_fields.query_string, false)) ? [1] : []
    
    content {
      query_string {}
    }
  }

  dynamic "redacted_fields" {
    for_each = (each.value.redacted_fields != null && try(each.value.redacted_fields.uri_path, false)) ? [1] : []
    
    content {
      uri_path {}
    }
  }
}