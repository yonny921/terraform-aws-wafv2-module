resource "aws_wafv2_web_acl" "this" {

  # CREACION DE MULTIPLES WAF ACL

  for_each = var.web_acls_config

  name        = each.key
  description = each.value.description
  scope       = each.value.scope
  tags        = each.value.tags

  default_action {
    dynamic "allow" {
      for_each = lower(each.value.default_action) == "allow" ? [1] : []
      content {}
    }
    dynamic "block" {
      for_each = lower(each.value.default_action) == "block" ? [1] : []
      content {}
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = each.value.visibility_config.cloudwatch_metrics_enabled
    metric_name                = each.value.visibility_config.metric_name != null ? each.value.visibility_config.metric_name : "${each.key}-metrics" # Default Metric Name Dinamico
    sampled_requests_enabled   = each.value.visibility_config.sampled_requests_enabled
  }


  # REGLAS ADMINISTRADAS DE AWS (MANAGED RULES)

  dynamic "rule" {
    for_each = each.value.managed_rules

    content {
      name     = rule.key
      priority = rule.value.priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.rule_set_name
          vendor_name = rule.value.vendor_name

          # Logica de Rule Overrides

          dynamic "rule_action_override" {
            for_each = rule.value.rule_overrides
            content {
              name = rule_action_override.key
              action_to_use {
                dynamic "count" {
                  for_each = rule_action_override.value == "count" ? [1] : []
                  content {}
                }
                dynamic "allow" {
                  for_each = rule_action_override.value == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = rule_action_override.value == "block" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = rule_action_override.value == "captcha" ? [1] : []
                  content {}
                }
              }
            }
          }

          # Lógica de Bot Control

          dynamic "managed_rule_group_configs" {
            for_each = rule.value.bot_control_config != null ? [1] : []
            content {
              aws_managed_rules_bot_control_rule_set {
                inspection_level = rule.value.bot_control_config.inspection_level
              }
            }
          }

          # Lógica de Scope Down
          dynamic "scope_down_statement" {
            for_each = length(rule.value.excluded_paths) > 0 ? [1] : []
            content {
              not_statement {
                statement {
                  or_statement {
                    dynamic "statement" {
                      for_each = rule.value.excluded_paths
                      content {
                        byte_match_statement {
                          field_to_match {
                            uri_path {}
                          }
                          search_string         = statement.key
                          positional_constraint = statement.value
                          text_transformation {
                            priority = 0
                            type     = "NONE"
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = rule.value.visibility_config.cloudwatch_metrics_enabled
        sampled_requests_enabled   = rule.value.visibility_config.sampled_requests_enabled
        metric_name = (
          rule.value.visibility_config.metric_name != null ? rule.value.visibility_config.metric_name : (rule.value.metric_name != null ? rule.value.metric_name : "${rule.key}-metric")
        )
      }
    }
  }

  # REGLAS CUSTOM (CUSTOM RULES)

  dynamic "rule" {
    for_each = each.value.custom_rules

    content {
      name     = rule.key
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        # Rate Limit
        dynamic "rate_based_statement" {
          for_each = rule.value.rate_limit != null ? [1] : []
          content {
            limit              = rule.value.rate_limit
            aggregate_key_type = "IP"
          }
        }

        # Geo Match
        dynamic "geo_match_statement" {
          for_each = rule.value.geo_match != null ? [1] : []
          content {
            country_codes = rule.value.geo_match
          }
        }

        # IP Set Reference
        dynamic "ip_set_reference_statement" {
          for_each = (rule.value.ip_set_arn != null || rule.value.ip_set_key != null) ? [1] : []
          content {
            arn = rule.value.ip_set_key != null ? aws_wafv2_ip_set.this[rule.value.ip_set_key].arn : rule.value.ip_set_arn
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = rule.value.visibility_config.cloudwatch_metrics_enabled
        sampled_requests_enabled   = rule.value.visibility_config.sampled_requests_enabled
        metric_name = (
          rule.value.visibility_config.metric_name != null ? rule.value.visibility_config.metric_name : (rule.value.metric_name != null ? rule.value.metric_name : "${rule.key}-metric")
        )
      }
    }
  }
}


resource "aws_wafv2_web_acl_logging_configuration" "this" {
  for_each = { for k, v in var.logging_configs : k => v if v.enabled }

  log_destination_configs = each.value.destination_arns
  resource_arn            = aws_wafv2_web_acl.this[each.key].arn

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


resource "aws_wafv2_ip_set" "this" {
  for_each = var.ip_sets_config

  name               = each.key
  description        = each.value.description
  scope              = each.value.scope
  ip_address_version = each.value.ip_version
  addresses          = each.value.addresses
}