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

  dynamic visibility_config {
    for_each = length(keys(each.value.visibility_config)) > 0 ? [1] : []
      content {
        cloudwatch_metrics_enabled = try(visibility_config.value.cloudwatch_metrics_enabled, false)
        metric_name                = try(visibility_config.value.metric_name, "${each.key}-metrics") 
        sampled_requests_enabled   = try(visibility_config.value.sampled_requests_enabled, true)
      }
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

          # Lógica de Scope Down Statements

          dynamic "scope_down_statement" {
            for_each = length(rule.value.scope_down_statements) > 0 ? [1] : []

            content {
              and_statement {
                dynamic "statement" {
                  for_each = rule.value.scope_down_statements

                  content {
                    dynamic "not_statement" {
                      for_each = contains(["NOT_BYTE_MATCH", "NOT_IP_SET_REFERENCE", "NOT_HEADER_MATCH"], statement.value.type) ? [1] : []
                      content {
                        statement {
                          dynamic "byte_match_statement" {
                            for_each = contains(["NOT_BYTE_MATCH", "NOT_HEADER_MATCH"], statement.value.type) ? [1] : []
                            content {
                              field_to_match {
                                dynamic "uri_path" {
                                  for_each = statement.value.match_key == "URI_PATH" ? [1] : []
                                  content {}
                                }
                                dynamic "single_header" {
                                  for_each = statement.value.match_key != "URI_PATH" && statement.value.match_key != null ? [1] : []
                                  content {
                                    name = statement.value.match_key
                                  }
                                }
                              }
                              search_string       =   statement.value.match_value[0]
                              positional_constraint = statement.value.positional_constraint
                              text_transformation {
                                priority = 0
                                type     = statement.value.transformation_type
                              }
                            }
                          }
                          dynamic "ip_set_reference_statement" {
                            for_each = statement.value.type == "NOT_IP_SET_REFERENCE" ? [1] : []
                            content {
                              arn = aws_wafv2_ip_set.this[statement.value.ip_set_key_ref].arn
                            }
                          }
                        }
                      }
                    }
                      
                    dynamic "geo_match_statement" {
                      for_each = statement.value.type == "GEO_MATCH" ? [1] : []
                        content {
                          country_codes = statement.value.match_value # match_value aquí debe ser una lista de códigos de país
                        }
                      }
                      
                      # 2.2 BYTE MATCH Positivo (Para limitar la regla solo a un campo específico sin excluirlo)
                    dynamic "byte_match_statement" {
                      for_each = statement.value.type == "BYTE_MATCH" ? [1] : []
                      content {
                        field_to_match {
                          dynamic "uri_path" {
                            for_each = statement.value.match_key == "URI_PATH" ? [1] : []
                            content {}
                          }
                          dynamic "single_header" {
                            for_each = statement.value.match_key == "HEADER" ? [1] : []
                            content {
                              name = statement.value.match_key
                            }
                          }
                        }
                        search_string         = statement.value.match_value[0]
                        positional_constraint = statement.value.positional_constraint
                        text_transformation {
                          priority = 0
                          type     = statement.value.transformation_type
                        }
                      }
                    }
                          
                          # 2.3 IP SET REFERENCE Positiva (Para limitar la regla solo a ciertas IPs)
                    dynamic "ip_set_reference_statement" {
                      for_each = statement.value.type == "IP_SET_REFERENCE" ? [1] : []
                      content {
                        # Referencia al IP Set creado localmente
                        arn = aws_wafv2_ip_set.this[statement.value.ip_set_key_ref].arn
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = length(keys(rule.value.visibility_config)) > 0 ? [1] : []
        
        content {
          cloudwatch_metrics_enabled = try(visibility_config.value.cloudwatch_metrics_enabled, false)
          sampled_requests_enabled   = try(visibility_config.value.sampled_requests_enabled, true)
          metric_name                = try(visibility_config.value.metric_name, rule.value.metric_name, "${rule.key}-metric")
        }
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
        dynamic "rate_based_statement" {
          for_each = rule.value.rate_limit != null ? [1] : []
          
          content {
            limit              = rule.value.rate_limit
            aggregate_key_type = "IP"
            
            dynamic "scope_down_statement" {
              for_each = (rule.value.geo_match != null || rule.value.ip_set_key != null || rule.value.ip_set_arn != null) ? [1] : []
              
              content {
                and_statement { 
                  
                  dynamic "statement" {
                    for_each = rule.value.geo_match != null ? [1] : []
                    content {
                      geo_match_statement { country_codes = rule.value.geo_match }
                    }
                  }
                  
                  dynamic "statement" {
                    for_each = (rule.value.ip_set_arn != null || rule.value.ip_set_key != null) ? [1] : []
                    content {
                      ip_set_reference_statement {
                        arn = rule.value.ip_set_key != null ? aws_wafv2_ip_set.this[rule.value.ip_set_key].arn : rule.value.ip_set_arn
                      }
                    }
                  }
                }
              }
            }
          }
        }
        
        dynamic "and_statement" {
          for_each = rule.value.rate_limit == null && (rule.value.geo_match != null || rule.value.ip_set_key != null || rule.value.ip_set_arn != null) ? [1] : []
          
          content {
             dynamic "statement" {
                for_each = rule.value.geo_match != null ? [1] : []
                content {
                    geo_match_statement { country_codes = rule.value.geo_match }
                }
             }
             dynamic "statement" {
                for_each = (rule.value.ip_set_arn != null || rule.value.ip_set_key != null) ? [1] : []
                content {
                    ip_set_reference_statement {
                        arn = rule.value.ip_set_key != null ? aws_wafv2_ip_set.this[rule.value.ip_set_key].arn : rule.value.ip_set_arn
                    }
                }
             }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = length(keys(rule.value.visibility_config)) > 0 ? [1] : []
        
        content {
          cloudwatch_metrics_enabled = try(visibility_config.value.cloudwatch_metrics_enabled, false)
          sampled_requests_enabled   = try(visibility_config.value.visibility_config.sampled_requests_enabled, true)
          metric_name                = try(visibility_config.value.metric_name, rule.value.metric_name, "${rule.key}-metric")
        }
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
  ip_address_version = each.value.ip_address_version
  addresses          = each.value.addresses
}