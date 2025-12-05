#Este modulo de terraform permite crear multiples WAF ACLs con reglas administradas y custom, asi como IP Sets y Regex Pattern Sets.
#Creado por Yonny Arias - Ingeniero de Seguridad Cloud AWS
#Tiene muchas funcionalidades avanzadas como scope down statements, overrides de reglas, logging avanzado, etc. sin embargo no se han probado todas las
#caracteriticas, por lo que se recomienda revisar y adaptar el código para algunas funcionalidades especificas.

resource "aws_wafv2_web_acl" "this" {

  for_each = var.web_acls_config

  name        = each.key
  description = each.value.description
  scope       = each.value.scope
  tags        = merge(var.tags, each.value.tags) #Unión de tags globales y específicos

  default_action {
    dynamic "allow" {
      for_each = lower(each.value.default_action) == "allow" ? [1] : [] #Si la acción por defecto es ALLOW, creamos el bloque allow
      content {}
    }
    dynamic "block" {
      for_each = lower(each.value.default_action) == "block" ? [1] : [] #Si la acción por defecto es BLOCK, creamos el bloque block
      content {}
    }
  }

  # Configuración de Visibilidad (Opcional para usar CloudWatch)
  dynamic "visibility_config" {
    for_each = length(keys(each.value.visibility_config)) > 0 ? [1] : []
    content {
      cloudwatch_metrics_enabled = try(visibility_config.value.cloudwatch_metrics_enabled, false)
      metric_name                = try(visibility_config.value.metric_name, "${each.key}-metrics")
      sampled_requests_enabled   = try(visibility_config.value.sampled_requests_enabled, true)
    }
  }

  dynamic "custom_response_body" {
    for_each = each.value.custom_response_bodies
    content {
      key          = custom_response_body.key
      content      = custom_response_body.value.content
      content_type = custom_response_body.value.content_type
    }
  }

  # Reglas Administradas (Managed Rules)
  dynamic "rule" {
    for_each = each.value.managed_rules

    content {
      name     = rule.key
      priority = rule.value.priority
      # definición de la acción por defecto de la regla administrada
      override_action {
        dynamic "count" {
          for_each = lower(try(rule.value.override_action, "none")) == "count" ? [1] : [] #si la acción es COUNT creamos el bloque count
          content {}
        }

        dynamic "none" {
          for_each = lower(try(rule.value.override_action, "none")) == "count" ? [] : [1] #si la acción no es COUNT creamos el bloque none
          content {}
        }
      }
      # definición de la sentencia de la regla administrada
      statement {
        managed_rule_group_statement {
          name        = rule.value.rule_set_name
          vendor_name = rule.value.vendor_name

          # definición de overrides de acciones por regla individual
          dynamic "rule_action_override" {
            for_each = rule.value.rule_overrides
            content {
              name = rule_action_override.key
              action_to_use {
                dynamic "count" {
                  for_each = lower(rule_action_override.value) == "count" ? [1] : []
                  content {}
                }
                dynamic "allow" {
                  for_each = lower(rule_action_override.value) == "allow" ? [1] : []
                  content {}
                }
                dynamic "block" {
                  for_each = lower(rule_action_override.value) == "block" ? [1] : []
                  content {}
                }
                dynamic "captcha" {
                  for_each = lower(rule_action_override.value) == "captcha" ? [1] : []
                  content {}
                }
              }
            }
          }
          # configuración de Bot Control (si aplica)
          dynamic "managed_rule_group_configs" {
            for_each = rule.value.bot_control_config != null ? [1] : []
            content {
              aws_managed_rules_bot_control_rule_set {
                inspection_level = rule.value.bot_control_config.inspection_level
              }
            }
          }

          # SCOPE DOWN (Exclusiones e Inclusiones) (si aplica)
          dynamic "scope_down_statement" {
            for_each = length(rule.value.scope_down_statements) > 0 ? [1] : []

            content {
              and_statement {
                dynamic "statement" {
                  for_each = rule.value.scope_down_statements

                  content {
                    # 1. Exclusiones (Negativas)
                    dynamic "not_statement" {
                      for_each = contains(["NOT_BYTE_MATCH", "NOT_IP_SET_REFERENCE", "NOT_HEADER_MATCH", "NOT_REGEX_MATCH"], upper(statement.value.type)) ? [1] : []
                      content {
                        statement {
                          dynamic "byte_match_statement" {
                            for_each = contains(["NOT_BYTE_MATCH", "NOT_HEADER_MATCH"], upper(statement.value.type)) ? [1] : []
                            content {
                              field_to_match {
                                dynamic "uri_path" {
                                  for_each = try(upper(statement.value.match_key), "URI_PATH") == "URI_PATH" ? [1] : []
                                  content {}
                                }
                                dynamic "single_header" {
                                  for_each = try(upper(statement.value.match_key), "URI_PATH") != "URI_PATH" && statement.value.match_key != null ? [1] : []
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
                          dynamic "ip_set_reference_statement" {
                            for_each = upper(statement.value.type) == "NOT_IP_SET_REFERENCE" ? [1] : []
                            content {
                              arn = aws_wafv2_ip_set.this[statement.value.ip_set_key_ref].arn
                            }
                          }
                          dynamic "regex_pattern_set_reference_statement" {
                            for_each = upper(statement.value.type) == "NOT_REGEX_MATCH" ? [1] : []
                            content {
                              arn = statement.value.regex_set_key_ref != null ? aws_wafv2_regex_pattern_set.this[statement.value.regex_set_key_ref].arn : statement.value.regex_set_arn
                              field_to_match {
                                dynamic "uri_path" {
                                  for_each = try(upper(statement.value.match_key), "URI_PATH") == "URI_PATH" ? [1] : []
                                  content {}
                                }
                                dynamic "single_header" {
                                  for_each = try(upper(statement.value.match_key), "URI_PATH") != "URI_PATH" && statement.value.match_key != null ? [1] : []
                                  content {
                                    name = statement.value.match_key
                                  }
                                }
                              }
                              text_transformation {
                                priority = 0
                                type     = statement.value.transformation_type
                              }
                            }
                          }
                        }
                      }
                    }

                    # 2. Inclusiones (Positivas)
                    dynamic "geo_match_statement" {
                      for_each = upper(statement.value.type) == "GEO_MATCH" ? [1] : []
                      content {
                        country_codes = statement.value.match_value
                      }
                    }
                    dynamic "byte_match_statement" {
                      for_each = upper(statement.value.type) == "BYTE_MATCH" ? [1] : []
                      content {
                        field_to_match {
                          dynamic "uri_path" {
                            for_each = try(upper(statement.value.match_key), "URI_PATH") == "URI_PATH" ? [1] : []
                            content {}
                          }
                          dynamic "single_header" {
                            for_each = try(upper(statement.value.match_key), "URI_PATH") != "URI_PATH" && upper(statement.value.match_key) != null ? [1] : []
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
                    dynamic "ip_set_reference_statement" {
                      for_each = upper(statement.value.type) == "IP_SET_REFERENCE" ? [1] : []
                      content {
                        arn = aws_wafv2_ip_set.this[statement.value.ip_set_key_ref].arn
                      }
                    }
                    dynamic "regex_pattern_set_reference_statement" {
                      for_each = upper(statement.value.type) == "REGEX_MATCH" ? [1] : []
                      content {
                        arn = statement.value.regex_set_key_ref != null ? aws_wafv2_regex_pattern_set.this[statement.value.regex_set_key_ref].arn : statement.value.regex_set_arn
                        field_to_match {
                          dynamic "uri_path" {
                            for_each = try(upper(statement.value.match_key), "URI_PATH") == "URI_PATH" ? [1] : []
                            content {}
                          }
                          dynamic "single_header" {
                            for_each = try(upper(statement.value.match_key), "URI_PATH") != "URI_PATH" && statement.value.match_key != null ? [1] : []
                            content {
                              name = statement.value.match_key
                            }
                          }
                        }
                        text_transformation {
                          priority = 0
                          type     = statement.value.transformation_type
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
      # configuración de visibilidad de la regla (si aplica)
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

  # Reglas Custom (Personalizadas)
  dynamic "rule" {
    for_each = each.value.custom_rules

    content {
      name     = rule.key
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {
            dynamic "custom_response" {
              for_each = try(rule.value.response_config.custom_response_body_key, null) != null ? [1] : []
              content {
                response_code            = rule.value.response_config.response_code
                custom_response_body_key = rule.value.response_config.custom_response_body_key
              }
            }
          }
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
        # --- PATH 1: REGLAS RATE BASED ---
        dynamic "rate_based_statement" {
          for_each = length([for k, v in rule.value.statements : k if upper(v.type) == "RATE_BASED"]) > 0 ? [1] : []

          content {
            limit              = [for k, v in rule.value.statements : v.limit if upper(v.type) == "RATE_BASED"][0]
            aggregate_key_type = "IP"

            dynamic "scope_down_statement" {
              for_each = length({ for k, v in rule.value.statements : k => v if upper(v.type) != "RATE_BASED" }) > 0 ? [1] : []

              content {
                and_statement {
                  dynamic "statement" {
                    for_each = { for k, v in rule.value.statements : k => v if upper(v.type) != "RATE_BASED" && upper(v.type) == "GEO_MATCH" }
                    content {
                      geo_match_statement {
                        country_codes = statement.value.match_value
                      }
                    }
                  }
                  dynamic "statement" {
                    for_each = { for k, v in rule.value.statements : k => v if upper(v.type) != "RATE_BASED" && upper(v.type) == "IP_SET_REFERENCE" }
                    content {
                      ip_set_reference_statement {
                        arn = statement.value.ip_set_key_ref != null ? aws_wafv2_ip_set.this[statement.value.ip_set_key_ref].arn : statement.value.ip_set_arn
                      }
                    }
                  }
                  dynamic "statement" {
                    for_each = { for k, v in rule.value.statements : k => v if upper(v.type) != "RATE_BASED" && upper(v.type) == "BYTE_MATCH" }
                    content {
                      byte_match_statement {
                        field_to_match {
                          dynamic "uri_path" {
                            for_each = try(upper(statement.value.match_key), "URI_PATH") == "URI_PATH" ? [1] : []
                            content {}
                          }
                          dynamic "single_header" {
                            for_each = try(upper(statement.value.match_key), "URI_PATH") != "URI_PATH" && upper(statement.value.match_key) != null ? [1] : []
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
                  }
                  dynamic "statement" {
                    for_each = { for k, v in rule.value.statements : k => v if upper(v.type) != "RATE_BASED" && upper(v.type) == "REGEX_MATCH" }
                    content {
                      regex_pattern_set_reference_statement {
                        arn = statement.value.regex_set_key_ref != null ? aws_wafv2_regex_pattern_set.this[statement.value.regex_set_key_ref].arn : statement.value.regex_set_arn
                        field_to_match {
                          dynamic "uri_path" {
                            for_each = try(upper(statement.value.match_key), "URI_PATH") == "URI_PATH" ? [1] : []
                            content {}
                          }
                          dynamic "single_header" {
                            for_each = try(upper(statement.value.match_key), "URI_PATH") != "URI_PATH" && upper(statement.value.match_key) != null ? [1] : []
                            content {
                              name = statement.value.match_key
                            }
                          }
                        }
                        text_transformation {
                          priority = 0
                          type     = statement.value.transformation_type
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }

        # --- PATH 2: REGLAS ESTÁNDAR ---
        dynamic "and_statement" {
          for_each = length([for k, v in rule.value.statements : k if upper(v.type) == "RATE_BASED"]) == 0 && length(keys(rule.value.statements)) > 0 ? [1] : []

          content {
            dynamic "statement" {
              for_each = { for k, v in rule.value.statements : k => v if upper(v.type) == "GEO_MATCH" }
              content {
                geo_match_statement {
                  country_codes = statement.value.match_value
                }
              }
            }
            dynamic "statement" {
              for_each = { for k, v in rule.value.statements : k => v if upper(v.type) == "IP_SET_REFERENCE" }
              content {
                ip_set_reference_statement {
                  arn = statement.value.ip_set_key_ref != null ? aws_wafv2_ip_set.this[statement.value.ip_set_key_ref].arn : statement.value.ip_set_arn
                }
              }
            }
            dynamic "statement" {
              for_each = { for k, v in rule.value.statements : k => v if upper(v.type) == "BYTE_MATCH" }
              content {
                byte_match_statement {
                  field_to_match {
                    dynamic "uri_path" {
                      for_each = try(upper(statement.value.match_key), "URI_PATH") == "URI_PATH" ? [1] : []
                      content {}
                    }
                    dynamic "single_header" {
                      for_each = try(upper(statement.value.match_key), "URI_PATH") != "URI_PATH" && statement.value.match_key != null ? [1] : []
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
            }
            dynamic "statement" {
              for_each = { for k, v in rule.value.statements : k => v if upper(v.type) == "REGEX_MATCH" }
              content {
                regex_pattern_set_reference_statement {
                  arn = statement.value.regex_set_key_ref != null ? aws_wafv2_regex_pattern_set.this[statement.value.regex_set_key_ref].arn : statement.value.regex_set_arn
                  field_to_match {
                    dynamic "uri_path" {
                      for_each = try(upper(statement.value.match_key), "URI_PATH") == "URI_PATH" ? [1] : []
                      content {}
                    }
                    dynamic "single_header" {
                      for_each = try(upper(statement.value.match_key), "URI_PATH") != "URI_PATH" && statement.value.match_key != null ? [1] : []
                      content {
                        name = statement.value.match_key
                      }
                    }
                  }
                  text_transformation {
                    priority = 0
                    type     = statement.value.transformation_type
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
}

# Configuración de Logging para cada WAF ACL
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  for_each = { for k, v in var.logging_configs : k => v if v.enabled }

  log_destination_configs = each.value.destination_arns
  resource_arn            = aws_wafv2_web_acl.this[each.key].arn

  # Redacción de Headers
  dynamic "redacted_fields" {
    for_each = try(each.value.redacted_fields.headers, [])
    content {
      single_header {
        name = redacted_fields.value
      }
    }
  }

  # Redacción de Query String
  dynamic "redacted_fields" {
    for_each = try(each.value.redacted_fields.query_string, false) ? [1] : []
    content {
      query_string {}
    }
  }

  # Redacción de URI Path
  dynamic "redacted_fields" {
    for_each = try(each.value.redacted_fields.uri_path, false) ? [1] : []
    content {
      uri_path {}
    }
  }

  # Redacción de Cookies
  dynamic "redacted_fields" {
    for_each = try(each.value.redacted_fields.cookies, [])
    content {
      single_header {
        name = redacted_fields.value
      }
    }
  }

  # 5. Filtros de Logs (Opicional)
  dynamic "logging_filter" {
    for_each = each.value.logging_filter != null ? [1] : []

    content {
      default_behavior = each.value.logging_filter.default_behavior

      dynamic "filter" {
        for_each = each.value.logging_filter.filters

        content {
          behavior    = filter.value.behavior
          requirement = filter.value.requirement

          dynamic "condition" {
            for_each = filter.value.conditions
            content {
              dynamic "action_condition" {
                for_each = condition.value.action != null ? [1] : []
                content {
                  action = condition.value.action
                }
              }

              dynamic "label_name_condition" {
                for_each = condition.value.label_name != null ? [1] : []
                content {
                  label_name = condition.value.label_name
                }
              }
            }
          }
        }
      }
    }
  }
}

# Configuración de IP Sets
resource "aws_wafv2_ip_set" "this" {
  for_each = var.ip_sets_config

  name               = each.key
  description        = each.value.description
  scope              = each.value.scope
  ip_address_version = each.value.ip_address_version
  addresses          = each.value.addresses
  tags               = merge(var.tags, try(each.value.tags, {}))
}

# Configuración de Regex Pattern Sets
resource "aws_wafv2_regex_pattern_set" "this" {
  for_each = var.regex_sets_config

  name        = each.key
  description = each.value.description
  scope       = each.value.scope

  dynamic "regular_expression" {
    for_each = each.value.regex_list
    content {
      regex_string = regular_expression.value
    }
  }
  tags = merge(var.tags, try(each.value.tags, {}))
}