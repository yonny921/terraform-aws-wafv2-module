#Uso del módulo WAFv2 para crear ACLs, reglas administradas y personalizadas, sets de regex e IPs, y configuración de logs.

module "waf_acl" {
  source = "../../modules/waf-acl"

  # 1. Tags Globales (Se aplican a TODO: WAF, IPs, Regex)
  tags = {
    Environment = "Prod"
    Terraform   = "True"
    Owner       = "DevOps Team"
  }

  web_acls_config = {
    #map para crear múltiples WAFs
    "wafv2-Backend" = {
      scope          = "REGIONAL" #puede ser CLOUDFRONT o REGIONAL
      description    = "WAFv2 de prueba IAC"
      default_action = "ALLOW" #puede ser ALLOW, BLOCK

      tags = {
        Project = "WAFv2-IAC"
      }

      # Se puede descomentar para habilitar métricas CloudWatch

      /*
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "wafv2-cloudfront-logs"
        sampled_requests_enabled   = true
      }
      */

      # Multiples reglas administradas (Managed Rules) 

      managed_rules = {

        "AWS-Admin-protection" = {
          priority       = 40
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesAdminProtectionRuleSet"
          metric_name    = "aws-admin-protection"
          rule_overrides = {}
        }

        "AWS-Linux-Rule-Set" = {
          priority       = 50
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesLinuxRuleSet"
          metric_name    = "aws-linux-rule-set"
          rule_overrides = {}
        }

        "AWS-PHP-Rule-Set" = {
          priority       = 60
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesPHPRuleSet"
          metric_name    = "aws-php-rule-set"
          rule_overrides = {}
        }

        "AWS-Unix-Rule-Set" = {
          priority       = 70
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesUnixRuleSet"
          metric_name    = "aws-unix-rule-set"
          rule_overrides = {}
        }

        "AWS-SQLi" = {
          priority       = 80
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesSQLiRuleSet"
          metric_name    = "aws-sqli-metrics"
          rule_overrides = {}
          scope_down_statements = {
            "Restriccion-Geo" = {
              type        = "GEO_MATCH"
              match_value = ["US", "CA"] # match_value ahora acepta la lista de códigos de país
            },
            "Excluir-API-Legacy" = {
              type                  = "NOT_BYTE_MATCH"
              match_key             = "URI_PATH"
              match_value           = ["/api/legacy/"]
              positional_constraint = "STARTS_WITH"
              transformation_type   = "NONE"
            },
            "Excluir-Login" = {
              type                  = "NOT_BYTE_MATCH"
              match_key             = "URI_PATH"
              match_value           = ["/login.php"]
              positional_constraint = "EXACTLY"
              transformation_type   = "NONE"
            },
            "Excluir-Static-Images" = {
              type                  = "NOT_BYTE_MATCH"
              match_key             = "URI_PATH"
              match_value           = ["/static/images"]
              positional_constraint = "STARTS_WITH"
              transformation_type   = "NONE"
            }
          }
        }

        "AWS-WordPress-Rule-Set" = {
          priority       = 90
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesWordPressRuleSet"
          metric_name    = "aws-wordpress-rule-set"
          rule_overrides = {}
        }
      }


      # Multiples reglas personalizadas (Custom Rules)

      custom_rules = {
        # Custom 1: Límite de tasa de solicitudes (Rate-based rule)
        "RateLimit-General" = {
          priority    = 10
          action      = "block"
          metric_name = "custom-ratelimit"
          statements = {
            "rate-limit" = {
              type  = "RATE_BASED"
              limit = 2000
            }
          }
        },

        "RateLimit-GeoBlock" = {
          priority    = 12
          action      = "block"
          metric_name = "custom-combined"
          statements = {
            "rate-limit" = {
              type  = "RATE_BASED"
              limit = 2000
            },
            "geo-match" = {
              type        = "GEO_MATCH"
              match_value = ["CN", "RU"]
            }
          }
        },

        # Custom 2: Bloqueo de ips maliciosas manuales (Requiere IP Set)
        "Bloqueo-IPs-Manuales" = {
          priority    = 20
          action      = "block"
          metric_name = "custom-ip-block"
          statements = {
            "ip-block" = {
              type           = "IP_SET_REFERENCE"
              ip_set_key_ref = "Black_List_Custom_Backend" #Referencia al IP Set creado
            }
          }
        },

        # Custom 3: Permitir IPs confiables manuales (Requiere IP Set)
        "Permitir-IPs-Confiables" = {
          priority    = 30
          action      = "allow"
          metric_name = "custom-ip-allow"

          statements = {
            "ip-allow" = {
              type           = "IP_SET_REFERENCE"
              ip_set_key_ref = "White_List_Custom_Backend" #Referencia al IP Set creado
            }
          }
        }
        "Bloqueo-Bots" = {
          priority = 50
          action   = "block"
          statements = {
            "regex-rule" = {
              type              = "REGEX_MATCH"
              regex_set_key_ref = "Bad-Bots-Set"
              match_key         = "User-Agent" # Buscar en el Header User-Agent
            }
          }
        }
      }
    }
  }

  regex_sets_config = {
    "Bad-Bots-Set" = {
      regex_list  = ["^BadBot.*", ".*Scraper.*"]
      description = "Regex set para identificar Bad Bots en User-Agent"
      scope       = "REGIONAL"
    }
  }

  logging_configs = {
    #map para crear configuración de logs por WAF
    "wafv2-Backend" = {
      enabled          = true
      destination_arns = ["arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-prod"] # Reemplazar con el ARN real del grupo de logs. Se debe crear previamente.

      redacted_fields = {
        headers      = ["Authorization", "X-Auth-Token"] # Ocultar secretos
        cookies      = ["session_id"]
        query_string = false # Ocultar parámetros GET (?user=...)
      }

      logging_filter = {
        default_behavior = "DROP" #puede ser DROP o KEEP
        filters = {
          "guardar-bloqueos" = {
            behavior    = "KEEP"
            requirement = "MEETS_ANY" #puede ser MEETS_ALL o MEETS_ANY
            conditions = [
              { action = "BLOCK" } #puede ser ALLOW, BLOCK o COUNT
            ]
          }
        }
      }
    }
  }


  ip_sets_config = {
    # Ip sets para bloqueo de IPs maliciosas.
    "Black_List_Custom_Backend" = {
      description = "IPs maliciosas bloqueadas manualmente"
      addresses   = ["203.0.113.0/24"] #lista de IPs maliciosas
      scope       = "REGIONAL"
    },
    # Ip sets para permitir IPs confiables.
    "White_List_Custom_Backend" = {
      description = "IPs confiables permitidas manualmente"
      addresses   = ["198.51.100.55/32"] #lista de IPs confiables
      scope       = "REGIONAL"
    }
  }
}
