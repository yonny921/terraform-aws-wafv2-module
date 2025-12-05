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
    "wafv2-cloudfront" = {
      scope          = "CLOUDFRONT" #REGIONAL o CLOUDFRONT
      description    = "WAFv2 de prueba IAC"
      default_action = "ALLOW"

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

      custom_response_bodies = {
        "JSON-Access-Denied" = {
          content      = "{\"error\": \"Acceso denegado por WAF\", \"code\": 403}"
          content_type = "APPLICATION_JSON"
        }
        "JSON-Rate-Limit" = {
          content      = "{\"error\": \"Demasiadas solicitudes. Calma.\", \"retry_after\": 60}"
          content_type = "APPLICATION_JSON"
        }
      }

      managed_rules = {

        "AWS-Common" = {
          priority      = 70
          vendor_name   = "AWS"
          rule_set_name = "AWSManagedRulesCommonRuleSet"
          metric_name   = "aws-common"

          rule_overrides = {
            "SizeRestrictions_BODY" = "count"
            "NoUserAgent_HEADER"    = "count"
          }
        }

        "AWS-IP-Reputation" = {
          priority       = 50
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesAmazonIpReputationList"
          metric_name    = "aws-ip-reputation"
          rule_overrides = {}
          visibility_config = {
            cloudwatch_metrics_enabled = true
            sampled_requests_enabled   = true
            metric_name                = "aws-ip-reputation-metrics"
          }
        }

        "AWS-Anonimus-Ip-List" = {
          priority       = 60
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesAnonymousIpList"
          metric_name    = "aws-anonymous-ip"
          rule_overrides = {}
        }

        "AWS-Known-Bad-Inputs" = {
          priority       = 80
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesKnownBadInputsRuleSet"
          metric_name    = "aws-known-bad-inputs"
          rule_overrides = {}
        }

        "AWS-Bot-Control" = {
          priority       = 90
          vendor_name    = "AWS"
          rule_set_name  = "AWSManagedRulesBotControlRuleSet"
          metric_name    = "aws-bot-control"
          rule_overrides = {}
          bot_control_config = {
            inspection_level = "COMMON"
          }
        }
      }

      # Multiples reglas personalizadas (Custom Rules)

      custom_rules = {

        # Custom 1: Límite de tasa de solicitudes (Rate-based rule)
        "RateLimit-General" = {
          priority    = 10
          action      = "block"
          metric_name = "custom-ratelimit"
          response_config = {
            response_code            = 429 # Too Many Requests
            custom_response_body_key = "JSON-Rate-Limit"
          }
          statements = {
            "rate-limit" = {
              type  = "RATE_BASED"
              limit = 2000
            }
          }
        },

        # Custom 2: Bloqueo de países de riesgo
        "Bloqueo-Paises-Riesgo" = {
          priority    = 40
          action      = "block"
          metric_name = "custom-geoblock"
          statements = {
            "geo-match" = {
              type        = "GEO_MATCH"
              match_value = ["CN", "RU", "KP"]
            }
          }
        },

        # Custom 3: Bloqueo de IPs maliciosas manuales (Requiere IP Set)
        "Bloqueo-IPs-Manuales" = {
          priority    = 20
          action      = "block"
          metric_name = "custom-ip-block" #Referencia al IP Set creado
          statements = {
            "ip-block" = {
              type           = "IP_SET_REFERENCE"
              ip_set_key_ref = "Black_List_Custom_Cloudfront"
            }
          }
        },

        # Custom 4: Permitir IPs confiables manuales (Requiere IP Set)
        "Permitir-IPs-Confiables" = {
          priority    = 30
          action      = "allow"
          metric_name = "custom-ip-allow" #Referencia al IP Set creado
          statements = {
            "ip-allow" = {
              type           = "IP_SET_REFERENCE"
              ip_set_key_ref = "White_List_Custom_Cloudfront"
            }
          }
        }
      }
    }
  }

  logging_configs = {
    #map para crear configuración de logs por WAF
    "wafv2-cloudfront" = {
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
    "Black_List_Custom_Cloudfront" = {
      description = "IPs maliciosas bloqueadas manualmente"
      addresses   = ["203.0.113.0/24"] #lista de IPs maliciosas
      scope       = "CLOUDFRONT"
    },
    # Ip sets para permitir IPs confiables.
    "White_List_Custom_Cloudfront" = {
      description = "IPs confiables permitidas manualmente"
      addresses   = ["198.51.100.55/32"] #lista de IPs confiables
      scope       = "CLOUDFRONT"
    }
  }
}