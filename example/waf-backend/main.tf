# 1. LLAMADA AL MÓDULO DE IP SETS

module "ip_sets" {
  source = "../../modules/waf-ipset"
  scope  = "REGIONAL" #REGIONAL o CLOUDFRONT

  ip_sets_config = {
    # Ip sets para bloqueo de IPs maliciosas.
    "Black_List_Custom_Backend" = {
      description = "IPs maliciosas bloqueadas manualmente"
      addresses = ["203.0.113.0/24"] #lista de IPs maliciosas
    },
    # Ip sets para permitir IPs confiables.
    "White_List_Custom_Backend" = {
      description = "IPs confiables permitidas manualmente"
      addresses = ["198.51.100.55/32"] #lista de IPs confiables
    }
  }
}

# 2. LLAMADA AL MÓDULO DE LOGS WAF
module "waf_logging" {
  source = "../../modules/waf-logs"
  waf_arns = module.waf_acl.web_acl_arns 

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
    }

  }
}

# 3. LLAMADA AL MÓDULO WAF ACL

module "waf_acl" {
  source = "../../modules/waf-acl"
  ip_set_references = module.ip_sets.arn_map

  web_acls_config = {
    #map para crear múltiples WAFs
    "wafv2-Backend" = {
      scope       = "REGIONAL" #REGIONAL o CLOUDFRONT
      description = "WAFv2 de prueba IAC"
      default_action = "ALLOW"

      tags = {
        Environment = "Development"
        Project     = "WAFv2-IAC"
      }

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
          priority      = 40
          vendor_name   = "AWS"
          rule_set_name = "AWSManagedRulesAdminProtectionRuleSet"
          metric_name   = "aws-admin-protection"
          rule_overrides = {}
        }

        "AWS-Linux-Rule-Set" = {
          priority      = 50
          vendor_name   = "AWS"
          rule_set_name = "AWSManagedRulesLinuxRuleSet"
          metric_name   = "aws-linux-rule-set"
          rule_overrides = {}
        }

        "AWS-PHP-Rule-Set" = {
          priority      = 60
          vendor_name   = "AWS"
          rule_set_name = "AWSManagedRulesPHPRuleSet"
          metric_name   = "aws-php-rule-set"
          rule_overrides = {}
        }

        "AWS-Unix-Rule-Set" = {
          priority      = 70
          vendor_name   = "AWS"
          rule_set_name = "AWSManagedRulesUnixRuleSet"
          metric_name   = "aws-unix-rule-set"
          rule_overrides = {}
        }

        "AWS-SQLi" = {
          priority      = 80
          vendor_name   = "AWS"
          rule_set_name = "AWSManagedRulesSQLiRuleSet"
          metric_name   = "aws-sqli-metrics"
          rule_overrides = {}
          excluded_paths = {
            "/api/legacy/"    = "STARTS_WITH" # Excluye todo lo que empiece por aquí
            "/login.php"      = "EXACTLY"     # Excluye SOLO este archivo exacto
            "debug-mode"      = "CONTAINS"    # Excluye si la URL contiene esta palabra (CUIDADO con este)
            "/static/images"  = "STARTS_WITH" 
          }
        },

        "AWS-WordPress-Rule-Set" = {
          priority      = 90
          vendor_name   = "AWS"
          rule_set_name = "AWSManagedRulesWordPressRuleSet"
          metric_name   = "aws-wordpress-rule-set"
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
          rate_limit  = 2000
        },

        # Custom 2: Bloqueo de países de riesgo
        "Bloqueo-IPs-Manuales" = {
          priority    = 20
          action      = "block"
          metric_name = "custom-ip-block"
          ip_set_key  = "Black_List_Custom_Backend"
        },

        # Custom 3: Permitir IPs confiables manuales
        "Permitir-IPs-Confiables" = {
          priority    = 30
          action      = "allow"
          metric_name = "custom-ip-allow"
          ip_set_key  = "White_List_Custom_Backend" 
        }
      }
    }
  }
}