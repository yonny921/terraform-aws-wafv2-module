variable "ip_set_references" {
  description = "Mapa global de IP Sets disponibles para todos los WAFs"
  type        = map(string)
  default     = {}
}

variable "web_acls_config" {
  description = "Mapa de configuración para crear múltiples WAFs"
  type = map(object({
    description    = optional(string, "WAF-ACL Managed by Terraform")
    scope          = optional(string, "REGIONAL")
    default_action = optional(string, "allow")
    tags           = optional(map(string), {})

    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool, false)
      sampled_requests_enabled   = optional(bool, true)
      metric_name                = optional(string)
    }), {})


    managed_rules = optional(map(object({
      priority           = number
      vendor_name        = string
      rule_set_name      = string
      rule_overrides     = optional(map(string), {})
      excluded_paths     = optional(map(string), {})
      bot_control_config = optional(object({ inspection_level = string }))
      metric_name        = optional(string)
      visibility_config = optional(object({
        cloudwatch_metrics_enabled = optional(bool, false)
        sampled_requests_enabled   = optional(bool, true)
        metric_name                = optional(string)
      }), {})
    })), {})


    custom_rules = optional(map(object({
      priority    = number
      action      = string
      rate_limit  = optional(number)
      geo_match   = optional(list(string))
      ip_set_arn  = optional(string)
      ip_set_key  = optional(string)
      metric_name = optional(string)
      visibility_config = optional(object({
        cloudwatch_metrics_enabled = optional(bool, false)
        sampled_requests_enabled   = optional(bool, true)
        metric_name                = optional(string)
      }), {})
    })), {})
  }))
}