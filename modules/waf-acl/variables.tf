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
      scope_down_statements = optional(map(object({
        type                  = string                           # Tipo de sentencia (e.g., "NOT_BYTE_MATCH", "NOT_IP_SET_REFERENCE")
        match_key             = optional(string)                 # Campo a chequear (e.g., "URI_PATH", "HEADER")
        match_value           = optional(list(string))           # Valor(es) de búsqueda. Lista para GEO_MATCH, lista de 1 para Byte Match.
        ip_set_key_ref        = optional(string)                 # Clave al IP Set local (si aplica)
        positional_constraint = optional(string, "CONTAINS")
        transformation_type   = optional(string, "NONE")
      })), {})
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


variable "ip_sets_config" {
  description = "Mapa de configuración de IP Sets"
  type = map(object({
    description = optional(string, "Managed by Terraform")
    ip_address_version  = optional(string, "IPV4")
    addresses   = list(string)
    scope       = optional(string, "REGIONAL")
  }))
}


variable "logging_configs" {
  description = "Mapa de configuración de logs por WAF"
  type = map(object({
    enabled          = optional(bool, true)
    destination_arns = list(string)

    redacted_fields = optional(object({
      headers      = optional(list(string), [])
      cookies      = optional(list(string), [])
      query_string = optional(bool, false)
      uri_path     = optional(bool, false)
    }), null)
  }))
  default = {}
}