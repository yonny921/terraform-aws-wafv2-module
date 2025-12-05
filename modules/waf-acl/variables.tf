# Definición de variables para el módulo WAF ACL

variable "web_acls_config" {
  description = "Mapa de configuración para crear múltiples WAFs"
  type = map(object({
    description    = optional(string, "WAF-ACL Managed by Terraform")
    scope          = optional(string, "REGIONAL") # Puede ser CLOUDFRONT o REGIONAL por defecto es REGIONAL
    default_action = optional(string, "allow")    # Puede ser ALLOW o BLOCK, por defecto es ALLOW
    tags           = optional(map(string), {})

    visibility_config = optional(object({
      cloudwatch_metrics_enabled = optional(bool, false)
      sampled_requests_enabled   = optional(bool, true)
      metric_name                = optional(string)
    }), {})

    # Múltiples reglas administradas (Managed Rules)
    managed_rules = optional(map(object({
      priority        = number
      vendor_name     = string
      rule_set_name   = string
      override_action = optional(string, "none") # Puede ser count o none por defecto es none para uso en producción
      rule_overrides  = optional(map(string), {})
      scope_down_statements = optional(map(object({
        type                  = string                       # Soporta: "BYTE_MATCH", "SQLI_MATCH", "XSS_MATCH", "SIZE_CONSTRAINT", "GEO_MATCH", "IP_SET_REFERENCE", "RATE_BASED"
        match_key             = optional(string)             # Clave de coincidencia (e.g., "URI_PATH", "QUERY_STRING", "HEADER", "METHOD", "BODY", "SINGLE_QUERY_ARG", "ALL_QUERY_ARGS", "COUNTRY")
        match_value           = optional(list(string))       # Valor(es) de búsqueda. Lista para GEO_MATCH, lista de 1 para Byte Match.
        ip_set_key_ref        = optional(string)             # Referencia a un IP Set creado en este módulo (si aplica)
        ip_set_arn            = optional(string)             # Referencia a un ARN externo para IP Set (si aplica)
        regex_set_key_ref     = optional(string)             # Referencia a un Regex Set creado en este módulo (si aplica)
        regex_set_arn         = optional(string)             # Referencia a un ARN externo para Regex Set (si aplica)
        positional_constraint = optional(string, "CONTAINS") #puede ser CONTAINS, ENDS_WITH, EXACTLY, STARTS_WITH, etc.
        transformation_type   = optional(string, "NONE")     #puede ser NONE, LOWERCASE, CMD_LINE, URL_DECODE, etc.
      })), {})
      bot_control_config = optional(object({ inspection_level = string }))
      metric_name        = optional(string)
      visibility_config = optional(object({
        cloudwatch_metrics_enabled = optional(bool, false)
        sampled_requests_enabled   = optional(bool, true)
        metric_name                = optional(string)
      }), {})
    })), {})

    # Múltiples reglas personalizadas (Custom Rules)
    custom_rules = optional(map(object({
      priority    = number
      action      = string
      metric_name = optional(string)
      visibility_config = optional(object({
        cloudwatch_metrics_enabled = optional(bool, false)
        sampled_requests_enabled   = optional(bool, true)
        metric_name                = optional(string)
      }), {})
      statements = optional(map(object({
        type                  = string                 # Soporta: "BYTE_MATCH", "SQLI_MATCH", "XSS_MATCH", "SIZE_CONSTRAINT", "GEO_MATCH", "IP_SET_REFERENCE", "RATE_BASED"
        limit                 = optional(number)       # Solo si type es RATE_BASED
        match_key             = optional(string)       # Soporta: "URI_PATH", "QUERY_STRING", "HEADER", "METHOD", "BODY", "SINGLE_QUERY_ARG", "ALL_QUERY_ARGS", "COUNTRY"
        match_value           = optional(list(string)) # Soporta lista para GEO_MATCH, lista de 1 para Byte Match.
        ip_set_key_ref        = optional(string)       # Clave al IP Set local (si aplica)
        ip_set_arn            = optional(string)       # ARN externo (si aplica, opcional)
        regex_set_key_ref     = optional(string)       # Referencia a un Regex Set creado en este módulo
        regex_set_arn         = optional(string)       # Referencia a un ARN externo para Regex Set
        positional_constraint = optional(string, "CONTAINS")
        transformation_type   = optional(string, "NONE")
      })), {})
    })), {})
  }))
}

# Configuración de Regex Pattern Sets
variable "regex_sets_config" {
  description = "(Opcional) Configuración de Regex Pattern Sets"
  type = map(object({
    description = optional(string, "Regex Pattern Set managed by Terraform")
    scope       = optional(string, "REGIONAL")
    regex_list  = list(string)
    tags        = optional(map(string), {})
  }))
  default = {}
}

# Configuración de IP Sets
variable "ip_sets_config" {
  description = "Mapa de configuración de IP Sets"
  type = map(object({
    description        = optional(string, "Ip Set managed by Terraform")
    ip_address_version = optional(string, "IPV4")
    addresses          = list(string)
    scope              = optional(string, "REGIONAL")
    tags               = optional(map(string), {})
  }))
  default = {}
}

# Configuración de Logs por WAF
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

    logging_filter = optional(object({
      default_behavior = string
      filters = map(object({
        behavior    = string
        requirement = string
        conditions = list(object({
          action     = optional(string)
          label_name = optional(string)
        }))
      }))
    }), null)
  }))
  default = {}
}

# Tags por defecto para todos los recursos
variable "tags" {
  description = "Mapa de etiquetas (tags) para aplicar a todos los recursos creados por este módulo."
  type        = map(string)
  default     = {}
}
