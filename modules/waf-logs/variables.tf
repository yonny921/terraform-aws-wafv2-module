variable "waf_arns" {
  description = "Mapa de ARNs de WAF proveniente del output del módulo WAF"
  type        = map(string)
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