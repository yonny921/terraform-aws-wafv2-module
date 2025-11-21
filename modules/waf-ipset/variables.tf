variable "scope" { type = string } # REGIONAL o CLOUDFRONT

variable "ip_sets_config" {
  description = "Mapa de configuración de IP Sets"
  type = map(object({
    description = optional(string, "Managed by Terraform")
    ip_version  = optional(string, "IPV4")
    addresses   = list(string)
  }))
}