output "vault_url" {
  description = "URL to access Vault UI"
  value       = join("", ["https://", aws_route53_record.this.fqdn])
}
