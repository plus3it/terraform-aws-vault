# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------

variable "policy_vars" {
  description = "Variables for interpolation within the template. Must include the following vars: bucket_name, dynamodb_table, kms_key_id, stack_name, ssm_path"
  type        = map(string)
}

variable "role_name" {
  description = "Name of the role to be create for vault"
  type        = string
}

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------
variable "url_suffix" {
  default     = "amazonaws.com"
  description = "URL suffix associated with the current partition"
  type        = string
}
