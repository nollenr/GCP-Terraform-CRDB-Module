# ----------------------------------------
# GCP Project
# ----------------------------------------
  variable "gcp_project_name" {
    description = "Existing GCP Project Name"
    type = string
    default = "no"
  }

# ----------------------------------------
# VPC
# ----------------------------------------
  variable "vpc_name" {
    description = "Name of the VPC"
    type = string
    default = "no"
  }

# ----------------------------------------
# CIDR
# ----------------------------------------
    variable "vpc_cidr" {
      description = "CIDR block for the VPC"
      type        = string
      default     = "192.168.6.0/24"
    }

# ----------------------------------------
# My IP Address
# This is used in the creation of the security group 
# and will allow access to the ec2-instances on ports
# 22 (ssh), 26257 (database), 8080 (for observability)
# and 3389 (rdp)
# ----------------------------------------
    variable "my_ip_address" {
      description = "User IP address for access to the ec2 instances."
      type        = string
      default     = "0.0.0.0"
    }

# ----------------------------------------
# My Linux User
# In GCP, this is the user to be associated with 
# linux instance
# ----------------------------------------
    variable "my_linux_user" {
      description = "Linux user name"
      type        = string
      default     = ""
    }


# ----------------------------------------
# Regions
# ----------------------------------------
    # Needed for the multi-region-demo
    variable "gcp_region" {
      description = "GCP region"
      type        = string
      default     = "us-central1"
    }

# ----------------------------------------
# Create Compute Instances
# ----------------------------------------
  variable "create_gcp_instances" {
    description = "create the ec2 instances (yes/no)?  If set to 'no', then only the VPC, subnets, routes tables, routes, peering, etc are created"
    type = string
    default = "yes"
    validation {
      condition = contains(["yes", "no"], var.create_gcp_instances)
      error_message = "Valid value for variable 'create_gcp_instances' is : 'yes' or 'no'"        
    }
  }

# ----------------------------------------
# CRDB Instance Specifications
# ----------------------------------------
    variable "join_string" {
      description = "The CRDB join string to use at start-up.  Do not supply a value"
      type        = string
      default     = ""
    }

    variable "crdb_nodes" {
      description = "Number of crdb nodes.  This should be a multiple of 3.  Each node is an AWS Instance"
      type        = number
      default     = 3
      validation {
        condition = var.crdb_nodes%3 == 0 || var.crdb_nodes == 1
        error_message = "The variable 'crdb_nodes' must be a multiple of 3"
      }
    }

    variable "crdb_instance_type" {
      description = "The GCP instance type for the crdb instances."
      type        = string
      default     = "n2-standard-4"
    }

    variable "run_init" {
      description = "'yes' or 'no' to run init on the cluster"
      type        = string
      default     = "yes"
      validation {
        condition = contains(["yes", "no"], var.run_init)
        error_message = "Valid values for variable 'run_init' are : 'yes' or 'no'"        
      }
    }

# ----------------------------------------
# CRDB Instance Specifications
# ----------------------------------------
    variable "crdb_version" {
      description = "CockroachDB Version"
      type        = string
      default     = "22.2.5"
      validation  {
        condition = contains([
          "23.1.2",
          "23.1.1",
          "23.1.0-beta.2",
          "23.1.0-alpha.8",
          "23.1.0-alpha.4",
          "22.2.10",
          "22.2.9",
          "22.2.8",
          "22.2.7",
          "22.2.6",
          "22.2.5",
          "22.2.4",
          "22.2.3",
          "22.2.2",
          "22.2.1",
          "22.1.18",
          "22.1.14",
          "22.1.13",
          "22.1.12",
          "22.1.11",
          "22.1.10",
          "22.1.9",
          "22.1.8",
          "22.1.7",
          "22.1.6",
          "22.1.5",
          "22.1.4",
          "22.1.2",
          "22.1.0",
          "21.2.17",
          "21.2.16",
          "21.2.14",
          "21.2.13",
          "21.2.10",
          "21.2.9",
          "21.2.5",
          "21.2.4",
          "21.2.3",
          "21.1.15",
          "21.1.13",
          "20.2.18",
          "20.1.17",
          "19.2.12"
        ], var.crdb_version)
        error_message = "Select an appropriate 'crdb_version' for the CockroachDB Instances.  See the list in variables.tf"
      }
    }

# ----------------------------------------
# HA Proxy Instance Specifications
# ----------------------------------------
    variable "include_ha_proxy" {
      description = "'yes' or 'no' to include an HAProxy Instance"
      type        = string
      default     = "yes"
      validation {
        condition = contains(["yes", "no"], var.include_ha_proxy)
        error_message = "Valid value for variable 'include_ha_proxy' is : 'yes' or 'no'"        
      }
    }

    variable "haproxy_instance_type" {
      description = "HA Proxy Instance Type"
      type        = string
      default     = "e2-micro"
    }

# ----------------------------------------
# APP
# ----------------------------------------
    variable "include_app_instance" {
      description = "'yes' or 'no' to include an Application Instance"
      type        = string
      default     = "yes"
      validation {
        condition = contains(["yes", "no"], var.include_app_instance)
        error_message = "Valid value for variable 'include_app_instance' is : 'yes' or 'no'"        
      }
    }

    variable "app_instance_type" {
      description = "App Instance Type"
      type        = string
      default     = "e2-micro"
    }

# ----------------------------------------
# Demo
# ----------------------------------------
    variable "include_demo" {
      description = "'yes' or 'no' to include an HAProxy Instance"
      type        = string
      default     = "yes"
      validation {
        condition = contains(["yes", "no"], var.include_demo)
        error_message = "Valid value for variable 'include_demo' is : 'yes' or 'no'"        
      }
    }

    variable "create_admin_user" {
      description = "'yes' or 'no' to create an admin user in the database.  This might only makes sense when adding an app instance since the certs will be created and configured automatically for connection to the database."
      type        = string
      default     = "yes"
      validation {
        condition = contains(["yes", "no"], var.create_admin_user)
        error_message = "Valid value for variable 'include_ha_proxy' is : 'yes' or 'no'"        
      }      
    }

    variable "admin_user_name"{
      description = "An existing admin user that will be used to run the multi-region/multi-cloud demo"
      type        = string
      default     = ""
    }


# ----------------------------------------
# TLS Vars -- Leave blank to have then generated
# ----------------------------------------
    variable "tls_private_key" {
      description = "tls_private_key.crdb_ca_keys.private_key_pem -> ca.key / TLS Private Key PEM"
      type        = string
      default     = ""
    }

    variable "tls_public_key" {
      description = "tls_private_key.crdb_ca_keys.public_key_pem -> ca.pub / TLS Public Key PEM"
      type        = string
      default     = ""
    }

    variable "tls_cert" {
      description = "tls_self_signed_cert.crdb_ca_cert.cert_pem -> ca.crt / TLS Cert PEM"
      type        = string
      default     = ""
    }

    variable "tls_user_cert" {
      description = "tls_locally_signed_cert.user_cert.cert_pem -> client.name.crt"
      type        = string
      default     = ""
    }

    variable "tls_user_key" {
      description = "tls_private_key.client_keys.private_key_pem -> client.name.key"
      type        = string
      default     = ""
    }
