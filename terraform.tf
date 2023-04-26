terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.61.0"
    }
  }

  required_version = ">= 1.4.5"
}
