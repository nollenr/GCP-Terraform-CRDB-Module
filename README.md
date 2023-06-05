### Run this Terraform Script
```terraform
git clone https://github.com/nollenr/GCP-Terraform-CRDB-Module.git
cd GCP-Terraform-CRDB-Module/
export AWS_ACCESS_KEY_ID={ID}
export AWS_SECRET_ACCESS_KEY={SECRET}
terraform init
terraform fmt (optinal)
terraform validate
terraform plan
terraform apply
terraform destroy
```