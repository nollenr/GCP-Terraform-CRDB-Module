### Run this Terraform Script
```terraform
git clone https://github.com/nollenr/GCP-Terraform-CRDB-Module.git
cd GCP-Terraform-CRDB-Module/
export TF_VAR_cluster_organization={CLUSTER ORG}
export TF_VAR_enterprise_license={LICENSE}
terraform init
terraform fmt (optinal)
terraform validate
terraform plan
terraform apply
terraform destroy
```