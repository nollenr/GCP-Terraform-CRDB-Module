gcp_project_name     = "nollen-test"
vpc_name             = "terraform-vpc-01"
vpc_cidr             = "192.168.6.0/24"
my_ip_address        = "98.148.51.154"
my_linux_user        = "nollen"
gcp_region           = "us-central1"
create_gcp_instances = "yes"
crdb_nodes           = 3
crdb_instance_type   = "e2-micro"
crdb_version         = "22.2.10"
run_init             = "no"               #For multi-cloud this must be 'no'!
join_string          = "3.141.30.20,3.145.24.144,18.223.114.50"

include_ha_proxy     = "yes"
haproxy_instance_type   = "e2-micro"

include_app_instance = "yes"
app_instance_type    = "e2-micro"
create_admin_user    = "no"
admin_user_name      = "ron"
include_demo         = "no"