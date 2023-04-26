# https://www.middlewareinventory.com/blog/create-linux-vm-in-gcp-with-terraform-remote-exec/
data "google_compute_zones" "available" {
  status = "UP"
  project      = "${var.gcp_project_name}"
  region = "${var.gcp_region}"
}

locals {
  subnet_list = cidrsubnets(var.vpc_cidr,3,3,3,3,3,3)
  availability_zone_count = 3
  availability_zone_list = slice(data.google_compute_zones.available.names,0,local.availability_zone_count)
}

resource "random_id" "id" {
  byte_length = 8
}

#=============================================
# START Temporary Section
#=============================================

# -----------------------------------------------------------------------
#  CRDB Keys and ca.crt
# -----------------------------------------------------------------------
# Create both the keys and cert required for secure mode
# https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key#private_key_openssh
resource "tls_private_key" "crdb_ca_keys" {
  algorithm = "RSA"
  rsa_bits  = 2048 
}

# https://www.cockroachlabs.com/docs/v22.2/create-security-certificates-openssl
# https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/self_signed_cert
# also created cert with : su - ec2-user -c 'openssl req -new -x509 -key my-safe-directory/ca.key -out certs/ca.crt -days 1831 -subj "/O=Cockroach /CN=Cockroach CA /keyUsage=critical,digitalSignature,keyEncipherment /extendedKeyUsage=clientAuth"'
resource "tls_self_signed_cert" "crdb_ca_cert" {
  private_key_pem = tls_private_key.crdb_ca_keys.private_key_pem

  subject {
    common_name  = "Cockroach CA"
    organization = "Cockroach"
  }

  validity_period_hours = 43921
  is_ca_certificate = true

  allowed_uses = [
    "any_extended",
    "cert_signing",
    "client_auth",
    "code_signing",
    "content_commitment",
    "crl_signing",
    "data_encipherment",
    "digital_signature",
    "email_protection",
    "key_agreement",
    "key_encipherment",
    "ocsp_signing",
    "server_auth"
  ]
}

locals {
  tls_private_key = coalesce(var.tls_private_key, tls_private_key.crdb_ca_keys.private_key_pem)
  tls_public_key  = coalesce(var.tls_public_key,  tls_private_key.crdb_ca_keys.public_key_pem)
  tls_cert        = coalesce(var.tls_cert,        tls_self_signed_cert.crdb_ca_cert.cert_pem)
#   tls_user_cert   = tls_locally_signed_cert.user_cert.cert_pem
#   tls_user_key    = tls_private_key.client_keys.private_key_pem
}

resource "google_compute_address" "internal" {
  count        = var.crdb_nodes
  project      = "${var.gcp_project_name}"
  name         = "crdb-internal-ip-${count.index}"
  address_type = "INTERNAL"
  region       = "${var.gcp_region}"
  subnetwork   = google_compute_subnetwork.cockroach-subnets[count.index%3].id
}

resource "google_compute_address" "external" {
  count        = var.crdb_nodes
  project      = "${var.gcp_project_name}"
  name         = "crdb-external-ip-${count.index}"
  address_type = "EXTERNAL"
  region       = "${var.gcp_region}"
}

locals {
  private_ip_list = join(",", google_compute_address.internal[*].address)
  join_string     = coalesce(var.join_string, local.private_ip_list)
}

#=============================================
# END Temporary Section
#=============================================

# https://registry.tfpla.net/providers/hashicorp/google/4.59.0/docs/resources/compute_network
resource "google_compute_network" "cockroach-vpc" {
  description             = "VPC for the Cockroach Cluster"
  project                 = "${var.gcp_project_name}"
  name                    = "cockroach-vpc"
  auto_create_subnetworks = false
  mtu                     = 1460
}

resource "google_compute_subnetwork" "cockroach-subnets" {
  count         = 3
  name          = "cockroach-subnet-${count.index}"
  ip_cidr_range = local.subnet_list[count.index]
  region        = "${var.gcp_region}"
  project       = "${var.gcp_project_name}"
  network       = google_compute_network.cockroach-vpc.id
}

resource "google_compute_network_firewall_policy" "cockroach-firewall-policy" {
  name        = "cockroach-firewall-policy"
  project       = "${var.gcp_project_name}"
  description = "Network firewall policy"
}

resource "google_compute_network_firewall_policy_rule" "external-access" {
  firewall_policy = google_compute_network_firewall_policy.cockroach-firewall-policy.name
  project       = "${var.gcp_project_name}"
  description = "Allow access from my IP address"
  priority = 1000
  enable_logging = false
  action = "allow"
  direction = "INGRESS"
  disabled = false
  match {
    layer4_configs {
      ip_protocol = "tcp"
      ports = [22, 8080, 26257]
    }
    src_ip_ranges = ["98.148.51.154/32"]
  }
}

resource "google_compute_network_firewall_policy_rule" "inter-node-access" {
  firewall_policy = google_compute_network_firewall_policy.cockroach-firewall-policy.name
  project       = "${var.gcp_project_name}"
  description = "Allow access on all TCP ports between nodes in the 3 defined subnets"
  priority = 1001
  enable_logging = false
  action = "allow"
  direction = "INGRESS"
  disabled = false
  match {
    layer4_configs {
      ip_protocol = "tcp"
    }
    src_ip_ranges = ["${local.subnet_list[0]}","${local.subnet_list[1]}","${local.subnet_list[2]}"]
  }
}

resource "google_compute_network_firewall_policy_rule" "deny-ipv4-access" {
  firewall_policy = google_compute_network_firewall_policy.cockroach-firewall-policy.name
  project       = "${var.gcp_project_name}"
  description = "Deny ingress on any port, not already defined on IPV4"
  priority = 10000
  enable_logging = false
  action = "deny"
  direction = "INGRESS"
  disabled = false
  match {
    layer4_configs {
      ip_protocol = "all"
    }
    src_ip_ranges = ["0.0.0.0/0"]
  }
}

resource "google_compute_network_firewall_policy_rule" "deny-ipv6-access" {
  firewall_policy = google_compute_network_firewall_policy.cockroach-firewall-policy.name
  project       = "${var.gcp_project_name}"
  description = "Deny ingress on any port, not already defined on IPV6"
  priority = 10001
  enable_logging = false
  action = "deny"
  direction = "INGRESS"
  disabled = false
  match {
    layer4_configs {
      ip_protocol = "all"
    }
    src_ip_ranges = ["::/0"]
  }
}

resource "google_compute_network_firewall_policy_association" "primary" {
  project           = "${var.gcp_project_name}"
  name              = "cockorach-firewall-policy-association"
  attachment_target = google_compute_network.cockroach-vpc.id
  firewall_policy   =  google_compute_network_firewall_policy.cockroach-firewall-policy.name
}

resource "google_compute_instance" "cockroachdb-instances" {
  count        = var.create_gcp_instances == "yes" ? var.crdb_nodes : 0
  project      = "${var.gcp_project_name}"
  name         = "cockroachdb-instance-${count.index}"
  machine_type = "e2-micro"
  zone         = local.availability_zone_list[count.index%3]

  tags = ["foo", "bar"]

  boot_disk {
    initialize_params {
      image = "rhel-7-v20230411"
    }
  }

  network_interface {
    # subnetwork = google_compute_subnetwork.cockroach-subnets[count.index].id
    # Think of this a modulo math.  The "element" function "wraps around" -- so that if I have 6 instances, but 3 subnets, the subnets will be used "round-robin"
    subnetwork = google_compute_subnetwork.cockroach-subnets[count.index%3].id
    network_ip = google_compute_address.internal[count.index].id

    access_config {  
        nat_ip =  google_compute_address.external[count.index].address  
    }
  }

  metadata = {
    ssh-keys = "nollen:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3aU6attuC55MjNYEu92xxEj4ZenBbOPbp032IFYXvJm1iZyqZHIerIejSBFB/2gDR3u76Edh3/R+bzU85EnT+APAJw52LboPvGquqDwgZIyQyDpN5MZTIa40KU5kS6Ekv2UnPaHiHxn9X84B7ZBGj1On29fTuuAW6ct9fxaJZqjPB3KZebT5YxTma+OAr9eKshxZj1vjG1XrOEyWaw3diravhjzeM8gAvi+2RyHqaXdrRNg7HihVGzdeCNwM4Wn7MiVzSE2GngkWHkUAW9vdRia42Ru+qGSSC0rxI5zBJD9XMxee4haGm+dvgd6rCk7KUJ/l7xwfnAkTdiPOZFcHv nollen"

  }

  # In GCP, I'm downloading and install Cockroach first, since the /home/user/bashrc file may not yet be created.
  metadata_startup_script = <<EOF
    #!/bin/bash

    echo "Downloading and installing CockroachDB along with the Geo binaries"
    curl https://binaries.cockroachdb.com/cockroach-v${var.crdb_version}.linux-amd64.tgz | tar -xz && cp -i cockroach-v${var.crdb_version}.linux-amd64/cockroach /usr/local/bin/
    mkdir -p /usr/local/lib/cockroach
    cp -i cockroach-v${var.crdb_version}.linux-amd64/lib/libgeos.so /usr/local/lib/cockroach/
    cp -i cockroach-v${var.crdb_version}.linux-amd64/lib/libgeos_c.so /usr/local/lib/cockroach/

    echo "Setting variables"
    echo 'export ip_local=`curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip`' >> /home/${var.my_linux_user}/.bashrc
    echo 'export ip_public=`curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip`' >> /home/${var.my_linux_user}/.bashrc
    echo 'export gcp_project_zone=`curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone`' >> /home/${var.my_linux_user}/.bashrc
    echo "export gcp_az=\`echo \$gcp_project_zone | awk -F'/' '{print \$4}'\`" >> /home/${var.my_linux_user}/.bashrc
    echo "export gcp_region=\`echo \$gcp_az | awk -F'-' '{print \$1"\""-"\""\$2}'\`" >> /home/${var.my_linux_user}/.bashrc
    echo 'export COCKROACH_CERTS_DIR=/home/${var.my_linux_user}/certs' >> /home/${var.my_linux_user}/.bashrc
    echo 'export JOIN_STRING="${local.join_string}" ' >> /home/${var.my_linux_user}/.bashrc

    echo "Creating the public and private keys"
    su ${var.my_linux_user} -c 'mkdir /home/${var.my_linux_user}/certs; mkdir /home/${var.my_linux_user}/my-safe-directory'
    echo '${local.tls_private_key}' >> /home/${var.my_linux_user}/my-safe-directory/ca.key
    echo '${local.tls_public_key}' >> /home/${var.my_linux_user}/certs/ca.pub
    echo '${local.tls_cert}' >> /home/${var.my_linux_user}/certs/ca.crt

    echo "Changing ownership on permissions on keys and certs"
    chown ${var.my_linux_user}:${var.my_linux_user} /home/${var.my_linux_user}/certs/ca.crt
    chown ${var.my_linux_user}:${var.my_linux_user} /home/${var.my_linux_user}/certs/ca.pub
    chown ${var.my_linux_user}:${var.my_linux_user} /home/${var.my_linux_user}/my-safe-directory/ca.key
    chmod 640 /home/${var.my_linux_user}/certs/ca.crt
    chmod 640 /home/${var.my_linux_user}/certs/ca.pub
    chmod 600 /home/${var.my_linux_user}/my-safe-directory/ca.key     

    echo "Creating the CREATENODECERT bashrc function"
    echo "CREATENODECERT() {" >> /home/${var.my_linux_user}/.bashrc
    echo "  cockroach cert create-node \\" >> /home/${var.my_linux_user}/.bashrc
    echo '  $ip_local \' >> /home/${var.my_linux_user}/.bashrc
    echo '  $ip_public \' >> /home/${var.my_linux_user}/.bashrc
    echo "  localhost \\" >> /home/${var.my_linux_user}/.bashrc
    echo "  127.0.0.1 \\" >> /home/${var.my_linux_user}/.bashrc
    echo "Adding haproxy to the CREATENODECERT function if var.include_ha_proxy is yes"
    echo "  --certs-dir=certs \\" >> /home/${var.my_linux_user}/.bashrc
    echo "  --ca-key=my-safe-directory/ca.key" >> /home/${var.my_linux_user}/.bashrc
    echo "}" >> /home/${var.my_linux_user}/.bashrc

    echo "Creating the CREATEROOTCERT bashrc function"
    echo "CREATEROOTCERT() {" >> /home/${var.my_linux_user}/.bashrc
    echo "  cockroach cert create-client \\" >> /home/${var.my_linux_user}/.bashrc
    echo '  root \' >> /home/${var.my_linux_user}/.bashrc
    echo "  --certs-dir=certs \\" >> /home/${var.my_linux_user}/.bashrc
    echo "  --ca-key=my-safe-directory/ca.key" >> /home/${var.my_linux_user}/.bashrc
    echo "}" >> /home/${var.my_linux_user}/.bashrc   

    echo "Creating the STARTCRDB bashrc function"
    echo "STARTCRDB() {" >> /home/${var.my_linux_user}/.bashrc
    echo "  cockroach start \\" >> /home/${var.my_linux_user}/.bashrc
    echo '  --locality=region="$gcp_region",zone="$gcp_az" \' >> /home/${var.my_linux_user}/.bashrc
    echo "  --certs-dir=certs \\" >> /home/${var.my_linux_user}/.bashrc
    echo '  --advertise-addr=$ip_local \' >> /home/${var.my_linux_user}/.bashrc
    echo '  --join=$JOIN_STRING \' >> /home/${var.my_linux_user}/.bashrc
    echo '  --max-offset=250ms \' >> /home/${var.my_linux_user}/.bashrc
    echo "  --background " >> /home/${var.my_linux_user}/.bashrc
    echo " }" >> /home/${var.my_linux_user}/.bashrc

    echo "Creating the node cert, root cert and starting CRDB"
    sleep 20; su ${var.my_linux_user} -lc 'CREATENODECERT; CREATEROOTCERT; STARTCRDB'

    echo "Validating if init needs to be run"
    echo "RunInit: ${var.run_init}  Count.Index: ${count.index}   Count: ${var.crdb_nodes}"
    if [[ '${var.run_init}' = 'yes' && ${count.index + 1} -eq ${var.crdb_nodes} ]]; then echo "Initializing Cockroach Database" && su ${var.my_linux_user} -lc 'cockroach init'; fi

  EOF

}
