# https://www.middlewareinventory.com/blog/create-linux-vm-in-gcp-with-terraform-remote-exec/
data "google_compute_zones" "available" {
  status  = "UP"
  project = "${var.gcp_project_name}"
  region  = "${var.gcp_region}"
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

# -----------------------------------------------------------------------
# Client Keys and cert
# -----------------------------------------------------------------------
# https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key#private_key_openssh
resource "tls_private_key" "client_keys" {
  algorithm = "RSA"
  rsa_bits  = 2048 
}

resource "tls_cert_request" "client_csr" {
  private_key_pem = tls_private_key.client_keys.private_key_pem

  subject {
    organization = "Cockroach"
    common_name = "${var.admin_user_name}"
  }

  dns_names = ["root"]

}

resource "tls_locally_signed_cert" "user_cert" {
  cert_request_pem = tls_cert_request.client_csr.cert_request_pem
  ca_private_key_pem = tls_private_key.crdb_ca_keys.private_key_pem
  ca_cert_pem = tls_self_signed_cert.crdb_ca_cert.cert_pem

  validity_period_hours = 43921

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
  #ca.key
  tls_private_key = coalesce(var.tls_private_key, tls_private_key.crdb_ca_keys.private_key_pem)
  #ca.pub
  tls_public_key  = coalesce(var.tls_public_key,  tls_private_key.crdb_ca_keys.public_key_pem)
  #ca.crt
  tls_cert        = coalesce(var.tls_cert,        tls_self_signed_cert.crdb_ca_cert.cert_pem)
  #client.name.crt
  tls_user_cert   = coalesce(var.tls_user_cert,   tls_locally_signed_cert.user_cert.cert_pem)
  #client.name.key
  tls_user_key    = coalesce(var.tls_user_key,    tls_private_key.client_keys.private_key_pem)
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

resource "google_compute_address" "internal-haproxy" {
  count        = 1
  project      = "${var.gcp_project_name}"
  name         = "haproxy-internal-ip-${count.index}"
  address_type = "INTERNAL"
  region       = "${var.gcp_region}"
  subnetwork   = google_compute_subnetwork.cockroach-subnets[0].id
}

resource "google_compute_address" "external-haproxy" {
  count        = 1
  project      = "${var.gcp_project_name}"
  name         = "haproxy-external-ip-${count.index}"
  address_type = "EXTERNAL"
  region       = "${var.gcp_region}"
}

resource "google_compute_address" "internal-app" {
  count        = 1
  project      = "${var.gcp_project_name}"
  name         = "app-internal-ip-${count.index}"
  address_type = "INTERNAL"
  region       = "${var.gcp_region}"
  subnetwork   = google_compute_subnetwork.cockroach-subnets[0].id
}

resource "google_compute_address" "external-app" {
  count        = 1
  project      = "${var.gcp_project_name}"
  name         = "app-external-ip-${count.index}"
  address_type = "EXTERNAL"
  region       = "${var.gcp_region}"
}

locals {
  private_ip_list = join(",", google_compute_address.internal[*].address)
  private_ip_nocomma_list = join(" ", google_compute_address.internal[*].address)
  join_string     = coalesce(var.join_string, local.private_ip_list)
  # This is for a limitation of GCP (as I understand it).  I was not able to use google_compute_address.internal-haproxy[*].address in the metadata b/c it is not a string!
  haproxy_ip_string = join(" ",  google_compute_address.internal-haproxy[*].address)
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
  machine_type = "${var.crdb_instance_type}"
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

  # In GCP, I'm downloading and installing Cockroach first, since the /home/user/bashrc file may not yet be created.
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
    if [ "${var.include_ha_proxy}" = "yes" ]; then echo "  ${local.haproxy_ip_string} \\" >> /home/${var.my_linux_user}/.bashrc; fi
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
    if [[ '${var.run_init}' = 'yes' && ${count.index + 1} -eq ${var.crdb_nodes} && ${var.create_admin_user} = 'yes' ]]; then echo "Creating admin user ${var.admin_user_name}" && su ec2-user -lc 'cockroach sql --execute "create user ${var.admin_user_name}; grant admin to ${var.admin_user_name}"'; fi

  EOF

}

resource "google_compute_instance" "haproxy" {
  count         = var.include_ha_proxy == "yes" && var.create_gcp_instances == "yes" ? 1 : 0
  project      = "${var.gcp_project_name}"
  name         = "cockroachdb-haproxy-${count.index}"
  machine_type = "${var.haproxy_instance_type}"
  zone         = local.availability_zone_list[0]

  boot_disk {
    initialize_params {
      image = "rhel-7-v20230411"
    }
  }

  network_interface {
    # subnetwork = google_compute_subnetwork.cockroach-subnets[count.index].id
    # Think of this a modulo math.  The "element" function "wraps around" -- so that if I have 6 instances, but 3 subnets, the subnets will be used "round-robin"
    subnetwork = google_compute_subnetwork.cockroach-subnets[0].id
    network_ip = google_compute_address.internal-haproxy[0].id

    access_config {  
        nat_ip =  google_compute_address.external-haproxy[count.index].address  
    }
  }

  metadata = {
    ssh-keys = "nollen:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3aU6attuC55MjNYEu92xxEj4ZenBbOPbp032IFYXvJm1iZyqZHIerIejSBFB/2gDR3u76Edh3/R+bzU85EnT+APAJw52LboPvGquqDwgZIyQyDpN5MZTIa40KU5kS6Ekv2UnPaHiHxn9X84B7ZBGj1On29fTuuAW6ct9fxaJZqjPB3KZebT5YxTma+OAr9eKshxZj1vjG1XrOEyWaw3diravhjzeM8gAvi+2RyHqaXdrRNg7HihVGzdeCNwM4Wn7MiVzSE2GngkWHkUAW9vdRia42Ru+qGSSC0rxI5zBJD9XMxee4haGm+dvgd6rCk7KUJ/l7xwfnAkTdiPOZFcHv nollen"
  }

  metadata_startup_script = <<EOF
    #!/bin/bash -xe
    echo 'export CLUSTER_PRIVATE_IP_LIST="${local.private_ip_nocomma_list}" ' >> /home/${var.my_linux_user}/.bashrc
    export CLUSTER_PRIVATE_IP_LIST="${local.private_ip_nocomma_list}"
    echo "HAProxy Config and Install"
    echo 'global' > /home/${var.my_linux_user}/haproxy.cfg
    echo '  maxconn 4096' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '' >> /home/${var.my_linux_user}/haproxy.cfg
    echo 'defaults' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    mode                tcp' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # Timeout values should be configured for your specific use.' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # See: https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-timeout%20connect' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # With the timeout connect 5 secs,' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # if the backend server is not responding, haproxy will make a total' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # of 3 connection attempts waiting 5s each time before giving up on the server,' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # for a total of 15 seconds.' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    retries             2' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    timeout connect     5s' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # timeout client and server govern the maximum amount of time of TCP inactivity.' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # The server node may idle on a TCP connection either because it takes time to' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # execute a query before the first result set record is emitted, or in case of' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # some trouble on the server. So these timeout settings should be larger than the' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # time to execute the longest (most complex, under substantial concurrent workload)' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # query, yet not too large so truly failed connections are lingering too long' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # (resources associated with failed connections should be freed reasonably promptly).' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    timeout client      10m' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    timeout server      10m' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    # TCP keep-alive on client side. Server already enables them.' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    option              clitcpka' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '' >> /home/${var.my_linux_user}/haproxy.cfg
    echo 'listen psql' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    bind :26257' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    mode tcp' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    balance roundrobin' >> /home/${var.my_linux_user}/haproxy.cfg
    echo '    option httpchk GET /health?ready=1' >> /home/${var.my_linux_user}/haproxy.cfg
    counter=1;for IP in $CLUSTER_PRIVATE_IP_LIST; do echo "    server cockroach$counter $IP:26257 check port 8080" >> /home/${var.my_linux_user}/haproxy.cfg; (( counter++ )); done
    chown ${var.my_linux_user}:${var.my_linux_user} /home/${var.my_linux_user}/haproxy.cfg
    echo "Installing HAProxy"; yum -y install haproxy
    echo "Starting HAProxy as ${var.my_linux_user}"; su ${var.my_linux_user} -lc 'haproxy -f haproxy.cfg > haproxy.log 2>&1 &'
  EOF
}

resource "google_compute_instance" "app" {
  count         = var.include_app_instance == "yes" && var.create_gcp_instances == "yes" ? 1 : 0
  project      = "${var.gcp_project_name}"
  name         = "cockroachdb-app-${count.index}"
  machine_type = "${var.app_instance_type}"
  zone         = local.availability_zone_list[0]

  boot_disk {
    initialize_params {
      # image = "rhel-7-v20230411"
      image = "debian-10-buster-v20230510"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.cockroach-subnets[0].id
    network_ip = google_compute_address.internal-app[0].id

    access_config {  
      nat_ip =  google_compute_address.external-app[count.index].address  
    }
  }

  metadata = {
    ssh-keys = "nollen:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3aU6attuC55MjNYEu92xxEj4ZenBbOPbp032IFYXvJm1iZyqZHIerIejSBFB/2gDR3u76Edh3/R+bzU85EnT+APAJw52LboPvGquqDwgZIyQyDpN5MZTIa40KU5kS6Ekv2UnPaHiHxn9X84B7ZBGj1On29fTuuAW6ct9fxaJZqjPB3KZebT5YxTma+OAr9eKshxZj1vjG1XrOEyWaw3diravhjzeM8gAvi+2RyHqaXdrRNg7HihVGzdeCNwM4Wn7MiVzSE2GngkWHkUAW9vdRia42Ru+qGSSC0rxI5zBJD9XMxee4haGm+dvgd6rCk7KUJ/l7xwfnAkTdiPOZFcHv nollen"
  }

  # For GCP python3 also needs to be installed (this install includes pip3)
  metadata_startup_script = <<EOF
    #!/bin/bash -xe
    echo "Installing git, python3-pip and libpq-dev"
    apt --yes install git python3-pip
    apt --yes install libpq-dev

    echo "installing certs"
    su ${var.my_linux_user} -c 'mkdir /home/${var.my_linux_user}/certs'
    echo '${local.tls_cert}' >> /home/${var.my_linux_user}/certs/ca.crt 
    chown ${var.my_linux_user}:${var.my_linux_user} /home/${var.my_linux_user}/certs/ca.crt
    chmod 600 /home/${var.my_linux_user}/certs/ca.crt
    echo '${local.tls_user_cert}' >> /home/${var.my_linux_user}/certs/client.${var.admin_user_name}.crt
    chown ${var.my_linux_user}:${var.my_linux_user} /home/${var.my_linux_user}/certs/client.${var.admin_user_name}.crt
    chmod 600 /home/${var.my_linux_user}/certs/client.${var.admin_user_name}.crt
    echo '${local.tls_user_key}' >> /home/${var.my_linux_user}/certs/client.${var.admin_user_name}.key
    chown ${var.my_linux_user}:${var.my_linux_user} /home/${var.my_linux_user}/certs/client.${var.admin_user_name}.key
    chmod 600 /home/${var.my_linux_user}/certs/client.${var.admin_user_name}.key

    echo "Downloading and installing CockroachDB along with the Geo binaries"
    curl https://binaries.cockroachdb.com/cockroach-sql-v${var.crdb_version}.linux-amd64.tgz | tar -xz && cp -i cockroach-sql-v${var.crdb_version}.linux-amd64/cockroach-sql /usr/local/bin/

    echo "CRDB() {" >> /home/${var.my_linux_user}/.bashrc
    echo 'cockroach-sql sql --url "postgresql://${var.admin_user_name}@'"${local.haproxy_ip_string}:26257/defaultdb?sslmode=verify-full&sslrootcert="'$HOME/certs/ca.crt&sslcert=$HOME/certs/client.'"${var.admin_user_name}.crt&sslkey="'$HOME/certs/client.'"${var.admin_user_name}.key"'"' >> /home/${var.my_linux_user}/.bashrc
    echo "}" >> /home/${var.my_linux_user}/.bashrc   
    echo " " >> /home/${var.my_linux_user}/.bashrc   

    echo "Installing and Configuring Demo Function"
    echo "#!/bin/bash" >> /home/${var.my_linux_user}/multiregion_demo_setup.sh
    echo "sudo pip3 install sqlalchemy~=1.4" >> /home/${var.my_linux_user}/multiregion_demo_setup.sh
    echo "sudo pip3 install sqlalchemy-cockroachdb" >> /home/${var.my_linux_user}/multiregion_demo_setup.sh
    echo "sudo pip3 install psycopg2" >> /home/${var.my_linux_user}/multiregion_demo_setup.sh
    echo "git clone https://github.com/nollenr/crdb-multi-region-demo.git" >> /home/${var.my_linux_user}/multiregion_demo_setup.sh
    chown ${var.my_linux_user}:${var.my_linux_user} /home/${var.my_linux_user}/multiregion_demo_setup.sh
    chmod +x /home/${var.my_linux_user}/multiregion_demo_setup.sh
    echo "# For demo usage.  The python code expects these environment variables to be set" >> /home/${var.my_linux_user}/.bashrc
    echo "export DB_HOST="\""${local.haproxy_ip_string}"\"" " >> /home/${var.my_linux_user}/.bashrc
    echo "export DB_USER="\""${var.admin_user_name}"\"" " >> /home/${var.my_linux_user}/.bashrc
    echo "export DB_SSLCERT="\""/home/${var.my_linux_user}/certs/client.${var.admin_user_name}.crt"\"" " >> /home/${var.my_linux_user}/.bashrc
    echo "export DB_SSLKEY="\""/home/${var.my_linux_user}/certs/client.${var.admin_user_name}.key"\"" " >> /home/${var.my_linux_user}/.bashrc
    echo "export DB_SSLROOTCERT="\""/home/${var.my_linux_user}/certs/ca.crt"\"" " >> /home/${var.my_linux_user}/.bashrc
    echo "export DB_SSLMODE="\""require"\"" " >> /home/${var.my_linux_user}/.bashrc
    if [[ '${var.include_demo}' == 'yes' ]]; then echo "Installing Demo"; su ${var.my_linux_user} -c "/home/${var.my_linux_user}/multiregion_demo_setup.sh"; fi;
    EOF
}