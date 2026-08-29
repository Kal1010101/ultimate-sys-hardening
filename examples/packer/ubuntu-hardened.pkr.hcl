# =============================================================================
#  Ultimate Hardening — Packer golden image example
#
#  Builds a CIS-hardened Ubuntu 24.04 AMI by running the free-tier script
#  as a shell provisioner, then verifying the resulting CIS score.
#
#  Usage:
#    packer init  ubuntu-hardened.pkr.hcl
#    packer build ubuntu-hardened.pkr.hcl
# =============================================================================

packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "hardening_ref" {
  type        = string
  default     = "main"
  description = "Git ref (tag/branch) of ultimate-sys-hardening to install"
}

source "amazon-ebs" "ubuntu" {
  region        = var.region
  instance_type = "t3.small"
  ssh_username  = "ubuntu"
  ami_name      = "ubuntu-24.04-cis-hardened-{{timestamp}}"

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"] # Canonical
    most_recent = true
  }

  tags = {
    Name       = "ubuntu-24.04-cis-hardened"
    Hardening  = "ultimate-sys-hardening"
    Compliance = "CIS-aligned"
    BuildDate  = "{{timestamp}}"
  }
}

build {
  name    = "cis-hardened-ubuntu"
  sources = ["source.amazon-ebs.ubuntu"]

  # 1. Fetch the hardening script
  provisioner "shell" {
    inline = [
      "set -euo pipefail",
      "sudo apt-get update -qq",
      "sudo apt-get install -y git",
      "git clone --depth 1 --branch ${var.hardening_ref} https://github.com/Kal1010101/ultimate-sys-hardening.git /tmp/uh",
    ]
  }

  # 2. Preview first — the build log records exactly what will change
  provisioner "shell" {
    inline = [
      "set -euo pipefail",
      "sudo bash /tmp/uh/src/free/ultimate_hardening.sh --auto-mode --dry-run",
    ]
  }

  # 3. Apply hardening
  #    --skip-backup is safe here: the source AMI is the rollback path,
  #    and backups would otherwise bloat the resulting image.
  provisioner "shell" {
    inline = [
      "set -euo pipefail",
      "sudo bash /tmp/uh/src/free/ultimate_hardening.sh --auto-mode --skip-backup",
    ]
    # SSH hardening restarts sshd; let Packer reconnect cleanly
    expect_disconnect = true
  }

  # 4. Verify the score meets a threshold, fail the build if it doesn't
  provisioner "shell" {
    inline = [
      "set -euo pipefail",
      "sudo bash /tmp/uh/src/free/ultimate_hardening.sh --auto-mode --cis-only | tee /tmp/cis.txt",
      "score=$(grep -oP 'CIS Score: \\K[0-9]+' /tmp/cis.txt | head -1)",
      "echo \"Final CIS score: $${score}%\"",
      "if [ \"$${score}\" -lt 80 ]; then echo 'FAIL: CIS score below 80% threshold'; exit 1; fi",
    ]
  }

  # 5. Clean up build artifacts so they don't ship in the image
  provisioner "shell" {
    inline = [
      "sudo rm -rf /tmp/uh /tmp/cis.txt",
      "sudo rm -f /var/log/ultimate_hardening_*.log",
      "sudo cloud-init clean --logs || true",
    ]
  }

  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}
