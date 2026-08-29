# Packer integration

The hardening script runs as a plain shell provisioner, so it drops into any
Packer build without a plugin.

## Files

| File | Purpose |
|------|---------|
| `ubuntu-hardened.pkr.hcl` | Builds a CIS-hardened Ubuntu 24.04 AMI and fails the build if the score drops below 80% |

## The pattern

Four provisioner steps, in this order:

1. **Fetch** — clone the repo into `/tmp` on the build instance
2. **Preview** — run with `--dry-run` so the build log records every intended change
3. **Apply** — run with `--auto-mode --skip-backup`
4. **Verify** — re-run the checks and exit non-zero if the score is under threshold

Step 4 is what makes this useful in CI: a regression in the base image or a
package update that reopens a port fails the build instead of shipping.

## Notes

- `expect_disconnect = true` is required on the apply step. SSH hardening restarts
  `sshd`, which drops Packer's connection; without this flag the build errors out.
- `--skip-backup` is intentional here. In an image build the source AMI *is* the
  rollback path, and `/root/hardening_backup_*` would otherwise ship inside the image.
- Adjust the score threshold to taste. 80% is realistic for a cloud image where
  separate-partition checks will always fail on a single-volume root disk.

## Terraform

Reference the built AMI from the manifest:

```hcl
data "aws_ami" "hardened" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["ubuntu-24.04-cis-hardened-*"]
  }
}

resource "aws_instance" "app" {
  ami           = data.aws_ami.hardened.id
  instance_type = "t3.medium"
}
```

## Other builders

The provisioner block is builder-agnostic — swap `amazon-ebs` for `googlecompute`,
`azure-arm`, `qemu`, or `vsphere-iso` and the shell steps are unchanged.
