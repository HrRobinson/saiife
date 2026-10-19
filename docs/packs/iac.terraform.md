# IaC: Terraform (iac.terraform)

This pack makes sure that Terraform changes infrastructure only from a plan
a person has reviewed. The safe way is: `terraform plan -out=plan.tfplan`,
a person reviews the plan, then `terraform apply plan.tfplan`. The pack
blocks the ways around that, and the commands that tamper with Terraform's
records.

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack iac.terraform`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["iac.terraform"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `terraform destroy` and `terraform apply -destroy`. They remove every
  resource Terraform manages.
- `-auto-approve` on `apply` or `destroy`. It skips the confirmation step.
- `terraform apply` without a saved plan file. It makes a new plan and
  applies it at once, with no review.
- `terraform state rm` and `terraform state mv`. They take resources out of
  Terraform's records; a later apply can then lose track of them or create
  them again.
- `terraform force-unlock`. It removes the lock that stops two runs from
  changing the same infrastructure at once.

## Allowed on purpose

- `terraform plan`, including `plan -out=plan.tfplan`.
- `terraform apply <plan file>`. This is the reviewed path.
- Read and setup commands: `output`, `show`, `state list`, `state show`,
  `state pull`, `init`, `validate`, `fmt`, `version`.

## Not covered

- Any `terraform apply` with a file name after it is treated as a reviewed
  plan. saiife does not check that a person actually reviewed that plan, or
  that the file is a plan.
- `terraform import`, `terraform taint` and `terraform state push` are
  allowed.
- Changes made outside Terraform (cloud consoles, cloud command-line tools)
  are not seen by this pack. See the `cloud.*` packs.

## Examples

```saiife-examples
deny terraform destroy
deny terraform apply -destroy
deny terraform apply -auto-approve
deny terraform apply
deny terraform apply -var region=us-east-1
deny terraform state rm aws_instance.web
deny terraform force-unlock 1234
allow terraform plan -out=plan.tfplan
allow terraform apply plan.tfplan
allow terraform state list
allow terraform output -json
```
