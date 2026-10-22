# saiife packs

A pack is a set of rules for one area, such as git or a cloud provider. Each
rule either blocks a command or file access, or allows it on purpose. The
four `core` packs are always on, and `core.lock` is on in locked mode. The
others are opt-in: turn one on for a project with `saiife init --pack <id>`
in your own terminal, or by adding its id to the `packs` list in
`.saiife/config.toml`.

`saiife packs` shows which packs are on in the current project, and
`saiife packs <id>` lists one pack's rules.

| Pack | On by default? | What it stops |
| --- | --- | --- |
| [core.filesystem](core.filesystem.md) | yes | Wiping the disk, the home folder or system folders; overwriting or formatting a disk. |
| [core.git](core.git.md) | yes | Git commands that throw away work: hard reset, clean, force-push, force branch delete. |
| [core.secrets](core.secrets.md) | yes | Reading secret files, printing all environment variables, printing secrets from secret managers and cloud tools. |
| [core.self](core.self.md) | yes | Turning saiife off, changing its settings or hook, replacing it, hiding the audit log. |
| [core.lock](core.lock.md) | in locked mode | Changing privileges, stopping saiife's service, jobs that run later, changing saiife's system files and the managed agent settings. |
| [cloud.aws](cloud.aws.md) | no | Deleting AWS stacks, tables, databases and instances; emptying S3 buckets; IAM and organization changes. |
| [cloud.azure](cloud.azure.md) | no | Deleting Azure resource groups, VMs, storage accounts and clusters; role changes. |
| [cloud.gcloud](cloud.gcloud.md) | no | Deleting Google Cloud projects, databases, VMs, buckets and keys; removing access rights. |
| [container.docker](container.docker.md) | no | Removing Docker volumes, force-removing containers and images, removing networks. |
| [container.k8s](container.k8s.md) | no | Deleting Kubernetes namespaces and volumes, bulk deletes, draining nodes, Helm uninstall. |
| [db.mongo](db.mongo.md) | no | Dropping a MongoDB database or collection; deleting every document. |
| [db.mysql](db.mysql.md) | no | MySQL DROP, TRUNCATE, DELETE without WHERE, GRANT ALL, `mysqladmin drop`. |
| [db.postgres](db.postgres.md) | no | PostgreSQL DROP, TRUNCATE, DELETE without WHERE, `dropdb`. |
| [iac.terraform](iac.terraform.md) | no | Terraform changes without a reviewed plan: destroy, auto-approve, bare apply, state surgery. |

Each page has the same parts: what is blocked, what is allowed on purpose,
what is not covered, and examples. The examples are checked against saiife by
a test, so they show what saiife really does. Limits that apply to every pack
are listed at the end of the `core.secrets` and `core.self` pages.
