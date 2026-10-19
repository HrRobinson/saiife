# Cloud: gcloud (cloud.gcloud)

This pack stops Google Cloud command-line operations (`gcloud`, `gsutil`)
that cannot be undone: deleting projects, databases, virtual machines,
storage buckets and encryption keys, deleting stored files in bulk, and
removing access rights.

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack cloud.gcloud`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["cloud.gcloud"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `gcloud projects delete`. It deletes a whole project and everything in it.
- `remove-iam-policy-binding` on a project, folder or organization. It can
  lock people out.
- `gcloud sql instances delete`. It deletes a Cloud SQL instance and all its
  databases.
- `gcloud compute instances delete`. It deletes the virtual machine and its
  local disks.
- `gcloud storage buckets delete` and `gsutil rb`. They delete a storage
  bucket.
- A recursive delete of stored files (`gcloud storage rm -r`, `gsutil rm -r`).
- Destroying or deleting a Cloud KMS key or key ring. Data encrypted with it
  can no longer be read.
- Any other `gcloud ... delete`.

## Allowed on purpose

- Read commands: `gcloud projects list`, `gcloud sql instances describe`,
  `gsutil ls`.
- Copying files and setting configuration: `gsutil cp`,
  `gcloud config set project`, `gcloud auth login`.
- Adding access with `add-iam-policy-binding`.
- A resource that is only named like an operation, for example a VM called
  `delete-me-vm`.

## Not covered

- Only `gcloud` and `gsutil` are judged. Changes made in the Cloud Console,
  through Terraform (see `iac.terraform`) or SDK scripts are not seen.
- Deleting a single stored file (`gsutil rm gs://bucket/file`) is allowed.
- Granting broad access with `add-iam-policy-binding` (for example the owner
  role) is allowed.
- Reading Google Cloud secrets and tokens is covered by `core.secrets`, not by
  this pack.

## Examples

```saiife-examples
deny gcloud projects delete my-project
deny gcloud projects remove-iam-policy-binding p --member=user:x --role=roles/owner
deny gcloud sql instances delete db1
deny gcloud compute instances delete vm1 --zone us-central1-a
deny gsutil rb gs://my-bucket
deny gsutil rm -r gs://my-bucket/data
deny gcloud kms keys destroy k --keyring r --location global
deny gcloud iam service-accounts delete sa@p.iam.gserviceaccount.com
allow gcloud projects list
allow gsutil cp local.txt gs://my-bucket/
allow gcloud compute instances describe delete-me-vm
allow gcloud projects add-iam-policy-binding p --member=user:x --role=roles/viewer
```
