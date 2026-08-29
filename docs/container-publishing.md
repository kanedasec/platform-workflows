# Container publishing contract

The reusable container workflow builds one or more images from a caller
repository and publishes them to GHCR. It runs only for the caller's default
branch and authenticates with the workflow-scoped `GITHUB_TOKEN`.

Caller workflows must grant only `contents: read` and `packages: write`:

```yaml
name: Publish containers

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  packages: write

concurrency:
  group: publish-${{ github.ref }}
  cancel-in-progress: false

jobs:
  containers:
    uses: kanedasec/platform-workflows/.github/workflows/container-publish.yaml@WORKFLOW_COMMIT_SHA
    with:
      images: >-
        [
          {"name":"backend","context":"./backend","dockerfile":"./backend/Dockerfile"},
          {"name":"frontend","context":"./frontend","dockerfile":"./frontend/Dockerfile"}
        ]
```

For a repository named `sgp-manager`, this publishes:

- `ghcr.io/kanedasec/sgp-manager-backend:sha-<full-commit>`
- `ghcr.io/kanedasec/sgp-manager-frontend:sha-<full-commit>`
- a mutable `dev` convenience tag for each image

Deployment automation must use the immutable `sha-<full-commit>` tag, never the
`dev` tag. Both images share the same tag, linking them to one source revision.
The workflow also writes OCI source, revision, and version labels and records
the registry digest in the workflow summary.

GHCR package visibility is configured separately from repository visibility.
Keep packages private when the VPS has an appropriately scoped read credential,
or deliberately make them public when the source and distributable images are
intended to be public.
