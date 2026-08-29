# Tailscale SSH deployment contract

The deployment action joins the Tailnet as an ephemeral
`tag:github-deploy` node, invokes one forced SSH deployment command, and checks
the application's public HTTPS origin and readiness endpoint.

The caller job must bind directly to its protected GitHub environment. Secrets
stored in `platform-workflows` are intentionally not used by cross-repository
callers.

```yaml
  deploy:
    name: Development deployment
    needs: containers
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    environment:
      name: development
    permissions:
      contents: read
    steps:
      - name: Deploy immutable containers
        uses: kanedasec/platform-workflows/actions/tailscale-ssh-deploy@WORKFLOW_COMMIT_SHA
        with:
          oauth_client_id: ${{ secrets.TS_OAUTH_CLIENT_ID }}
          oauth_secret: ${{ secrets.TS_OAUTH_SECRET }}
          ssh_private_key: ${{ secrets.DEPLOY_SSH_PRIVATE_KEY }}
          target_host: ${{ vars.DEPLOY_HOST }}
          target_user: ${{ vars.DEPLOY_USER }}
          known_hosts: ${{ vars.DEPLOY_KNOWN_HOSTS }}
          deploy_command: ${{ vars.DEPLOY_COMMAND }}
          image_tag: sha-${{ github.sha }}
          public_url: ${{ vars.DEPLOY_URL }}
          root_expected_status: "200"
          readiness_path: /ready
```

Required environment secrets:

- `TS_OAUTH_CLIENT_ID`
- `TS_OAUTH_SECRET`
- `DEPLOY_SSH_PRIVATE_KEY`

Required environment variables:

- `DEPLOY_HOST`: a Tailscale IPv4 address inside `100.64.0.0/10`
- `DEPLOY_USER`: the restricted Unix account
- `DEPLOY_KNOWN_HOSTS`: a trusted, pinned SSH host key entry
- `DEPLOY_COMMAND`: a forced command name without arguments
- `DEPLOY_URL`: an HTTPS origin without a path

The action requires an exact `200` from the readiness path. The root defaults
to `200`, but an application that deliberately protects `/` may set
`root_expected_status: "401"` or `"403"`. This verifies that the protected
route is reachable without copying application credentials into GitHub. Other
client and server error statuses are rejected as configuration errors.

The Tailscale OAuth client must have only writable auth-key scope and must be
restricted to `tag:github-deploy`. Tailnet policy must grant that tag only
TCP/22 to the deployment target.

The SSH private key is written only beneath the ephemeral runner's temporary
directory with mode `0600` and removed in an `always()` cleanup step. Strict
host-key checking, public-key-only authentication, and batch mode are required.

The action accepts only an image tag shaped as `sha-` followed by a full
lowercase 40-character Git commit SHA. The server-side deployment script must
independently validate the same contract and must remain root-owned.
