# Patchline deploy automation

After Patchline merges a remediation PR it runs `deploy.yml`. The playbook builds the
service image, replaces its container on the local Podman machine, checks `/healthz`,
and rolls back to the previous image if the new one does not come up.

## One-time setup

```sh
cd ansible
ansible-galaxy collection install -r requirements.yml -p collections   # containers.podman
podman machine start                                                    # if not running
```

`ansible.cfg` points `collections_path` at `./collections` and `inventory` at
`inventory.ini`, which targets `localhost` with the local connection and the Python
interpreter that Homebrew's Ansible uses. If Ansible is upgraded, fix that path with
`head -1 $(which ansible-playbook)`.

## Running a deploy manually

Pass extra vars as **JSON**. Checkouts on macOS often sit under paths with spaces
(`~/Library/Application Support/...`), and `-e key=value` splits on whitespace.

```sh
cd ansible
ansible-playbook deploy.yml -e '{
  "service":    "supplier-portal",
  "source_dir": "/abs/path/to/demo/services/supplier-portal",
  "port":       8082,
  "git_sha":    "3f2c1ab"
}'
```

From any other directory, set `ANSIBLE_CONFIG=/abs/path/to/ansible/ansible.cfg`.
Without it, Ansible will not find the inventory or collections.

| Var | Required | Meaning |
|---|---|---|
| `service` | yes | Container name and image repo suffix: `localhost/patchline/<service>:<git_sha>` |
| `source_dir` | yes | Absolute path to a directory with a `Containerfile` |
| `port` | yes | Host port published to the container's 8080 |
| `git_sha` | yes | Image tag. Use a unique value per deploy, because rollback goes to whatever image was running before. |
| `health_path` | no | Default `/healthz` |
| `health_retries` / `health_delay` | no | Default 15 tries, 2 s apart |
| `container_port` | no | Default 8080. Also passed to the container as `PORT` |
| `result_file` | no | Also writes the result JSON (unescaped) to this path |

## What it does

1. Records the image of the running `<service>` container, if one exists, as the rollback target.
2. Builds `localhost/patchline/<service>:<git_sha>` with `containers.podman.podman_image`.
3. Recreates container `<service>` with `restart_policy: always` and `-p <port>:8080`.
4. Polls `http://localhost:<port>/healthz` until it returns 200.
5. On failure (`block`/`rescue`):
   - **Build failed:** the running container is untouched. Status `build_failed`.
   - **Health check failed:** prints the container's last log lines, recreates the
     container from the previous image, and health-checks it. Status `rolled_back`.
     If there was no previous image, it removes the broken container and the status is
     `failed_no_previous`. If the restored image also fails, the status is `rollback_failed`.
6. Always prints a single line:

```
"msg": "PATCHLINE_RESULT={\"status\":\"healthy\",\"service\":\"supplier-portal\",\"image\":\"localhost/patchline/supplier-portal:3f2c1ab\",\"previous\":\"localhost/patchline/supplier-portal:9e8d7c6\",\"port\":8082,\"git_sha\":\"3f2c1ab\",\"health_url\":\"http://localhost:8082/healthz\",\"error\":null}"
```

The default callback prints `msg` as a JSON string. To parse it, match
`"msg": ("PATCHLINE_RESULT=.*")$`, `JSON.parse` the captured string literal, strip the
prefix, then `JSON.parse` again. The simpler option is to pass `result_file` and read that.

Exit code: `0` only when `status` is `healthy`. A `rolled_back` deploy exits non-zero,
even though the service is still serving the previous version.

## Useful checks

```sh
podman ps --format '{{.Names}} {{.Image}} {{.Status}} {{.Ports}}'
curl -s localhost:8081/healthz   # telemetry-ingest
curl -s localhost:8082/healthz   # supplier-portal
podman logs --tail 50 <service>
```
