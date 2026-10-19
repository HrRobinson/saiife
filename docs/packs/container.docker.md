# Container: docker (container.docker)

This pack stops Docker commands that destroy stored data or force-stop
running containers: removing volumes, a system clean-up that also removes
volumes, force-removing containers or images, and removing networks.
Everyday Docker work is never blocked.

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack container.docker`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["container.docker"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `docker system prune --volumes`. It also deletes unused volumes and the data
  in them.
- `docker volume rm` and `docker volume prune`. They delete the volume and all
  data stored in it.
- `docker rm -f` (also `docker container rm --force`). It removes a running
  container, and data not kept in a volume is lost.
- Force image removal (`docker rmi -f`, `docker image rm --force`). It deletes
  an image that containers still use.
- `docker network rm` and `docker network prune`. Running containers lose
  their network connection.

These rules also apply with global options before the subcommand
(`docker --context prod volume rm ...`) and through `sudo`.

## Allowed on purpose

- Everyday commands: `docker ps`, `build`, `run`, `logs`, `images`, `exec`,
  `start`, `stop`, `volume ls`, `network ls`, `system df`.
- `docker run --rm`. This removes the container when it exits, as intended.
- `docker system prune` without `--volumes`. It only clears caches and unused
  images, which can be rebuilt or pulled again.
- Plain `docker rm` of a stopped container and plain `docker rmi`. Docker
  refuses to remove an image that is in use.

## Not covered

- `docker compose down -v` (which removes volumes) is not judged.
- Deleting data inside a container (`docker exec db rm -rf /data`) is not
  judged by this pack.
- `docker stop` and `docker kill` are allowed.

## Examples

```saiife-examples
deny docker system prune -a --volumes
deny docker volume rm mydata
deny docker volume prune
deny docker rm -f web
deny docker rmi -f myimage
deny docker network rm frontend
deny docker --context prod volume rm data
allow docker ps
allow docker run --rm -it ubuntu bash
allow docker system prune
allow docker rm web
allow docker rmi myimage
```
