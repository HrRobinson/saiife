//! Golden corpus for `container.docker` (opt-in — must be enabled explicitly).
//!
//! Precision is the whole point: the routine verbs an agent runs constantly
//! (`ps`/`build`/`run`/`logs`) and resource NAMES that merely contain "delete"
//! must pass, while genuinely irreversible operations (volume removal, forced
//! removal, prune-with-volumes) must block.

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::profile::select_active;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["container.docker".to_string()]))
}

fn deny(e: &Engine, cmd: &str) -> String {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => pack,
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn denies_destructive_docker_commands() {
    let e = engine();
    let cases = [
        // system prune that also wipes volumes
        "docker system prune -a --volumes",
        "docker system prune --volumes",
        "docker system prune --all --volumes --force",
        // volume removal
        "docker volume rm mydata",
        "docker volume remove mydata",
        "docker volume prune",
        "docker volume prune -f",
        // force container removal (running)
        "docker rm -f web",
        "docker rm --force web",
        "docker rm -fv web",
        "docker rm -vf web",
        "docker container rm -f web",
        "docker rm web -f", // flag after the name
        // force image removal
        "docker rmi -f myimage",
        "docker rmi --force myimage",
        "docker image rm -f myimage",
        "docker image remove --force myimage",
        // network removal
        "docker network rm frontend",
        "docker network remove frontend",
        "docker network prune",
        // global option before the subcommand (separate + attached value)
        "docker --context prod volume rm data",
        "docker -H unix:///var/run/docker.sock rm -f web",
        "docker --host=tcp://1.2.3.4:2375 volume prune",
        // sudo-wrapped (wrapper peeled before matching)
        "sudo docker volume rm data",
        "sudo docker rm -f web",
        // chained after a benign command
        "cd infra && docker volume rm data",
    ];
    for cmd in cases {
        assert_eq!(deny(&e, cmd), "container.docker", "for {cmd:?}");
    }
}

#[test]
fn allows_safe_docker_commands() {
    let e = engine();
    let allow = [
        // routine read/build/run verbs
        "docker ps",
        "docker ps -a",
        "docker build -t app .",
        "docker run --rm -it ubuntu bash", // --rm is a run flag, not `rm`
        "docker run -d --name web nginx",
        "docker logs web",
        "docker images",
        "docker exec -it web sh",
        "docker start web",
        "docker stop web",
        "docker volume ls",
        "docker volume inspect data",
        "docker network ls",
        "docker network inspect frontend",
        "docker network create frontend",
        "docker system df",
        // bare prune WITHOUT --volumes only reclaims recoverable cache/images
        "docker system prune",
        "docker system prune -a",
        // plain (non-force) container/image removal is routine cleanup
        "docker rm web",
        "docker container rm web",
        "docker rmi myimage",
        // "delete"/"drop" only in a NAME, never the operation
        "docker run --name delete-me nginx",
        "docker logs delete-me",
        "docker ps --filter name=drop-me",
        "docker start delete-me",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}
