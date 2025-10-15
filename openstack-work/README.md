# Honeypot Digital Twin

## Local development setup

**Recommendation**
- Use Linux, WSL2 or Virtual Machine(Linux).
- When using WSL2 add repo inside Ubuntu connect to WSL2 with Visual Studio Code.
- Run docker commands inside WSL2 or Virtual Machine(Linux) terminal

---

**First time setup**

1. Clone repo: `git clone https://github.com/iairu/dp.git`
2. `cd openstack-work`
3. Force Windows Git to not be CRLF but LF for Docker Shell Scripts to work: `echo "core.autocrlf=false" >> .git/config ; git rm --cached -r . ; git reset --hard`
4. Go to a non-production branch where you will develop: `git checkout -b dev`
5. Set environment variables for all Docker services: `cp .env.example .env` + FILL IN THE BLANK VARIABLES WITH RANDOM VALUES
6. Just in case: Stop and remove all remaining Docker containers and networks prefixed with "twin-": `docker stop $(docker ps -a -q -f name=twin-) ; docker rm -f $(docker ps -a -q -f name=twin-) ; docker network rm $(docker network ls -q -f name=twin_)`
7. Start the service chain: `docker compose up -d` in the root directory (`-d` for detached mode)
8. Wait for `nginx` service to be up and running (last in chain)
9. Work within container if applicable: `docker exec -it twin-servicename-1 /bin/bash`

---

Often used: **Restart** after minor config changes, inconsistencies or computer reboot:
- Turn off: `docker compose down`
- Stop and remove all remaining Docker containers and networks prefixed with "twin-": `docker stop $(docker ps -a -q -f name=twin-) ; docker rm -f $(docker ps -a -q -f name=twin-) ; docker network rm $(docker network ls -q -f name=twin_)`
- Turn on again: `docker compose --profile dev up -d`

**Here it is in one line** (you may be copy-pasting this a lot, recommended to add to .bashrc as an alias):
```bash
docker compose down ; docker stop $(docker ps -a -q -f name=twin-) ; docker rm -f $(docker ps -a -q -f name=twin-) ; docker network rm $(docker network ls -q -f name=twin_) ; docker compose --profile dev up -d
```

---

Also often used: **Rebuild** after major changes:
- Turn off: `docker compose down`
- Stop and remove all remaining Docker containers and networks prefixed with "twin-": `docker stop $(docker ps -a -q -f name=twin-) ; docker rm -f $(docker ps -a -q -f name=twin-) ; docker network rm $(docker network ls -q -f name=twin_)`
- Important step - Rebuild without cache: `docker compose build --no-cache`
- Turn on: `docker compose --profile dev up -d`

**Here it is in one line** (you may be copy-pasting this a lot, recommended to add to .bashrc as an alias):
```bash
docker compose down ; docker stop $(docker ps -a -q -f name=twin-) ; docker rm -f $(docker ps -a -q -f name=twin-) ; docker network rm $(docker network ls -q -f name=twin_) ; docker compose build --no-cache ; docker compose --profile dev up -d
```

Also useful if you're only changing **nginx** configuration (`nginx.template.conf`) locally may be this selective restart:
```bash
docker compose -p twin stop nginx_reverse_proxy && docker compose -p twin build nginx_reverse_proxy && docker compose -p twin build nginx-dev-reconfig && docker compose -p twin up -d nginx-dev-reconfig && docker compose -p twin up -d nginx_reverse_proxy
```

---

If **broken**: Purge all containers and images (**WARNING**: this will remove **!!!ALL!!!** containers on your machine):
- Stop and remove Docker containers then remove Docker images: `docker stop $(docker ps -a -q) ; docker rm -f $(docker ps -a -q) ; docker rmi $(docker images -q)`
- Afterwards remove all Docker volumes and Docker networks: `docker system prune -a --volumes --force`
- Start again from docker-compose.yml like fresh install: `docker compose --profile dev up -d`

For debugging:
- `docker container ls -a` to get container names and ids
- `docker compose logs -f` to see logs or `docker logs container_id_goes_here`
- `docker exec -it <container-name> /bin/bash` to get bash in the container, if no such command then try `/bin/sh` instead
