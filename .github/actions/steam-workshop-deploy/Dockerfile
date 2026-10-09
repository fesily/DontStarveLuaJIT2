FROM steamcmd/steamcmd:ubuntu-22
COPY steam_deploy.sh /root/steam_deploy.sh
COPY .deployignore /root/.defaultdeployignore
# fork addition: a Windows-authored checkout can materialise steam_deploy.sh without the
# executable bit (git blob 100644 → 644 on the Linux runner), which makes the container
# fail with 'exec: "/root/steam_deploy.sh": permission denied'. Set it explicitly.
RUN chmod +x /root/steam_deploy.sh
RUN apt-get update && apt-get install -y rsync
ENTRYPOINT ["/root/steam_deploy.sh"]
