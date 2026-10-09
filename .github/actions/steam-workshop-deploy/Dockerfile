FROM steamcmd/steamcmd:ubuntu-22
COPY steam_deploy.sh /root/steam_deploy.sh
COPY .deployignore /root/.defaultdeployignore
RUN apt-get update && apt-get install -y rsync
ENTRYPOINT ["/root/steam_deploy.sh"]
