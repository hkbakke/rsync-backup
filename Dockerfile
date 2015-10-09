FROM debian:latest

RUN apt-get update && apt-get install -y \
    openssh-client \
    rsync \
    python3

ENTRYPOINT ["/root/rsync-backup/backup.py"]
