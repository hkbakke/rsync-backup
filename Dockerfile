FROM debian:latest

RUN apt-get update && apt-get install -y \
    openssh-client \
    rsync \
    python3

COPY . /root/rsync-backup

ENTRYPOINT ["/root/rsync-backup/backup.py"]
CMD ["--help"]
