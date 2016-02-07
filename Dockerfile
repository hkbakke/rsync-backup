FROM debian:latest

RUN apt-get update && apt-get install -y \
    openssh-client \
    rsync \
    python3 \
    python3-pip \
    python3-dev

RUN pip3 install scandir

COPY . /root/rsync-backup

ENTRYPOINT ["/root/rsync-backup/backup.py"]
CMD ["--help"]
