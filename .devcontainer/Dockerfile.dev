FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    USER=calitp

# create $USER and home directory
RUN useradd --create-home --shell /bin/bash $USER && \
    chown -R $USER /home/$USER && \
    # install tools for development
    apt-get update && apt-get install -y git

USER $USER

RUN python -m pip install --upgrade pip && \
    pip install pre-commit

# enter app directory
WORKDIR /home/$USER/app
