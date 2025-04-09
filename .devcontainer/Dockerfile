FROM python:3.12

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    USER=calitp

# create $USER and home directory
RUN useradd --create-home --shell /bin/bash $USER && \
    chown -R $USER /home/$USER

# switch to non-root $USER
USER $USER

# update PATH for local pip installs
ENV PATH "$PATH:/home/$USER/.local/bin"

RUN python -m pip install --upgrade pip

# enter src directory
WORKDIR /home/$USER/src

# install docs tooling:
COPY docs/requirements.txt docs/requirements.txt
RUN pip install --no-cache-dir -r docs/requirements.txt

# install python dependencies
COPY eligibility_api eligibility_api
COPY pyproject.toml pyproject.toml
RUN pip install -e .[dev,test]

# install pre-commit environments in throwaway Git repository
# https://stackoverflow.com/a/68758943
COPY .pre-commit-config.yaml .
RUN git init . && \
    pre-commit install-hooks && \
    rm -rf .git

CMD ["sleep", "infinity"]
