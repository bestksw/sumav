FROM python:3.8.13
ENV INTERSECTION_RATIO, WAIT_FOR_RECONNECTION, WORKER_CONCURRENCY
ENV PSQL_HOST, PSQL_PORT, PSQL_DB, PSQL_USER, PSQL_PASSWORD

# Install postgresql clients which are used in sumav
RUN apt update && apt install -y postgresql-client gridsite-clients

# Install sumav
COPY dist/sumav-1.0.1-py3-none-any.whl .
RUN pip install sumav-1.0.1-py3-none-any.whl

CMD ["sh", "-c", "tail -f /dev/null"]
