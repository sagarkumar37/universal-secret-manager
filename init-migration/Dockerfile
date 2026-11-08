FROM postgres:16-alpine
COPY migrations /migrations
COPY migrate.sh /migrate.sh
RUN chmod +x /migrate.sh
USER postgres
ENTRYPOINT ["/migrate.sh"]
