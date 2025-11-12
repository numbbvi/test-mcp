# Bomtori

## Docker로 실행하기

```bash
docker build -t bomtori .

docker run --rm \
  -v "$(pwd)/output:/app/output" \
  bomtori \
  https://github.com/makenotion/notion-mcp-server.git \
  --output-dir ./output
```