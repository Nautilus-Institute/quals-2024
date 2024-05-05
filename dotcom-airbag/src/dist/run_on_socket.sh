#!/bin/bash
docker build -t dcq2023-airbag .

echo "Running on 0.0.0.0:8080"
socat tcp4-listen:8080,reuseaddr,fork 'exec:docker run --rm -i dcq2023-airbag'
