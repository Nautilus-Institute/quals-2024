#!/bin/bash
docker build -t dcq2023-npc-ua .

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <./flag.txt> <./private_key.pem> <./public_key.pem>"
    exit 1
fi

FLAG=$(realpath $1)
PRIVATE=$(realpath $2)
PUBLIC=$(realpath $3)

echo "Running on 0.0.0.0:8080"
socat tcp4-listen:8080,reuseaddr,fork "exec:docker \
    run --rm 
    -v $FLAG:/flag.txt \
    -v $PRIVATE:/opt/private.ec.pem \
    -v $PUBLIC:/opt/public.ec.pem \
    -i dcq2023-npc-ua"
