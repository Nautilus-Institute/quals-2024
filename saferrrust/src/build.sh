#!/bin/bash

rm error.log; rm -r target; rm savefile1 savefile2 savefile3
rm ../bin/saferrrust

touch error.log;

RUSTFLAGS="-A warnings" cargo build;

rm saferrrust;
strip -s target/debug/rustdefcon
cp target/debug/rustdefcon ./saferrrust

cp ./saferrrust ../bin/


rm ../solver/solver.py
cp solver.py ../solver/
