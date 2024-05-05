#!/bin/bash
git clone --depth 1 --branch v0.14.0 https://github.com/urcu/userspace-rcu.git && cd userspace-rcu && ./bootstrap && ./configure && make && make install
git clone --depth 1 https://github.com/Tencent/rapidjson.git && cd rapidjson && cp -r include/rapidjson /usr/local/include
