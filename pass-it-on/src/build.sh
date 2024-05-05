#!/bin/bash
set -e

swiftc -O -gnone -Xfrontend -disable-reflection-metadata -Xfrontend -internalize-at-link -Xfrontend -reflection-metadata-for-debugger-only -Xlinker -x main.swift
strip main
