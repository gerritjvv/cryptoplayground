#!/usr/bin/env bash


### This scripts redirects commands back to the parent directory build

dir=$(cd -P -- "$(dirname -- "$)")" && pwd -P)


"$dir"/../build.sh $@