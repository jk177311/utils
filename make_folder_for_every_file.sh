#!/bin/bash

for x in ./*.txt; do
  mkdir "${x%.*}" && mv "$x" "${x%.*}"
done
