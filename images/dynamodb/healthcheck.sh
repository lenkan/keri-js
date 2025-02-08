#!/bin/bash

if [ "$(curl -s -o /dev/null -I -w ''%{http_code}'' http://localhost:8000)" == "400" ]; then
    exit 0;
else 
    exit 1;
fi
