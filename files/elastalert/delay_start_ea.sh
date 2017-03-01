#!/bin/bash

EA_SERVICE=ElastAlert

while [ 1 ]; do
	service ${EA_SERVICE} status 2>&1 >/dev/null
	if [ $? -ne 0 ]; then
		while [ 1 ]; do
			curl 'http://localhost:9200/_cluster/health' 2>&1 >/dev/null
			[ $? -eq 0 ] && break
			sleep 10
		done
		service ${EA_SERVICE} start 2>&1 >/dev/null
	fi
	sleep 10
done


