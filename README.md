# Kubernetes-Harvester

## Overview
harvester.py is a fairly simple script that attempt to utilize the automountservicetoken or ~/.kube/config 
credentials to request all pod specs from kubernetes. 

The each pod spec's container(s) environment variables are then reviewed for key words which could indicate potential credentials.

The script then goes further to similar examine any configmaps loaded into a containers Env and also reviews the Env hardcoded with the image manifest.

Finally it checks to see if auth tokens for the main cloud providers can be requested via the metadata API.


## Basic Usage
usage: harvester.py [-h] [-v] [-w] [-o OUTFILE]

Try to gather potential creds from kubernetes

optional arguments:

  -h, --help            show this help message and exit
  
  -v, --verbose         Whether or not to display additional log information
  
  -w, --write           Whether to write a log file, can be used with -0 to
                        specify name/location
  
  -o OUTFILE, --outfile OUTFILE
                        The file to write results (needs to be writable for
                        current user)
                        
## TODO
* Enhance configmap code to include nested maps and function loads like container envFrom
* Review command history for other interesting files that might be embedded within the image