#!/usr/bin/python

import os
from kubernetes import client, config

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
                print('Your context does not contain a namespace, add a new contest or edit ~/.kube/config')
        self.core_client = client.CoreV1Api()
        self.all_pods = self.core_client.list_pod_for_all_namespaces()
    def get_pod_data_for_all_namespaces(self):
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
                        image_version = 'UNDECLARED'
                except ValueError:
                    continue
                tmp_pod_env[container.name] = ({'name': container.name, 'env': tmp_env, 'image': image_name + ":" + image_version})
            pod_map[pod.metadata.name] = {"namespace": pod.metadata.namespace, "containers": tmp_pod_env}
        return pod_map

if __name__ == '__main__':
    new_harvester = harvester()
    pod_map = new_harvester.get_pod_data_for_all_namespaces()