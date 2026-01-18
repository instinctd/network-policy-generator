#!/usr/bin/env python3

import json
import argparse
import sys
import re
import ipaddress
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
import subprocess

class HubbleCollector:

    DEFAULT_PORTS = {
        'rabbitmq': {'port': '5672', 'protocol': 'TCP'},
        'rabbitmq-management': {'port': '15672', 'protocol': 'TCP'},
        'redis': {'port': '6379', 'protocol': 'TCP'},
        'redis-sentinel': {'port': '26379', 'protocol': 'TCP'},
        'postgresql': {'port': '5432', 'protocol': 'TCP'},
        'postgres': {'port': '5432', 'protocol': 'TCP'},
        'vmagent': {'port': '8429', 'protocol': 'TCP'},
        'victoria-metrics': {'port': '8428', 'protocol': 'TCP'},
        'vmsingle': {'port': '8429', 'protocol': 'TCP'},
        'vmselect': {'port': '8481', 'protocol': 'TCP'},
        'vminsert': {'port': '8480', 'protocol': 'TCP'},
        'vmstorage': {'port': '8482', 'protocol': 'TCP'},
        'prometheus': {'port': '9090', 'protocol': 'TCP'},
        'alertmanager': {'port': '9093', 'protocol': 'TCP'},
        'grafana': {'port': '3000', 'protocol': 'TCP'},
        'kube-dns': {'port': '53', 'protocol': 'UDP'},
        'coredns': {'port': '53', 'protocol': 'UDP'},
    }

    def __init__(self, namespace: str, from_label: str = None, to_label: str = None, verdict: str = None,
                 pod_cidr: str = None, service_cidr: str = None):
        self.namespace = namespace
        self.from_label = from_label
        self.to_label = to_label
        self.verdict = verdict
        self.flows = []
        self.connections = defaultdict(lambda: defaultdict(int))
        self.pod_labels = {}
        self.flow_details = defaultdict(lambda: defaultdict(list))
        self.ip_to_pod = {}
        self.ip_to_namespace = {}
        self.ip_to_service = {}
        self.unresolved_ips = set()
        self.internal_networks = []

        if pod_cidr:
            try:
                self.internal_networks.append(ipaddress.ip_network(pod_cidr))
            except ValueError as e:
                print(f"Warning: invalid pod_cidr '{pod_cidr}': {e}")

        if service_cidr:
            try:
                self.internal_networks.append(ipaddress.ip_network(service_cidr))
            except ValueError as e:
                print(f"Warning: invalid service_cidr '{service_cidr}': {e}")

        if not self.internal_networks:
            self.internal_networks = [
                ipaddress.ip_network('10.39.0.0/16'),
                ipaddress.ip_network('10.40.0.0/16'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('100.64.0.0/10'),
            ]

        print(f"Загрузка Pod IP mappings из кластера...")
        self._fetch_all_pods_ips()
        print(f"Загрузка Service IP mappings из кластера...")
        self._fetch_all_services_ips()

    def collect_flows(self, duration: int = 60, follow: bool = False):
        cmd = [
            "hubble", "observe", "flows",
            "--namespace", self.namespace,
            "--output", "json",
        ]

        if self.from_label:
            cmd.extend(["--from-label", self.from_label])

        if self.to_label:
            cmd.extend(["--to-label", self.to_label])

        if self.verdict:
            cmd.extend(["--verdict", self.verdict.upper()])

        if not follow:
            cmd.extend(["--last", str(duration)])
        else:
            cmd.append("--follow")

        print(f"Запуск: {' '.join(cmd)}")

        try:
            if follow:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
                print(f"Мониторинг flows в namespace '{self.namespace}'...")

                for line in process.stdout:
                    if line.strip():
                        try:
                            flow = json.loads(line)
                            self.flows.append(flow)
                            self._process_flow(flow)
                        except json.JSONDecodeError:
                            continue
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            flow = json.loads(line)
                            self.flows.append(flow)
                            self._process_flow(flow)
                        except json.JSONDecodeError:
                            continue

        except subprocess.CalledProcessError as e:
            print(f"Ошибка: {e.stderr}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nОстановка...")

    def _process_flow(self, flow: Dict):
        try:
            if 'flow' not in flow:
                return

            flow_data = flow['flow']
            source = flow_data.get('source', {})
            destination = flow_data.get('destination', {})

            ip_info = flow_data.get('IP', {})
            source_ip = ip_info.get('source', 'unknown')
            dest_ip = ip_info.get('destination', 'unknown')

            source_ns = source.get('namespace', '')
            dest_ns = destination.get('namespace', '')

            if source_ns != self.namespace and dest_ns != self.namespace:
                return

            source_pod_name = source.get('pod_name')
            if source_pod_name and source_ns:
                source_labels = source.get('labels', [])
                if source_labels:
                    self.pod_labels[source_pod_name] = self._parse_labels(source_labels)
                if source_ip != 'unknown':
                    self.ip_to_pod[source_ip] = (source_pod_name, source_ns)

            dest_pod_name = destination.get('pod_name')
            if dest_pod_name and dest_ns:
                dest_labels = destination.get('labels', [])
                if dest_labels:
                    self.pod_labels[dest_pod_name] = self._parse_labels(dest_labels)
                if dest_ip != 'unknown':
                    self.ip_to_pod[dest_ip] = (dest_pod_name, dest_ns)

            source_pod = source.get('pod_name')
            if not source_pod:
                workloads = source.get('workloads', [])
                if workloads and isinstance(workloads, list) and len(workloads) > 0:
                    workload = workloads[0]
                    if isinstance(workload, dict):
                        workload_name = workload.get('name')
                        workload_kind = workload.get('kind', '')
                        if workload_name:
                            source_pod = f"{workload_name} ({workload_kind})"
                        else:
                            source_pod = f"{source_ip}"
                    else:
                        source_pod = f"{source_ip}"
                else:
                    source_labels = source.get('labels', [])
                    source_info = []
                    for label in source_labels:
                        if 'reserved:' in label:
                            source_info.append(label.replace('reserved:', ''))

                    if source_info:
                        source_pod = f"{source_ip} ({', '.join(source_info)})"
                    else:
                        source_pod = f"{source_ip}"

            dest_pod = destination.get('pod_name')
            dest_port = destination.get('port')
            l4_proto = flow_data.get('l4', {})
            protocol = list(l4_proto.keys())[0].upper() if l4_proto else 'unknown'

            if not dest_pod:
                dest_identity = destination.get('identity')
                dest_labels = []

                if isinstance(dest_identity, dict):
                    dest_labels = dest_identity.get('labels', [])
                elif isinstance(dest_identity, int):
                    dest_labels = destination.get('labels', [])

                workloads = destination.get('workloads', [])
                if workloads and isinstance(workloads, list) and len(workloads) > 0:
                    workload = workloads[0]
                    if isinstance(workload, dict):
                        workload_name = workload.get('name')
                        if workload_name:
                            dest_pod = workload_name

                if not dest_pod:
                    service_name = destination.get('service', {}).get('name') if isinstance(destination.get('service'), dict) else None
                    dest_ns_name = destination.get('namespace')

                    if not dest_port and l4_proto:
                        proto_data = list(l4_proto.values())[0] if l4_proto else {}
                        dest_port = proto_data.get('destination_port') if isinstance(proto_data, dict) else None

                    dest_info = []
                    for label in dest_labels:
                        if 'reserved:' in label:
                            dest_info.append(label.replace('reserved:', ''))
                        elif 'cidr:' in label:
                            dest_info.append(label.split('=')[1] if '=' in label else label)

                    if service_name and dest_ns_name:
                        dest_pod = f"{service_name}.{dest_ns_name}:{dest_port or '?'}/{protocol}"
                    elif service_name:
                        dest_pod = f"{service_name}:{dest_port or '?'}/{protocol}"
                    elif dest_info:
                        dest_pod = f"{dest_ip}:{dest_port or '?'}/{protocol} ({', '.join(dest_info)})"
                    elif dest_ip != 'unknown' and dest_port:
                        dest_pod = f"{dest_ip}:{dest_port}/{protocol}"
                    elif dest_ip != 'unknown':
                        dest_pod = f"{dest_ip}/{protocol}"
                    else:
                        dest_pod = f"unknown/{protocol}"
            elif dest_port:
                dest_pod = f"{dest_pod}:{dest_port}/{protocol}"

            if source_pod and dest_pod and source_pod != dest_pod:
                self.connections[source_pod][dest_pod] += 1

                flow_detail = {
                    'source_pod': source_pod_name,
                    'source_ns': source_ns,
                    'source_ip': source_ip,
                    'dest_pod': dest_pod_name,
                    'dest_ns': dest_ns,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'protocol': protocol.lower() if protocol != 'unknown' else None,
                    'source_labels': source.get('labels', []),
                    'dest_labels': destination.get('labels', [])
                }
                self.flow_details[source_pod][dest_pod].append(flow_detail)

        except Exception as e:
            print(f"  Error processing flow: {e}", file=sys.stderr)

    def _parse_labels(self, labels_list: List[str]) -> Dict[str, str]:
        labels = {}
        exclude_prefixes = [
            'io.cilium.',
            'io.kubernetes.pod.',
            'pod-template-hash',
            'controller-revision-hash',
            'statefulset.kubernetes.io/pod-name'
        ]

        for label in labels_list:
            if '=' in label and not label.startswith('reserved:'):
                key, value = label.split('=', 1)

                if key.startswith('k8s:'):
                    key = key[4:]

                if any(key.startswith(prefix) for prefix in exclude_prefixes):
                    continue

                if 'k8s.namespace.labels' in key:
                    continue

                if key in ['k8s.policy.cluster', 'k8s.policy.serviceaccount']:
                    continue

                if key.startswith('io.cilium.k8s.policy'):
                    continue

                if key == 'io.kubernetes.pod.namespace':
                    continue

                labels[key] = value

        return labels

    def _fetch_all_pods_ips(self):
        try:
            cmd = [
                "kubectl", "get", "pods",
                "--all-namespaces",
                "-o", "json"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)

            pods_loaded = 0
            pod_ips = []
            for item in data.get('items', []):
                pod_name = item['metadata']['name']
                pod_ns = item['metadata']['namespace']
                pod_ip = item['status'].get('podIP')
                labels_dict = item['metadata'].get('labels', {})

                if pod_ip:
                    self.ip_to_pod[pod_ip] = (pod_name, pod_ns)
                    self.ip_to_namespace[pod_ip] = pod_ns
                    pods_loaded += 1
                    pod_ips.append(pod_ip)

                    if pod_ns == self.namespace and labels_dict:
                        filtered_labels = self._filter_k8s_labels(labels_dict)
                        if filtered_labels:
                            self.pod_labels[pod_name] = filtered_labels

            print(f"  Загружено {pods_loaded} Pod IP mappings")

            if pod_ips and not any(net for net in self.internal_networks if str(net).startswith('10.39') or str(net).startswith('10.40')):
                self._auto_detect_pod_cidr(pod_ips)

        except subprocess.CalledProcessError as e:
            print(f"  Warning: не удалось получить Pod IPs через kubectl: {e.stderr}")
        except json.JSONDecodeError as e:
            print(f"  Warning: ошибка парсинга kubectl output: {e}")
        except Exception as e:
            print(f"  Warning: ошибка при получении Pod IPs: {e}")

    def _auto_detect_pod_cidr(self, pod_ips: List[str]):
        try:
            network_prefixes = defaultdict(int)
            for ip_str in pod_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    octets = ip_str.split('.')
                    if len(octets) == 4:
                        prefix = f"{octets[0]}.{octets[1]}.0.0/16"
                        network_prefixes[prefix] += 1
                except ValueError:
                    continue

            if network_prefixes:
                most_common_cidr = max(network_prefixes.items(), key=lambda x: x[1])[0]
                detected_network = ipaddress.ip_network(most_common_cidr)

                if detected_network not in self.internal_networks:
                    self.internal_networks.insert(0, detected_network)
                    print(f"  Auto-detected Pod CIDR: {most_common_cidr} ({network_prefixes[most_common_cidr]} pods)")

        except Exception as e:
            print(f"  Warning: не удалось auto-detect Pod CIDR: {e}")

    def _fetch_all_services_ips(self):
        try:
            cmd = [
                "kubectl", "get", "services",
                "--all-namespaces",
                "-o", "json"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)

            services_loaded = 0
            for item in data.get('items', []):
                service_name = item['metadata']['name']
                service_ns = item['metadata']['namespace']
                cluster_ip = item['spec'].get('clusterIP')

                if cluster_ip and cluster_ip != 'None':
                    self.ip_to_service[cluster_ip] = (service_name, service_ns)
                    self.ip_to_namespace[cluster_ip] = service_ns
                    services_loaded += 1

            print(f"  Загружено {services_loaded} Service IP mappings")

        except subprocess.CalledProcessError as e:
            print(f"  Warning: не удалось получить Service IPs через kubectl: {e.stderr}")
        except json.JSONDecodeError as e:
            print(f"  Warning: ошибка парсинга kubectl output: {e}")
        except Exception as e:
            print(f"  Warning: ошибка при получении Service IPs: {e}")

    def _filter_k8s_labels(self, labels_dict: Dict[str, str]) -> Dict[str, str]:
        exclude_prefixes = [
            'io.cilium.',
            'io.kubernetes.pod.',
            'pod-template-hash',
            'controller-revision-hash',
            'statefulset.kubernetes.io/pod-name'
        ]

        filtered = {}
        for key, value in labels_dict.items():
            if any(key.startswith(prefix) for prefix in exclude_prefixes):
                continue
            if 'k8s.namespace.labels' in key:
                continue
            if key in ['k8s.policy.cluster', 'k8s.policy.serviceaccount']:
                continue
            if key.startswith('io.cilium.k8s.policy'):
                continue
            if key == 'io.kubernetes.pod.namespace':
                continue

            filtered[key] = value

        return filtered

    def _resolve_ip_to_pod(self, ip: str) -> Optional[Tuple[str, str]]:
        if ip in self.ip_to_pod:
            return self.ip_to_pod[ip]

        if ip in self.unresolved_ips:
            return None

        if ip in self.ip_to_service:
            self.unresolved_ips.add(ip)
            return None

        try:
            cmd = [
                "kubectl", "get", "pods",
                "--all-namespaces",
                "-o", "json",
                "--field-selector", f"status.podIP={ip}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=3)
            data = json.loads(result.stdout)

            items = data.get('items', [])
            if items:
                pod_name = items[0]['metadata']['name']
                pod_ns = items[0]['metadata']['namespace']
                labels_dict = items[0]['metadata'].get('labels', {})

                self.ip_to_pod[ip] = (pod_name, pod_ns)
                self.ip_to_namespace[ip] = pod_ns

                if pod_ns == self.namespace and labels_dict:
                    filtered_labels = self._filter_k8s_labels(labels_dict)
                    if filtered_labels:
                        self.pod_labels[pod_name] = filtered_labels

                return (pod_name, pod_ns)
            else:
                self.unresolved_ips.add(ip)

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
            self.unresolved_ips.add(ip)

        return None

    def _is_external_ip(self, ip: str) -> bool:
        if ip == 'unknown':
            return False

        if ip in self.ip_to_pod or ip in self.ip_to_namespace:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_loopback:
                return False

            if ip_obj.is_link_local:
                return False

            if ip_obj.is_private:
                for network in self.internal_networks:
                    if ip_obj in network:
                        return False
                return False

            for network in self.internal_networks:
                if ip_obj in network:
                    return False

            return True

        except ValueError:
            return False

    def _get_default_port(self, labels: Dict[str, str]) -> Optional[Dict[str, str]]:
        if not labels:
            return None

        app_name = labels.get('app', '').lower()
        app_k8s_name = labels.get('app.kubernetes.io/name', '').lower()
        app_component = labels.get('app.kubernetes.io/component', '').lower()
        k8s_app = labels.get('k8s-app', '').lower()

        check_names = [app_name, app_k8s_name, app_component, k8s_app]

        for name in check_names:
            if name in self.DEFAULT_PORTS:
                return self.DEFAULT_PORTS[name]

        for name in check_names:
            for key in self.DEFAULT_PORTS.keys():
                if key in name or name in key:
                    return self.DEFAULT_PORTS[key]

        return None

    def export_to_json(self, filepath: str):
        data = {
            'namespace': self.namespace,
            'collected_at': datetime.utcnow().isoformat(),
            'total_flows': len(self.flows),
            'filters': {
                'from_label': self.from_label,
                'to_label': self.to_label,
                'verdict': self.verdict
            },
            'connections': []
        }

        for source in sorted(self.connections.keys()):
            destinations = self.connections[source]
            for dest in sorted(destinations.keys()):
                data['connections'].append({
                    'source': source,
                    'destination': dest,
                    'flows_count': destinations[dest]
                })

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Экспорт: {filepath}")

    def print_summary(self):
        print("\n" + "="*70)
        print(f"Namespace: {self.namespace}")
        if self.from_label:
            print(f"From Label: {self.from_label}")
        if self.to_label:
            print(f"To Label: {self.to_label}")
        if self.verdict:
            print(f"Verdict: {self.verdict}")
        print("="*70)
        print(f"Flows: {len(self.flows)}")

        total_connections = sum(len(destinations) for destinations in self.connections.values())
        print(f"Unique Connections: {total_connections}")
        print("\nNetwork Connections:")
        print("-"*70)

        for source in sorted(self.connections.keys()):
            destinations = self.connections[source]
            for dest in sorted(destinations.keys(), key=lambda x: destinations[x], reverse=True):
                count = destinations[dest]
                print(f"  {source:40} → {dest:40} ({count} flows)")

        print("="*70)

    def export_cilium_policies(self, output_dir: str):
        import os
        import yaml

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        policies_by_pod = defaultdict(lambda: {
            'egress': defaultdict(lambda: {'ports': set(), 'protocols': set()}),
            'ingress': defaultdict(lambda: {'ports': set(), 'protocols': set()})
        })

        for source_display, destinations in self.flow_details.items():
            for dest_display, flow_list in destinations.items():
                for flow in flow_list:
                    source_pod = flow.get('source_pod')
                    source_ns = flow.get('source_ns')
                    source_ip = flow.get('source_ip')
                    dest_pod = flow.get('dest_pod')
                    dest_ns = flow.get('dest_ns')
                    dest_ip = flow.get('dest_ip')
                    dest_port = flow.get('dest_port')
                    protocol = flow.get('protocol')

                    if source_pod and source_ns == self.namespace:
                        if dest_pod and dest_ns:
                            dest_key = f"pod:{dest_ns}/{dest_pod}"
                        elif dest_ns:
                            dest_key = f"ns:{dest_ns}"
                        elif dest_ip and dest_ip != 'unknown':
                            if dest_ip in self.ip_to_service:
                                service_name, service_ns = self.ip_to_service[dest_ip]
                                dest_key = f"ns:{service_ns}"
                            else:
                                pod_info = self._resolve_ip_to_pod(dest_ip)

                                if pod_info:
                                    dest_key = f"pod:{pod_info[1]}/{pod_info[0]}"
                                elif self._is_external_ip(dest_ip):
                                    dest_key = f"external:{dest_ip}"
                                elif dest_ip in self.ip_to_namespace:
                                    dest_key = f"ns:{self.ip_to_namespace[dest_ip]}"
                                else:
                                    print(f"  Warning: cannot resolve internal IP {dest_ip}:{dest_port} to pod - using toCIDR")
                                    dest_key = f"external:{dest_ip}"
                        else:
                            continue

                        if dest_port:
                            policies_by_pod[source_pod]['egress'][dest_key]['ports'].add(str(dest_port))
                        if protocol:
                            policies_by_pod[source_pod]['egress'][dest_key]['protocols'].add(protocol)

                    if dest_pod and dest_ns == self.namespace:
                        if source_pod and source_ns:
                            source_key = f"pod:{source_ns}/{source_pod}"
                        elif source_ns:
                            source_key = f"ns:{source_ns}"
                        elif source_ip and source_ip != 'unknown':
                            if source_ip in self.ip_to_service:
                                service_name, service_ns = self.ip_to_service[source_ip]
                                source_key = f"ns:{service_ns}"
                            else:
                                pod_info = self._resolve_ip_to_pod(source_ip)

                                if pod_info:
                                    source_key = f"pod:{pod_info[1]}/{pod_info[0]}"
                                elif self._is_external_ip(source_ip):
                                    source_key = f"external:{source_ip}"
                                elif source_ip in self.ip_to_namespace:
                                    source_key = f"ns:{self.ip_to_namespace[source_ip]}"
                                else:
                                    print(f"  Warning: cannot resolve internal source IP {source_ip} to pod - using fromCIDR")
                                    source_key = f"external:{source_ip}"
                        else:
                            continue

                        if dest_port:
                            policies_by_pod[dest_pod]['ingress'][source_key]['ports'].add(str(dest_port))
                        if protocol:
                            policies_by_pod[dest_pod]['ingress'][source_key]['protocols'].add(protocol)

        policy_files = []
        for pod_name, policy_data in policies_by_pod.items():
            pod_labels = self.pod_labels.get(pod_name, {})
            if not pod_labels:
                pod_labels = self._extract_labels_from_pod_name(pod_name)

            if not pod_labels:
                print(f"Skip pod '{pod_name}' - нет labels")
                continue

            if any(k.startswith('k8s:') or k.startswith('io.cilium') or k.startswith('io.kubernetes.pod')
                   for k in pod_labels.keys()):
                print(f"Warning: pod '{pod_name}' has invalid labels: {pod_labels}")

                pod_labels = {k: v for k, v in pod_labels.items()
                             if not k.startswith('k8s:')
                             and not k.startswith('io.cilium')
                             and not k.startswith('io.kubernetes.pod')}
                if not pod_labels:
                    print(f"Skip pod '{pod_name}' - все labels служебные")
                    continue
            policy = {
                'apiVersion': 'cilium.io/v2',
                'kind': 'CiliumNetworkPolicy',
                'metadata': {
                    'name': self._sanitize_name(pod_name),
                    'namespace': self.namespace
                },
                'spec': {
                    'endpointSelector': {
                        'matchLabels': pod_labels
                    },
                    'egress': []
                }
            }
            for dest_key, dest_info in policy_data['egress'].items():
                dest_type, dest_value = dest_key.split(':', 1)

                egress_rule = {}
                dest_pod_labels = {}

                if dest_type == 'pod':
                    dest_ns, dest_pod = dest_value.split('/', 1)
                    dest_pod_labels = self.pod_labels.get(dest_pod, {})

                    if dest_pod_labels:
                        egress_rule['toEndpoints'] = [{
                            'matchLabels': dict(dest_pod_labels)
                        }]
                    else:
                        egress_rule['toEndpoints'] = [{
                            'matchExpressions': [{
                                'key': 'io.kubernetes.pod.namespace',
                                'operator': 'In',
                                'values': [dest_ns]
                            }]
                        }]

                elif dest_type == 'ns':
                    egress_rule['toEndpoints'] = [{
                        'matchExpressions': [{
                            'key': 'io.kubernetes.pod.namespace',
                            'operator': 'In',
                            'values': [dest_value]
                        }]
                    }]

                elif dest_type == 'external':
                    egress_rule['toCIDR'] = [f"{dest_value}/32"]

                else:
                    continue

                if not dest_info['ports'] or not dest_info['protocols']:
                    default_port_info = self._get_default_port(dest_pod_labels)
                    if default_port_info:
                        dest_info['ports'].add(default_port_info['port'])
                        dest_info['protocols'].add(default_port_info['protocol'])
                        print(f"  Using default port {default_port_info['port']}/{default_port_info['protocol']} for {dest_key}")

                if dest_info['ports'] and dest_info['protocols']:
                    egress_rule['toPorts'] = []
                    protocols_list = list(dest_info['protocols'])

                    for protocol in protocols_list:
                        port_rule = {'protocol': protocol.upper()}
                        port_rule['ports'] = [{'port': port} for port in sorted(dest_info['ports'])]
                        egress_rule['toPorts'].append(port_rule)

                if egress_rule and (dest_info['ports'] or 'toCIDR' in egress_rule):
                    policy['spec']['egress'].append(egress_rule)

            if policy_data['ingress']:
                policy['spec']['ingress'] = []

                for source_key, source_info in policy_data['ingress'].items():
                    source_type, source_value = source_key.split(':', 1)

                    ingress_rule = {}
                    source_pod_labels = {}

                    if source_type == 'pod':
                        source_ns, source_pod = source_value.split('/', 1)
                        source_pod_labels = self.pod_labels.get(source_pod, {})

                        if source_pod_labels:
                            ingress_rule['fromEndpoints'] = [{
                                'matchLabels': dict(source_pod_labels)
                            }]
                        else:
                            ingress_rule['fromEndpoints'] = [{
                                'matchExpressions': [{
                                    'key': 'io.kubernetes.pod.namespace',
                                    'operator': 'In',
                                    'values': [source_ns]
                                }]
                            }]

                    elif source_type == 'ns':
                        ingress_rule['fromEndpoints'] = [{
                            'matchExpressions': [{
                                'key': 'io.kubernetes.pod.namespace',
                                'operator': 'In',
                                'values': [source_value]
                            }]
                        }]

                    elif source_type == 'external':
                        ingress_rule['fromCIDR'] = [f"{source_value}/32"]

                    else:
                        continue

                    if not source_info['ports'] or not source_info['protocols']:
                        default_port_info = self._get_default_port(source_pod_labels)
                        if default_port_info:
                            source_info['ports'].add(default_port_info['port'])
                            source_info['protocols'].add(default_port_info['protocol'])
                            print(f"  Using default port {default_port_info['port']}/{default_port_info['protocol']} for ingress from {source_key}")

                    if source_info['ports'] and source_info['protocols']:
                        ingress_rule['toPorts'] = []
                        protocols_list = list(source_info['protocols'])

                        for protocol in protocols_list:
                            port_rule = {'protocol': protocol.upper()}
                            port_rule['ports'] = [{'port': port} for port in sorted(source_info['ports'])]
                            ingress_rule['toPorts'].append(port_rule)

                    if ingress_rule and (source_info['ports'] or 'fromCIDR' in ingress_rule):
                        policy['spec']['ingress'].append(ingress_rule)

            has_dns_rule = any(
                'toEndpoints' in rule and
                any(
                    ep.get('matchLabels', {}).get('k8s-app') == 'kube-dns' or
                    ep.get('matchLabels', {}).get('k8s-app') == 'coredns'
                    for ep in rule.get('toEndpoints', [])
                )
                for rule in policy['spec']['egress']
            )

            if not has_dns_rule:
                dns_rule = {
                    'toEndpoints': [{
                        'matchLabels': {
                            'io.kubernetes.pod.namespace': 'kube-system',
                            'k8s-app': 'kube-dns'
                        }
                    }],
                    'toPorts': [{
                        'protocol': 'UDP',
                        'ports': [{'port': '53'}]
                    }]
                }
                policy['spec']['egress'].append(dns_rule)

            is_valid, error = self._validate_policy(policy)
            if not is_valid:
                print(f"ОШИБКА валидации политики '{pod_name}': {error}")
                print(f"Политика пропущена. Проверь flows для этого пода.")
                continue

            filename = f"{self._sanitize_name(pod_name)}-cnp.yaml"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'w') as f:
                yaml.dump(policy, f, default_flow_style=False, sort_keys=False)

            policy_files.append(filepath)

            egress_count = len(policy['spec'].get('egress', []))
            ingress_count = len(policy['spec'].get('ingress', []))
            print(f"Создана политика: {filepath} (egress: {egress_count} rules, ingress: {ingress_count} rules)")

        return policy_files

    def _sanitize_name(self, name: str) -> str:
        name = re.sub(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', '', name)
        name = re.sub(r'-[a-f0-9]{9,10}$', '', name)

        name = re.sub(r'[^a-z0-9-]', '-', name.lower())
        name = re.sub(r'-+', '-', name)
        name = name.strip('-')

        if len(name) > 63:
            name = name[:63].rstrip('-')

        return name

    def _extract_labels_from_pod_name(self, pod_name: str) -> Dict[str, str]:
        base_name = re.sub(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', '', pod_name)
        base_name = re.sub(r'-[a-f0-9]{9,10}$', '', base_name)
        base_name = re.sub(r'-\d+$', '', base_name)

        if base_name and base_name != pod_name:
            return {'app': base_name}

        return {}

    def _validate_policy(self, policy: Dict) -> Tuple[bool, Optional[str]]:
        if 'spec' not in policy:
            return False, "Missing 'spec' field"

        spec = policy['spec']

        if 'endpointSelector' not in spec:
            return False, "Missing endpointSelector"

        endpoint_selector = spec['endpointSelector']
        if 'matchLabels' not in endpoint_selector and 'matchExpressions' not in endpoint_selector:
            return False, "endpointSelector must have matchLabels or matchExpressions"

        for idx, rule in enumerate(spec.get('egress', [])):
            if 'toEntities' in rule and 'toPorts' in rule:
                return False, f"Egress rule #{idx}: toEntities cannot be used with toPorts"

            if 'toEndpoints' in rule:
                for ep_idx, endpoint in enumerate(rule['toEndpoints']):
                    if not isinstance(endpoint, dict):
                        return False, f"Egress rule #{idx}, endpoint #{ep_idx}: must be dict"

                    if 'matchLabels' not in endpoint and 'matchExpressions' not in endpoint:
                        return False, f"Egress rule #{idx}, endpoint #{ep_idx}: need matchLabels or matchExpressions"

                    if 'matchLabels' in endpoint:
                        for key in endpoint['matchLabels'].keys():
                            if key.startswith('k8s:'):
                                return False, f"Egress rule #{idx}: invalid label key '{key}' with 'k8s:' prefix"

            if 'matchExpressions' in rule.get('toEndpoints', [{}])[0]:
                for expr in rule['toEndpoints'][0]['matchExpressions']:
                    if 'key' in expr and expr['key'].startswith('k8s:'):
                        return False, f"Egress rule #{idx}: invalid expression key '{expr['key']}'"

        for idx, rule in enumerate(spec.get('ingress', [])):
            if 'toEntities' in rule and 'toPorts' in rule:
                return False, f"Ingress rule #{idx}: toEntities cannot be used with toPorts"

            if 'fromEndpoints' in rule:
                for ep_idx, endpoint in enumerate(rule['fromEndpoints']):
                    if not isinstance(endpoint, dict):
                        return False, f"Ingress rule #{idx}, endpoint #{ep_idx}: must be dict"

                    if 'matchLabels' not in endpoint and 'matchExpressions' not in endpoint:
                        return False, f"Ingress rule #{idx}, endpoint #{ep_idx}: need matchLabels or matchExpressions"

                    if 'matchLabels' in endpoint:
                        for key in endpoint['matchLabels'].keys():
                            if key.startswith('k8s:'):
                                return False, f"Ingress rule #{idx}: invalid label key '{key}' with 'k8s:' prefix"

            if 'matchExpressions' in rule.get('fromEndpoints', [{}])[0]:
                for expr in rule['fromEndpoints'][0]['matchExpressions']:
                    if 'key' in expr and expr['key'].startswith('k8s:'):
                        return False, f"Ingress rule #{idx}: invalid expression key '{expr['key']}'"

        return True, None

def main():
    parser = argparse.ArgumentParser(description="Сбор flows из Hubble и генерация CiliumNetworkPolicy")
    parser.add_argument('-n', '--namespace', required=True, help='Namespace')
    parser.add_argument('-o', '--output', required=True, help='Выходной JSON файл')
    parser.add_argument('--follow', action='store_true', help='Режим follow')
    parser.add_argument('--duration', type=int, default=60, help='Секунд (default: 60)')
    parser.add_argument('--from-label', dest='from_label', help='Фильтр по source label')
    parser.add_argument('--to-label', dest='to_label', help='Фильтр по destination label')
    parser.add_argument('--verdict', choices=['FORWARDED', 'DROPPED', 'ERROR', 'AUDIT', 'REDIRECTED', 'TRACED'],
                       help='Фильтр по verdict')
    parser.add_argument('--debug-flows', dest='debug_flows', help='Сохранить raw flows')
    parser.add_argument('--cilium', choices=['true', 'false'], default='false',
                       help='Создать CiliumNetworkPolicy (default: false)')
    parser.add_argument('--cilium-output-dir', dest='cilium_output_dir', default='./cilium-policies',
                       help='Директория для политик (default: ./cilium-policies)')
    parser.add_argument('--pod-cidr', dest='pod_cidr',
                       help='Pod CIDR (например: 10.244.0.0/16)')
    parser.add_argument('--service-cidr', dest='service_cidr',
                       help='Service CIDR (например: 10.96.0.0/12)')

    args = parser.parse_args()

    collector = HubbleCollector(
        namespace=args.namespace,
        from_label=args.from_label,
        to_label=args.to_label,
        verdict=args.verdict,
        pod_cidr=args.pod_cidr,
        service_cidr=args.service_cidr
    )

    print(f"Сбор flows из: {args.namespace}")
    if args.from_label:
        print(f"   From Label: {args.from_label}")
    if args.to_label:
        print(f"   To Label: {args.to_label}")
    if args.verdict:
        print(f"   Verdict: {args.verdict}")

    collector.collect_flows(duration=args.duration, follow=args.follow)
    collector.print_summary()
    collector.export_to_json(args.output)

    if args.cilium == 'true':
        print(f"\nГенерация CiliumNetworkPolicy...")
        try:
            policy_files = collector.export_cilium_policies(args.cilium_output_dir)
            print(f"\nСоздано {len(policy_files)} файлов политик в '{args.cilium_output_dir}'")
        except ImportError:
            print("\nТребуется PyYAML для генерации политик")
            print("   Установка: pip install pyyaml")
        except Exception as e:
            print(f"\nОшибка создания политик: {e}", file=sys.stderr)

    if args.debug_flows:
        with open(args.debug_flows, 'w') as f:
            json.dump(collector.flows, f, indent=2)
        print(f"Debug flows: {args.debug_flows}")

    print(f"\nВсего flows: {len(collector.flows)}")

if __name__ == '__main__':
    main()
