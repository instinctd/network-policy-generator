#!/usr/bin/env python3
"""
Hubble Network Flow Collector
Собирает сетевые взаимодействия между подами через Hubble CLI
и генерирует CiliumNetworkPolicy на основе реального трафика

Примеры использования:
    # Базовый сбор flows
    python3 hubble-collector.py -n production -o flows.json

    # Генерация CiliumNetworkPolicy
    python3 hubble-collector.py -n production -o flows.json \
        --cilium true --cilium-output-dir ./policies

    # С фильтрацией по приложению
    python3 hubble-collector.py -n production -o flows.json \
        --from-label "app=backend-api" \
        --cilium true

Зависимости:
    - hubble CLI (должен быть установлен)
    - PyYAML (для генерации CiliumNetworkPolicy): pip install pyyaml
"""

import json
import argparse
import sys
import re
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Tuple
import subprocess


class HubbleCollector:
    """Сборщик сетевых flows из Hubble"""
    
    def __init__(self, namespace: str, from_label: str = None, to_label: str = None, verdict: str = None):
        self.namespace = namespace
        self.from_label = from_label
        self.to_label = to_label
        self.verdict = verdict
        self.flows = []
        self.connections = defaultdict(lambda: defaultdict(int))  # source -> {destination: count}
        self.pod_labels = {}  # pod_name -> labels dict
        self.flow_details = defaultdict(lambda: defaultdict(list))  # source -> {destination: [flow_details]}
        self.ip_to_pod = {}  # ip -> (pod_name, namespace) маппинг для определения подов по IP
        
    def collect_flows(self, duration: int = 60, follow: bool = False):
        """Собрать flows через hubble CLI"""
        cmd = [
            "hubble", "observe", "flows",
            "--namespace", self.namespace,
            "--output", "json",
        ]
        
        # Добавляем фильтры по лейблам
        if self.from_label:
            cmd.extend(["--from-label", self.from_label])
        
        if self.to_label:
            cmd.extend(["--to-label", self.to_label])
        
        # Фильтр по verdict
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
        """Обработать один flow"""
        try:
            if 'flow' not in flow:
                return
                
            flow_data = flow['flow']
            source = flow_data.get('source', {})
            destination = flow_data.get('destination', {})
            
            # IP-адреса находятся в верхнем уровне
            ip_info = flow_data.get('IP', {})
            source_ip = ip_info.get('source', 'unknown')
            dest_ip = ip_info.get('destination', 'unknown')
            
            source_ns = source.get('namespace', '')
            dest_ns = destination.get('namespace', '')
            
            if source_ns != self.namespace and dest_ns != self.namespace:
                return
            
            # Сохраняем labels для подов и маппинг IP -> Pod
            source_pod_name = source.get('pod_name')
            if source_pod_name and source_ns:
                source_labels = source.get('labels', [])
                if source_labels:
                    self.pod_labels[source_pod_name] = self._parse_labels(source_labels)
                # Сохраняем маппинг IP -> Pod
                if source_ip != 'unknown':
                    self.ip_to_pod[source_ip] = (source_pod_name, source_ns)
            
            dest_pod_name = destination.get('pod_name')
            if dest_pod_name and dest_ns:
                dest_labels = destination.get('labels', [])
                if dest_labels:
                    self.pod_labels[dest_pod_name] = self._parse_labels(dest_labels)
                # Сохраняем маппинг IP -> Pod
                if dest_ip != 'unknown':
                    self.ip_to_pod[dest_ip] = (dest_pod_name, dest_ns)
            
            # Получаем информацию об источнике
            source_pod = source.get('pod_name')
            if not source_pod:
                # Пытаемся получить имя из workload
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
                    # Проверяем labels
                    source_labels = source.get('labels', [])
                    source_info = []
                    for label in source_labels:
                        if 'reserved:' in label:
                            source_info.append(label.replace('reserved:', ''))
                    
                    if source_info:
                        source_pod = f"{source_ip} ({', '.join(source_info)})"
                    else:
                        source_pod = f"{source_ip}"
            
            # Получаем информацию о назначении
            dest_pod = destination.get('pod_name')
            dest_port = destination.get('port')
            l4_proto = flow_data.get('l4', {})
            protocol = list(l4_proto.keys())[0].upper() if l4_proto else 'unknown'
            
            if not dest_pod:
                dest_identity = destination.get('identity')
                dest_labels = []
                
                # Проверяем, что identity - это словарь
                if isinstance(dest_identity, dict):
                    dest_labels = dest_identity.get('labels', [])
                elif isinstance(dest_identity, int):
                    # Если identity число, проверяем labels на верхнем уровне
                    dest_labels = destination.get('labels', [])
                
                # Пытаемся получить имя из workload
                workloads = destination.get('workloads', [])
                if workloads and isinstance(workloads, list) and len(workloads) > 0:
                    workload = workloads[0]
                    if isinstance(workload, dict):
                        workload_name = workload.get('name')
                        if workload_name:
                            dest_pod = workload_name
                
                if not dest_pod:
                    # Пытаемся получить имя сервиса
                    service_name = destination.get('service', {}).get('name') if isinstance(destination.get('service'), dict) else None
                    dest_ns_name = destination.get('namespace')
                    
                    # Извлекаем порт из l4 если нет в destination
                    if not dest_port and l4_proto:
                        proto_data = list(l4_proto.values())[0] if l4_proto else {}
                        dest_port = proto_data.get('destination_port') if isinstance(proto_data, dict) else None
                    
                    # Пытаемся получить DNS имя или другую полезную информацию
                    dest_info = []
                    for label in dest_labels:
                        if 'reserved:' in label:
                            # reserved:host, reserved:world, reserved:init и т.д.
                            dest_info.append(label.replace('reserved:', ''))
                        elif 'cidr:' in label:
                            dest_info.append(label.split('=')[1] if '=' in label else label)
                    
                    # Формируем имя назначения
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
                
                # Сохраняем детали flow для создания политик
                flow_detail = {
                    'source_pod': source_pod_name,
                    'source_ns': source_ns,
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
            print(f"  Ошибка обработки flow: {e}", file=sys.stderr)
    
    def _parse_labels(self, labels_list: List[str]) -> Dict[str, str]:
        """Конвертировать список labels в словарь, исключая служебные Cilium labels"""
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
                
                # Пропускаем служебные Cilium и Kubernetes labels
                if any(key.startswith(prefix) for prefix in exclude_prefixes):
                    continue
                
                # Пропускаем labels с namespace metadata (создаются Cilium автоматически)
                if 'k8s.namespace.labels' in key:
                    continue
                
                # Пропускаем cluster и policy labels
                if key in ['k8s.policy.cluster', 'k8s.policy.serviceaccount']:
                    continue
                
                labels[key] = value
        
        return labels
    
    def _is_external_ip(self, ip: str) -> bool:
        """Определить является ли IP внешним (не внутри кластера)"""
        if ip == 'unknown':
            return False
        
        # Проверяем частные сети (RFC 1918)
        if ip.startswith('10.'):
            return False
        if ip.startswith('172.'):
            # 172.16.0.0 - 172.31.255.255
            second_octet = int(ip.split('.')[1])
            if 16 <= second_octet <= 31:
                return False
        if ip.startswith('192.168.'):
            return False
        
        # Loopback
        if ip.startswith('127.'):
            return False
        
        # Link-local
        if ip.startswith('169.254.'):
            return False
        
        # Kubernetes service CIDR (часто 100.64.x.x или другие)
        if ip.startswith('100.64.'):
            return False
        
        # Все остальное считаем внешним
        return True
    
    def export_to_json(self, filepath: str):
        """Экспорт в JSON"""
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
        """Вывести summary"""
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
        """Экспорт в CiliumNetworkPolicy"""
        import os
        import yaml
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Группируем политики по source pod
        policies_by_pod = defaultdict(lambda: {
            'egress': defaultdict(lambda: {'ports': set(), 'protocols': set()})
        })
        
        for source_display, destinations in self.flow_details.items():
            for dest_display, flow_list in destinations.items():
                for flow in flow_list:
                    source_pod = flow.get('source_pod')
                    if not source_pod or flow.get('source_ns') != self.namespace:
                        continue
                    
                    dest_pod = flow.get('dest_pod')
                    dest_ns = flow.get('dest_ns')
                    dest_ip = flow.get('dest_ip')
                    dest_port = flow.get('dest_port')
                    protocol = flow.get('protocol')
                    
                    # Определяем тип назначения
                    if dest_pod and dest_ns:
                        # Pod to Pod - известен конкретный pod
                        dest_key = f"pod:{dest_ns}/{dest_pod}"
                    elif dest_ns:
                        # Namespace известен, но pod нет
                        dest_key = f"ns:{dest_ns}"
                    elif dest_ip and dest_ip != 'unknown':
                        # Проверяем есть ли этот IP в маппинге (значит это внутренний pod)
                        if dest_ip in self.ip_to_pod:
                            pod_info = self.ip_to_pod[dest_ip]
                            dest_key = f"pod:{pod_info[1]}/{pod_info[0]}"  # namespace/pod_name
                        elif self._is_external_ip(dest_ip):
                            # Внешний IP
                            dest_key = f"external:{dest_ip}"
                        else:
                            # Внутренний IP без информации о поде - используем toEntities
                            dest_key = f"internal:{dest_ip}"
                    else:
                        # Неизвестное назначение - пропускаем
                        continue
                    
                    if dest_port:
                        policies_by_pod[source_pod]['egress'][dest_key]['ports'].add(str(dest_port))
                    if protocol:
                        policies_by_pod[source_pod]['egress'][dest_key]['protocols'].add(protocol)
        
        # Создаём файлы политик для каждого пода
        policy_files = []
        for pod_name, policy_data in policies_by_pod.items():
            # Получаем labels для пода
            pod_labels = self.pod_labels.get(pod_name, {})
            if not pod_labels:
                # Пытаемся извлечь из имени пода основные labels
                pod_labels = self._extract_labels_from_pod_name(pod_name)
            
            if not pod_labels:
                print(f"Пропускаем pod '{pod_name}' - нет labels для селектора")
                continue
            
            # Создаём CiliumNetworkPolicy
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
            
            # Добавляем egress rules
            for dest_key, dest_info in policy_data['egress'].items():
                dest_type, dest_value = dest_key.split(':', 1)
                
                egress_rule = {}
                
                if dest_type == 'pod':
                    # Pod to Pod
                    dest_ns, dest_pod = dest_value.split('/', 1)
                    dest_pod_labels = self.pod_labels.get(dest_pod, {})
                    
                    if dest_pod_labels:
                        egress_rule['toEndpoints'] = [{
                            'matchLabels': dest_pod_labels
                        }]
                    else:
                        # Fallback к namespace
                        egress_rule['toEndpoints'] = [{
                            'matchExpressions': [{
                                'key': 'k8s:io.kubernetes.pod.namespace',
                                'operator': 'In',
                                'values': [dest_ns]
                            }]
                        }]
                
                elif dest_type == 'ns':
                    # Namespace
                    egress_rule['toEndpoints'] = [{
                        'matchExpressions': [{
                            'key': 'k8s:io.kubernetes.pod.namespace',
                            'operator': 'In',
                            'values': [dest_value]
                        }]
                    }]
                
                elif dest_type == 'external':
                    # Только внешние IP используют toCIDR
                    egress_rule['toCIDR'] = [f"{dest_value}/32"]
                
                elif dest_type == 'internal':
                    # Внутренний IP без информации о поде - используем toEntities
                    egress_rule['toEntities'] = ['cluster']
                
                # Добавляем порты
                if dest_info['ports'] or dest_info['protocols']:
                    egress_rule['toPorts'] = []
                    
                    protocols_list = list(dest_info['protocols']) if dest_info['protocols'] else ['TCP']
                    
                    for protocol in protocols_list:
                        port_rule = {'protocol': protocol.upper()}
                        
                        if dest_info['ports']:
                            port_rule['ports'] = [{'port': port} for port in sorted(dest_info['ports'])]
                        
                        egress_rule['toPorts'].append(port_rule)
                
                if egress_rule:
                    policy['spec']['egress'].append(egress_rule)
            
            # DNS разрешение (добавляем по умолчанию)
            dns_rule = {
                'toEndpoints': [{
                    'matchLabels': {
                        'k8s:io.kubernetes.pod.namespace': 'kube-system',
                        'k8s:k8s-app': 'kube-dns'
                    }
                }],
                'toPorts': [{
                    'protocol': 'UDP',
                    'ports': [{'port': '53'}]
                }]
            }
            policy['spec']['egress'].append(dns_rule)
            
            # Сохраняем в файл
            filename = f"{self._sanitize_name(pod_name)}-cnp.yaml"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w') as f:
                yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
            
            policy_files.append(filepath)
            print(f"Создана политика: {filepath}")
        
        return policy_files
    
    def _sanitize_name(self, name: str) -> str:
        """Очистить имя для использования в Kubernetes"""
        # Убираем хеш deployment/replicaset из имени
        name = re.sub(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', '', name)
        name = re.sub(r'-[a-f0-9]{9,10}$', '', name)
        
        # Заменяем недопустимые символы
        name = re.sub(r'[^a-z0-9-]', '-', name.lower())
        name = re.sub(r'-+', '-', name)
        name = name.strip('-')
        
        # Ограничиваем длину
        if len(name) > 63:
            name = name[:63].rstrip('-')
        
        return name
    
    def _extract_labels_from_pod_name(self, pod_name: str) -> Dict[str, str]:
        """Попытка извлечь labels из имени пода"""
        # Убираем хеш и индекс пода
        base_name = re.sub(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', '', pod_name)
        base_name = re.sub(r'-[a-f0-9]{9,10}$', '', base_name)
        base_name = re.sub(r'-\d+$', '', base_name)
        
        if base_name and base_name != pod_name:
            return {
                'app': base_name
            }
        
        return {}


def main():
    parser = argparse.ArgumentParser(description="Собрать flows из Hubble")
    parser.add_argument('-n', '--namespace', required=True, help='Namespace')
    parser.add_argument('-o', '--output', required=True, help='Выходной файл')
    parser.add_argument('--follow', action='store_true', help='Непрерывный мониторинг')
    parser.add_argument('--duration', type=int, default=60, help='Секунд (default: 60)')
    parser.add_argument('--from-label', dest='from_label', help='Фильтр по source label (например: app.kubernetes.io/name=api)')
    parser.add_argument('--to-label', dest='to_label', help='Фильтр по destination label')
    parser.add_argument('--verdict', choices=['FORWARDED', 'DROPPED', 'ERROR', 'AUDIT', 'REDIRECTED', 'TRACED'], 
                       help='Фильтр по verdict (FORWARDED, DROPPED, etc)')
    parser.add_argument('--debug-flows', dest='debug_flows', help='Сохранить сырые flows в файл для отладки')
    parser.add_argument('--cilium', choices=['true', 'false'], default='false',
                       help='Создать CiliumNetworkPolicy файлы (default: false)')
    parser.add_argument('--cilium-output-dir', dest='cilium_output_dir', default='./cilium-policies',
                       help='Директория для CiliumNetworkPolicy файлов (default: ./cilium-policies)')
    
    args = parser.parse_args()
    
    collector = HubbleCollector(
        namespace=args.namespace,
        from_label=args.from_label,
        to_label=args.to_label,
        verdict=args.verdict
    )
    
    print(f"Сбор flows: {args.namespace}")
    if args.from_label:
        print(f"   From Label: {args.from_label}")
    if args.to_label:
        print(f"   To Label: {args.to_label}")
    if args.verdict:
        print(f"   Verdict: {args.verdict}")
    
    collector.collect_flows(duration=args.duration, follow=args.follow)
    collector.print_summary()
    collector.export_to_json(args.output)
    
    # Создаём CiliumNetworkPolicy если указан флаг
    if args.cilium == 'true':
        print(f"\nГенерация CiliumNetworkPolicy...")
        try:
            policy_files = collector.export_cilium_policies(args.cilium_output_dir)
            print(f"\nСоздано {len(policy_files)} файлов политик в '{args.cilium_output_dir}'")
        except ImportError:
            print("\nДля генерации CiliumNetworkPolicy требуется библиотека PyYAML")
            print("   Установите: pip install pyyaml")
        except Exception as e:
            print(f"\nОшибка создания политик: {e}", file=sys.stderr)
    
    # Сохраняем сырые flows для отладки
    if args.debug_flows:
        with open(args.debug_flows, 'w') as f:
            json.dump(collector.flows, f, indent=2)
        print(f"Debug flows: {args.debug_flows}")
    
    print(f"\nFlows: {len(collector.flows)}")


if __name__ == '__main__':
    main()

