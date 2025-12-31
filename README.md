# Hubble Network Flow Collector

Сбор сетевых взаимодействий между подами через Hubble и автоматическая генерация CiliumNetworkPolicy на основе реального трафика.

**Возможности:**
- Автоматическое создание egress и ingress правил
- Интеграция с реальным Pod CIDR и Service CIDR
- Поддержка внешних источников (LoadBalancer, Ingress Controller)
- Фильтрация служебных Kubernetes/Cilium labels
- Валидация политик перед сохранением
- Мониторинг и аудит сетевого трафика

## Установка

### Требования

1. Hubble CLI (обязательно):

```bash
# macOS
brew install cilium-cli

# Linux
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -L --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz
tar xzvf hubble-linux-amd64.tar.gz
sudo mv hubble /usr/local/bin
```

2. PyYAML (для генерации CiliumNetworkPolicy):

```bash
pip install pyyaml
```

3. Port-forward к Hubble Relay (если нужен):

```bash
kubectl port-forward -n kube-system svc/hubble-relay 4245:80
```

## Использование

### Базовые команды

```bash
# Собрать flows за последние 60 секунд
python3 hubble-collector.py -n production -o flows.json

# Собрать flows за 30 минут
python3 hubble-collector.py -n production -o flows.json --duration 1800

# Непрерывный мониторинг (Ctrl+C для остановки)
python3 hubble-collector.py -n production -o flows.json --follow
```

### Генерация CiliumNetworkPolicy

```bash
# Собрать flows и создать политики
python3 hubble-collector.py -n production -o flows.json \
  --cilium true \
  --cilium-output-dir ./policies

# Для конкретного приложения
python3 hubble-collector.py -n production -o flows.json \
  --from-label "app=backend-api" \
  --cilium true

# Длительный сбор для точности (рекомендуется)
python3 hubble-collector.py -n production -o flows.json \
  --duration 3600 \
  --cilium true
```

### Фильтрация

```bash
# По source label (откуда идёт трафик)
python3 hubble-collector.py -n dev01 -o flows.json \
  --from-label "app.kubernetes.io/name=notifications-push"

# По destination label (куда идёт трафик)
python3 hubble-collector.py -n prod -o flows.json \
  --to-label "app=postgres"

# Только заблокированные соединения
python3 hubble-collector.py -n prod -o dropped.json --verdict DROPPED

# Комбинация фильтров
python3 hubble-collector.py -n dev01 -o flows.json \
  --from-label "app=api" \
  --to-label "app=database" \
  --verdict FORWARDED
```

### Опции

| Опция | Описание | По умолчанию |
|-------|----------|--------------|
| `-n`, `--namespace` | Namespace для мониторинга | обязательно |
| `-o`, `--output` | Выходной JSON файл | обязательно |
| `--duration` | Секунд для сбора flows | 60 |
| `--follow` | Непрерывный мониторинг | false |
| `--from-label` | Фильтр по source label | нет |
| `--to-label` | Фильтр по destination label | нет |
| `--verdict` | Фильтр по verdict (FORWARDED, DROPPED, ERROR, AUDIT, REDIRECTED, TRACED) | нет |
| `--cilium` | Создать CiliumNetworkPolicy (true/false) | false |
| `--cilium-output-dir` | Директория для политик | ./cilium-policies |
| `--pod-cidr` | Pod CIDR кластера (критично для корректных политик) | 10.39.0.0/16 |
| `--service-cidr` | Service CIDR кластера (критично для корректных политик) | 10.40.0.0/16 |
| `--debug-flows` | Сохранить сырые flows для отладки | нет |

## Критично важные параметры

### Pod CIDR и Service CIDR

Параметры `--pod-cidr` и `--service-cidr` критически важны для корректной генерации политик.

#### Зачем нужны

Скрипт должен различать:
- Pod IP (внутренние IP подов)
- Service IP (ClusterIP сервисов)
- Внешние публичные IP

Без указания CIDR скрипт использует стандартные частные сети (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), что может привести к неправильной классификации IP.

#### Как узнать CIDR своего кластера

```bash
# Способ 1: Через kube-controller-manager
kubectl -n kube-system get pod -l component=kube-controller-manager -o yaml | grep -E "cluster-cidr|service-cluster-ip-range"

# Пример вывода:
#   - --cluster-cidr=10.39.0.0/16
#   - --service-cluster-ip-range=10.40.0.0/16

# Способ 2: Через cluster-info
kubectl cluster-info dump | grep -m 1 cluster-cidr
kubectl cluster-info dump | grep -m 1 service-cluster-ip-range

# Способ 3: Из configmap (если есть)
kubectl -n kube-system get cm kubeadm-config -o yaml | grep -E "podSubnet|serviceSubnet"
```

#### Правильное использование

```bash
# С указанием CIDR (рекомендуется)
python3 hubble-collector.py -n production -o flows.json \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"
```

#### Что будет без указания CIDR

Если не указать `--pod-cidr` и `--service-cidr`, скрипт использует дефолтные диапазоны:
- 10.39.0.0/16 (Pod CIDR)
- 10.40.0.0/16 (Service CIDR)
- 172.16.0.0/12 (RFC1918)
- 192.168.0.0/16 (RFC1918)
- 100.64.0.0/10 (Shared address)

Это подходит для большинства кластеров, но если ваши CIDR отличаются:
1. IP могут быть неправильно классифицированы
2. Создаются правила `toCIDR` вместо `toEndpoints`
3. Политики становятся нестабильными (ломаются при рестарте подов)

**Пример проблемы:**

Без CIDR:
```yaml
egress:
- toCIDR:
  - 10.39.36.20/32  # IP пода - нестабильно!
  toPorts:
  - protocol: TCP
    ports:
    - port: '8080'
```

С правильным CIDR:
```yaml
egress:
- toEndpoints:
  - matchLabels:
      app: backend-api  # Стабильно, не зависит от IP
  toPorts:
  - protocol: TCP
    ports:
    - port: '8080'
```

### Оптимальная продолжительность сбора

Параметр `--duration` определяет как долго собирать flows.

#### Рекомендации

| Сценарий | Duration | Причина |
|----------|----------|---------|
| Тестирование скрипта | 60-300 сек | Быстрая проверка |
| Production политики | 300-600 сек | Баланс покрытия и актуальности |
| Полное покрытие | 1800-3600 сек | Все сценарии, но риск мёртвых подов |
| Живые поды только | 300 сек | Минимум мёртвых IP |

#### Проблема мёртвых подов

Hubble хранит исторические flows. Если за время `--duration`:
- Под был удалён
- Под перезапустился и получил новый IP

То скрипт увидит flows со старым IP, но пода с таким IP уже не будет.

**Результат:** Скрипт выведет warning и пропустит такие flows:
```
Warning: unknown internal IP 10.39.36.20 (port 14816) - pod may have been deleted
```

#### Рекомендуемый подход

Для production используйте короткий период с указанием CIDR:

```bash
python3 hubble-collector.py -n production -o flows.json \
  --duration 300 \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"
```

Если нужно больше покрытия - запускайте несколько раз в разное время и объединяйте политики вручную.

#### Режим follow

Для непрерывного мониторинга используйте `--follow`:

```bash
python3 hubble-collector.py -n production -o flows.json \
  --follow \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"

# Остановите через Ctrl+C когда накопится достаточно flows
```

## Примеры сценариев

### 1. Создание политик на основе реального трафика

```bash
# Шаг 1: Собрать flows за длительный период
python3 hubble-collector.py -n production -o flows.json \
  --duration 3600 \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"

# Вывод:
# Собрано flows: 15234
# Создано connections: 542
# Создана политика: ./cilium-policies/backend-api-cnp.yaml (egress: 5 rules, ingress: 3 rules)
# Создана политика: ./cilium-policies/frontend-cnp.yaml (egress: 8 rules, ingress: 2 rules)

# Шаг 2: Проверить созданные политики
ls -la ./cilium-policies/
cat ./cilium-policies/backend-api-cnp.yaml

# Шаг 3: Dry-run применение
kubectl apply -f ./cilium-policies/ --dry-run=server

# Шаг 4: Применить
kubectl apply -f ./cilium-policies/
```

### 2. Аудит сетевых политик

```bash
# Собрать actual трафик
python3 hubble-collector.py -n production -o actual.json --duration 1800

# Проверить заблокированные соединения
python3 hubble-collector.py -n production -o blocked.json --verdict DROPPED

# Найти что блокируется от конкретного сервиса
python3 hubble-collector.py -n prod -o api-blocked.json \
  --from-label "app=api" --verdict DROPPED
```

### 3. Мониторинг конкретного приложения

```bash
# Исходящие connections (egress)
python3 hubble-collector.py -n prod -o api-outbound.json \
  --from-label "app=backend-api" --follow

# Входящие connections (ingress)
python3 hubble-collector.py -n prod -o db-clients.json \
  --to-label "app=postgres" --follow

# Полная картина (egress + ingress) для сервиса
python3 hubble-collector.py -n prod -o service-flows.json \
  --from-label "app=api" \
  --cilium true \
  --duration 600
```

### 4. Миграция на CiliumNetworkPolicy

```bash
# Шаг 1: Собрать flows
python3 hubble-collector.py -n production -o flows.json \
  --duration 7200 --cilium true

# Шаг 2: Применить в test namespace
for policy in ./cilium-policies/*.yaml; do
  sed 's/namespace: production/namespace: test/' "$policy" | kubectl apply -f -
done

# Шаг 3: Мониторить dropped flows
python3 hubble-collector.py -n test -o validation.json \
  --verdict DROPPED --duration 600

# Шаг 4: Если OK, применить в production
kubectl apply -f ./cilium-policies/
```

### 5. Security audit

```bash
# Все заблокированные flows
python3 hubble-collector.py -n production -o security-audit.json \
  --verdict DROPPED --duration 3600

# Проверить изоляцию frontend от database
python3 hubble-collector.py -n prod -o frontend-to-db.json \
  --from-label "tier=frontend" \
  --to-label "tier=database"
```

## Формат вывода

### JSON (connections graph)

```json
{
  "namespace": "production",
  "collected_at": "2024-12-31T10:30:00Z",
  "total_flows": 1234,
  "filters": {
    "from_label": "app=api",
    "to_label": null,
    "verdict": "FORWARDED"
  },
  "connections": [
    {
      "source": "backend-api-7d9f8b6c5-x9k2m",
      "destination": "postgres-0:5432/TCP",
      "flows_count": 245
    }
  ]
}
```

### CiliumNetworkPolicy (автоматически генерируемые)

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend-api
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: backend-api
  
  egress:
  - toEndpoints:
    - matchLabels:
        app: postgres
    toPorts:
    - protocol: TCP
      ports:
      - port: "5432"
  
  - toCIDR:
    - "8.8.8.8/32"
    toPorts:
    - protocol: UDP
      ports:
      - port: "53"
  
  - toEndpoints:
    - matchLabels:
        io.kubernetes.pod.namespace: kube-system
        k8s-app: kube-dns
    toPorts:
    - protocol: UDP
      ports:
      - port: "53"
  
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"
  
  - fromCIDR:
    - "203.0.113.5/32"
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"
```

## Как работает генерация политик

Скрипт анализирует flows и автоматически генерирует **egress и ingress правила** на основе реального трафика.

### Egress и Ingress

Для каждого пода создаётся комплексная политика:

**Egress (исходящий трафик):**
- Контролирует куда под может подключаться
- Правила `toEndpoints` для pod-to-pod
- Правила `toCIDR` для внешних IP
- Автоматически добавляется DNS

**Ingress (входящий трафик):**
- Контролирует кто может подключаться к поду
- Правила `fromEndpoints` для pod-to-pod
- Правила `fromCIDR` для внешних источников (loadbalancer, ingress-controller)
- Учитывает реальные порты и протоколы

**Пример генерируемой политики:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend-api
spec:
  endpointSelector:
    matchLabels:
      app: backend-api
  
  egress:
  - toEndpoints:
    - matchLabels:
        app: postgres
    toPorts:
    - protocol: TCP
      ports:
      - port: "5432"
  
  - toCIDR:
    - "8.8.8.8/32"
    toPorts:
    - protocol: UDP
      ports:
      - port: "53"
  
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"
  
  - fromCIDR:
    - "203.0.113.5/32"
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"
```

### Логика определения типа назначения

Скрипт умно определяет тип назначения и использует правильные селекторы:

| Тип соединения | IP адрес | Egress селектор | Ingress селектор |
|----------------|----------|----------------|------------------|
| Pod в том же NS | 10.39.1.20 | toEndpoints + matchLabels | fromEndpoints + matchLabels |
| Pod в другом NS | 10.39.2.30 | toEndpoints + matchExpressions | fromEndpoints + matchExpressions |
| Pod по IP | 10.39.3.40 | toEndpoints + matchLabels | fromEndpoints + matchLabels |
| Внешний API/LB | 8.8.8.8 | toCIDR | fromCIDR |
| Мёртвый под | 10.39.36.20 | пропускается | пропускается |

### Определение внешних IP

С параметрами `--pod-cidr` и `--service-cidr`:
- Проверяется реальный CIDR кластера
- Точная классификация Pod vs External IP

Без параметров (дефолт для типичных кластеров):
- 10.39.0.0/16 (Pod CIDR)
- 10.40.0.0/16 (Service CIDR)
- 172.16.0.0/12 (RFC1918)
- 192.168.0.0/16 (RFC1918)
- 100.64.0.0/10 (Shared address space)

**Важно:** Если ваш кластер использует другие диапазоны, обязательно укажите `--pod-cidr` и `--service-cidr`.

### Генерация Ingress правил

Скрипт автоматически создаёт ingress правила на основе flows:

**Внешние источники (LoadBalancer, Ingress Controller):**
```yaml
ingress:
- fromCIDR:
  - "203.0.113.5/32"
  toPorts:
  - protocol: TCP
    ports:
    - port: "8080"
```

**Внутренние источники (pod-to-pod):**
```yaml
ingress:
- fromEndpoints:
  - matchLabels:
      app: frontend
  toPorts:
  - protocol: TCP
    ports:
    - port: "8080"
```

**Преимущества:**
- Полная изоляция (контроль входящего и исходящего трафика)
- Защита от несанкционированных подключений
- Явное разрешение для LoadBalancer и Ingress Controller
- Автоматическая синхронизация egress и ingress (из одних flows)

### Дефолтные порты для инфраструктуры

Если Hubble не может определить порт (например, соединение прервалось до установки), скрипт автоматически подставляет известные порты для популярных компонентов:

| Компонент | Порт | Протокол |
|-----------|------|----------|
| RabbitMQ | 5672 | TCP |
| RabbitMQ Management | 15672 | TCP |
| Redis | 6379 | TCP |
| Redis Sentinel | 26379 | TCP |
| PostgreSQL | 5432 | TCP |
| VictoriaMetrics (vmagent) | 8429 | TCP |
| VictoriaMetrics (vmsingle) | 8429 | TCP |
| VictoriaMetrics (vmselect) | 8481 | TCP |
| VictoriaMetrics (vminsert) | 8480 | TCP |
| VictoriaMetrics (vmstorage) | 8482 | TCP |
| Prometheus | 9090 | TCP |
| Alertmanager | 9093 | TCP |
| Grafana | 3000 | TCP |
| DNS (kube-dns, coredns) | 53 | UDP |

**Определение по labels:**
Скрипт анализирует `app`, `app.kubernetes.io/name`, `app.kubernetes.io/component`, `k8s-app` для подстановки дефолтного порта.

**Пример:**
```
Using default port 6379/TCP for pod:dev01/redis-sentinel-0
Using default port 8429/TCP for ingress from pod:monitoring/vmagent-0
```

**Важно:** Дефолтные порты используются только если Hubble не смог определить реальный порт. Если порт известен - используется реальный порт из flows.

### Фильтрация labels

Скрипт автоматически исключает служебные labels из политик:

**Исключаются:**
- io.cilium.* (все Cilium служебные labels)
- io.kubernetes.pod.* (внутренние Kubernetes labels)
- k8s.namespace.labels.* (namespace metadata)
- k8s.policy.* (policy metadata)
- pod-template-hash (меняется при каждом deployment)
- controller-revision-hash (меняется при обновлении)
- statefulset.kubernetes.io/pod-name (специфично для пода)

**Используются только пользовательские labels:**
- app
- version
- component
- tier
- environment
- app.kubernetes.io/name
- app.kubernetes.io/component
- и другие

## Применение политик

```bash
# Проверка перед применением
kubectl apply -f ./cilium-policies/ --dry-run=server

# Просмотр конкретной политики
cat ./cilium-policies/backend-api-cnp.yaml

# Применение
kubectl apply -f ./cilium-policies/

# Проверка статуса
kubectl get ciliumnetworkpolicies -n production
kubectl describe ciliumnetworkpolicy backend-api -n production

# Мониторинг после применения
python3 hubble-collector.py -n production -o dropped.json \
  --verdict DROPPED --follow
```

## Troubleshooting

### Ошибка: hubble: command not found

```bash
# Установите Hubble CLI (см. раздел Установка)
which hubble
```

### Ошибка: failed to connect to Hubble

```bash
# Проверьте что Hubble Relay запущен
kubectl get pods -n kube-system | grep hubble

# Port-forward
kubectl port-forward -n kube-system svc/hubble-relay 4245:80
```

### Пустой output (нет flows)

```bash
# Проверьте что в namespace есть трафик
kubectl get pods -n <namespace>

# Проверьте что Hubble видит flows
hubble observe --namespace <namespace> --last 10

# Увеличьте --duration
python3 hubble-collector.py -n prod -o flows.json --duration 300
```

### Нет labels для пода

```
Пропускаем pod 'some-pod' - нет labels для селектора
```

Решение:
- Добавьте labels к подам в Deployment/StatefulSet
- Или используйте --from-label для подов с labels

### Нужна библиотека PyYAML

```
Для генерации CiliumNetworkPolicy требуется библиотека PyYAML
```

```bash
pip install pyyaml
```

### Политика слишком широкая

Если политика разрешает больше, чем нужно:
- Увеличьте период сбора --duration
- Используйте фильтры --from-label / --to-label
- Отредактируйте политику вручную

### Политика блокирует нужный трафик

```bash
# Удалить политику
kubectl delete ciliumnetworkpolicy <name> -n <namespace>

# Пересобрать flows с большим периодом
python3 hubble-collector.py -n production -o flows.json \
  --duration 7200 --cilium true
```

## Рекомендации

### Период сбора

Собирайте flows достаточно долго для покрытия всех сценариев:

```bash
# Минимум 30 минут
--duration 1800

# Лучше 1-2 часа для production
--duration 7200

# Идеально - покрыть пиковую нагрузку
--duration 14400  # 4 часа
```

### Фильтрация

Для больших namespace используйте фильтры:

```bash
# Только конкретное приложение
--from-label "app=backend-api"

# Только tier
--from-label "tier=backend"
```

### Тестирование

Всегда тестируйте политики перед применением в production:

1. Применить в test namespace
2. Мониторить dropped flows
3. Проверить работоспособность всех сервисов
4. Проверить работу ingress (LoadBalancer, Ingress Controller)
5. Только потом применять в production

### Ingress правила

При использовании LoadBalancer или Ingress Controller:

**Проверьте что внешние IP разрешены:**
```bash
# Найти IP LoadBalancer
kubectl get svc -n ingress-nginx

# Проверить что этот IP есть в fromCIDR правилах
grep -r "203.0.113" ./cilium-policies/
```

**Если ingress блокируется:**
```bash
# Найти источник трафика
python3 hubble-collector.py -n production -o ingress-flows.json \
  --to-label "app=backend-api" \
  --duration 300

# Проверить dropped flows
python3 hubble-collector.py -n production -o dropped.json \
  --verdict DROPPED \
  --to-label "app=backend-api"
```

### Мониторинг после применения

```bash
# Мониторим dropped flows сразу после применения
python3 hubble-collector.py -n production -o dropped.json \
  --verdict DROPPED --follow
```

## CI/CD интеграция

### GitLab CI - генерация и проверка политик

```yaml
network-policy-generate:
  stage: test
  image: python:3.9
  before_script:
    - pip install pyyaml
    - apt-get update && apt-get install -y hubble
  script:
    - kubectl port-forward -n kube-system svc/hubble-relay 4245:80 &
    - sleep 5
    
    # Собрать flows и сгенерировать политики
    - python3 hubble-collector.py -n $CI_ENVIRONMENT_NAME -o flows.json
        --duration 600 --cilium true --cilium-output-dir ./generated-policies
    
    # Dry-run применение
    - kubectl apply -f ./generated-policies/ --dry-run=server
    
  artifacts:
    paths:
      - flows.json
      - generated-policies/
    expire_in: 30 days

network-policy-validate:
  stage: deploy
  dependencies:
    - network-policy-generate
  script:
    # Применить в staging
    - kubectl apply -f ./generated-policies/ -n staging
    
    # Проверить dropped flows
    - sleep 60
    - python3 hubble-collector.py -n staging -o validation.json
        --verdict DROPPED --duration 120
    
    # Проверить что критичные сервисы работают
    - |
      BLOCKED=$(jq '.connections[] | select(.source | contains("critical"))' validation.json | wc -l)
      if [ "$BLOCKED" -gt 0 ]; then
        echo "Политики блокируют критичный трафик!"
        exit 1
      fi
  only:
    - main
```

## Пример вывода

```
Сбор flows: production
   From Label: app=backend-api
Запуск: hubble observe flows --namespace production --output json --from-label app=backend-api --last 60

======================================================================
Namespace: production
From Label: app=backend-api
======================================================================
Flows: 1523
Unique Connections: 8

Network Connections:
----------------------------------------------------------------------
  backend-api-7d9f8b6c5-x9k2m      → postgres-0:5432/TCP               (245 flows)
  backend-api-7d9f8b6c5-x9k2m      → redis-master-0:6379/TCP           (156 flows)
  backend-api-7d9f8b6c5-x9k2m      → 8.8.8.8:53/UDP                    (45 flows)
======================================================================

Экспорт: flows.json

Генерация CiliumNetworkPolicy...
Создана политика: ./cilium-policies/backend-api-cnp.yaml

Создано 1 файлов политик в './cilium-policies'

Flows: 1523
```

## Дополнительные ресурсы

- [Hubble Documentation](https://docs.cilium.io/en/stable/observability/hubble/)
- [Cilium Network Policies](https://docs.cilium.io/en/stable/policy/)
- [Network Policy Best Practices](https://kubernetes.io/docs/concepts/services-networking/network-policies/)


