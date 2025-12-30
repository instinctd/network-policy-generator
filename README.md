# Hubble Network Flow Collector

Сбор сетевых взаимодействий между подами через Hubble и автоматическая генерация CiliumNetworkPolicy на основе реального трафика.

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
| `--debug-flows` | Сохранить сырые flows для отладки | нет |

## Примеры сценариев

### 1. Создание политик на основе реального трафика

```bash
# Шаг 1: Собрать flows за длительный период
python3 hubble-collector.py -n production -o flows.json \
  --duration 3600 --cilium true

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
# Исходящие connections
python3 hubble-collector.py -n prod -o api-outbound.json \
  --from-label "app=backend-api" --follow

# Входящие connections к базе
python3 hubble-collector.py -n prod -o db-clients.json \
  --to-label "app=postgres" --follow
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
      k8s:app: backend-api
  egress:
  # Pod-to-Pod (по labels)
  - toEndpoints:
    - matchLabels:
        k8s:app: postgres
    toPorts:
    - protocol: TCP
      ports:
      - port: "5432"
  
  # Внутрикластерный IP без информации о поде
  - toEntities:
    - cluster
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"
  
  # Внешний публичный IP
  - toCIDR:
    - "8.8.8.8/32"
    toPorts:
    - protocol: UDP
      ports:
      - port: "53"
  
  # DNS (добавляется автоматически)
  - toEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: kube-system
        k8s:k8s-app: kube-dns
    toPorts:
    - protocol: UDP
      ports:
      - port: "53"
```

## Как работает генерация политик

Скрипт умно определяет тип назначения и использует правильные селекторы:

| Тип соединения | IP адрес | Используемый селектор | Причина |
|----------------|----------|----------------------|---------|
| Pod в том же NS | 10.244.1.20 | toEndpoints + matchLabels | Известны labels пода |
| Pod в другом NS | 10.244.2.30 | toEndpoints + matchExpressions (NS) | Известен namespace |
| Pod по IP | 10.244.3.40 | toEndpoints + matchLabels | IP найден в маппинге |
| Service IP | 10.96.0.10 | toEntities: ['cluster'] | Внутренний IP без pod info |
| Внешний API | 8.8.8.8 | toCIDR | Публичный IP |

### Определение внешних IP

Скрипт считает IP внешним (используя toCIDR), если он НЕ в диапазонах:
- 10.0.0.0/8 (частная сеть)
- 172.16.0.0/12 (частная сеть)
- 192.168.0.0/16 (частная сеть)
- 127.0.0.0/8 (loopback)
- 169.254.0.0/16 (link-local)
- 100.64.0.0/10 (service CIDR)

Всё остальное = внешний публичный IP → используется toCIDR

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
3. Проверить работоспособность
4. Только потом применять в production

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


