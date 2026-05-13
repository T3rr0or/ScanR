from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class RabbitKafkaZookeeperExposurePlugin(PluginBase):
    id = "services.rabbitmq_kafka_zookeeper_exposure"
    name = "RabbitMQ / Kafka / ZooKeeper Exposure"
    description = "Detect exposed messaging and coordination services"
    category = PluginCategory.services
    severity = Severity.high
    ports = [15672, 5672, 9092, 2181]

    async def check(self, context, host):
        for port in _open(host, {15672}):
            got = await _http_get(context, host.ip, port, "/api/overview")
            if got and got[1].status_code == 200 and "rabbitmq" in got[1].text.lower():
                return [_finding(self.id, Severity.high, "RabbitMQ Management API Exposed", "RabbitMQ management API is reachable without authentication.", f"{got[0]} returned overview", "Require strong RabbitMQ credentials, disable guest remote access, and restrict management UI.", port)]
        if 2181 in _open(host, {2181}):
            try:
                data = await _tcp_probe(host.ip, 2181, b"ruok\n", 64)
                if b"imok" in data:
                    return [_finding(self.id, Severity.high, "ZooKeeper Four-Letter Command Exposed", "ZooKeeper responds to unauthenticated four-letter commands.", "ruok -> imok", "Disable four-letter commands or restrict ZooKeeper to cluster-only networks.", 2181)]
            except Exception:
                pass
        if 9092 in _open(host, {9092}):
            return [_finding(self.id, Severity.medium, "Kafka Broker Exposed", "Kafka broker port is reachable. Without SASL/TLS and ACLs this can expose topics and messages.", "TCP/9092 open", "Require TLS/SASL, configure ACLs, and restrict Kafka listeners.", 9092)]
        return []

