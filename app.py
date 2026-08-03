#!/usr/bin/env python3
import base64
import json
import os
import sys
import traceback
import socket
import datetime
from itertools import takewhile
from time import sleep
from urllib.parse import urlparse

import kubernetes
import requests
from kubernetes import client, config
from loguru import logger
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Never block the scan loop forever on a wedged socket. A hung request is the
# silent twin of a crash: the unsealer looks alive but stops unsealing.
HTTP_TIMEOUT = float(os.environ.get("VAULT_HTTP_TIMEOUT", 10))


def get_kubernetes_client():
    try:
        config.load_incluster_config()
        client.configuration.assert_hostname = False
    except kubernetes.config.config_exception.ConfigException:
        config.load_kube_config()
        client.configuration.assert_hostname = False
    return client


def tracing_formatter(record):
    def function(f):
        return "/loguru/" not in f.filename

    frames = takewhile(function, traceback.extract_stack())
    stack = " > ".join("{}:{}:{}".format(f.filename, f.name, f.lineno) for f in frames)
    record["extra"]["stack"] = stack
    record["extra"]["timestamp"] = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
    return "{level} | {extra[timestamp]} {extra[stack]} - {message}\n{exception}"


def request_json(method, url, payload=None):
    """Perform an HTTP request and decode the JSON body, or return None.

    Every remote failure mode collapses to None so callers never have to reason
    about partial results:
      - transport failures (ConnectionError, ReadTimeout, TLS errors)
      - non-2xx responses
      - 2xx responses whose body is not JSON

    That last case is the one that used to kill this process: when an ingress
    or proxy sits in front of Vault it answers an outage with an HTML error
    page, and an unguarded .json() raises JSONDecodeError out of the main loop.
    """
    try:
        response = requests.request(
            method,
            url,
            data=json.dumps(payload) if payload is not None else None,
            timeout=HTTP_TIMEOUT,
            verify=False,  # nosec
        )
    except requests.exceptions.RequestException as request_error:
        logger.warning("{} {} failed: {}", method, url, request_error)
        return None

    if not response.ok:
        logger.warning(
            "{} {} returned HTTP {} ({} bytes, content-type {})",
            method,
            url,
            response.status_code,
            len(response.content),
            response.headers.get("Content-Type", "unknown"),
        )
        return None

    try:
        return response.json()
    except ValueError:
        logger.warning(
            "{} {} returned HTTP {} with a non-JSON body (content-type {}): {!r}",
            method,
            url,
            response.status_code,
            response.headers.get("Content-Type", "unknown"),
            response.text[:200],
        )
        return None


def list_convert(lst):
    converted_dict = {i: lst[i] for i in range(0, len(lst))}
    return converted_dict


def init_vault(vault_instance_url):
    logger.info(f"Initializing Vault at {vault_instance_url}")
    return request_json(
        "PUT", f"{vault_instance_url}/v1/sys/init", payload=auto_unseal_payload
    )


def create_secrets(secret):
    if not secret or "root_token" not in secret or "keys" not in secret:
        logger.error(
            "Vault init returned no usable key material ({}); not writing secrets",
            secret,
        )
        return False

    k8s_secret.metadata = client.V1ObjectMeta(name=root_token)
    k8s_secret.type = "Opaque"
    k8s_secret.string_data = {"root_token": secret["root_token"]}
    try:
        api_instance.create_namespaced_secret(namespace=namespace, body=k8s_secret)
    except kubernetes.client.exceptions.ApiException as create_secret_error:
        logger.error("Error during creation on Vault secret {}", create_secret_error)

    k8s_secret.metadata = client.V1ObjectMeta(name=vault_keys)
    k8s_secret.type = "Opaque"
    k8s_secret.string_data = list_convert(secret["keys"])
    try:
        api_instance.create_namespaced_secret(namespace=namespace, body=k8s_secret)
    except kubernetes.client.exceptions.ApiException as create_secret_error:
        logger.error("Error during creation on Vault secret {}", create_secret_error)

    return True


def read_secret(name, vault_instance_url):
    try:
        secret_client = api_instance.read_namespaced_secret(
            name=name, namespace=namespace
        ).data
    except kubernetes.client.exceptions.ApiException as read_secret_error:
        logger.error("Could not read secret {}: {}", name, read_secret_error)
        return
    for secret in (secret_client or {}).values():
        key = base64.b64decode(secret)
        vault_unseal(key.decode(), vault_instance_url)


def get_secret(name):
    secret = api_instance.read_namespaced_secret(name=name, namespace=namespace).data
    if secret:
        return True


def vault_unseal(key, vault_instance_url):
    if key is None:
        logger.info("Unseal key not found")
        return
    # A rejected key is not fatal: with secret_shares > threshold some of the
    # stored keys legitimately belong to a different quorum set.
    request_json("PUT", f"{vault_instance_url}/v1/sys/unseal", payload={"key": key})
    logger.info("{} has been provided an unseal key", vault_instance_url)


def get_seal_status(vault_instance_url, vault_status):
    seal_status = request_json(
        "GET", f"{vault_instance_url}/v1/sys/seal-status"
    )
    if seal_status is None or "initialized" not in seal_status:
        # Unreachable or unintelligible. Report an error and let the next scan
        # cycle retry -- do NOT propagate, or a transient proxy hiccup takes
        # the unsealer down exactly when Vault needs it.
        logger.warning(
            "No usable seal status from {}; will retry next cycle", vault_instance_url
        )
        return status_error

    if not seal_status["initialized"]:
        if vault_status:
            logger.info(
                "Vault has already been initialized, establishing quorum instead"
            )
            return status_init  # Return status_init to establish quorum

        logger.info("Going to init and unseal Vault")
        try:
            delete_secret([root_token, vault_keys])
        except kubernetes.client.exceptions.ApiException as delete_secret_error:
            logger.error("During  initialize got a error -> {}", delete_secret_error)
        if not create_secrets(init_vault(vault_instance_url)):
            return status_error

        logger.info("Unsealing Vault node {}", vault_instance_url)
        read_secret(vault_keys, vault_instance_url)

        return status_init

    if seal_status.get("sealed"):
        logger.info("Unsealing Vault node {}", vault_instance_url)
        read_secret(vault_keys, vault_instance_url)

        return status_unseal

    return status_ok


def delete_secret(secret_name):
    for secret in secret_name:
        secret_for_delete = api_instance.delete_namespaced_secret(
            name=secret, namespace=namespace
        )
        logger.info("Secret {} has been deleted", secret_for_delete.details.name)


def get_quorum_established(quorum_established, replica_list, main_url):
    while not quorum_established:
        quorum_established = True
        for vault_instance_url in replica_list:
            if vault_instance_url == main_url:
                continue

            leader_status = request_json(
                "GET", f"{vault_instance_url}/v1/sys/leader"
            )

            if leader_status is None or "leader_address" not in leader_status:
                quorum_established = False
                logger.info(
                    "Vault node {} is not ready: {}", vault_instance_url, leader_status
                )
                continue
            if leader_status["leader_address"] == main_url:
                logger.info(
                    "Vault node {} has acknowledged {} as the leader",
                    vault_instance_url,
                    main_url,
                )
            else:
                logger.info(
                    "Vault node {} has not acknowledged {} as the leader",
                    vault_instance_url,
                    main_url,
                )

                quorum_established = False
                break

        sleep(scan_delay)


def wait_for_quorum(replica_list, main_url):
    payload = {"leader_api_addr": main_url}
    leader_status = request_json("GET", f"{main_url}/v1/sys/leader")
    logger.info("Leader response json {}", leader_status)
    for vault_instance_url in replica_list:
        if vault_instance_url == main_url:
            continue

        logger.info("Joining {} to leader", vault_instance_url)
        if (
            request_json(
                "POST",
                f"{vault_instance_url}/v1/sys/storage/raft/join",
                payload=payload,
            )
            is None
        ):
            logger.warning(
                "Raft join of {} failed; will retry on the next cycle",
                vault_instance_url,
            )
            return status_error

        logger.info("Unsealing {}", vault_instance_url)
        read_secret(vault_keys, vault_instance_url)

    get_quorum_established(
        quorum_established=False,
        replica_list=replica_list,
        main_url=main_url,
    )

    logger.info("Quorum has been established with {} as the leader", main_url)


def get_vault_pods():
    if pod_retrieval_max_retries <= 0:
        logger.error("Pod retrieval max retries cannot be lower than 1: {}", pod_retrieval_max_retries)
        exit(2)

    tries = 0
    while tries < pod_retrieval_max_retries:
        tries = tries + 1
        try:
            pod_list = api_instance.list_namespaced_pod(
                namespace=vault_namespace, label_selector=vault_label_selector
            )
        except kubernetes.client.exceptions.ApiException as list_pods_error:
            logger.warning("Listing Vault pods failed: {}", list_pods_error)
            sleep(scan_delay)
            continue

        if len(pod_list.items) == 0:
            # Not fatal: the selector may transiently match nothing while pods
            # reschedule. Retry rather than exiting into CrashLoopBackOff.
            logger.warning(
                "No Vault pods matched selector {} in namespace {}",
                vault_label_selector,
                vault_namespace,
            )
            sleep(scan_delay)
            continue

        vault_pods_with_no_ip = [pod.metadata.name for pod in pod_list.items if pod.status.pod_ip is None]

        if len(vault_pods_with_no_ip) > 0:
            logger.warning("Vault pods have no assigned IP address: {}", vault_pods_with_no_ip)
            sleep(scan_delay)
            continue

        return pod_list

    logger.warning("Waiting for Vault pods to be ready timed out; retrying next cycle.")
    return None


if __name__ == "__main__":

    vault_initialized = False
    leader_url = ""
    secret_shares = ""  # nosec
    secret_threshold = ""  # nosec
    namespace = ""
    root_token = ""  # nosec
    vault_keys = ""  # nosec
    scan_delay = ""
    vault_url = ""
    pod_retrieval_max_retries = ""
    try:
        vault_url = os.environ["VAULT_URL"]
        secret_shares = os.environ["VAULT_SECRET_SHARES"]
        secret_threshold = os.environ["VAULT_SECRET_THRESHOLD"]
        namespace = os.environ["NAMESPACE"]
        root_token = os.environ["VAULT_ROOT_TOKEN_SECRET"]
        vault_keys = os.environ["VAULT_KEYS_SECRET"]
        scan_delay = int(os.environ["VAULT_SCAN_DELAY"])
        pod_retrieval_max_retries = int(os.environ.get("VAULT_POD_RETRIEVAL_MAX_RETRIES", 5))
        vault_label_selector = os.environ.get("VAULT_LABEL_SELECTOR", "vault-sealed=true")
        if not vault_url or vault_url == "":
            print("No Vault URL specified, relying on scan mechanism with label selector {}", vault_label_selector)
            #raise KeyError
    except KeyError as error:
        if not secret_shares:
            secret_shares = 5
        if not namespace:
            namespace = "default"
        if not root_token:
            root_token = "root-token"  # nosec
        if not vault_keys:
            vault_keys = "vault-keys"
        if not secret_threshold:
            secret_threshold = 5
        if not scan_delay:
            scan_delay = 5
        else:
            print("Please check system variable {}", error)
            exit(2)

    # Scan mode built these from `url.scheme` and `vault_port`. Upstream
    # derived them by urlparse()ing VAULT_URL, which cannot work once VAULT_URL
    # holds several endpoints, and derived the namespace as
    # `url.hostname.split(".")[1]` -- that yields "rootlease" for
    # vault.rootlease.be and IndexErrors outright on a dotless hostname. Read
    # them from the environment instead, defaulting to Vault's own defaults.
    vault_namespace = os.environ.get("VAULT_NAMESPACE", namespace)
    vault_scheme = os.environ.get("VAULT_SCHEME", "http")
    vault_port = int(os.environ.get("VAULT_PORT", 8200))
    # Opt-in: expand a single VAULT_URL to one endpoint per resolved address.
    # Off by default because it is the strictly weaker way to reach a
    # StatefulSet -- resolved IPs are correct only until the next reschedule,
    # whereas per-pod DNS names survive one.
    resolve_dns = os.environ.get("VAULT_RESOLVE_DNS", "").lower() in ("1", "true", "yes")

    logger.remove()
    logger.add(sys.stderr, format=tracing_formatter)
    logger.info("Start Vault auto unseal")
    k8s_client = get_kubernetes_client()
    api_instance = k8s_client.CoreV1Api()
    k8s_secret = k8s_client.V1Secret()
    status_init = 0
    status_unseal = 1
    status_ok = 2
    status_error = 3
    auto_unseal_payload = {
        "secret_shares": int(secret_shares),
        "secret_threshold": int(secret_threshold),
    }

    # Endpoints are recomputed on EVERY scan cycle (see below). Upstream
    # resolved them once, before the loop: after a pod reschedule -- a spot
    # preemption, a rollout -- the cached IPs pointed at pods that no longer
    # existed, and the unsealer kept talking to nothing for the rest of its
    # lifetime. Vault would sit sealed with a healthy-looking unsealer.
    def resolve_replicas():
        """Return the Vault endpoints to unseal, freshly resolved."""
        if vault_url:
            # Whitespace-separated, so a StatefulSet can be addressed by its
            # stable per-pod DNS names. That is deterministic where resolving
            # one Service name is not: in HA, EVERY replica boots sealed and
            # must be unsealed individually, and a Service hands back one pod
            # per lookup.
            entries = vault_url.split()
            if resolve_dns and len(entries) == 1:
                expanded = _expand_dns(entries[0])
                if expanded:
                    return expanded
            return entries

        pods = get_vault_pods()
        if pods is None:
            return []
        return [
            f"{vault_scheme}://{pod.status.pod_ip}:{vault_port}"
            for pod in pods.items
        ]

    def _expand_dns(endpoint):
        """Expand one URL into per-address URLs, or [] if it will not resolve."""
        try:
            parsed = urlparse(endpoint)
            port = parsed.port or vault_port
            return sorted(
                f"{parsed.scheme}://{info[4][0]}:{info[4][1]}"
                for info in socket.getaddrinfo(
                    parsed.hostname, port, proto=socket.IPPROTO_TCP
                )
            )
        except (socket.gaierror, ValueError) as resolve_error:
            logger.warning(
                "Could not resolve {}: {}; using it verbatim",
                endpoint,
                resolve_error,
            )
            return []

    previous_replicas = None
    while True:
        # This daemon must outlive every transient fault it can encounter.
        # While it is restarting it is not unsealing, and CrashLoopBackOff
        # makes each successive failure cost more downtime than the last --
        # so the process that exists to recover Vault is asleep for longest
        # exactly when Vault has been down longest.
        try:
            vault_replicas = resolve_replicas()
            if not vault_replicas:
                logger.warning("No Vault endpoints resolved; retrying next cycle")
                sleep(scan_delay)
                continue

            # Logged on change only. At the default 5s scan delay this line
            # was 17k identical INFO records a day, which is how a real
            # transition gets lost.
            if vault_replicas != previous_replicas:
                logger.info("Vault instance(s): {}", vault_replicas)
                previous_replicas = vault_replicas

            for replica_url in vault_replicas:
                logger.debug("Checking seal status for: {}", replica_url)
                status = get_seal_status(replica_url, vault_initialized)
                if status == status_init:
                    if len(vault_replicas) > 1:
                        logger.info(
                            "Vault running in High Availability mode will unseal Vault nodes one by one"
                        )
                    else:
                        logger.info("Vault running in Single Node mode will unseal")

                    # Only set the Leader URL once
                    if not vault_initialized:
                        vault_initialized = True
                        leader_url = replica_url
                    logger.info(
                        "Vault was just initialized, waiting for quorum to be established"
                    )
                    wait_for_quorum(vault_replicas, leader_url)

                if status == status_unseal:
                    # If we've unsealed an instance, then by definition vault has been initialized
                    vault_initialized = True
                    logger.info("Vault has been unsealed")
        except Exception:  # noqa: BLE001 -- deliberate: staying up beats being right
            logger.exception("Unhandled error in scan cycle; continuing")

        sleep(scan_delay)
