# vault-auto-unseal
## Disclaimer
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## What for

As you know, Vault provides several mechanisms for auto unsealing. However, sometimes I couldn't use AWS or GCP as the cloud provider. The main idea was to use Kubernetes secrets as the source for auto unsealing.

## Tested on

| Engine     | Version       | Vault mode |
|------------|---------------|------------|
| kind       | v1.29.1       | single/ha  |
| crc        | 2.32.0+54a6f9 | single     |
| OpenShift  | 4.14.8        | single/ha  |
| Kubernetes | v1.29.1       | single/ha  |
|            |               |            |

## Dependencies

- Kubernetes
- Python > 3.7

## How to use

Checkout source code from the repository

Install dependencies  via pip: `pip install -r requirements.txt`

Setup system environment

Run script `python app.py`

## System environments

| Name                    | Description                                                                                                                                     |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| VAULT_URL               | Vault server url with port e.g http://127.0.0.1:8200                                                                                            |
| VAULT_SECRET_SHARES     | Specifies the number of shares that should be encrypted by the HSM and stored for auto-unsealing. Currently must be the same as `secret_shares` |
| VAULT_SECRET_THRESHOLD  | Specifies the number of shares required to reconstruct the recovery key. This must be less than or equal to `recovery_shares`.                  |
| NAMESPACE               | Kubernetes namespace for storing vault root key and keys                                                                                        |
| VAULT_ROOT_TOKEN_SECRET | Kubernetes secret name for root token                                                                                                           |
| VAULT_KEYS_SECRET       | Kubernetes secret name for vault key                                                                                                            |
| VAULT_CLIENT_CERT       | Optional. Path to a client certificate (PEM) to present for mutual TLS. Unset = no client certificate, i.e. unchanged behaviour.                 |
| VAULT_CLIENT_KEY        | Optional. Path to the client private key. Omit when `VAULT_CLIENT_CERT` is a combined cert+key PEM.                                              |
| VAULT_CA_BUNDLE         | Optional. Path to a CA bundle used to verify the Vault endpoint. Unset preserves this image's historical `verify=False`.                         |

### Mutual TLS

Set `VAULT_CLIENT_CERT` (and `VAULT_CLIENT_KEY`) when Vault sits behind a proxy
that authenticates callers by **client certificate** rather than by source IP.

Prefer this over a source-IP allowlist whenever the unsealer's egress address is
not under your control -- ephemeral node IPs, a NAT pool, anything autoscaled.
An allowlist in that situation fails **closed and silently**: the proxy answers
`403`, every seal-status probe returns `None`, and the unsealer stays `Running`
1/1 while unsealing nothing. That failure is invisible until the next time a
Vault pod actually needs unsealing -- i.e. during an incident.


## Deployment

The solution can be run as docker container or inside Kubernetes

Building docker container

```shell
docker build . -t vault-autounseal:latest

```
or build multiarch docker image:

```shell
make docker
```

or You can pull existing image from DockerHub

```shell
docker pull opennix/vault-autounseal
```

### Using helm chart

[Helm](https://helm.sh) must be installed to use the charts.  Please refer to
Helm's [documentation](https://helm.sh/docs) to get started.

Once Helm has been set up correctly, add the repo as follows:

  helm repo add vault-autounseal https://pytoshka.github.io/vault-autounseal

If you had already added this repo earlier, run `helm repo update` to retrieve
the latest versions of the packages.  You can then run `helm search repo
vault-autounseal` to see the charts.

To install the vault-autounseal chart:

    helm install vault-autounseal vault-autounseal/vault-autounseal --set=settings.vault_url=http://vault.vault:8200

To uninstall the chart:

    helm delete vault-autounseal

<a href="https://www.buymeacoffee.com/pyToshka" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
