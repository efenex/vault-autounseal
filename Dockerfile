# MUST stay on the same CPython minor as the runtime stage below. Wheels
# with compiled extensions are tagged for one ABI (cp311), so a mismatch
# imports pure-Python modules fine and then dies on the first .so --
# ModuleNotFoundError: No module named '_cffi_backend', via cryptography,
# via google-auth, via kubernetes.
FROM python:3.11-slim AS build-env
LABEL description='Vaultauto-unseal for Kubernetes'
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PYTHONUNBUFFERED 1
COPY ./ /app
WORKDIR app
RUN pip install --no-cache-dir --upgrade -r requirements.txt  && rm -rf requirements.txt

# Pinned to debian12 (CPython 3.11). The floating :nonroot tag moved from
# 3.9 to 3.11 under this Dockerfile, which is what broke the build.
FROM gcr.io/distroless/python3-debian12:nonroot
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages
ENV VAULT_URL ""
ENV VAULT_SECRET_SHARES ""
ENV VAULT_SECRET_THRESHOLD ""
ENV NAMESPACE ""
ENV VAULT_ROOT_TOKEN_SECRET ""
ENV VAULT_KEYS_SECRET ""
ENV PYTHONWARNINGS "ignore:Unverified HTTPS request"

COPY --from=build-env /app /app
COPY --from=build-env /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
WORKDIR /app
CMD ["/app/app.py"]
