#!/usr/bin/env python3
"""Interactive Ubuntu installer. Run from a clean production checkout as root."""
import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SECRETS = ROOT / ".secrets"
IMAGE = "onlinekeygen-installer:local"


def run(*args, capture=False):
    return subprocess.run(args, cwd=ROOT, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def compose(*args, capture=False):
    return run("docker", "compose", "--env-file", str(ROOT / ".env"),
               "-f", "docker-compose.production.yml", *args, capture=capture)


def ask(label, default=""):
    value = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
    return value or default


def yes(label):
    return ask(label + " (да/нет)", "нет").lower() in ("да", "yes", "y")


def save(path, value):
    temporary = path.with_name(path.name + ".new")
    with open(temporary, "w", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def docker_setup():
    if shutil.which("docker"):
        run("docker", "info", capture=True)
        run("docker", "compose", "version")
        return
    if not yes("Docker отсутствует. Установить из официального репозитория Docker?"):
        raise RuntimeError("Установите Docker Engine и Compose plugin и повторите запуск.")
    # Existing container packages are not removed automatically.
    for package in ("docker.io", "containerd", "runc", "podman-docker"):
        check = subprocess.run(["dpkg-query", "-W", "-f=${Status}", package], capture_output=True, text=True)
        if "install ok installed" in check.stdout:
            raise RuntimeError("Обнаружены сторонние контейнерные пакеты. Настройте Docker вручную без нарушения действующих сервисов.")
    run("apt-get", "update")
    run("apt-get", "install", "-y", "ca-certificates", "curl")
    Path("/etc/apt/keyrings").mkdir(mode=0o755, exist_ok=True)
    run("curl", "--fail", "--silent", "--show-error", "--location", "https://download.docker.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/docker.asc")
    os.chmod("/etc/apt/keyrings/docker.asc", 0o644)
    architecture = run("dpkg", "--print-architecture", capture=True).strip()
    release = read_release()
    Path("/etc/apt/sources.list.d/docker.sources").write_text(
        "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: " + release["VERSION_CODENAME"] +
        "\nComponents: stable\nArchitectures: " + architecture + "\nSigned-By: /etc/apt/keyrings/docker.asc\n")
    os.chmod("/etc/apt/sources.list.d/docker.sources", 0o644)
    run("apt-get", "update")
    run("apt-get", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin")
    run("systemctl", "enable", "--now", "docker")


def read_release():
    return dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().replace('"', '').splitlines() if "=" in line)


def prepare():
    settings_path = SECRETS / "install-settings.json"
    if settings_path.exists():
        settings = json.loads(settings_path.read_text())
        print("Продолжение установки:", settings["domain"], "— секреты сохраняются.")
        return settings
    if (ROOT / ".env").exists() or (SECRETS / "keystore.json").exists():
        raise RuntimeError("Найдена конфигурация, созданная не установщиком. Используйте отдельную чистую копию проекта; данные не изменены.")
    pending = SECRETS / "installer/input.json"
    if (SECRETS / "installer/material").exists():
        settings = json.loads(pending.read_text())
        settings.pop("auditToken", None)
        save(settings_path, json.dumps(settings, ensure_ascii=False, indent=2))
        return settings
    domain = ask("Домен (без https://)").lower()
    if len(domain) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise RuntimeError("Некорректный домен; для международного имени используйте punycode.")
    addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(domain, 443)})
    print("DNS:", ", ".join(addresses))
    if not yes("Эти адреса ведут на этот сервер, TCP 80/443 открыты во внешнем firewall?"):
        raise RuntimeError("Настройте DNS и firewall и повторите запуск.")
    for port in (80, 443):
        with socket.socket() as probe:
            probe.bind(("0.0.0.0", port))
    def identifier(label, default, pattern):
        while True:
            value = ask(label, default).lower()
            if re.fullmatch(pattern, value):
                return value
            print("Используйте латинские буквы и цифры; не копируйте текст приглашения.")
    settings = {"domain": domain,
                "admin": identifier("Логин администратора", "administrator", r"[a-z0-9][a-z0-9_]{2,31}"),
                "slug": identifier("Идентификатор продукта", "keyspace", r"[a-z0-9-]{3,64}"),
                "name": ask("Название продукта", "Keyspace"),
                "offline": yes("Разрешить offline-лицензирование?")}
    settings["auditUrl"] = ask("HTTPS URL приемника аудита (Enter — тестовый режим, аудит только в БД)")
    settings["auditMode"] = "external" if settings["auditUrl"] else "database-only"
    if settings["auditUrl"] and not settings["auditUrl"].startswith("https://"):
        raise RuntimeError("Приемник аудита должен использовать HTTPS.")
    token = getpass.getpass("Токен приемника аудита (скрытый ввод): ") if settings["auditUrl"] else ""
    if not settings["auditUrl"]:
        print("Тестовый режим: аудит сохраняется в PostgreSQL, внешняя доставка отложена.")
    backup = ask("Каталог для будущих резервных копий (вне каталога проекта)", "/var/backups/keyspace")
    backup_path = Path(backup).resolve()
    if not Path(backup).is_absolute() or backup_path == ROOT or ROOT in backup_path.parents:
        raise RuntimeError("Нужен абсолютный путь за пределами проекта.")
    settings["backupDirectory"] = str(backup_path)
    setup = SECRETS / "installer"
    setup.mkdir(mode=0o700, exist_ok=True)
    save(setup / "input.json", json.dumps({**settings, "auditToken": token}))
    # The validated material is committed before the resume marker.
    run("docker", "run", "--rm", "--network", "none", "--mount", f"type=bind,src={setup},dst=/setup", IMAGE,
        "npx", "--no-install", "tsx", "scripts/setup-production.ts")
    save(settings_path, json.dumps(settings, ensure_ascii=False, indent=2))
    return settings


def install_material():
    material = SECRETS / "installer/material"
    if (SECRETS / "material-installed").exists():
        if not (ROOT / ".env").is_file() or not (SECRETS / "keystore.json").is_file():
            raise RuntimeError("Рабочая конфигурация потеряна. Восстановите ее из резервной копии; новые ключи не создаются.")
        return
    for name in ("keystore.json", "manifest-root.pem", "manifest-root-public.pem"):
        destination = SECRETS / name
        if not destination.exists():
            save(destination, (material / name).read_text())
    if not (ROOT / ".env").exists():
        save(ROOT / ".env", (material / "production.env").read_text())
    # Only the online signing keystore is readable by container UID 1000.
    os.chown(SECRETS / "keystore.json", 1000, 1000)
    os.chmod(SECRETS / "keystore.json", 0o600)
    # The root private key is never mounted into the backend.
    (SECRETS / "installer/input.json").unlink(missing_ok=True)
    save(SECRETS / "material-installed", "1\n")
    # Drop staging duplicates, especially the root private key.
    for name in ("keystore.json", "manifest-root.pem", "manifest-root-public.pem", "production.env"):
        (material / name).unlink(missing_ok=True)
    material.rmdir()


def bootstrap():
    compose("-f", "docker-compose.bootstrap.yml", "--profile", "ops", "run", "--rm", "--no-deps",
            "migrate", "npx", "--no-install", "tsx", "scripts/bootstrap-production.ts")


def main():
    if "--help" in sys.argv:
        print("sudo python3 scripts/install-production.py\nUbuntu Server 22.04/24.04; clean production checkout. Re-run to resume. No data deletion.")
        return
    if os.geteuid() != 0:
        raise RuntimeError("Запустите установщик через sudo.")
    release = read_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") not in ("22.04", "24.04"):
        raise RuntimeError("Этот установщик поддерживает Ubuntu Server 22.04 и 24.04.")
    os.umask(0o077)
    SECRETS.mkdir(mode=0o700, exist_ok=True)
    with open(SECRETS / "install.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (ROOT / ".env").exists() and not (SECRETS / "install-settings.json").exists():
            raise RuntimeError("Существующий .env не принадлежит установщику. Нужна чистая production-копия.")
        free = shutil.disk_usage(ROOT).free // (1024 ** 3)
        memory = int(re.search(r"MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text())[1]) // 1024
        print(f"Доступно на диске: {free} ГБ; RAM: {memory} МБ. Ориентир: 8 ГБ RAM, 20 ГБ свободного места для сборки.")
        if free < 10 or memory < 3500:
            raise RuntimeError("Недостаточно ресурсов для сборки на сервере.")
        docker_setup()
        # Build before creating .env, using the existing migration/tooling target.
        run("docker", "build", "--target", "migrate", "-t", IMAGE, ".")
        settings = prepare()
        install_material()
        compose("--profile", "ops", "config", "--quiet")
        compose("--profile", "ops", "build")
        compose("up", "-d", "--wait", "postgres", "redis")
        compose("--profile", "ops", "run", "--rm", "migrate")
        compose("--profile", "ops", "run", "--rm", "migrate", "npx", "--no-install", "tsx", "scripts/provision.ts")
        compose("up", "-d", "--wait", "--wait-timeout", "180", "backend", "frontend", "worker", "reverse-proxy")
        url = "https://" + settings["domain"]
        print("Проверка HTTPS и readiness (до двух минут)...")
        for attempt in range(24):
            try:
                with urllib.request.urlopen(url + "/api/v1/health/ready", timeout=5) as response:
                    if response.status == 200:
                        break
            except Exception:
                pass
            time.sleep(5)
        else:
            raise RuntimeError("HTTPS readiness не подтвержден. Проверьте DNS, firewall и Caddy; затем повторите запуск.")
        bootstrap()
        backup = Path(settings["backupDirectory"])
        backup.mkdir(mode=0o700, parents=True, exist_ok=True)
        save(ROOT / "INSTALLATION_RESULT.txt", f"Система запущена: {url}\n"
             "Начальные учетные данные: .secrets/install-admin.json (только root).\n"
             "Завершите WebAuthn в течение 15 минут. Сохраните пароль и удалите этот файл.\n"
             "Публичная конфигурация desktop: .secrets/client-config.json.\n"
             f"Каталог резервных копий: {backup}\n"
             "Автоматическое резервное копирование НЕ настроено; настройте внешнее шифрованное хранилище и расписание.\n"
             "Проверьте получение событий внешним приемником аудита.\n"
             "Сделайте защищенную копию секретов и вынесите корневой приватный ключ из online-окружения.\n"
             "Инструкция: docs/runbooks/INSTALLER_RU.md\n")
        print("Готово:", url, "\nИтог: INSTALLATION_RESULT.txt\nУчетные данные: sudo cat .secrets/install-admin.json\nЗавершите WebAuthn за 15 минут; затем удалите файл учетных данных.")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        # CalledProcessError may contain command arguments: never echo it.
        print("\nУстановка остановлена. Данные и ключи сохранены. Можно повторить ту же команду.", file=sys.stderr)
        if isinstance(error, RuntimeError):
            print(str(error), file=sys.stderr)
        else:
            print("Тип ошибки: " + type(error).__name__ + ". Проверьте предыдущий этап; секреты не выводятся.", file=sys.stderr)
        sys.exit(1)
