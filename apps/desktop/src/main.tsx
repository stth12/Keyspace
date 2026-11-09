import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import "./style.css";
const messages: Record<string, string> = {
  INVALID_LICENSE: "Неверный лицензионный ключ.",
  LICENSE_EXPIRED: "Срок лицензии истёк.",
  LICENSE_REVOKED: "Лицензия отозвана.",
  LICENSE_BLOCKED: "Лицензия заблокирована.",
  DEVICE_LIMIT_REACHED: "Достигнут лимит устройств.",
  DEVICE_REVOKED: "Устройство отозвано.",
  INVALID_SESSION: "Сессия завершена. Введите ключ снова.",
  SESSION_EXPIRED: "Сессия истекла.",
  NETWORK_ERROR: "Нет соединения с сервером.",
  OFFLINE_EXPIRED: "Для продолжения подключитесь к серверу.",
  INVALID_SIGNATURE: "Не удалось проверить подпись.",
  STORAGE_ERROR: "Защищённое хранилище недоступно.",
  OFFLINE_DISABLED: "Offline-режим отключён для продукта.",
};
function App() {
  const [key, setKey] = useState(""),
    [data, setData] = useState<any>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<any>) => {
    setBusy(true);
    setError("");
    try {
      setData(await fn());
    } catch (e) {
      const c = String(e);
      setError(messages[c] || "Операция не выполнена. Попробуйте войти снова.");
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    run(() => invoke("resume"));
    const timer = setInterval(() => {
      invoke("resume")
        .then(setData)
        .catch((e) => {
          setError(messages[String(e)] || "Проверка доступа не выполнена.");
          setData(null);
        });
    }, 60000);
    return () => clearInterval(timer);
  }, []);
  return (
    <main>
      <header>
        <span className="logo">⌘</span> Keyspace{" "}
        <span className="edition">DESKTOP</span>
      </header>
      {!data ? (
        <section>
          <div className="eyebrow">ДОСТУП К ПРИЛОЖЕНИЮ</div>
          <h1>
            Один ключ.
            <br />
            Всё готово к работе.
          </h1>
          <p className="muted">
            Введите лицензионный ключ. Срок действия начнётся при первой
            успешной активации.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              run(async () => {
                const result = await invoke("login", { licenseKey: key });
                setKey("");
                return result;
              });
            }}
          >
            <label>
              License key
              <input
                value={key}
                onChange={(e) => setKey(e.target.value)}
                required
                placeholder="LK1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <button disabled={busy}>{busy ? "Проверка…" : "Войти →"}</button>
          </form>
        </section>
      ) : (
        <section>
          <div className="eyebrow">
            {data.offline ? "OFFLINE ACCESS" : "CONNECTED"}
          </div>
          <h1>{data.user?.login || "Лицензия подтверждена"}</h1>
          <p className="muted">
            {data.offline
              ? "Используется ограниченное по времени offline-подтверждение."
              : "Доступ подтверждён сервером лицензирования."}
          </p>
          <div className="details">
            {[
              ["User ID", data.user?.id || data.user_id],
              ["License ID", data.license?.id || data.license_id],
              ["Продукт", data.license?.product?.name || data.product_id],
              ["Статус", data.license?.status || "OFFLINE"],
              [
                "Тип",
                data.license?.is_lifetime || data.lifetime
                  ? "Lifetime"
                  : "Temporary",
              ],
              [
                "Истекает",
                data.license?.expires_at ||
                  (data.license_expires_at
                    ? new Date(data.license_expires_at * 1000).toISOString()
                    : "—"),
              ],
              ...(data.offline
                ? [
                    [
                      "Offline до",
                      new Date(data.valid_until * 1000).toLocaleString(),
                    ],
                  ]
                : []),
            ].map(([label, value]) => (
              <div key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
          <div className="buttons">
            <button disabled={busy} onClick={() => run(() => invoke("resume"))}>
              Проверить
            </button>
            <button
              className="secondary"
              onClick={() =>
                run(async () => {
                  await invoke("logout");
                  return null;
                })
              }
            >
              Выйти
            </button>
          </div>
        </section>
      )}
      {error && (
        <div role="alert" className="error">
          {error}
        </div>
      )}
      <footer>
        <span>License Protocol v1</span>
        <span>Ed25519 · Server validated</span>
      </footer>
    </main>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
