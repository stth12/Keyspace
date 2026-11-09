"use client";
import { useState, useEffect, useCallback, type FormEvent } from "react";
import {
  KeyRound,
  LayoutDashboard,
  Users,
  ShieldCheck,
  LogOut,
  Plus,
  ArrowUpRight,
  Layers,
  Activity,
  RefreshCw,
  Copy,
  UserRound,
  ScrollText,
} from "lucide-react";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import { Button } from "../components/ui/button";
import { api, errorText, ApiError } from "../lib/api";
import {IssueFields,canIssue} from '../components/issue-fields';
type User = {
  id: string;
  login: string;
  role: string;
  status: string;
  created_at: string;
  mfa_verified_at?: string;
};
const durations = [
  3600, 43200, 86400, 259200, 604800, 1209600, 2592000, 7776000, 15552000,
  31536000,
];
const durationLabel = (n: number) =>
  n < 86400 ? `${n / 3600} ч.` : `${n / 86400} дней`;
const date = (d?: string | null) =>
  d ? new Date(d).toLocaleString("ru-RU") : "—";
const statusName: Record<string, string> = {
  ACTIVE: "Активна",
  NOT_ACTIVATED: "Не активирована",
  EXPIRED: "Истекла",
  BLOCKED: "Заблокирована",
  REVOKED: "Отозвана",
};
export default function Home() {
  const [user, setUser] = useState<User | null>(null),
    [loading, setLoading] = useState(true),
    [register, setRegister] = useState(false),
    [view, setView] = useState("licenses"),
    [rows, setRows] = useState<any[]>([]),
    [products, setProducts] = useState<any[]>([]),
    [stats, setStats] = useState<any>(null),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [modal, setModal] = useState<any>(null),
    [newKey, setNewKey] = useState(""),
    [search, setSearch] = useState(""),
    [filter, setFilter] = useState(""),
    [cursor, setCursor] = useState(""),
    [next, setNext] = useState<string | null>(null),
    [mfa, setMfa] = useState(false);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
      if (e instanceof ApiError && e.code === "MFA_REQUIRED") setMfa(true);
    } finally {
      setBusy(false);
    }
  };
  const load = useCallback(async () => {
    if (!user) return;
    const q = new URLSearchParams({ limit: "25" });
    if (cursor) q.set("cursor", cursor);
    if (search && view === "users") q.set("search", search);
    if (filter && ["licenses", "admin", "users"].includes(view))
      q.set("status", filter);
    const path =
      view === "users"
        ? "/admin/users"
        : view === "audit"
          ? "/admin/audit-logs"
          : view === "events"
            ? "/admin/security-events"
            : view === "admin"
              ? "/admin/licenses"
              : "/licenses";
    if (view !== "profile") {
      const r = await api(path + "?" + q);
      setRows(Array.isArray(r) ? r : r.items);
      setNext(r.next_cursor || null);
    }
    setProducts(await api("/products"));
    if (
      user.role === "ADMIN" &&
      ["admin", "users", "audit", "events"].includes(view)
    ) {
      setStats(await api("/admin/statistics"));
    }
  }, [user, view, cursor, search, filter]);
  useEffect(() => {
    api<User>("/auth/me")
      .then(setUser)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    if (user)
      load().catch((e) => {
        setError(errorText(e));
        if (e instanceof ApiError && e.code === "MFA_REQUIRED") setMfa(true);
      });
  }, [load, user]);
  const changeView = (v: string) => {
    setView(v);
    setCursor("");
    setSearch("");
    setFilter("");
    setRows([]);
    setError("");
  };
  async function submitAuth(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    await run(async () => {
      const body = {
        login: f.get("login"),
        password: f.get("password"),
        ...(register ? { confirm_password: f.get("confirm") } : {}),
      };
      const data = await api(
        register ? "/auth/register" : "/auth/login",
        "POST",
        body,
      );
      if (register) {
        setNotice(data.message);
        setRegister(false);
      } else setUser(data.user);
    });
  }
  async function mfaLogin(enroll: boolean, bootstrap = "") {
    await run(async () => {
      if (enroll) {
        const options = await api("/auth/mfa/enroll/challenge", "POST", {
          bootstrap,
        });
        const response = await startRegistration({ optionsJSON: options });
        await api("/auth/mfa/enroll/verify", "POST", { bootstrap, response });
      } else {
        const options = await api("/auth/mfa/challenge", "POST", {});
        const response = await startAuthentication({ optionsJSON: options });
        await api("/auth/mfa/verify", "POST", response);
      }
      setMfa(false);
      setUser(await api("/auth/me"));
    });
  }
  async function submitModal(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    await run(async () => {
      if (modal.type === "issue") {
        const isAdmin = view === "admin";
        const value = String(f.get("duration"));
        const duration =
          value === "custom"
            ? Number(f.get("custom"))
            : value === "lifetime"
              ? null
              : Number(value);
        const body = {
          product_id: f.get("product"),
          duration_seconds: duration,
          is_lifetime: value === "lifetime",
          ...(isAdmin
            ? {
                user_id: f.get("owner"),
                max_devices: f.get("max") === "" ? null : Number(f.get("max")),
                reason: f.get("reason"),
              }
            : {}),
        };
        const r = await api(
          isAdmin ? "/admin/licenses" : "/licenses",
          "POST",
          body,
        );
        setNewKey(r.license_key || "");
      } else if (modal.type === "entitlement") {
        await api(
          `/admin/users/${modal.row.id}/entitlements/${f.get("product")}`,
          "PUT",
          {
            remaining: Number(f.get("quota")),
            durations: durations,
            lifetime: f.get("lifetime") === "on",
            max_devices: Number(f.get("max")),
            reason: f.get("reason"),
          },
        );
      } else if (modal.type === "user") {
        await api(`/admin/users/${modal.row.id}/${modal.action}`, "POST", {
          reason: f.get("reason"),
          expected_version: modal.row.authVersion,
        });
      } else if (modal.type === "device") {
        await api(
          `/admin/licenses/${modal.row.id}/devices/${modal.device.deviceId}/${modal.action}`,
          "POST",
          { reason: f.get("reason") },
        );
      } else if (modal.type === "patch") {
        const operation = String(f.get("operation"));
        await api(`/admin/licenses/${modal.row.id}`, "PATCH", {
          operation,
          reason: f.get("reason"),
          expected_version: modal.row.version,
          ...(operation === "extend_by_seconds" ||
          operation === "set_unactivated_duration"
            ? { duration_seconds: Number(f.get("seconds")) }
            : {}),
          ...(operation === "set_expires_at"
            ? { expires_at: new Date(String(f.get("expires"))).toISOString() }
            : {}),
          ...(operation === "set_max_devices"
            ? { max_devices: f.get("max") === "" ? null : Number(f.get("max")) }
            : {}),
        });
      } else {
        await api(`/admin/licenses/${modal.row.id}/${modal.action}`, "POST", {
          reason: f.get("reason"),
          expected_version: modal.row.version,
        });
      }
      setModal(null);
      await load();
    });
  }
  if (loading) return <div className="loading">Подключение к Keyspace…</div>;
  if (!user)
    return (
      <div className="auth">
        <section className="auth-art">
          <div className="brand">
            <KeyRound />
            Keyspace
          </div>
          <div>
            <div className="eyebrow">LICENSE CONTROL / LP1</div>
            <h1>
              Доступ под
              <br />
              вашим контролем.
            </h1>
            <p>
              Лицензии, приложения и устройства — в одном пространстве. От
              первого ключа до полного управления доступом.
            </p>
          </div>
          <div className="tiny muted">
            OnlineKeyGen · Единый сервер лицензирования
          </div>
        </section>
        <section className="auth-form">
          <div className="auth-box">
            <h2>{register ? "Создать аккаунт" : "С возвращением"}</h2>
            <p className="muted">
              {register
                ? "Постоянный User ID будет создан автоматически."
                : "Войдите, чтобы управлять своими лицензиями."}
            </p>
            {error && (
              <div role="alert" className="notice error">
                {error}
              </div>
            )}
            {notice && <div className="notice">{notice}</div>}
            <form onSubmit={submitAuth} className="form">
              <label>
                Логин
                <input
                  name="login"
                  required
                  pattern="[A-Za-z0-9][A-Za-z0-9_]{2,31}"
                  autoComplete="username"
                  placeholder="your_login"
                />
              </label>
              <label>
                Пароль
                <input
                  type="password"
                  name="password"
                  required
                  minLength={register ? 15 : 1}
                  maxLength={128}
                  autoComplete={register ? "new-password" : "current-password"}
                />
              </label>
              {register && (
                <label>
                  Подтвердите пароль
                  <input
                    type="password"
                    name="confirm"
                    minLength={15}
                    required
                    autoComplete="new-password"
                  />
                </label>
              )}
              <Button disabled={busy}>
                {register ? "Зарегистрироваться" : "Войти"}
                <ArrowUpRight size={16} />
              </Button>
            </form>
            <Button
              variant="ghost"
              onClick={() => {
                setRegister(!register);
                setError("");
              }}
            >
              {register
                ? "Уже есть аккаунт? Войти"
                : "Нет аккаунта? Зарегистрироваться"}
            </Button>
            <p className="tiny muted">
              Логин: 3–32 латинских символа, цифры и _. Пароль при регистрации:
              от 15 символов.
            </p>
          </div>
        </section>
      </div>
    );
  const adminView = ["admin", "users", "audit", "events"].includes(view);
  const titles: Record<string, string> = {
    licenses: "Мои лицензии",
    profile: "Профиль",
    admin: "Управление лицензиями",
    users: "Пользователи",
    audit: "Журнал аудита",
    events: "События безопасности",
  };
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <KeyRound />
          Keyspace
        </div>
        <div>
          <div className="eyebrow">Рабочее пространство</div>
          <nav className="nav">
            <button
              className={view === "licenses" ? "active" : ""}
              onClick={() => changeView("licenses")}
            >
              <Layers size={17} />
              Мои лицензии
            </button>
            <button
              className={view === "profile" ? "active" : ""}
              onClick={() => changeView("profile")}
            >
              <UserRound size={17} />
              Профиль
            </button>
          </nav>
        </div>
        {user.role === "ADMIN" && (
          <div>
            <div className="eyebrow">Администрирование</div>
            <nav className="nav">
              {[
                ["admin", "Лицензии", ShieldCheck],
                ["users", "Пользователи", Users],
                ["audit", "Аудит", ScrollText],
                ["events", "Безопасность", Activity],
              ].map(([v, t, Icon]: any) => (
                <button
                  key={v}
                  className={view === v ? "active" : ""}
                  onClick={() => changeView(v)}
                >
                  <Icon size={17} />
                  {t}
                </button>
              ))}
            </nav>
          </div>
        )}
        <div className="sidebar-footer">
          <div className="tiny muted">LICENSE PROTOCOL</div>
          <p style={{ marginTop: 10 }}>
            LP1 <span className="badge ACTIVE">v1</span>
          </p>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="live">
            <span className="dot" />
            Панель управления
          </div>
          <div className="actions">
            <Button variant="ghost" onClick={() => changeView("profile")}>
              {user.login} <span className="badge">{user.role}</span>
            </Button>
            <Button
              aria-label="Выйти"
              variant="ghost"
              onClick={() =>
                run(async () => {
                  await api("/auth/logout", "POST", {});
                  setUser(null);
                })
              }
            >
              <LogOut size={17} />
            </Button>
          </div>
        </header>
        <div className="content">
          <div className="heading">
            <div>
              <div className="eyebrow">
                {adminView ? "CONTROL CENTER" : "YOUR WORKSPACE"}
              </div>
              <h1>{titles[view]}</h1>
              <p>
                {view === "licenses"
                  ? "Ваши приложения, сроки действия и устройства."
                  : view === "admin"
                    ? "Выпускайте ключи и управляйте доступом пользователей."
                    : view === "users"
                      ? "Учётные записи и права на самостоятельную выдачу."
                      : view === "profile"
                        ? "Данные вашей учётной записи."
                        : "История действий и сигналов системы."}
              </p>
            </div>
            {["licenses", "admin"].includes(view) && (
              <Button disabled={view!=='admin'&&!products.some(canIssue)} onClick={() => setModal({ type: "issue" })}>
                <Plus size={17} />
                Новая лицензия
              </Button>
            )}
          </div>
          {error && (
            <div className="notice error" role="alert">
              {error}
            </div>
          )}
          {adminView && stats && (
            <div className="cards">
              {[
                ["Пользователи", stats.total_users, Users],
                ["Всего лицензий", stats.total_licenses, KeyRound],
                ["Активные", stats.statuses.ACTIVE || 0, Activity],
                ["Lifetime", stats.lifetime, ShieldCheck],
              ].map(([t, n, Icon]: any) => (
                <div className="card" key={t}>
                  <div className="tiny muted">
                    {t}
                    <Icon size={16} />
                  </div>
                  <strong>{n}</strong>
                </div>
              ))}
            </div>
          )}
          {adminView && stats && (
            <div className="filters">
              {Object.entries(stats.statuses).map(([s, n]) => (
                <span className={"badge " + s} key={s}>
                  {statusName[s]}: {String(n)}
                </span>
              ))}
            </div>
          )}
          {view === "profile" ? (
            <div className="panel">
              <div className="panelhead">
                <h2>Учётная запись</h2>
                <span className="badge">{user.role}</span>
              </div>
              <div className="profilegrid">
                {[
                  ["Логин", user.login],
                  ["User ID", user.id],
                  ["Дата регистрации", date(user.created_at)],
                  ["Статус", user.status],
                ].map(([a, b]) => (
                  <div key={a}>
                    <div className="tiny muted">{a}</div>
                    <div className="mono">{b}</div>
                  </div>
                ))}
              </div>
              {user.role === "ADMIN" && (
                <div className="panelhead">
                  <p className="muted">
                    WebAuthn для административных действий
                  </p>
                  <Button variant="outline" onClick={() => setMfa(true)}>
                    Настроить / подтвердить
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <>
              <div className="filters">
                {view === "users" && (
                  <input
                    aria-label="Поиск по логину"
                    placeholder="Поиск по логину…"
                    value={search}
                    onChange={(e) => {
                      setSearch(e.target.value);
                      setCursor("");
                    }}
                  />
                )}
                {["licenses", "admin", "users"].includes(view) && (
                  <select
                    aria-label="Фильтр статуса"
                    value={filter}
                    onChange={(e) => {
                      setFilter(e.target.value);
                      setCursor("");
                    }}
                  >
                    <option value="">Все статусы</option>
                    {Object.entries(statusName)
                      .filter(
                        ([s]) =>
                          view !== "users" || ["ACTIVE", "BLOCKED"].includes(s),
                      )
                      .map(([s, t]) => (
                        <option key={s} value={s}>
                          {t}
                        </option>
                      ))}
                  </select>
                )}
                <Button variant="outline" onClick={() => run(load)}>
                  <RefreshCw size={15} />
                  Обновить
                </Button>
              </div>
              <div className="panel">
                <div className="panelhead">
                  <h2>{titles[view]}</h2>
                  <span className="tiny muted">{rows.length} на странице</span>
                </div>
                {rows.length === 0 ? (
                  <div className="empty">
                    <KeyRound size={32} />
                    <h2>Пока нет записей</h2>
                    <p>Новые записи появятся здесь после создания.</p>
                  </div>
                ) : (
                  <div className="tablewrap">
                    <table>
                      <thead>
                        <tr>
                          {(view === "users"
                            ? [
                                "Пользователь",
                                "User ID",
                                "Роль",
                                "Статус",
                                "Лицензии",
                                "Действия",
                              ]
                            : ["audit", "events"].includes(view)
                              ? ["Время", "Действие", "Цель", "Данные"]
                              : [
                                  "Ключ / License ID",
                                  "Продукт",
                                  "Статус",
                                  "Создана / Активирована",
                                  "Истекает",
                                  "Устройства",
                                  ...(view === "admin"
                                    ? ["Владелец", "Действия"]
                                    : []),
                                ]
                          ).map((h) => (
                            <th key={h}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((r) => (
                          <tr key={r.id}>
                            {view === "users" ? (
                              <>
                                <td>{r.login}</td>
                                <td className="mono">{r.id}</td>
                                <td>{r.role}</td>
                                <td>
                                  <span className={"badge " + r.status}>
                                    {r.status}
                                  </span>
                                </td>
                                <td>{r._count.licenses}</td>
                                <td>
                                  <div className="actions">
                                    <Button
                                      variant="outline"
                                      onClick={() =>
                                        setModal({
                                          type: "user",
                                          row: r,
                                          action:
                                            r.status === "ACTIVE"
                                              ? "block"
                                              : "unblock",
                                        })
                                      }
                                    >
                                      {r.status === "ACTIVE"
                                        ? "Блокировать"
                                        : "Разблокировать"}
                                    </Button>
                                    <Button
                                      variant="outline"
                                      onClick={() =>
                                        setModal({
                                          type: "entitlement",
                                          row: r,
                                        })
                                      }
                                    >
                                      Квота
                                    </Button>
                                  </div>
                                </td>
                              </>
                            ) : ["audit", "events"].includes(view) ? (
                              <>
                                <td>{date(r.createdAt)}</td>
                                <td>{r.action || r.type}</td>
                                <td className="mono">{r.targetId || "—"}</td>
                                <td className="mono">
                                  {JSON.stringify(r.metadata)}
                                </td>
                              </>
                            ) : (
                              <>
                                <td>
                                  <div className="mono">{r.masked_key}</div>
                                  <div
                                    className="tiny muted"
                                    style={{ marginTop: 8 }}
                                  >
                                    {r.id}
                                  </div>
                                </td>
                                <td>{r.product?.name}</td>
                                <td>
                                  <span className={"badge " + r.status}>
                                    {statusName[r.status]}
                                  </span>
                                </td>
                                <td>
                                  {date(r.created_at)}
                                  <div
                                    className="muted"
                                    style={{ marginTop: 8 }}
                                  >
                                    {date(r.activated_at)}
                                  </div>
                                </td>
                                <td>
                                  {r.is_lifetime
                                    ? "Lifetime"
                                    : date(r.expires_at)}
                                  <div
                                    className="muted"
                                    style={{ marginTop: 8 }}
                                  >
                                    {r.duration_seconds
                                      ? durationLabel(r.duration_seconds)
                                      : ""}
                                  </div>
                                </td>
                                <td>
                                  <Button
                                    variant="ghost"
                                    onClick={() =>
                                      setModal({ type: "devices", row: r })
                                    }
                                  >
                                    {r.devices?.filter((d: any) => !d.revokedAt)
                                      .length || 0}{" "}
                                    / {r.max_devices ?? "∞"}
                                  </Button>
                                </td>
                                {view === "admin" && (
                                  <>
                                    <td>
                                      {r.owner?.login}
                                      <div className="tiny muted">
                                        {r.user_id}
                                      </div>
                                    </td>
                                    <td>
                                      <div className="actions">
                                        {r.status !== "REVOKED" && (
                                          <>
                                            <Button
                                              variant="outline"
                                              onClick={() =>
                                                setModal({
                                                  type: "action",
                                                  action:
                                                    r.status === "BLOCKED"
                                                      ? "unblock"
                                                      : "block",
                                                  row: r,
                                                })
                                              }
                                            >
                                              {r.status === "BLOCKED"
                                                ? "Разблок."
                                                : "Блок."}
                                            </Button>
                                            <Button
                                              variant="outline"
                                              onClick={() =>
                                                setModal({
                                                  type: "patch",
                                                  row: r,
                                                })
                                              }
                                            >
                                              Изменить
                                            </Button>
                                            <Button
                                              variant="destructive"
                                              onClick={() =>
                                                setModal({
                                                  type: "action",
                                                  action: "revoke",
                                                  row: r,
                                                })
                                              }
                                            >
                                              Отозвать
                                            </Button>
                                          </>
                                        )}
                                      </div>
                                    </td>
                                  </>
                                )}
                              </>
                            )}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="pagination">
                  <Button variant="ghost" onClick={() => setCursor("")}>
                    В начало
                  </Button>
                  <Button
                    variant="outline"
                    disabled={!next}
                    onClick={() => setCursor(next || "")}
                  >
                    Следующая →
                  </Button>
                </div>
              </div>
            </>
          )}
        </div>
      </main>
      {newKey && (
        <div className="overlay">
          <div className="modal">
            <h2>Лицензия создана</h2>
            <p className="muted">
              Сохраните ключ сейчас. Повторно увидеть полный ключ нельзя.
            </p>
            <div className="key">{newKey}</div>
            <div className="modal-actions">
              <Button
                variant="outline"
                onClick={() => navigator.clipboard.writeText(newKey)}
              >
                <Copy size={15} />
                Копировать
              </Button>
              <Button onClick={() => setNewKey("")}>Я сохранил ключ</Button>
            </div>
          </div>
        </div>
      )}
      {mfa && (
        <div className="overlay">
          <div className="modal">
            <h2>Подтверждение администратора</h2>
            <p className="muted" style={{ marginBottom: 20 }}>
              Используйте ключ безопасности или passkey. Для первой настройки
              нужен одноразовый код из операционной CLI.
            </p>
            <Button disabled={busy} onClick={() => mfaLogin(false)}>
              Подтвердить WebAuthn
            </Button>
            <form
              className="form"
              style={{ marginTop: 24 }}
              onSubmit={(e) => {
                e.preventDefault();
                mfaLogin(
                  true,
                  String(new FormData(e.currentTarget).get("bootstrap")),
                );
              }}
            >
              <label>
                Код первоначальной настройки
                <input name="bootstrap" type="password" autoComplete="off" />
              </label>
              <Button variant="outline" disabled={busy}>
                Добавить authenticator
              </Button>
            </form>
            {error && (
              <p className="notice error" style={{ marginTop: 16 }}>
                {error}
              </p>
            )}
            <div className="modal-actions">
              <Button variant="ghost" onClick={() => setMfa(false)}>
                Закрыть
              </Button>
            </div>
          </div>
        </div>
      )}
      {modal && (
        <div className="overlay">
          <div className="modal">
            <h2>
              {modal.type === "issue"
                ? "Новая лицензия"
                : modal.type === "devices"
                  ? "Устройства лицензии"
                  : "Изменение доступа"}
            </h2>
            {modal.type === "devices" ? (
              <>
                {modal.row.devices?.map((d: any) => (
                  <div key={d.id} className="notice">
                    <div className="mono">{d.deviceId}</div>
                    <p className="tiny muted">
                      Первое: {date(d.firstSeenAt)} · Последнее:{" "}
                      {date(d.lastSeenAt)}
                    </p>
                    <p>{d.revokedAt ? "Отозвано" : "Активно"}</p>
                    {adminView && (
                      <Button
                        variant="outline"
                        onClick={() =>
                          setModal({
                            type: "device",
                            row: modal.row,
                            device: d,
                            action: d.revokedAt ? "restore" : "revoke",
                          })
                        }
                      >
                        {d.revokedAt ? "Восстановить" : "Отозвать"}
                      </Button>
                    )}
                  </div>
                ))}
                <Button onClick={() => setModal(null)}>Закрыть</Button>
              </>
            ) : (
              <form onSubmit={submitModal} className="form">
                {modal.type === "entitlement" && (
                  <label>
                    Продукт
                    <select name="product" required>
                      {products.map((p) => (
                        <option value={p.id} key={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  </label>
                )}
                {modal.type === "issue" && <IssueFields products={products} admin={view==='admin'}/>}
                {modal.type === "entitlement" && (
                  <>
                    <label>
                      Доступных выдач
                      <input
                        name="quota"
                        type="number"
                        min="0"
                        defaultValue="1"
                        required
                      />
                    </label>
                    <label>
                      Лимит устройств
                      <input
                        name="max"
                        type="number"
                        min="1"
                        defaultValue="1"
                        required
                      />
                    </label>
                    <label>
                      <span>
                        <input
                          style={{ width: "auto" }}
                          type="checkbox"
                          name="lifetime"
                        />{" "}
                        Разрешить Lifetime
                      </span>
                    </label>
                    <p className="tiny muted">
                      Разрешаются все стандартные сроки. Квота применяется
                      сервером.
                    </p>
                  </>
                )}
                {modal.type === "patch" && (
                  <>
                    <label>
                      Операция
                      <select name="operation">
                        <option value="extend_by_seconds">Продлить</option>
                        <option value="set_expires_at">
                          Изменить дату окончания
                        </option>
                        <option value="set_unactivated_duration">
                          Срок до активации
                        </option>
                        <option value="set_lifetime">Выдать Lifetime</option>
                        <option value="set_max_devices">Лимит устройств</option>
                      </select>
                    </label>
                    <label>
                      Секунд
                      <input
                        name="seconds"
                        type="number"
                        min="1"
                        defaultValue="86400"
                      />
                    </label>
                    <label>
                      Новая дата окончания
                      <input name="expires" type="datetime-local" />
                    </label>
                    <label>
                      Устройства (пусто — без лимита)
                      <input
                        name="max"
                        type="number"
                        min="1"
                        defaultValue={modal.row.max_devices ?? ""}
                      />
                    </label>
                  </>
                )}
                {(modal.type !== "issue" || view === "admin") && (
                  <label>
                    Причина
                    <input
                      name="reason"
                      minLength={3}
                      maxLength={500}
                      required
                    />
                  </label>
                )}
                {error && <div className="notice error">{error}</div>}
                <div className="modal-actions">
                  <Button
                    variant="ghost"
                    type="button"
                    onClick={() => setModal(null)}
                  >
                    Отмена
                  </Button>
                  <Button
                    disabled={
                      busy || (products.length === 0 && modal.type === "issue")
                    }
                  >
                    Подтвердить
                  </Button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
