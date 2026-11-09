let csrf = "";
let pending: Promise<void> | undefined;
export function setCsrf(value: string) {
  csrf = value;
}
export class ApiError extends Error {
  constructor(
    public code: string,
    public status: number,
  ) {
    super(code);
  }
}
async function csrfToken() {
  if (!csrf) {
    const r = await fetch("/api/v1/auth/csrf", {
      credentials: "include",
      cache: "no-store",
    });
    if (!r.ok) throw new ApiError("INVALID_SESSION", r.status);
    csrf = (await r.json()).csrf_token;
  }
  return csrf;
}
async function refresh() {
  const work = async () => {
    await csrfToken();
    const r = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: "{}",
    });
    const data = await r.json();
    if (!r.ok)
      throw new ApiError(data.error?.code || "INVALID_SESSION", r.status);
    csrf = data.csrf_token;
  };
  if (!pending)
    pending = (
      navigator.locks
        ? navigator.locks
            .request("keyspace-refresh", async () => {
              await work();
            })
            .then(() => {})
        : work()
    ).finally(() => (pending = undefined));
  return pending;
}
export async function api<T = any>(
  path: string,
  method = "GET",
  body?: unknown,
  retry = true,
): Promise<T> {
  const authPublic = ["/auth/login", "/auth/register"].includes(path);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (method !== "GET" && !authPublic)
    headers["X-CSRF-Token"] = await csrfToken();
  if (method === "POST" && (path === "/licenses" || path === "/admin/licenses"))
    headers["Idempotency-Key"] = crypto.randomUUID();
  const r = await fetch("/api/v1" + path, {
    method,
    credentials: "include",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  if (r.status === 401 && !authPublic && retry) {
    await refresh();
    return api(path, method, body, false);
  }
  if (r.status === 204) return undefined as T;
  const data = await r.json();
  if (!r.ok) throw new ApiError(data.error?.code || "REQUEST_FAILED", r.status);
  if (data.csrf_token) csrf = data.csrf_token;
  return data;
}
export const messages: Record<string, string> = {
  INVALID_CREDENTIALS: "Неверный логин или пароль.",
  INVALID_SESSION: "Войдите в аккаунт снова.",
  MFA_REQUIRED: "Подтвердите вход ключом безопасности.",
  FORBIDDEN: "Недостаточно прав.",
  ISSUANCE_NOT_ALLOWED:
    "Самостоятельная выдача недоступна или квота исчерпана.",
  RATE_LIMITED: "Слишком много запросов. Попробуйте позже.",
  VERSION_CONFLICT: "Запись изменилась. Обновите страницу.",
  CSRF_REJECTED: "Сессия изменилась. Обновите страницу.",
  INVALID_REQUEST: "Проверьте введённые данные.",
  DEVICE_LIMIT_REACHED: "Достигнут лимит устройств.",
};
export function errorText(e: unknown) {
  return e instanceof ApiError
    ? messages[e.code] || `Операция не выполнена (${e.code}).`
    : "Не удалось связаться с сервером.";
}
