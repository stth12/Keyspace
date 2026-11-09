import "./globals.css";
export const dynamic = "force-dynamic";
export const metadata = {
  title: "Keyspace — лицензирование",
  description: "Управление доступом к вашим приложениям",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}
