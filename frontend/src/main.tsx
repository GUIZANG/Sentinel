import React from "react";
import ReactDOM from "react-dom/client";
import { ConfigProvider, theme } from "antd";
import zhCN from "antd/locale/zh_CN";
import enUS from "antd/locale/en_US";
import App from "./App";
import { LangProvider, useLang } from "./i18n";
import "antd/dist/reset.css";
import "./styles.css";

// 与 styles.css 的 shadcn zinc 浅色令牌对齐，让 antd 的 Table/Tag/Button 同款观感。
function Root() {
  const { lang } = useLang();
  return (
    <ConfigProvider
      locale={lang === "en" ? enUS : zhCN}
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: "#18181b",
          colorText: "#09090b",
          colorTextSecondary: "#52525b",
          colorBgContainer: "#ffffff",
          colorBgElevated: "#ffffff",
          colorBorder: "#e4e4e7",
          colorBorderSecondary: "#f4f4f5",
          borderRadius: 8,
          controlHeight: 36,
          fontFamily:
            '-apple-system, "PingFang SC", "Microsoft YaHei", Inter, Segoe UI, Roboto, Helvetica, Arial, sans-serif',
        },
        components: {
          Table: {
            headerBg: "#fafafa",
            headerColor: "#52525b",
            borderColor: "#f4f4f5",
            rowHoverBg: "#f4f4f5",
          },
          Button: { primaryShadow: "none", defaultShadow: "none" },
          Select: {
            optionSelectedBg: "#f4f4f5",
            optionSelectedColor: "#18181b",
            optionActiveBg: "#fafafa",
          },
        },
      }}
    >
      <App />
    </ConfigProvider>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LangProvider>
      <Root />
    </LangProvider>
  </React.StrictMode>
);
