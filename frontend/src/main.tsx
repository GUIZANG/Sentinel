import React from "react";
import ReactDOM from "react-dom/client";
import { ConfigProvider, theme } from "antd";
import zhCN from "antd/locale/zh_CN";
import enUS from "antd/locale/en_US";
import App from "./App";
import { LangProvider, useLang } from "./i18n";
import "antd/dist/reset.css";
import "./styles.css";

// 与 styles.css 的暖色令牌对齐，让 antd 的 Table/Tag/Button 同款观感。
function Root() {
  const { lang } = useLang();
  return (
    <ConfigProvider
      locale={lang === "en" ? enUS : zhCN}
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: "#b1563f",
          colorText: "#30251f",
          colorTextSecondary: "#74675f",
          colorBgContainer: "#fbf8f1",
          colorBgElevated: "#fbf8f1",
          colorBorder: "#dfd1be",
          colorBorderSecondary: "#eee4d5",
          borderRadius: 12,
          controlHeight: 36,
          fontFamily:
            '-apple-system, "PingFang SC", "Microsoft YaHei", Inter, Segoe UI, Roboto, Helvetica, Arial, sans-serif',
        },
        components: {
          Table: {
            headerBg: "#f6efe4",
            headerColor: "#74675f",
            borderColor: "#eee4d5",
            rowHoverBg: "#f5eadc",
          },
          Button: { primaryShadow: "none", defaultShadow: "none" },
          Select: {
            optionSelectedBg: "#f5eadc",
            optionSelectedColor: "#30251f",
            optionActiveBg: "#fbf8f1",
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
