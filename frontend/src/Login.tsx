import { useState } from "react";
import { LockOutlined, UserOutlined, EyeOutlined, EyeInvisibleOutlined, LoadingOutlined } from "@ant-design/icons";
import { login } from "./api";
import { brand } from "./brand";
import { t, LangSelect } from "./i18n";

// 纯 shadcn/ui 风格登录页：原生表单控件 + 设计令牌，不依赖 antd 外观。
export default function Login({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    if (!username || !password) {
      setError(t("请输入账号和密码"));
      return;
    }
    setLoading(true);
    try {
      await login(username, password);
      onSuccess();
    } catch (e: any) {
      setError(e.message || t("登录失败"));
    } finally {
      setLoading(false);
    }
  }

  function onKey(e: React.KeyboardEvent) {
    if (e.key === "Enter") submit();
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-brand">
          <div className="logo">{brand.logo}</div>
          <div>
            <div className="name">{brand.name}</div>
            <div className="sub">{t(brand.subtitleKey)}</div>
          </div>
          <div style={{ marginLeft: "auto" }}>
            <LangSelect />
          </div>
        </div>
        <h2 className="login-title">{t("登录控制台")}</h2>
        <p className="login-desc">{t("请输入管理员账号与密码以访问仪表盘。首次部署请查看 server/.env 中的 DEFAULT_ADMIN_USER / DEFAULT_ADMIN_PASSWORD。")}</p>

        <div className="login-field">
          <label htmlFor="login-user">{t("账号")}</label>
          <div className="ui-input-wrap">
            <span className="ui-icon"><UserOutlined /></span>
            <input
              id="login-user"
              className="ui-input"
              placeholder={t("账号")}
              value={username}
              autoFocus
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={onKey}
            />
          </div>
        </div>

        <div className="login-field">
          <label htmlFor="login-pwd">{t("密码")}</label>
          <div className="ui-input-wrap">
            <span className="ui-icon"><LockOutlined /></span>
            <input
              id="login-pwd"
              className="ui-input"
              type={showPwd ? "text" : "password"}
              placeholder={t("密码")}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={onKey}
            />
            <button type="button" className="ui-eye" onClick={() => setShowPwd((v) => !v)} tabIndex={-1} aria-label={t("切换密码可见")}>
              {showPwd ? <EyeInvisibleOutlined /> : <EyeOutlined />}
            </button>
          </div>
        </div>

        <div className="login-error">{error}</div>

        <button className="ui-btn ui-btn-primary" disabled={loading} onClick={submit}>
          {loading ? <LoadingOutlined /> : null} {t("登 录")}
        </button>
      </div>
    </div>
  );
}
