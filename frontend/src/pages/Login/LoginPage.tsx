import React, { useEffect, useMemo, useState } from "react";
import styles from "./LoginPage.module.css";
import { Input } from "../../components/ui/Input/Input";
import { Button } from "../../components/ui/Button/Button";
import { login } from "../../api/authApi";
import { GITHUB_OAUTH_URL } from "../../config/env";

export function LoginPage() {
    const [loginValue, setLoginValue] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [formError, setFormError] = useState<string | null>(null);

    const canSubmit = useMemo(() => {
        return loginValue.trim().length > 0 && password.trim().length > 0 && !loading;
    }, [loginValue, password, loading]);

    async function onSubmit(e: React.FormEvent) {
        e.preventDefault();
        setFormError(null);

        try {
            setLoading(true);
            const res = await login({ login: loginValue.trim(), password });

            localStorage.setItem("token", res.token);

        } catch (err) {
            const msg = err instanceof Error ? err.message : "Ошибка входа";
            setFormError(msg);
        } finally {
            setLoading(false);
        }
    }

    function onGithubLogin() {
        window.location.href = GITHUB_OAUTH_URL;
    }

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const token = params.get("token");
        const error = params.get("error");

        if (error) {
            setFormError(`OAuth ошибка: ${error}`);
        }

        if (token) {
            localStorage.setItem("token", token);
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }, []);

    return (
        <div className={styles.page}>
            <form className={styles.card} onSubmit={onSubmit}>
                <h1 className={styles.title}>Вход</h1>
                <p className={styles.subtitle}>Введите логин и пароль</p>

                <div className={styles.fields}>
                    <Input
                        label="Логин"
                        placeholder="email или username"
                        value={loginValue}
                        onChange={(e) => setLoginValue(e.target.value)}
                        autoComplete="username"
                    />
                    <Input
                        label="Пароль"
                        type="password"
                        placeholder="••••••••"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoComplete="current-password"
                    />
                </div>

                {formError ? <div className={styles.formError}>{formError}</div> : null}

                <Button type="submit" disabled={!canSubmit}>
                    {loading ? "Входим..." : "Войти"}
                </Button>

                <Button type="button" variant="secondary" onClick={onGithubLogin}>
                    Войти через GitHub
                </Button>
            </form>
        </div>


    );
}
