import React from "react";
import styles from "./Input.module.css";

type Props = React.InputHTMLAttributes<HTMLInputElement> & {
    label: string;
    error?: string;
};

export function Input({ label, error, ...props }: Props) {
    return (
        <label className={styles.root}>
            <span className={styles.label}>{label}</span>
            <input className={styles.input} {...props} />
            {error ? <span className={styles.error}>{error}</span> : null}
        </label>
    );
}
