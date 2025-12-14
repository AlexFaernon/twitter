import React from "react";
import styles from "./Button.module.css";

type Props = React.ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: "primary" | "secondary";
};

export function Button({ variant = "primary", className, ...props }: Props) {
    const cn = [styles.btn, styles[variant], className].filter(Boolean).join(" ");
    return <button className={cn} {...props} />;
}
