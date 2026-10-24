from __future__ import annotations

import logging
import os
import sys
import time
import webbrowser
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, TOP, X, filedialog, messagebox
import tkinter as tk

log = logging.getLogger(__name__)

BG = "#090d12"
PANEL = "#101720"
PANEL_2 = "#141d28"
BORDER = "#26323f"
TEXT = "#e7eef7"
MUTED = "#8294a8"
ACCENT = "#36e6c2"
ACCENT_DARK = "#052d29"
BLUE = "#7c9cff"
AMBER = "#f0b35b"
DANGER = "#ff6b6b"
GREEN = "#4be2a2"

FONT = "Microsoft YaHei UI"


class ControlWindow:
    def __init__(self, app) -> None:
        self.app = app
        if sys.platform == "win32":
            try:
                import ctypes

                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        self.root = tk.Tk()
        self.root.title("EgressScope · 本机数据外发审计")
        self.root.configure(bg=BG)
        self.root.geometry("810x930")
        self.root.minsize(760, 800)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._closing = False
        self._values: dict[str, tk.Label] = {}
        self._buttons: dict[str, tk.Button] = {}
        self._build()
        self._refresh()

    # ---------- ui construction ----------
    def _build(self) -> None:
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill=BOTH, expand=True, padx=30, pady=24)

        header = tk.Frame(outer, bg=BG)
        header.pack(fill=X)
        logo = tk.Canvas(header, width=46, height=46, bg=BG, highlightthickness=0)
        logo.pack(side=LEFT, padx=(0, 12))
        logo.create_oval(4, 4, 42, 42, outline="#1f5e55", width=2)
        logo.create_oval(12, 12, 34, 34, outline=ACCENT, width=2)
        logo.create_oval(20, 20, 26, 26, fill=ACCENT, outline="")
        logo.create_line(23, 23, 42, 4, fill=ACCENT, width=2)
        title_box = tk.Frame(header, bg=BG)
        title_box.pack(side=LEFT)
        tk.Label(title_box, text="EgressScope", bg=BG, fg=TEXT, font=(FONT, 23, "bold")).pack(anchor="w")
        tk.Label(
            title_box,
            text="AI Agent / 本机应用 · 数据外发审计",
            bg=BG,
            fg=MUTED,
            font=(FONT, 10),
        ).pack(anchor="w", pady=(2, 0))
        tk.Label(header, text=f"v{self.app.status_snapshot().get('version', '')}", bg=BG, fg=MUTED, font=("Consolas", 9)).pack(side=RIGHT, anchor="n")

        banner = tk.Frame(outer, bg="#0f2a27", highlightthickness=1, highlightbackground="#1b5b52")
        banner.pack(fill=X, pady=(20, 16))
        self.banner_text = tk.Label(
            banner,
            text="本机审计已就绪。下一步：安装本地 CA，然后启用系统代理或使用 Agent 环境变量。",
            bg="#0f2a27",
            fg="#bdf5e9",
            font=(FONT, 10),
            anchor="w",
            justify="left",
            wraplength=700,
            padx=14,
            pady=11,
        )
        self.banner_text.pack(fill=X)

        status_grid = tk.Frame(outer, bg=BG)
        status_grid.pack(fill=X)
        for index in range(2):
            status_grid.columnconfigure(index, weight=1)
        self._card(status_grid, 0, 0, "proxy", "本地代理", "—")
        self._card(status_grid, 0, 1, "capture", "审计状态", "—")
        self._card(status_grid, 1, 0, "ca", "HTTPS 解密 CA", "—")
        self._card(status_grid, 1, 1, "sysproxy", "Windows 系统代理", "—")
        self._card(status_grid, 2, 0, "fileguard", "文件句柄守护 · Beta", "—")
        self._card(status_grid, 2, 1, "chain", "证据链状态", "—", padx_left=0)
        self._card(status_grid, 3, 0, "autostart", "开机自启（当前用户）", "—")
        self._card(status_grid, 3, 1, "reload", "配置热更新", "—", padx_left=0)

        controls = tk.Frame(outer, bg=BG)
        controls.pack(fill=BOTH, expand=True, pady=(22, 0))
        tk.Label(controls, text="控制台", bg=BG, fg=TEXT, font=(FONT, 12, "bold")).pack(anchor="w", pady=(0, 10))
        grid = tk.Frame(controls, bg=BG)
        grid.pack(fill=X)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        self._action(grid, 0, 0, "dashboard", "打开审计控制台", self._open_dashboard, kind="accent")
        self._action(grid, 0, 1, "intro", "查看项目介绍", self._open_intro)
        self._action(grid, 1, 0, "enable_proxy", "启用系统代理", self._enable_proxy)
        self._action(grid, 1, 1, "restore_proxy", "恢复原始系统代理", self._restore_proxy)
        self._action(grid, 2, 0, "install_ca", "安装本地 CA（当前用户）", self._install_ca)
        self._action(grid, 2, 1, "remove_ca", "移除本地 CA", self._remove_ca)
        self._action(grid, 3, 0, "env", "复制 Agent 环境变量", self._copy_env)
        self._action(grid, 3, 1, "export", "导出审计证据（JSONL）", self._export)
        self._action(grid, 4, 0, "capture", "暂停审计", self._toggle_capture)
        self._action(grid, 4, 1, "data", "打开数据目录", self._open_data)
        self._action(grid, 5, 0, "autostart", "关闭开机自启", self._toggle_autostart)
        self._action(grid, 5, 1, "guard", "注册断网保护", self._toggle_guard)

        note = tk.Frame(outer, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        note.pack(fill=X, pady=(20, 10))
        tk.Label(
            note,
            text=(
                "覆盖边界：只审计经过本地代理的 HTTP/HTTPS。未信任 CA、证书固定、mTLS、QUIC/HTTP3、"
                "E2EE 内容、服务/SYSTEM 进程与内核级程序不在可见范围内。文件守护为打开句柄抽样，"
                "不是完整文件读取审计。仅用于已授权设备。"
            ),
            bg=PANEL,
            fg=MUTED,
            font=(FONT, 9),
            justify="left",
            anchor="w",
            wraplength=700,
            padx=14,
            pady=11,
        ).pack(fill=X)
        footer = tk.Frame(outer, bg=BG)
        footer.pack(fill=X)
        tk.Label(footer, text="Local-only by default · 数据保存在本机", bg=BG, fg="#54657a", font=(FONT, 9)).pack(side=LEFT)
        tk.Label(footer, text="仅限授权审计", bg=BG, fg="#54657a", font=(FONT, 9)).pack(side=RIGHT)

    def _card(self, parent, row: int, col: int, key: str, title: str, value: str, padx_left: int = 0) -> None:
        padx = (0, 8) if col == 0 else (8, 0)
        card = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        card.grid(row=row, column=col, sticky="nsew", padx=padx, pady=5)
        tk.Label(card, text=title, bg=PANEL, fg=MUTED, font=(FONT, 9)).pack(anchor="w", padx=14, pady=(11, 2))
        label = tk.Label(card, text=value, bg=PANEL, fg=TEXT, font=(FONT, 11, "bold"), anchor="w", justify="left")
        label.pack(fill=X, padx=14, pady=(0, 11))
        self._values[key] = label

    def _action(self, parent, row: int, col: int, key: str, text: str, command, kind: str = "default") -> None:
        bg = ACCENT if kind == "accent" else PANEL_2
        fg = ACCENT_DARK if kind == "accent" else TEXT
        active = "#5cf0d1" if kind == "accent" else "#1d2a38"
        padx = (0, 8) if col == 0 else (8, 0)
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active,
            activeforeground=fg,
            disabledforeground="#536171",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER if kind != "accent" else "#2a8c7c",
            font=(FONT, 10),
            cursor="hand2",
            padx=14,
            pady=11,
            anchor="center",
        )
        button.grid(row=row, column=col, sticky="nsew", padx=padx, pady=5)
        self._buttons[key] = button

    # ---------- refresh ----------
    def _refresh(self) -> None:
        if self._closing:
            return
        try:
            status = self.app.status_snapshot()
            self._apply_status(status)
        except Exception:
            log.exception("status refresh failed")
        self.root.after(2000, self._refresh)

    def _apply_status(self, status: dict) -> None:
        proxy_ok = bool(status.get("proxy_running"))
        if proxy_ok:
            self._values["proxy"].configure(text=f"运行中  ·  {status.get('proxy_url')}", fg=GREEN)
        else:
            error = status.get("proxy_error") or "未启动"
            self._values["proxy"].configure(text="异常：" + error[:70], fg=DANGER)
        capture = bool(status.get("capture_enabled"))
        blocking = "阻断开启" if status.get("blocking_enabled") else "仅告警"
        self._values["capture"].configure(
            text=f"{'采集中' if capture else '已暂停'}  ·  {blocking}",
            fg=GREEN if capture else AMBER,
        )
        ca = bool(status.get("ca_installed"))
        self._values["ca"].configure(
            text="已安装（当前用户 Root）" if ca else "未安装 · 仅能看元数据",
            fg=GREEN if ca else AMBER,
        )
        state = status.get("system_proxy") or {}
        guard = status.get("proxy_guard") or {}
        guard_ok = bool(guard.get("installed"))
        if state.get("ours"):
            text, color = ("已启用 · 断网保护开启" if guard_ok else "已启用 · 无断网保护"), GREEN if guard_ok else AMBER
        elif state.get("auto_config_url"):
            text, color = "PAC 自动配置已启用 · 静态代理不可用", AMBER
        elif state.get("enabled"):
            text, color = "其他代理已启用", AMBER
        else:
            text, color = "未启用", MUTED
        if status.get("proxy_backup") and not state.get("ours"):
            text += " · 存在待恢复备份"
            color = AMBER
        self._values["sysproxy"].configure(text=text, fg=color)
        fg_status = status.get("fileguard") or {}
        if fg_status.get("enabled"):
            self._values["fileguard"].configure(
                text=f"运行中  ·  {fg_status.get('events', 0)} 个文件事件  ·  句柄抽样",
                fg=GREEN,
            )
        else:
            self._values["fileguard"].configure(text="已关闭", fg=MUTED)
        chain = status.get("chain") or {}
        if chain.get("valid"):
            self._values["chain"].configure(text=f"SHA-256 链完整 · {chain.get('entries', 0)} 条", fg=GREEN)
        elif chain:
            self._values["chain"].configure(text="校验失败 · 数据可能被修改", fg=DANGER)
        else:
            self._values["chain"].configure(text="暂无审计记录", fg=MUTED)
        autostart = status.get("autostart") or {}
        if not autostart.get("supported", True):
            self._values["autostart"].configure(text="仅 Windows 支持", fg=MUTED)
        elif autostart.get("enabled"):
            self._values["autostart"].configure(text="已注册 · 登录时自动启动", fg=GREEN)
        else:
            self._values["autostart"].configure(text="未注册", fg=MUTED)
        reload_info = status.get("config_reload") or {}
        if reload_info.get("error"):
            stamp = time.strftime("%H:%M:%S", time.localtime(reload_info.get("at")))
            self._values["reload"].configure(text=f"{stamp} · 配置有误 · 保留原设置", fg=DANGER)
        elif reload_info.get("at"):
            stamp = time.strftime("%H:%M:%S", time.localtime(reload_info.get("at")))
            source = "配置文件" if reload_info.get("source") == "file" else "控制台"
            keys = len(reload_info.get("keys") or [])
            self._values["reload"].configure(text=f"{stamp} · {source} · {keys} 项已生效", fg=GREEN)
        else:
            self._values["reload"].configure(text="无需重启 · 等待配置变更", fg=MUTED)

        self._buttons["capture"].configure(text="暂停审计" if capture else "继续审计")
        self._buttons["enable_proxy"].configure(state="normal" if proxy_ok else "disabled")
        self._buttons["restore_proxy"].configure(state="normal" if status.get("proxy_backup") else "disabled")
        self._buttons["install_ca"].configure(state="disabled" if ca else "normal")
        self._buttons["remove_ca"].configure(state="normal" if ca else "disabled")
        self._buttons["dashboard"].configure(state="normal" if status.get("web_url") else "disabled")
        self._buttons["intro"].configure(state="normal" if status.get("web_url") else "disabled")
        self._buttons["autostart"].configure(
            text="关闭开机自启" if autostart.get("enabled") else "开启开机自启",
            state="normal" if autostart.get("supported", True) else "disabled",
        )
        self._buttons["guard"].configure(
            text="移除断网保护" if guard_ok else "注册断网保护",
            state="normal" if status.get("proxy_backup") else "disabled",
        )

        guard_note = ""
        if state.get("ours"):
            guard_note = (
                "\n断网保护已启用：崩溃、强制结束、断电或关机注销后都会自动恢复原始代理。"
                if guard_ok
                else "\n注意：断网保护未启用；异常退出或断电后 Windows 可能无法上网，需手动恢复代理。"
            )
        if proxy_ok and not ca:
            self.banner_text.configure(text="代理运行中。要实现 HTTPS 内容审计，请先安装本地 CA，再启用系统代理或复制 Agent 环境变量。" + guard_note)
        elif proxy_ok and ca and not state.get("ours"):
            self.banner_text.configure(text="CA 已信任，代理运行中。可启用 Windows 系统代理，或把环境变量脚本注入到 AI Agent 启动终端。")
        elif proxy_ok and ca and state.get("ours"):
            self.banner_text.configure(text="正在捕获 Windows 当前用户流量。打开审计控制台查看请求、风险与证据链。" + guard_note)
        elif not proxy_ok:
            self.banner_text.configure(text="本地代理未运行，控制台仍可打开，但无法捕获流量。请检查日志后重启应用。")

    # ---------- actions ----------
    def _open_dashboard(self) -> None:
        self.app.open_dashboard()

    def _open_intro(self) -> None:
        if self.app.web.port:
            webbrowser.open(f"http://127.0.0.1:{self.app.web.port}/intro")

    def _enable_proxy(self) -> None:
        if not messagebox.askyesno(
            "启用系统代理",
            "将把当前 Windows 用户的系统代理设置为 EgressScope。\n\n"
            "仅覆盖使用 WinINet/WinHTTP/系统代理的应用（多数浏览器与部分桌面应用），"
            "不覆盖服务、SYSTEM 进程和忽略系统代理的程序。\n\n"
            "HTTPS 正文审计还需要安装本地 CA。Windows 会把系统代理设置持久保存；"
            "正常退出、关机或注销时会自动恢复原设置，崩溃或断电则由断网保护恢复。\n\n继续？",
            icon="warning",
        ):
            return
        try:
            result = self.app.enable_system_proxy()
        except Exception as exc:
            messagebox.showerror("启用失败", str(exc))
            self._refresh_once()
            return

        guard_ok = False
        guard_error = ""
        confirmed, want_guard = self._ask_with_check(
            "启用断网保护（推荐，默认开启）",
            "是否为当前用户注册断网保护看门狗？\n\n"
            "只创建一个不需要管理员权限的计划任务：登录时以及每 2 分钟检查一次本机代理，"
            "若代理已停止（崩溃、强制结束或断电重启），自动恢复启用前的系统代理。\n\n"
            "如果不启用，异常退出后 Windows 可能仍指向已停止的本地代理，导致无法上网。",
            "注册断网保护看门狗（推荐）",
            True,
        )
        if confirmed and want_guard:
            try:
                guard = self.app.install_proxy_guard()
                guard_ok = bool(guard.get("ok"))
                if not guard_ok:
                    errors = [
                        str((guard.get("recovery_task") or {}).get("message") or "").strip(),
                        str((guard.get("audit_task") or {}).get("message") or "").strip(),
                    ]
                    guard_error = "\n".join(e for e in errors if e)[:800]
            except Exception as exc:
                guard_error = str(exc)
        elif not confirmed:
            self._refresh_once()
            return

        autostart = (self.app.status_snapshot().get("autostart") or {})
        base = (
            f"代理地址：127.0.0.1:{result.get('port')}\n"
            f"通知 WinINet：{'成功' if result.get('notified') else '未确认'}\n"
            f"断网保护：{'已启用（每 2 分钟守护）' if guard_ok else '未启用'}\n"
            f"开机自启：{'已注册（登录时启动）' if autostart.get('enabled') else '未注册'}\n\n"
            "如果浏览器未生效，请重新打开浏览器，或使用 Agent 环境变量方式。"
        )
        if guard_ok:
            messagebox.showinfo("系统代理已启用", base)
        elif guard_error:
            messagebox.showwarning(
                "系统代理已启用，断网保护未启用",
                base + "\n\n断网保护注册失败：\n" + guard_error +
                "\n\n仍可通过“恢复原始系统代理”按钮，或运行 EgressScope.exe --restore-proxy 恢复网络。",
            )
        else:
            messagebox.showwarning(
                "系统代理已启用，但无断网保护",
                base + "\n\n崩溃、强制结束或断电后，Windows 可能仍指向已停止的代理，需要手动恢复。"
                "可随时运行 EgressScope.exe --restore-proxy，或在 Windows 设置 → 网络和 Internet → 代理 中关闭手动代理。",
            )
        self._refresh_once()

    def _restore_proxy(self) -> None:
        if not messagebox.askyesno(
            "恢复系统代理",
            "将把 Windows 当前用户代理恢复为 EgressScope 启用前的状态。\n"
            "断网保护看门狗任务也会一并移除；开机自启保持不变，可随时单独关闭。\n\n继续？",
        ):
            return
        try:
            result = self.app.restore_system_proxy()
            if (result.get("guard") or {}).get("ok") is False:
                messagebox.showwarning(
                    "代理已恢复，任务未完全移除",
                    "系统代理已恢复；部分断网保护计划任务可能仍在。\n"
                    "可在“任务计划程序”中删除 EgressScope Proxy Recovery 与 EgressScope Audit。",
                )
            else:
                messagebox.showinfo("已恢复", "系统代理设置与断网保护任务已恢复/移除。")
        except Exception as exc:
            messagebox.showerror("恢复失败", str(exc))
        self._refresh_once()

    def _install_ca(self) -> None:
        if not messagebox.askyesno(
            "安装本地 CA",
            "EgressScope 将生成并安装一个仅用于本机审计的根证书到“当前用户”的受信任根存储。\n\n"
            "这意味着：本机应用（信任该存储的应用）与 EgressScope 之间的 HTTPS 可被解密审计。\n"
            "请只在你自己拥有或获授权审计的设备上这样做。CA 私钥只保存在本机数据目录，切勿分享。\n\n"
            "Windows 可能弹出安全警告，请确认证书名称为 EgressScope Local Audit CA。\n\n继续安装？",
            icon="warning",
        ):
            return
        try:
            result = self.app.install_ca()
            if result.get("ok") and result.get("installed"):
                messagebox.showinfo("CA 已安装", "本地 CA 已加入当前用户受信任根。现在可启用系统代理或使用 Agent 环境变量。")
            else:
                messagebox.showwarning("安装结果未确认", str(result.get("message") or "请检查是否取消了 Windows 安全警告。")[:800])
        except Exception as exc:
            messagebox.showerror("安装失败", str(exc))
        self._refresh_once()

    def _remove_ca(self) -> None:
        if not messagebox.askyesno(
            "移除本地 CA",
            "将从当前用户受信任根中移除 EgressScope CA。\n"
            "移除后，HTTPS 内容审计将失效，直到重新安装。\n\n继续？",
            icon="warning",
        ):
            return
        try:
            result = self.app.remove_ca()
            if result.get("installed"):
                messagebox.showwarning("未移除", "证书仍存在，可能被取消或需要权限。")
            else:
                messagebox.showinfo("已移除", "EgressScope CA 已从当前用户受信任根移除。")
        except Exception as exc:
            messagebox.showerror("移除失败", str(exc))
        self._refresh_once()

    def _copy_env(self) -> None:
        try:
            path = self.app.write_env_script()
            text = self.app.env_text()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo(
                "Agent 环境变量已复制",
                "已复制到剪贴板，并写入：\n" + str(path) + "\n\n"
                "在启动 AI Agent 的终端先运行该脚本，或把变量注入 IDE/Agent 启动环境。\n"
                "这会同时设置 NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE / SSL_CERT_FILE，"
                "使 Python、Node.js 与 curl 信任审计 CA。",
            )
        except Exception as exc:
            messagebox.showerror("生成失败", str(exc))

    def _export(self) -> None:
        target = filedialog.asksaveasfilename(
            title="导出审计证据",
            defaultextension=".jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")],
            initialfile="egressscope-evidence.jsonl",
            initialdir=str(self.app.paths.exports),
        )
        if not target:
            return
        try:
            result = self.app.export_evidence(Path(target))
            messagebox.showinfo(
                "导出完成",
                f"已导出 {result.get('flows', 0)} 条流量记录。\n"
                f"证据链校验：{'通过' if result.get('chain_valid') else '未通过'}\n\n"
                f"{result.get('path')}\n\n注意：导出内容包含脱敏预览与元数据，不包含原始加密正文。",
            )
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))

    def _toggle_capture(self) -> None:
        try:
            self.app.update_settings({"capture_enabled": not self.app.settings.capture_enabled})
        except Exception as exc:
            messagebox.showerror("操作失败", str(exc))
        self._refresh_once()

    def _toggle_autostart(self) -> None:
        next_value = not self.app.settings.autostart_enabled
        if not next_value and not messagebox.askyesno(
            "关闭开机自启",
            "将移除当前用户的登录自启注册表项。\n\n"
            "关闭后，重启电脑不会自动启动 EgressScope；若此时系统代理仍指向本工具，"
            "断网保护看门狗会在登录后恢复原始代理。",
        ):
            return
        try:
            self.app.update_settings({"autostart_enabled": next_value})
        except Exception as exc:
            messagebox.showerror("操作失败", str(exc))
        self._refresh_once()

    def _toggle_guard(self) -> None:
        guard = (self.app.status_snapshot().get("proxy_guard") or {})
        if guard.get("installed"):
            if not messagebox.askyesno("移除断网保护", "将删除当前用户的看门狗计划任务。\n\n崩溃或断电后，系统代理将不再自动恢复。继续？"):
                return
            try:
                result = self.app.proxy_guard_remove()
            except Exception as exc:
                messagebox.showerror("操作失败", str(exc))
                self._refresh_once()
                return
            if not result.get("ok"):
                messagebox.showwarning("移除未完成", "可在任务计划程序中手动删除 EgressScope Proxy Recovery。")
        else:
            if not messagebox.askyesno(
                "注册断网保护",
                "为当前用户创建看门狗计划任务（不需要管理员权限）：\n"
                "登录时以及每 2 分钟检查本机代理，代理已停止时自动恢复原始系统代理。",
            ):
                return
            try:
                result = self.app.install_proxy_guard()
            except Exception as exc:
                messagebox.showerror("操作失败", str(exc))
                self._refresh_once()
                return
            if not result.get("ok"):
                messagebox.showwarning("注册失败", str((result.get("recovery_task") or {}).get("message") or "")[:600])
        self._refresh_once()

    def _ask_with_check(self, title: str, message: str, check_text: str, checked: bool = True) -> tuple[bool, bool]:
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        box = tk.Frame(dialog, bg=BG)
        box.pack(fill=BOTH, expand=True, padx=22, pady=18)
        tk.Label(box, text=title, bg=BG, fg=TEXT, font=(FONT, 12, "bold")).pack(anchor="w")
        tk.Label(box, text=message, bg=BG, fg=MUTED, font=(FONT, 10), justify="left", wraplength=520).pack(
            anchor="w", pady=(10, 12)
        )
        var = tk.BooleanVar(value=checked)
        check = tk.Checkbutton(
            box,
            text=check_text,
            variable=var,
            bg=BG,
            fg=TEXT,
            selectcolor=PANEL_2,
            activebackground=BG,
            activeforeground=TEXT,
            highlightthickness=0,
            font=(FONT, 10),
        )
        check.pack(anchor="w")
        result = {"ok": False}

        def finish(ok: bool) -> None:
            result["ok"] = ok
            dialog.destroy()

        buttons = tk.Frame(box, bg=BG)
        buttons.pack(fill=X, pady=(16, 0))
        tk.Button(
            buttons, text="确定", command=lambda: finish(True), bg=ACCENT, fg=ACCENT_DARK,
            relief="flat", bd=0, font=(FONT, 10), padx=18, pady=8, cursor="hand2",
        ).pack(side=LEFT)
        tk.Button(
            buttons, text="取消", command=lambda: finish(False), bg=PANEL_2, fg=TEXT,
            relief="flat", bd=0, font=(FONT, 10), padx=18, pady=8, cursor="hand2",
        ).pack(side=LEFT, padx=(8, 0))
        dialog.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        dialog.update_idletasks()
        dialog.geometry(f"+{self.root.winfo_x() + 90}+{self.root.winfo_y() + 140}")
        self.root.wait_window(dialog)
        return result["ok"], bool(var.get())

    def _open_data(self) -> None:
        try:
            self.app.open_data_dir()
        except Exception as exc:
            messagebox.showerror("打开失败", str(exc))

    def _refresh_once(self) -> None:
        try:
            self._apply_status(self.app.status_snapshot())
        except Exception:
            pass

    # ---------- lifecycle ----------
    def _on_close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self.banner_text.configure(text="正在停止代理并恢复系统代理…")
        self.root.update_idletasks()
        self.app.stop()
        self.root.destroy()

    def start_minimized(self) -> None:
        try:
            self.root.iconify()
        except Exception:
            pass

    def run(self) -> None:
        self.root.mainloop()
