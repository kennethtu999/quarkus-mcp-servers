#!/bin/sh
# macOS / Linux onboarding; passwords are read only by the gateway's terminal prompt.
set -eu
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

ask() {
    printf '%s' "$1"
    IFS= read -r ANSWER || { printf '\n已取消。\n' >&2; exit 1; }
}

if [ "${1:-}" = "--help" ]; then
    printf '用法：sh onboarding.sh\n顯示 DB 狀態、貼上設定、驗證，可選註冊預設 client。需 Java 17+ 與 Python 3。\n'
    exit 0
fi
if [ "$#" -ne 0 ]; then
    printf '不支援此參數；請執行 sh onboarding.sh。\n' >&2
    exit 1
fi
if [ ! -t 0 ]; then
    printf '請在互動式終端機執行：sh onboarding.sh\n' >&2
    exit 1
fi
command -v python3 >/dev/null || { printf '請先安裝 Python 3（用於狀態與連線驗證）。\n' >&2; exit 1; }
if [ -n "${JAVA_HOME:-}" ]; then
    JAVA="$JAVA_HOME/bin/java"
else
    JAVA=$(command -v java) || { printf '請先安裝 Java 17+。\n' >&2; exit 1; }
fi
"$JAVA" -version || exit 1
if [ ! -f "$APP_DIR/lib/ai-db-mcp.jar" ]; then
    printf '找不到 lib/ai-db-mcp.jar，請解壓完整安裝包。\n' >&2
    exit 1
fi
# Also checks that the installed Java can load the application classes.
"$JAVA" -jar "$APP_DIR/lib/ai-db-mcp.jar" --help >/dev/null
python3 "$APP_DIR/scripts/onboarding_check.py" "$APP_DIR" "$JAVA" --status

printf '\nAI Database MCP 設定\n預設 READ_ONLY 純查詢；可明確設定 UPDATE 白名單。\n權限範例：%s/sample.yaml\n' "$APP_DIR"
ask '新增／覆蓋 DB 設定？[Y/n]：'
case "$ANSWER" in
    n|N) ;;
    ''|y|Y)
        "$JAVA" -jar "$APP_DIR/lib/ai-db-mcp.jar" init --setup
        ;;
    *) printf '選項無效，已停止。\n' >&2; exit 1 ;;
esac

exec python3 "$APP_DIR/scripts/onboarding_check.py" "$APP_DIR" "$JAVA"
