#!/bin/sh

# Use environment variables with defaults
PID_FILE=${GALEPROXY_PID_FILE:-/var/run/galeproxy.pid}
LOG_FILE=${GALEPROXY_LOG_FILE:-/var/log/galeproxy.log}
CONFIG_PATH=${CONFIG_PATH:-/root/config.yaml}
BINARY_PATH=${GALEPROXY_BINARY:-/root/galeproxy}

start() {
    if [ -f "$PID_FILE" ]; then
        echo "GaleProxy is already running with PID $(cat "$PID_FILE")"
        exit 1
    fi
    echo "Starting GaleProxy..."
    nohup "$BINARY_PATH" "$CONFIG_PATH" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "GaleProxy started successfully with PID $(cat "$PID_FILE")"
    else
        echo "Failed to start GaleProxy. Check logs at $LOG_FILE"
        rm -f "$PID_FILE"
        exit 1
    fi
}

stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "GaleProxy is not running"
        exit 1
    fi
    PID=$(cat "$PID_FILE")
    echo "Stopping GaleProxy (PID: $PID)..."
    kill -TERM "$PID"
    sleep 1
    if kill -0 "$PID" 2>/dev/null; then
        echo "Force stopping GaleProxy..."
        kill -KILL "$PID"
    fi
    rm -f "$PID_FILE"
    echo "GaleProxy stopped"
}

restart() {
    if [ -f "$PID_FILE" ]; then
        stop
        sleep 1
    fi
    start
}

logs() {
    if [ -f "$LOG_FILE" ]; then
        cat "$LOG_FILE"
    else
        echo "No logs available yet. Start GaleProxy first."
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    logs)
        logs
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|logs}"
        echo "  start   - Start the GaleProxy service"
        echo "  stop    - Stop the GaleProxy service"
        echo "  restart - Restart the GaleProxy service"
        echo "  logs    - View GaleProxy logs"
        exit 1
        ;;
esac

exit 0