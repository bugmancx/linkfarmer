import asyncio
import os
import re
import socket
import threading
import nextcord
import logging
import json
import hashlib
from collections import deque
from nextcord.ext import commands, tasks
import urllib.parse
from datetime import datetime, timezone
from prometheus_client import Counter, Gauge, make_wsgi_app
from wsgiref.simple_server import make_server, WSGIServer, WSGIRequestHandler
from socketserver import ThreadingMixIn
import aiohttp

# Define environment variables for bot configuration
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
URL_LOG = os.getenv('LOG_FILE', '/data/log/url_log.txt')
JDOWNLOADER = os.getenv('JDOWNLOADER', 'false')
JDOWNLOADER_CRAWLJOB_PATH = os.getenv('JDOWNLOADER_CRAWLJOB_PATH', '/data/crawljobs')
JDOWNLOADER_ADDED_PATH = os.getenv('JDOWNLOADER_ADDED_PATH', os.path.join(JDOWNLOADER_CRAWLJOB_PATH, 'added'))
JDOWNLOADER_OUTPUT_PATH = os.getenv('JDOWNLOADER_OUTPUT_PATH', '/data/output')  # Default to '/output' if not provided
DISCORD_CHANNELS = os.getenv('DISCORD_CHANNELS', '')
EXCLUDED_DOMAINS = os.getenv('EXCLUDED_DOMAINS', '')
METRICS_PORT = int(os.getenv('METRICS_PORT', '9105'))
METRICS_ADDR = os.getenv('METRICS_ADDR', '0.0.0.0')
RECENT_GRABS_FILE = os.getenv('RECENT_GRABS_FILE', '/data/state/recent_grabs.json')
RECENT_GRABS_MAX = int(os.getenv('RECENT_GRABS_MAX', '40'))
MISSED_MESSAGE_HISTORY_LIMIT = int(os.getenv('MISSED_MESSAGE_HISTORY_LIMIT', '200'))

# Convert excluded domains from string to a set
excluded_domains = set(domain.strip() for domain in EXCLUDED_DOMAINS.split(',') if domain.strip())

# Create bot with appropriate intents
intents = nextcord.Intents.default()
intents.messages = True
intents.message_content = True  # Enable message content intent to access message content
bot = commands.Bot(command_prefix='!', intents=intents)

# Convert the channel list to a set of integers (channel IDs)
monitored_channels = set(int(cid) for cid in DISCORD_CHANNELS.split(',') if cid.strip().isdigit())
allow_all_channels = not monitored_channels
LAST_SEEN_MESSAGE_ID = {}
_has_connected_once = False


def _channel_label(cid: int) -> str:
    chan = bot.get_channel(cid)
    if chan and getattr(chan, 'name', None):
        guild_part = f"{chan.guild.name} / " if getattr(chan, 'guild', None) and getattr(chan.guild, 'name', None) else ''
        category_part = ''
        if getattr(chan, 'category', None) and getattr(chan.category, 'name', None):
            category_part = f"{chan.category.name} / "
        return f"{guild_part}{category_part}{chan.name} ({cid})"
    return str(cid)


def _channel_metric_label(channel) -> str:
    """Format channel label for metrics: Category / channel-name"""
    if not channel:
        return 'unknown'
    category_part = f"{channel.category.name} / " if getattr(channel, 'category', None) and getattr(channel.category, 'name', None) else ''
    return f"{category_part}{channel.name}"

# Set up logging to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Quiet noisy library logs (Discord gateway/connect chatter)
logging.getLogger('nextcord').setLevel(logging.ERROR)
logging.getLogger('discord').setLevel(logging.ERROR)
logging.getLogger('websockets').setLevel(logging.WARNING)

# Prometheus metrics
MESSAGE_TOTAL = Counter(
    'linkfarmer_message_total', 'Total Discord messages observed', ['channel', 'has_url']
)
SUBMISSIONS_TOTAL = Counter(
    'linkfarmer_submissions_total', 'Messages with at least one URL, by user', ['user']
)
URLS_EXTRACTED_TOTAL = Counter(
    'linkfarmer_urls_extracted_total', 'URLs extracted from messages', ['domain', 'status']
)
CRAWLJOB_CREATED_TOTAL = Counter(
    'linkfarmer_crawljob_created_total', 'Crawljobs created by domain', ['domain']
)
EXCLUDED_DOMAIN_TOTAL = Counter(
    'linkfarmer_excluded_domain_total', 'URLs skipped due to excluded domain', ['domain']
)
MALFORMED_URL_TOTAL = Counter(
    'linkfarmer_malformed_url_total', 'URLs rejected during extraction'
)
INPUT_FILE_PROCESSED_TOTAL = Counter(
    'linkfarmer_input_file_processed_total', 'Input file processing runs'
)
INPUT_FILE_LINES_TOTAL = Counter(
    'linkfarmer_input_file_lines_total', 'Lines processed from input file'
)
CRAWLJOB_QUEUE_FILES = Gauge(
    'linkfarmer_crawljob_queue_files', 'Current crawljob files in folderwatch'
)
RECENT_GRABS = deque(maxlen=RECENT_GRABS_MAX)
RECENT_GRABS_INFO = Gauge(
    'linkfarmer_recent_grab_info',
    'Most recent crawljobs (persisted)',
    ['timestamp', 'user', 'filename', 'status', 'channel', 'url', 'message', 'picked_up'],
)
RECONNECT_TOTAL = Counter(
    'linkfarmer_gateway_reconnect_total', 'Discord reconnect attempts', ['reason']
)
EVENT_LOOP_LAG_SECONDS = Gauge(
    'linkfarmer_event_loop_lag_seconds', 'Observed event loop lag in seconds'
)
WS_LATENCY_SECONDS = Gauge(
    'linkfarmer_ws_latency_seconds', 'Discord websocket latency in seconds'
)
WS_LATENCY_RECONNECT_THRESHOLD = float(os.getenv('WS_LATENCY_RECONNECT_THRESHOLD', '30'))

INPUT_FILE = os.getenv('INPUT_FILE', '/data/input/input_urls.txt')


def ensure_input_file_exists():
    input_dir = os.path.dirname(INPUT_FILE)
    if input_dir:
        os.makedirs(input_dir, exist_ok=True)
    if not os.path.exists(INPUT_FILE):
        open(INPUT_FILE, 'a').close()


def ensure_recent_grabs_file_exists():
    directory = os.path.dirname(RECENT_GRABS_FILE)
    if directory:
        os.makedirs(directory, exist_ok=True)
    if not os.path.exists(RECENT_GRABS_FILE):
        with open(RECENT_GRABS_FILE, 'w') as file:
            json.dump([], file)


def _resolved_added_path(filename: str) -> str:
    return os.path.join(JDOWNLOADER_ADDED_PATH, filename)


def _resolve_status(entry: dict) -> str:
    filename = entry.get('filename')
    added_path = entry.get('added_path') or ( _resolved_added_path(filename) if filename else None)
    pending_path = entry.get('path')

    try:
        if added_path and os.path.exists(added_path):
            return 'passed'
        if pending_path and os.path.exists(pending_path):
            return 'added'
    except Exception as exc:  # pragma: no cover - best-effort status resolution
        logging.debug(f'Failed to resolve status for {filename}: {exc}')

    return entry.get('status', 'unknown')


def _label_value(value, max_len=300) -> str:
    if value is None:
        return ''
    text = str(value).replace('\n', ' ').strip()
    if len(text) > max_len:
        return text[: max_len - 3] + '...'
    return text


def persist_recent_grabs():
    ensure_recent_grabs_file_exists()
    payload = []
    for entry in list(RECENT_GRABS):
        payload.append({
            "ts": entry.get('ts', datetime.now()).isoformat(),
            "user": entry.get('user', ''),
            "channel": entry.get('channel', ''),
            "url": entry.get('url', ''),
            "message": entry.get('message', ''),
            "filename": entry.get('filename', ''),
            "path": entry.get('path', ''),
            "added_path": entry.get('added_path', ''),
            "status": _resolve_status(entry),
        })

    payload = payload[:RECENT_GRABS_MAX]
    with open(RECENT_GRABS_FILE, 'w') as file:
        json.dump(payload, file, indent=2)


def load_recent_grabs():
    ensure_recent_grabs_file_exists()
    try:
        with open(RECENT_GRABS_FILE, 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        logging.warning('recent grabs file is corrupt; resetting %s', RECENT_GRABS_FILE)
        data = []
    except FileNotFoundError:
        data = []

    RECENT_GRABS.clear()
    for raw in data[-RECENT_GRABS_MAX:][::-1]:
        ts_raw = raw.get('ts')
        try:
            ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.now()
        except ValueError:
            ts = datetime.now()

        RECENT_GRABS.appendleft({
            "ts": ts,
            "user": raw.get('user', ''),
            "channel": raw.get('channel', ''),
            "url": raw.get('url', ''),
            "message": raw.get('message', ''),
            "filename": raw.get('filename', ''),
            "path": raw.get('path', ''),
            "added_path": raw.get('added_path', ''),
            "status": raw.get('status', 'unknown'),
        })

    update_recent_grabs_metric()


# Expose Prometheus metrics endpoint with a /healthz handler
class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, format, *args):  # pragma: no cover - quiet server logs
        return


def _health_metrics_app(environ, start_response):
    if environ.get('PATH_INFO') == '/healthz':
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [b'ok']
    return _metrics_app(environ, start_response)


_metrics_app = make_wsgi_app()


def start_metrics_server(addr: str, port: int):
    httpd = make_server(addr, port, _health_metrics_app, server_class=_ThreadingWSGIServer, handler_class=_QuietHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    logging.info(f'Started metrics/health server on {addr}:{port} (paths: /metrics, /healthz)')
    return httpd


start_metrics_server(METRICS_ADDR, METRICS_PORT)
CRAWLJOB_QUEUE_FILES.set(0)
ensure_input_file_exists()

@bot.event
async def on_ready():
    global _has_connected_once
    logging.info(f'Logged in as {bot.user}')
    if allow_all_channels:
        logging.info('DISCORD_CHANNELS not set; listening to all channels bot can access.')
    else:
        labels = [_channel_label(cid) for cid in sorted(monitored_channels)]
        logging.info('Monitoring channels:\n%s', '\n'.join(f' - {label}' for label in labels))
    # Load persisted grabs once the bot is ready so the data survives restarts.
    await asyncio.to_thread(load_recent_grabs)
    if not poll_input_file.is_running():
        poll_input_file.start()
    if not refresh_recent_grabs_from_disk.is_running():
        refresh_recent_grabs_from_disk.start()

    if _has_connected_once:
        await catch_up_missed_messages(reason='ready')
    else:
        _has_connected_once = True


def _hash_suffix(text: str, length: int = 8) -> str:
    return hashlib.sha1(text.encode('utf-8')).hexdigest()[:length]


def sanitize_filename(raw: str, max_length: int = 128) -> str:
    sanitized = re.sub(r'^https?://', '', raw)
    sanitized = sanitized.replace('/', '_')
    sanitized = re.sub(r'[^\w\.\-]', '_', sanitized)
    sanitized = re.sub(r'__+', '_', sanitized).strip('._')

    if not sanitized:
        sanitized = 'file'

    if len(sanitized) <= max_length:
        return sanitized

    suffix = _hash_suffix(sanitized)
    keep = max(1, max_length - len(suffix) - 1)
    return f"{sanitized[:keep]}-{suffix}"


def make_crawljob_names(username: str, source_text: str, max_component_length: int = 200):
    # Keep the filename component well below common FS limits and account for username + extension.
    base_max = max_component_length - len(username) - len('.crawljob') - 1
    base_max = max(16, base_max)

    sanitized = sanitize_filename(source_text, max_length=base_max)
    crawljob_filename = f'{username}-{sanitized}.crawljob'
    package_name = crawljob_filename[:-len('.crawljob')]
    return crawljob_filename, package_name

# Add this function to handle reading and processing URLs from the input file
def process_input_file():
    ensure_input_file_exists()

    with open(INPUT_FILE, 'r') as file:
        lines = file.readlines()

    # Clear the file after reading its contents
    with open(INPUT_FILE, 'w') as file:
        pass

    if not lines:
        return  # No content to process

    INPUT_FILE_PROCESSED_TOTAL.inc()
    INPUT_FILE_LINES_TOTAL.inc(len(lines))
    logging.debug(f"Processing URLs from {INPUT_FILE}")
    for line in lines:
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F])|[#])+', line)
        if urls:
            SUBMISSIONS_TOTAL.labels(user='InputFileUser').inc()
            processed_urls = []
            for url in urls:
                processed_urls.append(
                    process_url(url, 'InputFileUser', 'file', line.strip(), 'input_file')
                )

            excluded_urls = [entry["url"] for entry in processed_urls if entry["status"] == "excluded"]
            crawljob_files = [entry["crawljob"] for entry in processed_urls if entry["crawljob"]]

            logging.info(
                "message user=%s channel=%s urls=%s crawljobs=%s excluded=%s content=%s",
                'InputFileUser',
                'input_file',
                urls if urls else [],
                crawljob_files,
                excluded_urls,
                line.strip(),
            )


def process_urls_batch(urls, username, uid, message_content, channel_label=None):
    processed_urls = []
    for url in urls:
        processed_urls.append(
            process_url(url, username, uid, message_content, channel_label)
        )
    return processed_urls


def extract_urls(message_content):
    """
    Extract valid URLs from message content using refined regex and validation.
    Returns (valid_urls, malformed_count).
    """
    raw_urls = re.findall(r'https?://[^\s<>")]+', message_content)
    valid_urls = [url.strip() for url in raw_urls if is_valid_url(url)]
    malformed_count = len(raw_urls) - len(valid_urls)
    return valid_urls, malformed_count


def is_valid_url(url):
    """
    Validate the structure of the URL.
    """
    parsed = urllib.parse.urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def process_url(url, username, uid, message_content, channel_label=None):
    result = {
        "url": url,
        "status": "logged_only",
        "crawljob": None,
        "crawljob_path": None,
    }

    # Check if the URL domain is excluded
    domain = re.search(r'https?://([^/]+)', url).group(1)
    if domain in excluded_domains:
        result["status"] = "excluded"
        EXCLUDED_DOMAIN_TOTAL.labels(domain=domain).inc()
        URLS_EXTRACTED_TOTAL.labels(domain=domain, status='excluded').inc()
        logging.debug(f'URL {url} is excluded and will not be processed.')
        return result  # Skip processing if the domain is excluded

    log_entry = f'{datetime.now()} - {username} ({uid}): {url}'

    # Log URL to url_log.txt file
    with open(URL_LOG, 'a') as file:
        file.write(f'{log_entry}\n')

    URLS_EXTRACTED_TOTAL.labels(domain=domain, status='processed').inc()

    if JDOWNLOADER.lower() == 'true':
        # Determine if message content is just the URL or more
        if message_content.strip() == url:
            # Use the sanitized URL as the filename
            sanitized_url = url.replace('https://', '').replace('http://', '')
            sanitized_url = sanitized_url.replace('/', '_')  # Replace slashes with underscores
            sanitized_url = sanitize_filename(sanitized_url)  # Apply filename sanitization
            crawljob_filename, package_name = make_crawljob_names(username, sanitized_url)
        else:
            # Sanitize the message content to create a valid filename
            crawljob_filename, package_name = make_crawljob_names(username, message_content)

        # Construct crawljob content
        crawljob_content = [{
            "text": url,
            "downloadFolder": JDOWNLOADER_OUTPUT_PATH,
            "autoStart": "TRUE",
            "autoConfirm": "TRUE",
            "enabled": "TRUE",
            "packageName": package_name,
            "overwritePackagizerEnabled": True
        }]

        # Write crawljob content to file
        crawljob_file = os.path.join(JDOWNLOADER_CRAWLJOB_PATH, crawljob_filename)
        os.makedirs(JDOWNLOADER_CRAWLJOB_PATH, exist_ok=True)
        with open(crawljob_file, 'w') as file:
            file.write(json.dumps(crawljob_content, indent=4))

        result["status"] = "crawljob_created"
        result["crawljob"] = crawljob_filename
        result["crawljob_path"] = crawljob_file
        CRAWLJOB_CREATED_TOTAL.labels(domain=domain).inc()
        update_crawljob_queue_gauge()
        remember_recent_grab(username, crawljob_filename, crawljob_file, url, message_content, channel_label)

    return result


def update_crawljob_queue_gauge():
    try:
        if not os.path.exists(JDOWNLOADER_CRAWLJOB_PATH):
            CRAWLJOB_QUEUE_FILES.set(0)
            return
        files = [f for f in os.listdir(JDOWNLOADER_CRAWLJOB_PATH) if f.endswith('.crawljob')]
        CRAWLJOB_QUEUE_FILES.set(len(files))
    except Exception as exc:  # pragma: no cover - best-effort metric update
        logging.debug(f'Failed to update crawljob queue gauge: {exc}')


def remember_recent_grab(username, filename, path, url, message_content, channel_label=None):
    entry = {
        "ts": datetime.now(),
        "user": username,
        "channel": channel_label or 'unknown',
        "url": url,
        "message": message_content,
        "filename": filename,
        "path": path,
        "added_path": _resolved_added_path(filename),
        "status": 'added',
    }

    RECENT_GRABS.appendleft(entry)
    while len(RECENT_GRABS) > RECENT_GRABS_MAX:
        RECENT_GRABS.pop()

    persist_recent_grabs()
    update_recent_grabs_metric()


def update_recent_grabs_metric():
    try:
        RECENT_GRABS_INFO.clear()
        for entry in RECENT_GRABS:
            status = _resolve_status(entry)
            picked = status == 'passed'
            ts_label = entry["ts"].strftime("%b %d %H:%M")
            RECENT_GRABS_INFO.labels(
                timestamp=ts_label,
                user=_label_value(entry.get("user")),
                filename=_label_value(entry.get("filename")),
                status=_label_value(status),
                channel=_label_value(entry.get("channel")),
                url=_label_value(entry.get("url")),
                message=_label_value(entry.get("message")),
                picked_up=str(picked).lower(),
            ).set(1)
            entry["status"] = status
    except Exception as exc:  # pragma: no cover - best-effort metric update
        logging.debug(f'Failed to update recent grabs metric: {exc}')


@tasks.loop(seconds=5.0)
async def monitor_loop_health():
    loop = asyncio.get_running_loop()
    start = loop.time()
    await asyncio.sleep(1)
    end = loop.time()
    lag = max(0.0, (end - start) - 1.0)
    EVENT_LOOP_LAG_SECONDS.set(lag)

    ws_latency = getattr(bot, 'latency', None)
    if ws_latency is not None:
        WS_LATENCY_SECONDS.set(ws_latency)

    if lag > 5:
        logging.warning('Event loop lag %.1fs; possible host contention or blocking operations', lag)

    if ws_latency is not None and ws_latency > WS_LATENCY_RECONNECT_THRESHOLD:
        logging.error(
            'Websocket latency %.1fs exceeds threshold %.1fs (container pause/network issue)',
            ws_latency,
            WS_LATENCY_RECONNECT_THRESHOLD,
        )


@tasks.loop(seconds=30.0)
async def refresh_recent_grabs_from_disk():
    await asyncio.to_thread(update_recent_grabs_metric)
    await asyncio.to_thread(persist_recent_grabs)


@refresh_recent_grabs_from_disk.before_loop
async def before_refresh_recent_grabs_from_disk():
    await bot.wait_until_ready()


@bot.event
async def on_disconnect():
    logging.warning('Discord gateway disconnected; waiting to resume...')


@bot.event
async def on_resumed():
    logging.warning('Discord session resumed; scanning for missed messages...')
    await catch_up_missed_messages(reason='resume')


async def handle_incoming_message(message, *, from_history: bool = False):
    if message.author == bot.user:
        return

    if not allow_all_channels and message.channel.id not in monitored_channels:
        return

    if not from_history:
        await asyncio.to_thread(process_input_file)

    urls, malformed_count = extract_urls(message.content)
    if malformed_count:
        MALFORMED_URL_TOTAL.inc(malformed_count)

    channel_label = _channel_metric_label(message.channel)
    MESSAGE_TOTAL.labels(channel=channel_label, has_url=str(bool(urls)).lower()).inc()
    processed_urls = []
    if urls:
        SUBMISSIONS_TOTAL.labels(user=message.author.name).inc()
        processed_urls = await asyncio.to_thread(
            process_urls_batch, urls, message.author.name, message.author.id, message.content, channel_label
        )

    excluded_urls = [entry["url"] for entry in processed_urls if entry["status"] == "excluded"]
    crawljob_files = [entry["crawljob"] for entry in processed_urls if entry["crawljob"]]

    source = 'history' if from_history else 'live'
    logging.info(
        "message source=%s user=%s channel=%s urls=%s crawljobs=%s excluded=%s content=%s",
        source,
        message.author.name,
        message.channel.name,
        urls if urls else [],
        crawljob_files,
        excluded_urls,
        message.content,
    )

    LAST_SEEN_MESSAGE_ID[message.channel.id] = message.id


async def catch_up_missed_messages(*, reason: str = 'resume'):
    if not LAST_SEEN_MESSAGE_ID:
        return

    cutoff = datetime.now(timezone.utc)

    channel_ids = set(LAST_SEEN_MESSAGE_ID.keys())
    if not allow_all_channels:
        channel_ids |= monitored_channels

    replayed = 0
    for cid in sorted(channel_ids):
        channel = bot.get_channel(cid)
        if not channel:
            continue

        after_id = LAST_SEEN_MESSAGE_ID.get(cid)
        history_kwargs = {
            "limit": MISSED_MESSAGE_HISTORY_LIMIT,
            "oldest_first": True,
            "before": cutoff,
        }
        if after_id:
            history_kwargs["after"] = nextcord.Object(id=after_id)

        async for msg in channel.history(**history_kwargs):
            await handle_incoming_message(msg, from_history=True)
            replayed += 1

    logging.info('Missed message replay complete (reason=%s): %s messages processed', reason, replayed)


async def run_bot_with_resilience():
    max_backoff = 300.0
    backoff = 1.0

    while True:
        try:
            await bot.start(DISCORD_BOT_TOKEN)
            logging.warning('Discord client stopped unexpectedly; reconnecting...')
        except asyncio.CancelledError:
            RECONNECT_TOTAL.labels(reason='cancelled').inc()
            logging.warning('Discord client cancelled; reconnecting...')
        except nextcord.LoginFailure as exc:
            logging.error('Discord login failed (check DISCORD_BOT_TOKEN). Exiting.')
            raise SystemExit(1) from exc
        except nextcord.errors.ConnectionClosed as exc:
            RECONNECT_TOTAL.labels(reason='connection_closed').inc()
            logging.warning(
                'Discord websocket closed (code=%s shard=%s); retrying in %.1fs',
                getattr(exc, 'code', None),
                getattr(exc, 'shard_id', None),
                backoff,
            )
        except (aiohttp.ClientConnectorError, aiohttp.ClientConnectorSSLError, aiohttp.ClientConnectorCertificateError,
                aiohttp.ClientConnectorDNSError, socket.gaierror) as exc:
            RECONNECT_TOTAL.labels(reason='network').inc()
            logging.warning('Discord network/DNS issue, retrying in %.1fs: %s', backoff, exc)
        except Exception as exc:  # pragma: no cover - defensive safety net
            RECONNECT_TOTAL.labels(reason='other').inc()
            logging.exception('Discord client crashed, retrying in %.1fs', backoff)

        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, max_backoff)


@tasks.loop(seconds=15.0)
async def poll_input_file():
    # Periodically process any manually added URLs
    await asyncio.to_thread(process_input_file)


@poll_input_file.before_loop
async def before_poll_input_file():
    await bot.wait_until_ready()
    ensure_input_file_exists()

@bot.event
async def on_message(message):
    await handle_incoming_message(message)

if not DISCORD_BOT_TOKEN:
    logging.error('DISCORD_BOT_TOKEN is not set; exiting.')
else:
    try:
        asyncio.run(run_bot_with_resilience())
    except KeyboardInterrupt:
        logging.info('Shutdown requested, exiting.')