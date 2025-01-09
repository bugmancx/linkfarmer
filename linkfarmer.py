import os
import re
import nextcord
import logging
import json
from nextcord.ext import commands
from datetime import datetime
import urllib.parse

# Define environment variables for bot configuration
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
URL_LOG = os.getenv('LOG_FILE', '/data/log/url_log.txt')
JDOWNLOADER = os.getenv('JDOWNLOADER', 'false')
JDOWNLOADER_CRAWLJOB_PATH = os.getenv('JDOWNLOADER_CRAWLJOB_PATH', '/data/crawljobs')
JDOWNLOADER_OUTPUT_PATH = os.getenv('JDOWNLOADER_OUTPUT_PATH', '/data/output')
DISCORD_CHANNELS = os.getenv('DISCORD_CHANNELS', '')
EXCLUDED_DOMAINS = os.getenv('EXCLUDED_DOMAINS', '')

# Convert excluded domains from string to a set
excluded_domains = set(domain.strip() for domain in EXCLUDED_DOMAINS.split(',') if domain.strip())

# Create bot with appropriate intents
intents = nextcord.Intents.default()
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Convert the channel list to a set of integers (channel IDs)
monitored_channels = set(int(cid) for cid in DISCORD_CHANNELS.split(',') if cid.strip().isdigit())

# Set up logging to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


@bot.event
async def on_ready():
    logging.info(f'Logged in as {bot.user}')


def sanitize_filename(url, max_length=128):
    # Remove the protocol (http or https) from the URL
    sanitized_url = re.sub(r'^https?://', '', url)
    
    # Replace slashes with underscores
    sanitized_url = sanitized_url.replace('/', '_')

    # Remove problematic characters for filenames
    sanitized_url = re.sub(r'[^\w\.\-]', '_', sanitized_url)
    
    # Remove consecutive underscores
    sanitized_url = re.sub(r'__+', '_', sanitized_url)

    # Ensure filename doesn't exceed max_length (including file extension)
    if len(sanitized_url) > max_length:
        base, ext = os.path.splitext(sanitized_url)
        base = base[:max_length - len(ext)]
        sanitized_url = base + ext

    return sanitized_url


def is_valid_url(url):
    """
    Validate the structure of the URL.
    """
    parsed = urllib.parse.urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def extract_urls(message_content):
    """
    Extract valid URLs from message content using refined regex and validation.
    """
    raw_urls = re.findall(r'https?://[^\s<>"]+', message_content)
    valid_urls = [url for url in raw_urls if is_valid_url(url)]
    return valid_urls


def extract_episode_info(message_content):
    """
    Extract detailed episode information from the message content, including filenames.
    """
    # Look for a detailed string including show name, season/episode, and additional details
    match = re.search(r'(.+?) - S(\d{2})E(\d{2})(?: - (.+?))?', message_content)
    if match:
        # Extract show name, season/episode, and additional details if present
        show_name = match.group(1).strip()
        season_episode = f"S{match.group(2)}E{match.group(3)}"
        episode_name = match.group(4).strip() if match.group(4) else ""
        return f"{show_name} - {season_episode} - {episode_name}".strip(" -")

    # If no match, return the full quoted text string or the entire message
    quoted_match = re.search(r'"([^"]+)"', message_content)  # Look for quoted text
    if quoted_match:
        return quoted_match.group(1).strip()

    return message_content.strip()  # Default to the entire message content

def get_actual_username(username, message_content):
    """
    Determine the actual username to use for logging.
    If the Discord username is 'RelaTVity' and the message contains 'Uploaded by <uploader_name>',
    use the uploader's name instead.
    """
    if username == 'RelaTVity':
        match = re.search(r'Uploaded by (\w+)', message_content)
        if match:
            return match.group(1).strip()
    return username.strip()


def process_input_file():
    INPUT_FILE = os.getenv('INPUT_FILE', '/data/input/input_urls.txt')
    if not os.path.exists(INPUT_FILE):
        return

    with open(INPUT_FILE, 'r') as file:
        lines = file.readlines()

    with open(INPUT_FILE, 'w') as file:
        pass

    if not lines:
        return

    logging.info(f"Processing URLs from {INPUT_FILE}")
    for line in lines:
        urls = extract_urls(line)
        if urls:
            for url in urls:
                process_url(url, 'InputFileUser', 'file', line.strip())


def process_url(url, username, uid, message_content):
    """
    Process a single URL for logging and optional crawljob creation.
    """
    if not is_valid_url(url):
        logging.warning(f"Invalid URL skipped: {url}")
        return

    # Get the actual username and episode info
    actual_username = get_actual_username(username, message_content)
    episode_info = extract_episode_info(message_content)
    
    # Ensure episode_info is cleaned of unnecessary asterisks or formatting markers
    episode_info = episode_info.strip("*").strip()

    log_entry = f'{datetime.now()}|{actual_username}|{url}|{episode_info}'

    # Log the entry to the file
    with open(URL_LOG, 'a') as file:
        file.write(f'{log_entry}\n')

    if JDOWNLOADER.lower() == 'true':
        sanitized_url = sanitize_filename(url)
        crawljob_filename = f'{actual_username}-{sanitized_url}.crawljob'
        package_name = sanitized_url.replace('.crawljob', '')

        logging.info(f'Creating crawljob file {crawljob_filename} for URL {url}')

        crawljob_content = [{
            "text": url,
            "downloadFolder": JDOWNLOADER_OUTPUT_PATH,
            "autoStart": "TRUE",
            "autoConfirm": "TRUE",
            "enabled": "TRUE",
            "packageName": package_name,
            "overwritePackagizerEnabled": True
        }]

        crawljob_file = os.path.join(JDOWNLOADER_CRAWLJOB_PATH, crawljob_filename)
        os.makedirs(JDOWNLOADER_CRAWLJOB_PATH, exist_ok=True)
        with open(crawljob_file, 'w') as file:
            file.write(json.dumps(crawljob_content, indent=4))
            logging.info(f'URL {url} added to crawljob file {crawljob_file}')


@bot.event
async def on_message(message):
    if message.author == bot.user or message.channel.id not in monitored_channels:
        return

    process_input_file()
    urls = extract_urls(message.content)
    if urls:
        for url in urls:
            process_url(url, message.author.name, message.author.id, message.content)

    logging.info(f'User {message.author.name} in channel {message.channel.name} posted: {message.content}')


bot.run(DISCORD_BOT_TOKEN)
