import os
import re
import nextcord
import logging
import json
from nextcord.ext import commands
from datetime import datetime

# Define environment variables for bot configuration
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
URL_LOG = os.getenv('LOG_FILE', '/data/log/url_log.txt')
JDOWNLOADER = os.getenv('JDOWNLOADER', 'false')
JDOWNLOADER_CRAWLJOB_PATH = os.getenv('JDOWNLOADER_CRAWLJOB_PATH', '/data/crawljobs')
JDOWNLOADER_OUTPUT_PATH = os.getenv('JDOWNLOADER_OUTPUT_PATH', '/data/output')  # Default to '/output' if not provided
DISCORD_CHANNELS = os.getenv('DISCORD_CHANNELS', '')
EXCLUDED_DOMAINS = os.getenv('EXCLUDED_DOMAINS', '')

# Convert excluded domains from string to a set
excluded_domains = set(domain.strip() for domain in EXCLUDED_DOMAINS.split(',') if domain.strip())

# Create bot with appropriate intents
intents = nextcord.Intents.default()
intents.messages = True
intents.message_content = True  # Enable message content intent to access message content
bot = commands.Bot(command_prefix='!', intents=intents)

# Convert the channel list to a set of integers (channel IDs)
monitored_channels = set(int(cid) for cid in DISCORD_CHANNELS.split(',') if cid.strip().isdigit())

# Set up logging to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@bot.event
async def on_ready():
    logging.info(f'Logged in as {bot.user}')


def sanitize_filename(url, max_length=255):
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
        # Trim base to fit within the limit, leaving room for the extension
        base = base[:max_length - len(ext)]
        sanitized_url = base + ext

    # Return sanitized and trimmed filename
    return sanitized_url

def process_url(url, username, uid, message_content):
    
    # Check if the URL domain is excluded
    domain = re.search(r'https?://([^/]+)', url).group(1)
    if domain in excluded_domains:
        logging.info(f'URL {url} is excluded and will not be processed.')
        return  # Skip processing if the domain is excluded

    log_entry = f'{datetime.now()} - {username} ({uid}): {url}'

    # Log URL to url_log.txt file
    with open(URL_LOG, 'a') as file:
        file.write(f'{log_entry}\n')

    if JDOWNLOADER.lower() == 'true':
        # Determine if message content is just the URL or more
        if message_content.strip() == url:
            # Use the sanitized URL as the filename
            sanitized_url = url.replace('https://', '').replace('http://', '')
            sanitized_url = sanitized_url.replace('/', '_')  # Replace slashes with underscores
            sanitized_url = sanitize_filename(sanitized_url)  # Apply filename sanitization

            crawljob_filename = f'{username}-{sanitized_url}.crawljob'
            package_name = f'{username}-{sanitized_url}'
        else:
            # Sanitize the message content to create a valid filename
            filename_message_content = sanitize_filename(message_content)
            # Create crawljob file name with username and sanitized message content
            crawljob_filename = f'{username}-{filename_message_content}.crawljob'
            package_name = crawljob_filename.replace('.crawljob', '')

        logging.info(f'Creating crawljob file {crawljob_filename} for URL {url}')

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
            logging.info(f'URL {url} added to crawljob file {crawljob_file}')

@bot.event
async def on_message(message):
    if message.author == bot.user or message.channel.id not in monitored_channels:
        return

    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F])|[#])+', message.content)
    if urls:
        for url in urls:
            process_url(url, message.author.name, message.author.id, message.content)

    # Log message content to console
    logging.info(f'User {message.author.name} in channel {message.channel.name} posted: {message.content}')

bot.run(DISCORD_BOT_TOKEN)
